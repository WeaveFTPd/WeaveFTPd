package core

import (
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

const liveUploadIdleLimit = 30 * time.Second

// Each STOR reservation owns its completion result, including validation. Keep
// this separate from session transfer state, which ends before CRC/ZIP checks.
type uploadPathState struct {
	done      chan struct{}
	once      sync.Once
	succeeded bool // published by closing done
}

func (u *uploadPathState) finish(success bool) {
	u.once.Do(func() {
		u.succeeded = success
		close(u.done)
	})
}

func completeUploadPath(filePath string) {
	transferPathReservationsMu.Lock()
	u := activeUploadReservations[filePath]
	if u != nil {
		u.finish(true)
	}
	transferPathReservationsMu.Unlock()
}

func (u *uploadPathState) result() error {
	if !u.succeeded {
		return fmt.Errorf("source upload failed or was aborted")
	}
	return nil
}

func (u *uploadPathState) wait() error {
	timer := time.NewTimer(liveUploadIdleLimit)
	defer timer.Stop()
	select {
	case <-u.done:
		return u.result()
	case <-timer.C:
		return fmt.Errorf("timed out waiting for source upload verification")
	}
}

// File.Read returns EOF at the current end, even while another descriptor is
// writing. Wait for growth, then re-read once completion has been published so
// that an EOF racing with the final write never truncates a successful RETR.
type growingUploadReader struct {
	file         *os.File
	upload       *uploadPathState
	lastProgress time.Time
}

func (r *growingUploadReader) Read(p []byte) (int, error) {
	for {
		n, err := r.file.Read(p)
		if n > 0 {
			r.lastProgress = time.Now()
			return n, nil
		}
		if err != io.EOF {
			return n, err
		}
		select {
		case <-r.upload.done:
			if err := r.upload.result(); err != nil {
				return 0, err
			}
			return r.file.Read(p)
		default:
		}
		if time.Since(r.lastProgress) >= liveUploadIdleLimit {
			return 0, fmt.Errorf("source upload stalled while following")
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-r.upload.done:
			timer.Stop()
		case <-timer.C:
		}
	}
}
