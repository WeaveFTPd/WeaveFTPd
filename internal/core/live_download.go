package core

import (
	"net"
	"sync"
)

// A follower owns only its data resources, never the control session. Keep its
// path reservation until the transfer call has returned: cancellation alone
// does not prove that a delayed slave SEND can no longer open the pathname.
type liveDownload struct {
	mu        sync.Mutex
	cancelled bool
	hooks     []func()
	stop      chan struct{}
	stopped   chan struct{}
	once      sync.Once
	path      string
}

func newLiveDownload(filePath string, source *uploadPathState) *liveDownload {
	d := &liveDownload{path: filePath, stop: make(chan struct{}), stopped: make(chan struct{})}
	if source == nil {
		close(d.stopped)
		return d
	}
	go func() {
		defer close(d.stopped)
		select {
		case <-d.stop:
			return
		case <-source.done:
			if source.result() == nil {
				return
			}
		}
		d.mu.Lock()
		d.cancelled = true
		hooks := d.hooks
		d.hooks = nil
		d.mu.Unlock()
		for _, cancel := range hooks {
			cancel()
		}
	}()
	return d
}

// Registering after source failure must still cancel late-created resources.
func (d *liveDownload) onCancel(cancel func()) {
	d.mu.Lock()
	if !d.cancelled {
		d.hooks = append(d.hooks, cancel)
		d.mu.Unlock()
		return
	}
	d.mu.Unlock()
	cancel()
}

func (d *liveDownload) trackConn(conn net.Conn) {
	d.onCancel(func() { _ = conn.Close() })
}

func (d *liveDownload) trackSlave(manager interface{}, name string, index int32) {
	if aborter, ok := manager.(transferAborter); ok {
		d.onCancel(func() { aborter.AbortTransfer(name, index, "source upload failed verification or was aborted") })
	}
}

func (d *liveDownload) finish() {
	d.once.Do(func() {
		close(d.stop)
		<-d.stopped
		releaseDownloadPath(d.path)
	})
}

// Optional extension keeps bridge implementations compatible while exposing
// proxy-mode slave identity for the same targeted cancellation as passthrough.
type trackedDownloadBridge interface {
	DownloadFileTracked(string, net.Conn, string, string, int64, byte, TransferReadyFunc) (uint32, error)
}
