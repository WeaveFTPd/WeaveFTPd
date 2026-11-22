package core

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

const mailLimit = 100
const mailBodyLimit = 1024

var errMailboxFull = errors.New("mailbox is full")
var errMailNotFound = errors.New("message not found")
var errMailRate = errors.New("send limit reached; try again in a minute")

type mailMessage struct {
	ID     int64  `json:"id"`
	Sender string `json:"sender"`
	Body   string `json:"body"`
	SentAt int64  `json:"sent_at"`
	Read   bool   `json:"read"`
}

type mailbox struct {
	Version  int           `json:"version"`
	NextID   int64         `json:"next_id"`
	Messages []mailMessage `json:"messages"`
}

type mailStore struct {
	dir   string
	mu    sync.Mutex
	sends map[string][]time.Time
}

var privateMail = &mailStore{dir: "userdata/mail"}

func newMailboxID() (string, error) {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(id[:]), nil
}

func validMailboxID(id string) bool {
	b, err := hex.DecodeString(id)
	return err == nil && len(b) == 16 && id == strings.ToLower(id)
}

func validMailText(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) || r == '\u2028' || r == '\u2029' {
			return false
		}
	}
	return true
}

// One master owns its mailbox directory. Serialize read-modify-write operations
// and atomically replace each bounded mailbox, so concurrent sessions lose no mail.
func (m *mailStore) load(id string) (mailbox, error) {
	box := mailbox{Version: 1, NextID: 1}
	if !validMailboxID(id) {
		return box, errors.New("invalid mailbox identity")
	}
	f, err := os.Open(filepath.Join(m.dir, id+".json"))
	if os.IsNotExist(err) {
		return box, nil
	}
	if err != nil {
		return box, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 1024*1024+1))
	if err != nil {
		return box, err
	}
	if len(data) > 1024*1024 {
		return box, errors.New("mailbox too large")
	}
	if err := json.Unmarshal(data, &box); err != nil {
		return box, err
	}
	if box.Version != 1 || box.NextID < 1 || len(box.Messages) > mailLimit {
		return box, errors.New("invalid mailbox")
	}
	seen := map[int64]bool{}
	for _, msg := range box.Messages {
		if msg.ID < 1 || msg.ID >= box.NextID || seen[msg.ID] || !validMailText(msg.Sender) || !validMailText(msg.Body) || len(msg.Body) > mailBodyLimit {
			return box, errors.New("invalid mailbox message")
		}
		seen[msg.ID] = true
	}
	return box, nil
}

func (m *mailStore) save(id string, box mailbox) error {
	if err := os.MkdirAll(m.dir, 0700); err != nil {
		return err
	}
	data, err := json.Marshal(box)
	if err != nil {
		return err
	}
	return atomicWriteFile(filepath.Join(m.dir, id+".json"), data, 0600)
}

func (m *mailStore) send(id, sender, body string, now time.Time) (int64, error) {
	if strings.TrimSpace(body) == "" || len(body) > mailBodyLimit || !validMailText(body) || sender == "" || !validMailText(sender) {
		return 0, fmt.Errorf("message must contain 1-%d bytes without control characters", mailBodyLimit)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.sends == nil {
		m.sends = map[string][]time.Time{}
	}
	for name, times := range m.sends {
		keep := times[:0]
		for _, at := range times {
			if now.Sub(at) < time.Minute {
				keep = append(keep, at)
			}
		}
		if len(keep) == 0 {
			delete(m.sends, name)
		} else {
			m.sends[name] = keep
		}
	}
	if len(m.sends[sender]) >= 5 {
		return 0, errMailRate
	}
	box, err := m.load(id)
	if err != nil {
		return 0, err
	}
	if len(box.Messages) >= mailLimit {
		return 0, errMailboxFull
	}
	if box.NextID == int64(^uint64(0)>>1) {
		return 0, errors.New("message IDs exhausted")
	}
	msg := mailMessage{ID: box.NextID, Sender: sender, Body: body, SentAt: now.Unix()}
	box.NextID++
	box.Messages = append(box.Messages, msg)
	if err := m.save(id, box); err != nil {
		return 0, err
	}
	m.sends[sender] = append(m.sends[sender], now)
	return msg.ID, nil
}

func (m *mailStore) list(id string) ([]mailMessage, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	box, err := m.load(id)
	return box.Messages, err
}

func (m *mailStore) read(id string, number int64) (mailMessage, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	box, err := m.load(id)
	if err != nil {
		return mailMessage{}, err
	}
	for i := range box.Messages {
		if box.Messages[i].ID != number {
			continue
		}
		if !box.Messages[i].Read {
			box.Messages[i].Read = true
			if err := m.save(id, box); err != nil {
				return mailMessage{}, err
			}
		}
		return box.Messages[i], nil
	}
	return mailMessage{}, errMailNotFound
}

func (m *mailStore) delete(id string, number int64, all bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	box, err := m.load(id)
	if err != nil {
		return err
	}
	if all {
		box.Messages = nil
		return m.save(id, box)
	}
	for i, msg := range box.Messages {
		if msg.ID == number {
			box.Messages = append(box.Messages[:i], box.Messages[i+1:]...)
			return m.save(id, box)
		}
	}
	return errMailNotFound
}
