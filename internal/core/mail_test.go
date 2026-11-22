package core

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestMailPersistenceAndIsolation(t *testing.T) {
	m := &mailStore{dir: t.TempDir()}
	a, _ := newMailboxID()
	b, _ := newMailboxID()
	now := time.Now()
	id, err := m.send(a, "alice", "private text", now)
	if err != nil || id != 1 {
		t.Fatalf("send: %d %v", id, err)
	}
	m = &mailStore{dir: m.dir}
	messages, err := m.list(a)
	if err != nil || len(messages) != 1 || messages[0].Read {
		t.Fatalf("restart: %+v %v", messages, err)
	}
	if _, err = m.read(b, id); !errors.Is(err, errMailNotFound) {
		t.Fatalf("cross-user read: %v", err)
	}
	if err = m.delete(b, id, false); !errors.Is(err, errMailNotFound) {
		t.Fatalf("cross-user delete: %v", err)
	}
	msg, err := m.read(a, id)
	if err != nil || !msg.Read || msg.Body != "private text" {
		t.Fatalf("read: %+v %v", msg, err)
	}
	messages, err = (&mailStore{dir: m.dir}).list(a)
	if err != nil || !messages[0].Read {
		t.Fatal("read state not persisted")
	}
	if err = m.delete(a, id, false); err != nil {
		t.Fatal(err)
	}
	id, err = m.send(a, "alice", "next", now)
	if err != nil || id != 2 {
		t.Fatalf("reused ID: %d %v", id, err)
	}
	if err = m.delete(a, 0, true); err != nil {
		t.Fatal(err)
	}
	messages, err = m.list(a)
	if err != nil || len(messages) != 0 {
		t.Fatalf("delete all: %v %v", messages, err)
	}
}

func TestMailLimitsAndCorruption(t *testing.T) {
	m := &mailStore{dir: t.TempDir()}
	id, _ := newMailboxID()
	now := time.Now()
	for _, body := range []string{"", "  ", "hello\r\n200 injected", "\x03red", string([]byte{255}), strings.Repeat("x", 1025)} {
		if _, err := m.send(id, "alice", body, now); err == nil {
			t.Fatalf("accepted invalid body %q", body)
		}
	}
	if _, err := m.send("../../escape", "alice", "hello", now); err == nil {
		t.Fatal("accepted unsafe identity")
	}
	for i := 0; i < 5; i++ {
		if _, err := m.send(id, "alice", strings.Repeat("x", 1024), now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := m.send(id, "alice", "six", now); !errors.Is(err, errMailRate) {
		t.Fatalf("rate: %v", err)
	}
	if _, err := m.send(id, "alice", "later", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	for i := 6; i < mailLimit; i++ {
		if _, err := m.send(id, fmt.Sprint(i), "body", now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := m.send(id, "new", "full", now); !errors.Is(err, errMailboxFull) {
		t.Fatalf("capacity: %v", err)
	}
	path := filepath.Join(m.dir, id+".json")
	if err := os.WriteFile(path, []byte("broken mailbox"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := m.send(id, "new", "body", now); err == nil {
		t.Fatal("overwrote corrupt mailbox")
	}
	data, _ := os.ReadFile(path)
	if string(data) != "broken mailbox" {
		t.Fatal("corrupt mailbox changed")
	}
}

func TestMailConcurrentDelivery(t *testing.T) {
	m := &mailStore{dir: t.TempDir()}
	id, _ := newMailboxID()
	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if _, err := m.send(id, fmt.Sprint(i), "hello", time.Now()); err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	messages, err := m.list(id)
	if err != nil || len(messages) != 40 {
		t.Fatalf("lost messages: %d %v", len(messages), err)
	}
	for i, msg := range messages {
		if msg.ID != int64(i+1) {
			t.Fatalf("nonunique IDs: %+v", messages)
		}
	}
}

func TestMailWriteFailure(t *testing.T) {
	blocked := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blocked, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	m := &mailStore{dir: blocked}
	id, _ := newMailboxID()
	if _, err := m.send(id, "alice", "hello", time.Now()); err == nil {
		t.Fatal("reported delivery despite storage failure")
	}
	if len(m.sends["alice"]) != 0 {
		t.Fatal("failed send consumed rate limit")
	}
	data, _ := os.ReadFile(blocked)
	if string(data) != "keep" {
		t.Fatal("changed unrelated file")
	}
}
