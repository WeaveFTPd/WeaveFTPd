package slave

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"weaveftpd/internal/protocol"
)

func TestSetModTimeMountedFile(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "Race  Trade.exe")
	if err := os.WriteFile(file, []byte("payload"), 0644); err != nil {
		t.Fatal(err)
	}
	s := &Slave{roots: []MountedRoot{{Path: root, MountPath: "/iNFO"}}}
	stamp := "2026-11-20T23:00:09Z"
	response := s.handleCommand(&protocol.AsyncCommand{Index: "1", Name: "setModTime", Args: []string{"/iNFO/Race  Trade.exe", stamp}})
	if _, ok := response.(*protocol.AsyncResponse); !ok {
		t.Fatalf("response: %#v", response)
	}
	info, err := os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.ModTime().UTC().Format(time.RFC3339); got != stamp {
		t.Fatalf("timestamp = %s", got)
	}
	content, err := os.ReadFile(file)
	if err != nil || string(content) != "payload" {
		t.Fatalf("file changed: %q, %v", content, err)
	}
	for _, args := range [][]string{nil, {"/iNFO/Race  Trade.exe", "invalid"}, {"/iNFO/missing.exe", stamp}, {"/iNFO", stamp}} {
		response := s.handleCommand(&protocol.AsyncCommand{Index: "2", Name: "setModTime", Args: args})
		if _, ok := response.(*protocol.AsyncResponseError); !ok {
			t.Fatalf("args %v: %#v", args, response)
		}
	}
}
