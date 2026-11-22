package slave

import (
	"fmt"
	"os"
	"time"

	"weaveftpd/internal/protocol"
)

func (s *Slave) handleSetModTime(ac *protocol.AsyncCommand) interface{} {
	fail := func(message string) interface{} {
		return &protocol.AsyncResponseError{Index: ac.Index, Message: "setModTime: " + message}
	}
	if len(ac.Args) != 2 {
		return fail("need path and timestamp")
	}
	stamp, err := time.Parse(time.RFC3339Nano, ac.Args[1])
	if err != nil {
		return fail("invalid timestamp")
	}
	changed := false
	for _, root := range s.rootsForVirtualPath(ac.Args[0]) {
		fullPath := root.fullPath(ac.Args[0])
		info, err := os.Lstat(fullPath)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return fail(err.Error())
		}
		if !info.Mode().IsRegular() {
			return fail("not a regular file")
		}
		if err := os.Chtimes(fullPath, stamp, stamp); err != nil {
			return fail(fmt.Sprintf("cannot change timestamp: %v", err))
		}
		changed = true
	}
	if !changed {
		return fail("file not found on slave")
	}
	return &protocol.AsyncResponse{Index: ac.Index}
}
