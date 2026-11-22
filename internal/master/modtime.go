package master

import (
	"fmt"
	"path/filepath"
	"time"

	"weaveftpd/internal/protocol"
)

// SetModTime changes the physical file first; publish the VFS timestamp only
// after the slave acknowledges success so MDTM and MLSD remain consistent.
func (b *Bridge) SetModTime(filePath string, stamp time.Time) error {
	filePath = b.ResolvePath(filepath.ToSlash(filepath.Clean(filePath)))
	slave, file, err := b.resolveOwningSlave(filePath)
	if err != nil {
		return err
	}
	if file == nil || file.IsDir || file.IsSymlink || slave == nil {
		return fmt.Errorf("file has no writable owning slave: %s", filePath)
	}
	index, err := slave.FetchIndex()
	if err != nil {
		return err
	}
	if err := slave.SendCommand(&protocol.AsyncCommand{Index: index, Name: "setModTime", Args: []string{filePath, stamp.UTC().Format(time.RFC3339Nano)}}); err != nil {
		return err
	}
	response, err := slave.FetchResponse(index, 30*time.Second)
	if err != nil {
		return err
	}
	if failure, ok := response.(*protocol.AsyncResponseError); ok {
		return fmt.Errorf("%s", failure.Message)
	}
	if _, ok := response.(*protocol.AsyncResponse); !ok {
		return fmt.Errorf("unexpected setModTime response: %T", response)
	}
	b.sm.GetVFS().SetModTime(filePath, stamp)
	return nil
}

func (vfs *VirtualFileSystem) SetModTime(filePath string, stamp time.Time) {
	vfs.mu.Lock()
	defer vfs.mu.Unlock()
	filePath = cleanVFSPath(filePath)
	if file := vfs.files[filePath]; file != nil {
		copy := *file
		copy.LastModified = stamp.Unix()
		vfs.files[filePath] = &copy
		vfs.markPersistDirtyLocked()
	}
}
