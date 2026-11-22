package core

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"weaveftpd/internal/timeutil"
)

type modificationTimeSetter interface {
	SetModTime(string, time.Time) error
}

// MDTM normally queries a pathname. Some FTP clients also send the legacy
// MDTM <UTC timestamp> <pathname> form after STOR to preserve modification time.
func (s *Session) handleMDTM(args []string) {
	argument := strings.Join(args, " ")
	if argument == "" {
		fmt.Fprint(s.Conn, "501 Syntax error\r\n")
		return
	}
	name := argument
	var stamp time.Time
	setTime := false
	if end := strings.IndexFunc(argument, unicode.IsSpace); end >= 0 {
		first := argument[:end]
		if len(first) >= 14 && strings.IndexFunc(first[:14], func(r rune) bool { return r < '0' || r > '9' }) < 0 {
			var err error
			stamp, err = time.Parse("20060102150405.999999999", first)
			name = strings.TrimLeftFunc(argument[end:], unicode.IsSpace)
			if err != nil || name == "" {
				fmt.Fprint(s.Conn, "501 Invalid MDTM timestamp or pathname.\r\n")
				return
			}
			setTime = true
		}
	}
	vpath := resolveSessionPath(s.CurrentDir, name)
	var bridge MasterBridge
	if s.Config.Mode == "master" {
		bridge, _ = s.MasterManager.(MasterBridge)
		if bridge == nil {
			fmt.Fprint(s.Conn, "451 Master unavailable.\r\n")
			return
		}
		vpath = bridge.ResolvePath(vpath)
	}
	local := filepath.Join(s.Config.StoragePath, filepath.FromSlash(strings.TrimPrefix(vpath, "/")))
	if setTime {
		aclPath := path.Join(s.Config.ACLBasePath, vpath)
		allowed := s.ACLEngine != nil && s.ACLEngine.CanPerform(s.User, "UPLOAD", aclPath)
		if bridge != nil && allowed {
			allowed = s.pathOwnedByUser(vpath) || s.ACLEngine.CanPerform(s.User, "CHMOD", aclPath)
		}
		if !allowed {
			fmt.Fprint(s.Conn, "550 Access Denied: Cannot modify file timestamp.\r\n")
			return
		}
		if validator, ok := any(s.Config).(interface{ ValidateSectionWritePath(string) error }); ok {
			if err := validator.ValidateSectionWritePath(vpath); err != nil {
				fmt.Fprintf(s.Conn, "550 %s\r\n", err)
				return
			}
		}
		if activeUploadForPath(vpath) {
			fmt.Fprint(s.Conn, "550 File is currently being uploaded.\r\n")
			return
		}
		var err error
		if bridge != nil {
			setter, ok := bridge.(modificationTimeSetter)
			if !ok {
				fmt.Fprint(s.Conn, "502 Setting modification time is unavailable.\r\n")
				return
			}
			err = setter.SetModTime(vpath, stamp)
		} else {
			var info os.FileInfo
			info, err = os.Lstat(local)
			if err == nil {
				if !info.Mode().IsRegular() {
					err = fmt.Errorf("not a regular file")
				} else {
					err = os.Chtimes(local, stamp, stamp)
				}
			}
		}
		if err != nil {
			fmt.Fprintf(s.Conn, "550 MDTM failed: %v\r\n", err)
			return
		}
		fmt.Fprint(s.Conn, "213 Modify time set.\r\n")
		return
	}
	if bridge != nil {
		entry, ok := bridge.GetPathEntry(vpath)
		if ok {
			fmt.Fprintf(s.Conn, "213 %s\r\n", timeutil.FTPMachineUnix(entry.ModTime))
			return
		}
	} else if info, err := os.Stat(local); err == nil {
		fmt.Fprintf(s.Conn, "213 %s\r\n", timeutil.FTPMachine(info.ModTime()))
		return
	}
	fmt.Fprint(s.Conn, "550 File not found.\r\n")
}
