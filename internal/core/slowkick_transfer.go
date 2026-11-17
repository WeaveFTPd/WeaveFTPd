package core

import (
	"path"

	"weaveftpd/internal/plugin"
	"weaveftpd/internal/zipscript"
)

// Abort only the observed transfer generation, never its control connection
// or a later transfer which reused the same session.
func AbortActiveSessionTransfer(snap plugin.ActiveSession, reason string) bool {
	v, ok := activeSessions.Load(snap.ID)
	if !ok {
		return false
	}
	s := v.(*Session)
	s.stateMu.RLock()
	if s.TransferStartedAt != snap.TransferStartedAt || s.TransferPath != snap.TransferPath ||
		s.TransferDirection != snap.TransferDirection || s.TransferSlaveIdx != snap.TransferSlaveIdx ||
		s.TransferSlaveName != snap.TransferSlaveName {
		s.stateMu.RUnlock()
		return false
	}
	conn := s.transferConn
	s.stateMu.RUnlock()
	stopped := false
	if snap.TransferSlaveName != "" && snap.TransferSlaveIdx != 0 {
		if aborter, ok := s.MasterManager.(transferAborter); ok {
			stopped = aborter.AbortTransfer(snap.TransferSlaveName, snap.TransferSlaveIdx, reason)
		}
	}
	if conn != nil {
		_ = conn.Close()
		stopped = true
	}
	// The transfer handler owns cleanup and the final FTP response.
	return stopped
}

// Use configured release depths, including dated and nested sections. An
// unknown layout must never turn a release ban into a section-wide ban.
func SlowkickReleaseRoot(cfg zipscript.Config, filePath string) string {
	if len(cfg.Sections.ReleaseCheck) == 0 && len(cfg.Sections.SFV) == 0 && len(cfg.Sections.Zip) == 0 {
		return ""
	}
	root := ""
	for dir := path.Dir(path.Clean("/" + filePath)); dir != "/" && dir != "."; dir = path.Dir(dir) {
		if zipscript.UsesReleaseCheckEntry(cfg, dir) {
			root = dir
		}
	}
	return root
}
