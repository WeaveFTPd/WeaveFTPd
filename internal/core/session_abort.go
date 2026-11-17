package core

import "strings"

type transferAborter interface {
	AbortTransfer(slaveName string, transferIndex int32, reason string) bool
}

func (s *Session) abortCurrentTransfer(reason string) bool {
	if s == nil {
		return false
	}
	if strings.TrimSpace(reason) == "" {
		reason = "Transfer aborted"
	}

	aborted := false
	s.stateMu.RLock()
	slaveName := s.TransferSlaveName
	slaveIdx := s.TransferSlaveIdx
	hasTransfer := strings.TrimSpace(s.TransferDirection) != "" && strings.TrimSpace(s.TransferPath) != ""
	dataConn := s.transferConn
	s.stateMu.RUnlock()

	if hasTransfer {
		if aborter, ok := s.MasterManager.(transferAborter); ok && strings.TrimSpace(slaveName) != "" && slaveIdx != 0 {
			aborted = aborter.AbortTransfer(slaveName, slaveIdx, reason)
		}
	}
	if dataConn != nil {
		abortFileDataSend(dataConn)
		aborted = true
	}

	if s.DataListen != nil {
		_ = s.DataListen.Close()
		s.DataListen = nil
		aborted = true
	}
	if s.ActiveAddr != "" || s.PassthruSlave != nil || s.PassthruXferIdx != 0 || s.PretCmd != "" || s.PretArg != "" {
		aborted = true
	}
	s.ActiveAddr = ""
	s.PassthruSlave = nil
	s.PassthruXferIdx = 0
	s.PretCmd = ""
	s.PretArg = ""
	s.endTransfer()
	return aborted || hasTransfer
}
