package netutil

import (
	"crypto/tls"
	"io"
	"net"
	"time"
)

const tlsSendCloseGrace = 250 * time.Millisecond

// FinishDataSend closes a completed download. A TLS client that only writes
// may still have unread TLS 1.3 session tickets. Closing TCP with unread input
// can send a reset and discard the receiver's final application records.
// Send close_notify first and drain the peer's shutdown/tickets with a bound.
// Keep the existing close behavior for plaintext and TLS-server downloads.
func FinishDataSend(conn net.Conn, tlsClientMode bool) error {
	c, ok := conn.(*tls.Conn)
	if !ok || !tlsClientMode {
		return conn.Close()
	}
	defer conn.Close()
	if err := c.CloseWrite(); err != nil {
		return err
	}
	_ = c.SetReadDeadline(time.Now().Add(tlsSendCloseGrace))
	_, err := io.Copy(io.Discard, c)
	if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		// Some receivers wait for the FTP reply before closing their data side.
		// Pending tickets have been consumed; do not wait indefinitely for EOF.
		return nil
	}
	return err
}
