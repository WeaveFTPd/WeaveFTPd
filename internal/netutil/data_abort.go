package netutil

import "net"

// AbortDataSend must not send a TLS close_notify or a TCP FIN: either looks
// like a complete FTP data stream to a receiver without an expected checksum.
func AbortDataSend(conn net.Conn) error {
	if conn == nil {
		return nil
	}
	if wrapped, ok := conn.(interface{ NetConn() net.Conn }); ok {
		return AbortDataSend(wrapped.NetConn())
	}
	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.SetLinger(0)
	}
	return conn.Close()
}
