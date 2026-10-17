package slave

import (
	"context"
	"crypto/tls"
	"fmt"
	"hash/crc32"
	"io"
	"log"
	"net"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"weaveftpd/internal/netutil"
	"weaveftpd/internal/protocol"
)

var transferBufferPools sync.Map

func getTransferBuffer(size int) *[]byte {
	if size < minTransferBufferSize {
		size = defaultTransferBufferSize
	}
	poolIface, _ := transferBufferPools.LoadOrStore(size, &sync.Pool{
		New: func() interface{} {
			buf := make([]byte, size)
			return &buf
		},
	})
	return poolIface.(*sync.Pool).Get().(*[]byte)
}

func putTransferBuffer(bufPtr *[]byte) {
	if bufPtr == nil || *bufPtr == nil {
		return
	}
	size := cap(*bufPtr)
	if size <= 0 {
		return
	}
	buf := (*bufPtr)[:size]
	*bufPtr = buf
	poolIface, _ := transferBufferPools.LoadOrStore(size, &sync.Pool{
		New: func() interface{} {
			b := make([]byte, size)
			return &b
		},
	})
	poolIface.(*sync.Pool).Put(bufPtr)
}

const (
	TransferUnknown    = 'U'
	TransferReceiving  = 'R' // upload from client to slave
	TransferSending    = 'S' // download from slave to client
	transferPollTick   = 100 * time.Millisecond
	transferStatusTick = time.Second
	// leechFollowIdleLimit bounds how long a download may "follow" a still-running
	// upload of the same file (leech-while-upload) without receiving any new bytes.
	// A live upload that has stalled but not finished would otherwise spin here
	// forever, so the racing client (cbftp) hangs until its own timeout and leaves
	// the file missing. Giving up cleanly lets it retry, which succeeds once the
	// upload has completed.
	leechFollowIdleLimit = 20 * time.Second
	// dataWriteTimeout bounds a single chunk write so a receiver that stops reading
	// surfaces as an error instead of blocking the send indefinitely.
	dataWriteTimeout = 60 * time.Second
	// receiveIdleLimit aborts an upload that has received no new bytes for this
	// long. The poll-tick read deadline otherwise just resets and spins forever
	// when no min-speed is configured, so a stalled source would hold the upload
	// (and any leech-while-upload download following it) open indefinitely. Like
	// drftpd, killing the stalled upload releases the follower immediately.
	receiveIdleLimit = 30 * time.Second
	// transferSetupReapGrace bounds how long a LISTEN/CONNECT transfer may sit in
	// the slave's transfers map without a matching receive/send claiming it. Such
	// an entry leaks forever otherwise (master timed out the listen, picked another
	// slave, client never connected), and the map is range-scanned on every CWD
	// race-stats request, so the leak makes browsing slower the longer the daemon
	// runs. The grace is well beyond the normal listen->receive gap.
	transferSetupReapGrace = 2 * time.Minute
)

// Transfer represents a data transfer on the slave side.
type Transfer struct {
	listener      net.Listener // non-nil for passive (LISTEN)
	conn          net.Conn     // non-nil for active (CONNECT) or after passive accept
	transferIndex int32
	slave         *Slave
	encrypted     bool
	sslClientMode bool
	activeAddress string
	mode          byte

	path        string
	direction   byte
	started     time.Time
	finished    time.Time
	transferred atomic.Int64
	checksum    uint32
	abortReason string
	claimed     atomic.Bool // set once ReceiveFile/SendFile takes ownership
	mu          sync.Mutex
}

func NewTransfer(listener net.Listener, conn net.Conn, idx int32, slave *Slave, encrypted bool, sslClientMode bool) *Transfer {
	return &Transfer{
		listener:      listener,
		conn:          conn,
		transferIndex: idx,
		slave:         slave,
		encrypted:     encrypted,
		sslClientMode: sslClientMode,
		direction:     TransferUnknown,
		mode:          'I',
	}
}

func (t *Transfer) SetActiveAddress(address string) {
	t.mu.Lock()
	t.activeAddress = strings.TrimSpace(address)
	t.mu.Unlock()
}

func (t *Transfer) SetTransferMode(mode byte) {
	t.mu.Lock()
	switch mode {
	case 'A', 'I':
		t.mode = mode
	default:
		t.mode = 'I'
	}
	t.mu.Unlock()
}

func (t *Transfer) SetPath(path string) {
	t.mu.Lock()
	t.path = path
	t.mu.Unlock()
}

func (t *Transfer) currentConn() net.Conn {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.conn
}

func (t *Transfer) setConn(conn net.Conn) {
	t.mu.Lock()
	t.conn = conn
	t.mu.Unlock()
}

func (t *Transfer) currentListener() net.Listener {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.listener
}

func (t *Transfer) abortSnapshot() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.abortReason
}

func (t *Transfer) Path() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.path
}

func (t *Transfer) SnapshotLiveStat() protocol.TransferLiveStat {
	t.mu.Lock()
	defer t.mu.Unlock()

	transferred := t.transferred.Load()
	var startedUnixMs int64
	var speedBytes int64
	if !t.started.IsZero() {
		startedUnixMs = t.started.UnixMilli()
		elapsedMs := time.Since(t.started).Milliseconds()
		if elapsedMs > 0 && transferred > 0 {
			speedBytes = transferred * 1000 / elapsedMs
		}
	}

	return protocol.TransferLiveStat{
		TransferIndex: t.transferIndex,
		Direction:     t.direction,
		Path:          t.path,
		StartedUnixMs: startedUnixMs,
		Transferred:   transferred,
		SpeedBytes:    speedBytes,
	}
}

// ReceiveFile receives data from the FTP client and writes to disk.
// ().
func (t *Transfer) ReceiveFile(path string, position int64, expectedPeer string) protocol.TransferStatus {
	t.claimed.Store(true)
	t.mu.Lock()
	t.direction = TransferUnknown
	t.started = time.Time{}
	t.mu.Unlock()

	defer func() {
		t.mu.Lock()
		t.finished = time.Now()
		t.mu.Unlock()
		t.slave.removeTransfer(t.transferIndex)
	}()

	if err := t.acceptPassiveConn(); err != nil {
		return t.errorStatus(err.Error())
	}

	conn := t.currentConn()
	if conn == nil {
		return t.errorStatus("no connection")
	}
	defer conn.Close()

	// Determine where to write
	fullPath, err := t.slave.getDirForUpload(path)
	if err != nil {
		return t.errorStatus(fmt.Sprintf("cannot create file: %v", err))
	}
	if position <= 0 {
		if _, statErr := os.Stat(fullPath); statErr == nil {
			return t.errorStatus(fmt.Sprintf("File %s exists", path))
		}
	}

	var file *os.File
	if position > 0 {
		file, err = os.OpenFile(fullPath, os.O_WRONLY, 0644)
		if err != nil {
			return t.errorStatus(fmt.Sprintf("resume open failed: %v", err))
		}
		if _, err := file.Seek(position, io.SeekStart); err != nil {
			file.Close()
			return t.errorStatus(fmt.Sprintf("resume seek failed: %v", err))
		}
	} else {
		file, err = os.OpenFile(fullPath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0644)
	}
	if err != nil {
		return t.errorStatus(fmt.Sprintf("create failed: %v", err))
	}
	defer file.Close()
	if isUnexpectedTransferPeer(expectedPeer, conn.RemoteAddr()) {
		log.Printf("[Transfer] rejected receive: peer %s does not match expected %q (idx=%d)", conn.RemoteAddr(), expectedPeer, t.transferIndex)
		cleanupFailedReceive(file, fullPath, position)
		return t.errorStatus("The IP that connected to the socket was not the one that was expected.")
	}
	t.mu.Lock()
	t.direction = TransferReceiving
	// t.started is set on the first data byte, not here: the window between
	// slave readiness and the client actually sending (receive-ack round trip,
	// 150 reply, sender reaction) must not count as transfer time, or announced
	// speeds get deflated by a fixed per-file overhead (glftpd/drftpd measure
	// pure data time only).
	t.mu.Unlock()
	t.slave.registerUpload(t)
	defer t.slave.unregisterUpload(t)

	// Transfer with CRC32. Disk writes (and CRC) run on a separate goroutine
	// with double buffering so the socket read is never stalled behind a disk
	// write: in the old serial read->write->read loop the NIC sat idle during
	// every disk write, which caps sustained 10gbit throughput.
	h := crc32.NewIEEE()
	bufSize := t.slave.getTransferBufferSize()
	bufs := [2]*[]byte{getTransferBuffer(bufSize), getTransferBuffer(bufSize)}

	type writeChunk struct {
		buf *[]byte
		n   int
	}
	freeCh := make(chan *[]byte, len(bufs))
	for _, b := range bufs {
		freeCh <- b
	}
	writeCh := make(chan writeChunk, len(bufs))
	var writerFailed atomic.Bool
	var writerErr error
	var writerWG sync.WaitGroup
	writerWG.Add(1)
	go func() {
		defer writerWG.Done()
		for c := range writeCh {
			if writerErr == nil {
				if _, werr := file.Write((*c.buf)[:c.n]); werr != nil {
					writerErr = werr
					writerFailed.Store(true)
				} else {
					_, _ = h.Write((*c.buf)[:c.n])
					// Count bytes only after they hit the disk, matching the
					// old serial loop: live status and the final Transferred
					// must not include chunks still queued (or lost on a
					// write failure).
					t.transferred.Add(int64(c.n))
				}
			}
			freeCh <- c.buf
		}
	}()
	writerClosed := false
	// finishWriter drains the writer goroutine and returns its sticky error.
	// Must be called before touching file/h from this goroutine again.
	finishWriter := func() error {
		if !writerClosed {
			writerClosed = true
			close(writeCh)
			writerWG.Wait()
		}
		return writerErr
	}
	defer func() {
		_ = finishWriter()
		for _, b := range bufs {
			putTransferBuffer(b)
		}
	}()

	lastStatus := time.Now()
	lastProgress := time.Now()
	var dataStarted time.Time
	var curBuf *[]byte
	nextReadDeadline := time.Now().Add(transferPollTick)
	_ = conn.SetReadDeadline(nextReadDeadline)

	for {
		if reason := t.abortSnapshot(); reason != "" {
			_ = finishWriter()
			cleanupFailedReceive(file, fullPath, position)
			return t.errorStatus("aborted: " + reason)
		}
		if writerFailed.Load() {
			werr := finishWriter()
			cleanupFailedReceive(file, fullPath, position)
			return t.errorStatus(fmt.Sprintf("write error: %v", werr))
		}

		if curBuf == nil {
			curBuf = <-freeCh
		}
		n, err := conn.Read(*curBuf)
		if n > 0 {
			if dataStarted.IsZero() {
				dataStarted = time.Now()
				t.mu.Lock()
				t.started = dataStarted
				t.mu.Unlock()
			}
			writeCh <- writeChunk{buf: curBuf, n: n}
			curBuf = nil
			lastProgress = time.Now()
		}
		if time.Since(lastStatus) >= transferStatusTick {
			t.slave.writeStatusObject(&protocol.AsyncResponseTransferStatus{Status: t.currentStatus(false, "")})
			lastStatus = time.Now()
		}
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// Poll tick with no data. Abort if the source has gone silent for
				// too long so a stalled upload can't hold the slot (and any
				// leech-while-upload follower) open indefinitely.
				if time.Since(lastProgress) >= receiveIdleLimit {
					_ = finishWriter()
					cleanupFailedReceive(file, fullPath, position)
					return t.errorStatus("receive idle timeout: no data from source")
				}
				nextReadDeadline = time.Now().Add(transferPollTick)
				_ = conn.SetReadDeadline(nextReadDeadline)
				continue
			}
			if err == io.EOF {
				break
			}
			_ = finishWriter()
			cleanupFailedReceive(file, fullPath, position)
			return t.errorStatus(fmt.Sprintf("read error: %v", err))
		}
		if time.Until(nextReadDeadline) <= 0 {
			nextReadDeadline = time.Now().Add(transferPollTick)
			_ = conn.SetReadDeadline(nextReadDeadline)
		}
	}

	// Flush all queued disk writes before reading the checksum or file size.
	if werr := finishWriter(); werr != nil {
		cleanupFailedReceive(file, fullPath, position)
		return t.errorStatus(fmt.Sprintf("write error: %v", werr))
	}

	transferred := t.transferred.Load()
	log.Printf("[Transfer] Received %s (%d bytes, CRC32=%08X, offset=%d)", path, transferred, h.Sum32(), position)
	t.mu.Lock()
	t.checksum = h.Sum32()
	t.mu.Unlock()
	finalSize := transferred
	if info, statErr := file.Stat(); statErr == nil {
		finalSize = info.Size()
	}

	elapsedMs := int64(0)
	if !dataStarted.IsZero() {
		elapsedMs = time.Since(dataStarted).Milliseconds()
		if elapsedMs <= 0 && transferred > 0 {
			// A small file on a fast link can finish in under 1ms now that the
			// timer starts at the first byte. Clamp to 1ms: the race DB drops
			// records with duration_ms <= 0 and every stats query filters on
			// duration_ms > 0, so a 0 here silently loses the file from race
			// stats (intermittently missing stats on 10gbit LANs).
			elapsedMs = 1
		}
	}

	return protocol.TransferStatus{
		TransferIndex: t.transferIndex,
		Elapsed:       elapsedMs,
		Transferred:   transferred,
		FileSize:      finalSize,
		Checksum:      h.Sum32(),
		Finished:      true,
	}
}

func cleanupFailedReceive(file *os.File, fullPath string, position int64) {
	if position <= 0 {
		_ = os.Remove(fullPath)
		return
	}
	if file != nil {
		_ = file.Sync()
		_ = file.Truncate(position)
		_, _ = file.Seek(position, io.SeekStart)
	}
}

// SendFile sends a file from disk to the FTP client.
// ().
func (t *Transfer) SendFile(path string, position int64, expectedPeer string) protocol.TransferStatus {
	t.claimed.Store(true)
	t.mu.Lock()
	t.direction = TransferUnknown
	t.started = time.Time{}
	t.mu.Unlock()

	defer func() {
		t.mu.Lock()
		t.finished = time.Now()
		t.mu.Unlock()
		t.slave.removeTransfer(t.transferIndex)
	}()

	if err := t.acceptPassiveConn(); err != nil {
		return t.errorStatus(err.Error())
	}

	conn := t.currentConn()
	if conn == nil {
		return t.errorStatus("no connection")
	}
	defer conn.Close()
	if isUnexpectedTransferPeer(expectedPeer, conn.RemoteAddr()) {
		log.Printf("[Transfer] rejected send: peer %s does not match expected %q (idx=%d)", conn.RemoteAddr(), expectedPeer, t.transferIndex)
		return t.errorStatus("The IP that connected to the socket was not the one that was expected.")
	}
	t.mu.Lock()
	t.direction = TransferSending
	t.started = time.Now()
	t.mu.Unlock()

	// Find the file across roots
	fullPath, err := t.slave.getFileFromRoots(path)
	if err != nil {
		return t.errorStatus(fmt.Sprintf("file not found: %v", err))
	}

	file, err := os.Open(fullPath)
	if err != nil {
		return t.errorStatus(fmt.Sprintf("open failed: %v", err))
	}
	defer file.Close()
	if position > 0 {
		if _, err := file.Seek(position, io.SeekStart); err != nil {
			return t.errorStatus(fmt.Sprintf("resume seek failed: %v", err))
		}
	}

	lastStatus := time.Now()
	lastProgress := time.Now()
	associatedUpload := t.findAssociatedUpload(path)

	// The zero-copy sendfile(2) fast path is valid for plaintext downloads. TLS
	// needs userspace encryption.
	useSendfile := !t.encrypted

	chunkSize := int64(t.slave.getTransferBufferSize())
	var buf []byte
	var bufPtr *[]byte
	if !useSendfile {
		bufPtr = getTransferBuffer(int(chunkSize))
		defer putTransferBuffer(bufPtr)
		buf = *bufPtr
	}

	for {
		if reason := t.abortSnapshot(); reason != "" {
			return t.errorStatus("aborted: " + reason)
		}

		var n int64
		var err error
		if useSendfile {
			_ = conn.SetWriteDeadline(time.Now().Add(dataWriteTimeout))
			n, err = io.CopyN(conn, file, chunkSize)
			if n > 0 {
				t.transferred.Add(n)
			}
		} else {
			var r int
			r, err = file.Read(buf)
			if r > 0 {
				_ = conn.SetWriteDeadline(time.Now().Add(dataWriteTimeout))
				written, werr := conn.Write(buf[:r])
				if werr != nil {
					return t.errorStatus(fmt.Sprintf("write error: %v", werr))
				}
				if written != r {
					return t.errorStatus("write error: short write")
				}
				n = int64(r)
				t.transferred.Add(n)
			}
		}
		if n > 0 {
			lastProgress = time.Now()
		}

		if time.Since(lastStatus) >= transferStatusTick {
			t.slave.writeStatusObject(&protocol.AsyncResponseTransferStatus{Status: t.currentStatus(false, "")})
			lastStatus = time.Now()
		}
		if err != nil {
			if err == io.EOF {
				// Find a live upload of this same file to follow (leech-while-upload).
				// It may have registered after this send started, so re-check here.
				live := associatedUpload
				if live == nil || live.isFinished() {
					live = t.findAssociatedUpload(path)
				}
				if live != nil && !live.isFinished() {
					// Following a growing source file. If it has produced no new bytes
					// for too long the upload is stalled; give up so the client fails
					// fast and retries instead of hanging until its own timeout.
					if time.Since(lastProgress) >= leechFollowIdleLimit {
						return t.errorStatus("source upload stalled while following (leech idle timeout)")
					}
					associatedUpload = live
					time.Sleep(transferPollTick)
					continue
				}
				break
			}
			return t.errorStatus(fmt.Sprintf("transfer error: %v", err))
		}
	}

	transferred := t.transferred.Load()
	log.Printf("[Transfer] Sent %s (%d bytes, offset=%d)", path, transferred, position)
	t.mu.Lock()
	t.checksum = 0
	t.mu.Unlock()

	return protocol.TransferStatus{
		TransferIndex: t.transferIndex,
		Elapsed:       time.Since(t.started).Milliseconds(),
		Transferred:   transferred,
		Checksum:      0,
		Finished:      true,
	}
}

func (t *Transfer) acceptPassiveConn() error {
	if t.currentConn() != nil {
		return nil
	}
	listener := t.currentListener()
	if listener == nil {
		return t.connectActive()
	}
	timeout := t.setupTimeout()
	if deadlineListener, ok := listener.(interface{ SetDeadline(time.Time) error }); ok {
		deadlineListener.SetDeadline(time.Now().Add(timeout))
	}
	conn, err := listener.Accept()
	listener.Close()
	if err != nil {
		return fmt.Errorf("accept failed: %v", err)
	}
	t.configureDataSocket(conn)
	t.setConn(conn)
	if !t.encrypted {
		return nil
	}

	_ = conn.SetDeadline(time.Now().Add(timeout))
	defer conn.SetDeadline(time.Time{})

	if t.sslClientMode {
		tlsConn := tls.Client(conn, dataClientTLSConfig(conn))
		if err := tlsConn.Handshake(); err != nil {
			log.Printf("[Transfer] data TLS client handshake with %s failed (idx=%d): %v", conn.RemoteAddr(), t.transferIndex, err)
			conn.Close()
			return fmt.Errorf("TLS client handshake failed: %v", err)
		}
		t.setConn(tlsConn)
		return nil
	}

	tlsCfg, err := t.slave.serverTLSConfig()
	if err != nil {
		log.Printf("[Transfer] data TLS server cert load failed (idx=%d): %v", t.transferIndex, err)
		conn.Close()
		return fmt.Errorf("load TLS cert: %v", err)
	}
	tlsConn := tls.Server(conn, tlsCfg)
	if err := tlsConn.Handshake(); err != nil {
		log.Printf("[Transfer] data TLS server handshake with %s failed (idx=%d): %v", conn.RemoteAddr(), t.transferIndex, err)
		conn.Close()
		return fmt.Errorf("TLS server handshake failed: %v", err)
	}
	t.setConn(tlsConn)
	return nil
}

func (t *Transfer) connectActive() error {
	t.mu.Lock()
	address := t.activeAddress
	t.mu.Unlock()
	if address == "" {
		return fmt.Errorf("no connection")
	}

	timeout := t.setupTimeout()
	dialer := &net.Dialer{Timeout: timeout}
	if bindIP := strings.TrimSpace(t.slave.localBindIP); bindIP != "" {
		if ip := net.ParseIP(bindIP); ip != nil {
			dialer.LocalAddr = &net.TCPAddr{IP: ip}
		}
	}
	conn, err := dialer.Dial("tcp", address)
	if err != nil {
		return fmt.Errorf("connect failed: %v", err)
	}
	t.configureDataSocket(conn)
	t.setConn(conn)

	if !t.encrypted {
		return nil
	}

	_ = conn.SetDeadline(time.Now().Add(timeout))
	defer conn.SetDeadline(time.Time{})

	if t.sslClientMode {
		tlsConn := tls.Client(conn, dataClientTLSConfig(conn))
		if err := tlsConn.Handshake(); err != nil {
			log.Printf("[Transfer] data TLS client handshake with %s failed (idx=%d): %v", conn.RemoteAddr(), t.transferIndex, err)
			conn.Close()
			return fmt.Errorf("TLS client handshake failed: %v", err)
		}
		t.setConn(tlsConn)
		return nil
	}

	tlsCfg, err := t.slave.serverTLSConfig()
	if err != nil {
		log.Printf("[Transfer] data TLS server cert load failed (idx=%d): %v", t.transferIndex, err)
		conn.Close()
		return fmt.Errorf("load TLS cert: %v", err)
	}
	tlsConn := tls.Server(conn, tlsCfg)
	if err := tlsConn.Handshake(); err != nil {
		log.Printf("[Transfer] data TLS server handshake with %s failed (idx=%d): %v", conn.RemoteAddr(), t.transferIndex, err)
		conn.Close()
		return fmt.Errorf("TLS server handshake failed: %v", err)
	}
	t.setConn(tlsConn)
	return nil
}

// dataClientSessionCache is shared across all outbound data connections so the
// many files in one release can resume TLS instead of doing a full handshake
// (ECDSA verify + extra round-trips) every time. It's safe to share process-wide
// because entries are keyed per peer (see dataClientTLSConfig).
var dataClientSessionCache = tls.NewLRUClientSessionCache(512)

// dataClientTLSConfig builds the client TLS config for an outbound data channel.
// ServerName is set to the peer IP purely to give the session cache a stable key
// across the peer's changing passive ports. Go omits IP literals from the SNI
// extension, so nothing extra is sent on the wire. Resumption is best-effort: if
// the peer doesn't issue tickets, the handshake falls back to a full one.
func dataClientTLSConfig(conn net.Conn) *tls.Config {
	cfg := &tls.Config{
		// FTP data peers can be addressed by IP and may use self-signed certs.
		// Keep this legacy FXP path encrypted; the peer identity is not verified.
		InsecureSkipVerify:          true,
		DynamicRecordSizingDisabled: true,
		ClientSessionCache:          dataClientSessionCache,
	}
	if conn != nil {
		if host, _, err := net.SplitHostPort(conn.RemoteAddr().String()); err == nil && host != "" {
			cfg.ServerName = host
		}
	}
	return cfg
}

func (t *Transfer) configureDataSocket(conn net.Conn) {
	bufferSize := defaultTransferBufferSize * 4
	if t != nil && t.slave != nil {
		bufferSize = t.slave.getTransferBufferSize() * 4
	}
	netutil.ConfigureDataSocket(conn, bufferSize)
}

func (t *Transfer) setupTimeout() time.Duration {
	if t != nil && t.slave != nil && t.slave.timeout > 0 {
		return t.slave.timeout
	}
	return actualTimeout
}

func (t *Transfer) Abort(reason string) {
	t.mu.Lock()
	t.abortReason = reason
	conn := t.conn
	listener := t.listener
	t.mu.Unlock()
	if conn != nil {
		conn.Close()
	}
	if listener != nil {
		listener.Close()
	}
}

func (t *Transfer) errorStatus(msg string) protocol.TransferStatus {
	return t.currentStatus(true, msg)
}

func (t *Transfer) isFinished() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return !t.finished.IsZero() || t.abortReason != ""
}

func (t *Transfer) findAssociatedUpload(path string) *Transfer {
	return t.slave.findUploadByPath(path, t)
}

func (t *Transfer) currentStatus(finished bool, errMsg string) protocol.TransferStatus {
	t.mu.Lock()
	started := t.started
	checksum := t.checksum
	t.mu.Unlock()
	elapsed := int64(0)
	if !started.IsZero() {
		elapsed = time.Since(started).Milliseconds()
	}
	transferred := t.transferred.Load()
	return protocol.TransferStatus{
		TransferIndex: t.transferIndex,
		Elapsed:       elapsed,
		Transferred:   transferred,
		Checksum:      checksum,
		Finished:      finished,
		Error:         errMsg,
	}
}

func transferPathKey(p string) string {
	p = strings.TrimSpace(filepath.ToSlash(p))
	if p == "" {
		return ""
	}
	return strings.ToLower(cleanVirtualPath(p))
}

func (s *Slave) registerUpload(t *Transfer) {
	if s == nil || t == nil {
		return
	}
	t.mu.Lock()
	key := transferPathKey(t.path)
	t.mu.Unlock()
	if key == "" {
		return
	}
	s.uploadByPath.Store(key, t)
}

func (s *Slave) unregisterUpload(t *Transfer) {
	if s == nil || t == nil {
		return
	}
	t.mu.Lock()
	key := transferPathKey(t.path)
	t.mu.Unlock()
	if key == "" {
		return
	}
	s.uploadByPath.CompareAndDelete(key, t)
}

func (s *Slave) findUploadByPath(p string, exclude *Transfer) *Transfer {
	if s == nil {
		return nil
	}
	key := transferPathKey(p)
	if key == "" {
		return nil
	}
	value, ok := s.uploadByPath.Load(key)
	if !ok {
		return nil
	}
	upload, ok := value.(*Transfer)
	if !ok || upload == nil || upload == exclude || upload.isFinished() {
		if ok && upload != nil {
			s.unregisterUpload(upload)
		}
		return nil
	}
	return upload
}

func isUnexpectedTransferPeer(expected string, remote net.Addr) bool {
	expected = strings.TrimSpace(expected)
	if expected == "" || strings.EqualFold(expected, "master") {
		return false
	}
	remoteHost := ""
	if remote != nil {
		if parsedHost, _, err := net.SplitHostPort(remote.String()); err == nil {
			remoteHost = parsedHost
		} else {
			remoteHost = remote.String()
		}
	}
	remoteHost = strings.TrimSpace(remoteHost)
	remoteIP := net.ParseIP(remoteHost)
	if remoteIP == nil && remoteHost == "" {
		return false
	}
	hostMask := expected
	if at := strings.LastIndex(hostMask, "@"); at >= 0 {
		hostMask = hostMask[at+1:]
	}
	if parsedHost, _, err := net.SplitHostPort(hostMask); err == nil {
		hostMask = parsedHost
	}
	hostMask = strings.TrimSpace(hostMask)
	if hostMask == "" {
		hostMask = "*"
	}
	return !matchesTransferHostMask(hostMask, remoteHost, remoteIP)
}

func matchesTransferHostMask(hostMask string, remoteHost string, remoteIP net.IP) bool {
	if hostMask == "*" {
		return true
	}
	candidates := make([]string, 0, 3)
	if remoteIP != nil {
		candidates = append(candidates, remoteIP.String())
	}
	if remoteHost != "" {
		candidates = append(candidates, remoteHost)
	}
	if shouldResolveTransferHostname(hostMask, remoteHost, remoteIP) {
		candidates = append(candidates, resolveTransferHostnames(remoteIP)...)
	}
	for _, candidate := range candidates {
		candidate = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(candidate)), ".")
		if candidate == "" {
			continue
		}
		if matched, err := path.Match(strings.ToLower(hostMask), candidate); err == nil && matched {
			return true
		}
	}
	return false
}

func shouldResolveTransferHostname(hostMask string, remoteHost string, remoteIP net.IP) bool {
	if remoteIP == nil {
		return false
	}
	for _, r := range hostMask {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || r == '-' {
			return true
		}
	}
	return false
}

func resolveTransferHostnames(remoteIP net.IP) []string {
	if remoteIP == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	names, err := net.DefaultResolver.LookupAddr(ctx, remoteIP.String())
	if err != nil {
		return nil
	}
	results := make([]string, 0, len(names))
	for _, name := range names {
		name = strings.TrimSuffix(strings.TrimSpace(name), ".")
		if name != "" {
			results = append(results, name)
		}
	}
	return results
}
