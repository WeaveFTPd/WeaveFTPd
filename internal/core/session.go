package core

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"weaveftpd/internal/acl"
	"weaveftpd/internal/netutil"
	"weaveftpd/internal/user"
)

func sanitizeLoggedFTPLine(line string) string {
	line = strings.TrimSpace(line)
	if line == "" {
		return line
	}
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return line
	}
	cmd := strings.ToUpper(fields[0])
	switch cmd {
	case "PASS":
		return "PASS ********"
	case "SITE":
		if len(fields) < 2 {
			return line
		}
		switch strings.ToUpper(fields[1]) {
		case "ADDUSER", "GADDUSER", "CHPASS", "READD":
			if len(fields) >= 4 {
				fields[3] = "********"
			}
			return strings.Join(fields, " ")
		case "SELFIP":
			if len(fields) >= 5 {
				fields[4] = "********"
			}
			return strings.Join(fields, " ")
		}
	}
	return line
}

// Session represents an active FTP client connection and its state.
type Session struct {
	ID            uint64
	Conn          net.Conn
	User          *user.User
	Config        *Config
	ACLEngine     *acl.Engine    // Engine for handling permissions/flags
	DupeChecker   interface{}    // dupe.DupeChecker for duplicate checking
	MasterManager interface{}    // *master.Manager for master/slave operations
	IsLogged      bool           // Login state (synchronized with commands.go)
	CurrentDir    string         // Virtual path
	TransferType  string         // TYPE state ("A" or "I")
	RenameFrom    string         // Source for RNTO
	SSCN          bool           // Secure FXP mode
	DataListen    net.Listener   // For PASV mode
	ActiveAddr    string         // For PORT mode (Fixes the undefined error in commands.go)
	IsTLS         bool           // Control channel encryption state
	DataTLS       bool           // Data channel encryption state (PROT P)
	GroupMap      map[string]int // groupname -> GID mapping
	StartedAt     time.Time
	PendingUser   string
	PendingReason string

	// Passthrough transfer state (drftpd-style direct client→slave)
	PretCmd         string      // "STOR", "RETR", or "" — set by PRET
	PretArg         string      // filename from PRET
	PassthruSlave   interface{} // slave selected for passthrough (avoids import cycle)
	PassthruXferIdx int32       // slave transfer index for passthrough
	RestOffset      int64       // REST offset applied to the next STOR/RETR
	XDupeMode       int         // SITE XDUPE mode for duplicate listings on STOR
	QuietMode       bool        // glftpd-style "-password" login: suppress MOTD/section/CWD messages

	stateMu               sync.RWMutex
	lastDataConnActive    bool
	nextDataTLSClientMode bool
	LastCommandAt         time.Time
	TransferDirection     string
	TransferPath          string
	TransferBytes         atomic.Int64
	TransferStartedAt     time.Time
	TransferSlaveName     string
	TransferSlaveIdx      int32
	transferConn          net.Conn
}

func (s *Session) currentTransferTypeByte() byte {
	if s == nil || s.TransferType == "" {
		return 'A'
	}
	return s.TransferType[0]
}

// readLinePure reads one FTP command line from a buffered control socket.
func readLinePure(reader *bufio.Reader) (string, error) {
	var buf []byte
	for {
		part, err := reader.ReadSlice('\n')
		buf = append(buf, part...)
		if len(buf) > 4096 {
			return "", fmt.Errorf("command line too long")
		}
		if err == nil {
			return string(buf), nil
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		return "", err
	}
}

// HandleSession initializes the session and manages the command read loop.
func HandleSession(conn net.Conn, tlsConfig *tls.Config, cfg *Config, aclEngine *acl.Engine, dupeChecker interface{}) {
	session := &Session{
		Conn:          conn,
		Config:        cfg,
		ACLEngine:     aclEngine,
		DupeChecker:   dupeChecker,
		MasterManager: cfg.MasterManager,
		CurrentDir:    "/",
		TransferType:  "A",
		GroupMap:      LoadGroupFile("etc/group"),
		StartedAt:     time.Now(),
		LastCommandAt: time.Now(),
	}
	session.ID = registerSession(session)
	defer unregisterSession(session.ID)
	defer session.Conn.Close()

	// Initial Banner
	fmt.Fprintf(session.Conn, "220-%s WeaveFTPd v%s\r\n220 Ready.\r\n",
		session.Config.SiteNameShort, session.Config.Version)

	controlReader := bufio.NewReaderSize(session.Conn, 4096)

	// Main Command Loop
	for {
		line, err := readLinePure(controlReader)
		if err != nil {
			return
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if cfg.Debug {
			logLine := sanitizeLoggedFTPLine(line)
			if session.Config.Debug {
				log.Printf("[%s] -> %s", session.Conn.RemoteAddr(), logLine)
			}
		}

		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue
		}
		cmd := strings.ToUpper(parts[0])
		args := parts[1:]

		if session.Config.Debug {
			log.Printf("[CMD] raw=%q cmd=%q args=%q", sanitizeLoggedFTPLine(line), cmd, args)
		}
		session.touchActivity()

		// Handle AUTH TLS to upgrade the control channel
		if cmd == "AUTH" && len(args) > 0 && strings.ToUpper(args[0]) == "TLS" {
			if buffered := controlReader.Buffered(); buffered > 0 {
				_, _ = controlReader.Discard(buffered)
			}
			fmt.Fprintf(session.Conn, "234 AUTH TLS successful\r\n")

			tlsConn := tls.Server(session.Conn, tlsConfig)

			// Set a strict deadline so old/broken clients don't hang the server
			session.Conn.SetDeadline(time.Now().Add(10 * time.Second))
			if err := tlsConn.Handshake(); err != nil {
				if cfg.Debug {
					log.Printf("Handshake Error: %v", err)
				}
				return
			}

			// Handshake complete, clear the deadline
			session.Conn.SetDeadline(time.Time{})

			session.Conn = tlsConn
			session.IsTLS = true
			controlReader = bufio.NewReaderSize(session.Conn, 4096)

			if cfg.Debug {
				log.Printf("[%s] TLS Handshake Successful", session.Conn.RemoteAddr())
			}

			// --- THE SMART PEEK FIX ---
			// RushFTP waits for 220 in dead silence. cbftp pipelines USER instantly.
			// We give the client 250ms to say something.
			session.Conn.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
			_, peekErr := controlReader.Peek(1)
			session.Conn.SetReadDeadline(time.Time{}) // Clear deadline immediately!

			if peekErr != nil {
				// If we hit a timeout, the client is silent. It's RushFTP.
				if netErr, ok := peekErr.(net.Error); ok && netErr.Timeout() {
					fmt.Fprintf(session.Conn, "220 TLS connection established\r\n")
					controlReader = bufio.NewReaderSize(session.Conn, 4096)
					if cfg.Debug {
						log.Printf("[%s] Client silent after TLS, sent implicit 220 greeting", session.Conn.RemoteAddr())
					}
				}
			}
			// ----------------------------------------------------

			continue
		}

		// Execute the command via the shared processCommand logic
		if quit := session.processCommand(cmd, args, tlsConfig); quit {
			break
		}
	}
}

// getRawDataConn establishes the physical TCP connection for transfers (PORT or PASV).
func (s *Session) getRawDataConn() (net.Conn, error) {
	// Passive Mode (PASV)
	if s.DataListen != nil {
		if s.Config.Debug {
			log.Printf("Waiting for PASV connection on listener...")
		}
		s.DataListen.(*net.TCPListener).SetDeadline(time.Now().Add(10 * time.Second))
		conn, err := s.DataListen.Accept()
		s.DataListen.Close()
		s.DataListen = nil

		if err != nil {
			if s.Config.Debug {
				log.Printf("PASV Accept error: %v", err)
			}
			s.lastDataConnActive = false
			return nil, err
		}
		configureDataSocket(conn)
		s.lastDataConnActive = false
		return conn, nil
	}

	// Active Mode (PORT)
	if s.ActiveAddr != "" {
		if s.Config.Debug {
			log.Printf("Dialing PORT connection to %s", s.ActiveAddr)
		}
		dialer := &net.Dialer{Timeout: 10 * time.Second}
		conn, err := dialer.Dial("tcp", s.ActiveAddr)
		s.ActiveAddr = ""
		s.lastDataConnActive = true
		if err == nil {
			configureDataSocket(conn)
		}
		return conn, err
	}

	s.lastDataConnActive = false
	return nil, fmt.Errorf("no data connection method specified")
}

func configureDataSocket(conn net.Conn) {
	netutil.ConfigureDataSocket(conn, netutil.DefaultDataSocketBufferSize)
}

// upgradeDataTLS applies encryption to the data connection if PROT P is enabled.
func (s *Session) upgradeDataTLS(conn net.Conn, tlsConfig *tls.Config) (net.Conn, error) {
	if !s.DataTLS {
		if s.Config.Debug {
			log.Printf("Data connection in clear")
		}
		return conn, nil
	}
	defer func() {
		s.nextDataTLSClientMode = false
	}()

	if s.Config.Debug {
		log.Printf("Starting TLS handshake on data connection from %s", conn.RemoteAddr())
	}

	conn.SetDeadline(time.Now().Add(10 * time.Second))

	tlsCfg := tlsConfig.Clone()
	var tlsConn *tls.Conn
	if (s.lastDataConnActive && s.SSCN) || (!s.lastDataConnActive && s.nextDataTLSClientMode) {
		// Active/SSCN FXP data peers often use self-signed certificates or an IP
		// address that is not in the certificate SAN. Keep the compatibility path
		// encrypted, while documenting that the peer identity is not verified.
		tlsCfg.InsecureSkipVerify = true
		tlsConn = tls.Client(conn, tlsCfg)
	} else {
		tlsConn = tls.Server(conn, tlsCfg)
	}
	if err := tlsConn.Handshake(); err != nil {
		if s.Config.Debug {
			log.Printf("Data TLS Handshake error: %v", err)
		}
		conn.Close()
		return nil, err
	}

	conn.SetDeadline(time.Time{})

	if s.Config.Debug {
		log.Printf("Data TLS handshake successful")
	}
	return tlsConn, nil
}
