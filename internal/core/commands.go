package core

import (
	"crypto/tls"
	"fmt"
	"hash"
	"hash/crc32"
	"io"
	"io/fs"
	"log"
	"net"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"weaveftpd/internal/timeutil"
	"weaveftpd/internal/user"
	"weaveftpd/internal/zipscript"
)

// getMlsdPerm returns MLSD permissions string for a file
func getMlsdPerm(info os.FileInfo, isSymlink bool) string {
	perms := ""
	if isSymlink {
		perms = "flr"
	} else if info.IsDir() {
		perms = "flcdmpe"
	} else {
		perms = "flrwd"
	}
	return perms
}

func shouldStartRaceWindowForDir(cfg *Config, dirPath string) bool {
	if cfg == nil {
		return false
	}
	return zipscript.ShouldStartRaceWindow(cfg.Zipscript, dirPath)
}

func startReleaseRaceWindow(bridge MasterBridge, dirPath string, startMs int64) {
	starter, ok := bridge.(interface {
		StartReleaseRaceWindow(dirPath string, startMs int64)
	})
	if !ok {
		return
	}
	starter.StartReleaseRaceWindow(dirPath, startMs)
}

// processCommand handles the core RFC 959 FTP and FXP commands.
func (s *Session) processCommand(cmd string, args []string, tlsConfig *tls.Config) bool {
	switch cmd {
	case "FEAT":
		fmt.Fprintf(s.Conn, "211- Extensions supported:\r\n")
		if s.Config != nil && s.Config.TLSEnabled {
			fmt.Fprintf(s.Conn, " AUTH TLS\r\n")
			fmt.Fprintf(s.Conn, " PBSZ\r\n")
			fmt.Fprintf(s.Conn, " PROT\r\n")
			fmt.Fprintf(s.Conn, " SSCN\r\n")
			fmt.Fprintf(s.Conn, " CPSV\r\n")
		}
		fmt.Fprintf(s.Conn, " SIZE\r\n")
		fmt.Fprintf(s.Conn, " MDTM\r\n")
		fmt.Fprintf(s.Conn, " MLSD\r\n")
		fmt.Fprintf(s.Conn, " MLST Type*;Size*;Modify*;Perm*;\r\n")
		fmt.Fprintf(s.Conn, " REST STREAM\r\n")
		fmt.Fprintf(s.Conn, " PRET\r\n")
		fmt.Fprintf(s.Conn, " SITE\r\n")
		fmt.Fprintf(s.Conn, " UTF8\r\n")
		fmt.Fprintf(s.Conn, "211 End\r\n")

	case "OPTS":
		if len(args) > 0 && strings.ToUpper(args[0]) == "UTF8" {
			fmt.Fprintf(s.Conn, "200 UTF8 set to on\r\n")
		} else {
			fmt.Fprintf(s.Conn, "200 OPTS accepted.\r\n")
		}

	case "PBSZ":
		if s.Config == nil || !s.Config.TLSEnabled {
			fmt.Fprintf(s.Conn, "500 TLS not configured\r\n")
			return false
		}
		if !s.IsTLS {
			fmt.Fprintf(s.Conn, "503 Security exchange needs to be completed first\r\n")
			return false
		}
		if len(args) == 0 {
			fmt.Fprintf(s.Conn, "501 Syntax error\r\n")
			return false
		}
		if strings.TrimSpace(args[0]) != "0" {
			fmt.Fprintf(s.Conn, "200 PBSZ=0\r\n")
			return false
		}
		fmt.Fprintf(s.Conn, "200 PBSZ 0 successful\r\n")

	case "PROT":
		if s.Config == nil || !s.Config.TLSEnabled {
			fmt.Fprintf(s.Conn, "500 TLS not configured\r\n")
			return false
		}
		if !s.IsTLS {
			fmt.Fprintf(s.Conn, "500 You are not on a secure channel\r\n")
			return false
		}
		if len(args) == 0 {
			s.DataTLS = false
			fmt.Fprintf(s.Conn, "200 Command OK\r\n")
			return false
		}
		if len(strings.TrimSpace(args[0])) != 1 {
			fmt.Fprintf(s.Conn, "501 Syntax error\r\n")
			return false
		}
		switch strings.ToUpper(args[0]) {
		case "P":
			s.DataTLS = true
			fmt.Fprintf(s.Conn, "200 Protection set to Private\r\n")
		case "C":
			s.DataTLS = false
			fmt.Fprintf(s.Conn, "200 Protection set to Clear\r\n")
		default:
			fmt.Fprintf(s.Conn, "501 Syntax error\r\n")
			return false
		}

	case "SSCN":
		if !s.IsTLS {
			fmt.Fprintf(s.Conn, "500 You are not on a secure channel\r\n")
			return false
		}
		if !s.DataTLS {
			fmt.Fprintf(s.Conn, "500 SSCN only works for encrypted transfers\r\n")
			return false
		}
		if len(args) > 0 {
			switch strings.ToUpper(args[0]) {
			case "ON":
				s.SSCN = true
			case "OFF":
				s.SSCN = false
			}
		}
		if s.SSCN {
			fmt.Fprintf(s.Conn, "220 SSCN:CLIENT METHOD\r\n")
		} else {
			fmt.Fprintf(s.Conn, "220 SSCN:SERVER METHOD\r\n")
		}

	case "CPSV":
		if s.Config.Debug {
			log.Printf("[CPSV] Starting passive mode setup (passthrough=%v)", s.Config.Passthrough)
		}
		s.clearActiveTransferSetup()
		if !s.IsTLS {
			fmt.Fprintf(s.Conn, "500 You are not on a secure channel\r\n")
			return false
		}
		if !s.DataTLS {
			fmt.Fprintf(s.Conn, "500 SSCN only works for encrypted transfers\r\n")
			return false
		}
		if !hasPretForPassive(s) {
			s.clearPreparedTransferState()
			fmt.Fprintf(s.Conn, "500 You need to use a client supporting PRET (PRE Transfer) to use PASV\r\n")
			return false
		}

		if s.Config.Passthrough && s.Config.Mode == "master" && s.MasterManager != nil {
			if bridge, ok := s.MasterManager.(MasterBridge); ok {
				targetPath := s.resolvePretTargetPath(bridge)

				var slaveIP string
				var port int
				var xferIdx int32
				var slaveName string
				var err error
				if s.PretCmd == "RETR" {
					slaveIP, port, xferIdx, slaveName, err = bridge.SlaveListenForDownloadPassthrough(targetPath, s.DataTLS, true)
				} else {
					slaveIP, port, xferIdx, slaveName, err = bridge.SlaveListenForPassthrough(targetPath, s.DataTLS, true)
				}
				if err != nil {
					log.Printf("[CPSV] Passthrough slave listen failed for user %s path %s: %v", s.User.Name, targetPath, err)
					fmt.Fprintf(s.Conn, "450 No available slave for upcoming transfer.\r\n")
					return false
				}
				s.PassthruSlave = slaveName
				s.PassthruXferIdx = xferIdx
				if s.DataListen != nil {
					s.DataListen.Close()
					s.DataListen = nil
				}
				ip, err := ftpPassiveIPv4(slaveIP)
				if err != nil {
					fmt.Fprintf(s.Conn, "500 Invalid passive address for selected slave.\r\n")
					s.clearPassiveTransferSetup()
					return false
				}
				response := fmt.Sprintf("227 Entering Passive Mode (%s,%d,%d)\r\n", ip, port/256, port%256)
				if s.Config.Debug {
					log.Printf("[CPSV] Passthrough to slave %s: %s (port: %d)", slaveName, strings.TrimSpace(response), port)
				}
				fmt.Fprint(s.Conn, response)
				return false
			}
		}

		var l net.Listener
		var port int
		var err error
		for p := s.Config.PasvMin; p <= s.Config.PasvMax; p++ {
			l, err = net.Listen("tcp", fmt.Sprintf(":%d", p))
			if err == nil {
				port = p
				break
			}
		}
		if l == nil {
			fmt.Fprintf(s.Conn, "425 Can't open passive data connection.\r\n")
			return false
		}
		s.DataListen = l
		s.PassthruSlave = nil
		s.nextDataTLSClientMode = true
		ip, err := ftpPassiveIPv4(s.Config.PublicIP)
		if err != nil {
			fmt.Fprintf(s.Conn, "500 Invalid passive address configuration.\r\n")
			if s.DataListen != nil {
				s.DataListen.Close()
				s.DataListen = nil
			}
			return false
		}
		fmt.Fprintf(s.Conn, "227 Entering Passive Mode (%s,%d,%d)\r\n", ip, port/256, port%256)
		return false

	case "USER":
		if len(args) == 0 {
			fmt.Fprintf(s.Conn, "501 Syntax error.\r\n")
			return false
		}
		requestedUser := strings.TrimSpace(args[0])
		normalizedUser := normalizeLoginUsername(requestedUser)
		if normalizedUser == "" {
			s.PendingUser = requestedUser
			s.PendingReason = "unknown_user"
			s.User = nil
			fmt.Fprintf(s.Conn, "331 Password required for %s\r\n", requestedUser)
			return false
		}
		s.PendingUser = normalizedUser
		s.PendingReason = ""
		s.User = nil
		u, err := user.LoadUser(normalizedUser, s.GroupMap)
		if err != nil {
			if _, statErr := os.Stat(deletedUserPath(normalizedUser)); statErr == nil {
				s.PendingReason = "user_deleted"
			} else {
				s.PendingReason = "unknown_user"
			}
			if s.Config.Debug {
				log.Printf("[AUTH] Failed to load user '%s' (requested as '%s'): %v", normalizedUser, requestedUser, err)
			}
		} else {
			s.User = u
		}
		fmt.Fprintf(s.Conn, "331 Password required for %s\r\n", normalizedUser)

	case "PASS":
		if s.User != nil {
			remoteIP, _, _ := net.SplitHostPort(s.Conn.RemoteAddr().String())

			if s.Config.IPRestrictions != nil {
				if restrictedIPs, ok := s.Config.IPRestrictions[s.User.Name]; ok && len(restrictedIPs) > 0 {
					allowed := false
					for _, allowedIP := range restrictedIPs {
						if remoteIP == allowedIP || allowedIP == "*" {
							allowed = true
							break
						}
					}
					if !allowed {
						if s.Config.Debug {
							log.Printf("[PASS] User %s login rejected: IP %s not in whitelist", s.User.Name, remoteIP)
						}
						s.emitLoginFailure(s.User.Name, remoteIP, "ip_restricted")
						fmt.Fprintf(s.Conn, "530 Login not allowed from this IP.\r\n")
						return false
					}
				}
			}

			if s.User.IsExpired() {
				s.emitLoginFailure(s.User.Name, remoteIP, "account_expired")
				fmt.Fprintf(s.Conn, "530 Account expired.\r\n")
				return false
			}
			if s.User.IsDisabled() {
				s.emitLoginFailure(s.User.Name, remoteIP, "account_disabled")
				fmt.Fprintf(s.Conn, "530 Account disabled.\r\n")
				return false
			}
			if ban, ok := FindUserBan(s.User.Name); ok {
				s.emitLoginFailure(s.User.Name, remoteIP, "account_banned")
				if strings.TrimSpace(ban.Reason) != "" {
					fmt.Fprintf(s.Conn, "530 Account banned: %s.\r\n", ban.Reason)
				} else {
					fmt.Fprintf(s.Conn, "530 Account banned.\r\n")
				}
				return false
			}

			pass := ""
			if len(args) > 0 {
				pass = args[0]
			}

			verifyPass := func(p string) (bool, string) {
				ok := false
				hash := ""
				if passwds, err := LoadPasswdFile(s.Config.PasswdFile); err == nil {
					if h, found := passwds[s.User.Name]; found {
						hash = h
						ok = VerifyPasswordCached(s.User.Name, p, h)
					}
				}
				if !ok && s.User.Password != "" {
					ok = (s.User.Password == p)
				}
				return ok, hash
			}

			passwordOK, matchedHash := verifyPass(pass)
			// glftpd-compatible quiet login: prefixing the password with "-"
			// suppresses MOTD, tagline and section/CWD messages for this
			// session (racers keep only the credits line).
			if !passwordOK && len(pass) > 1 && strings.HasPrefix(pass, "-") {
				if ok, hash := verifyPass(pass[1:]); ok {
					pass = pass[1:]
					passwordOK, matchedHash = true, hash
					s.QuietMode = true
				}
			}
			if !passwordOK {
				s.emitLoginFailure(s.User.Name, remoteIP, "bad_password")
				fmt.Fprintf(s.Conn, "530 Login incorrect.\r\n")
				return false
			}
			if matchedHash != "" {
				if upgraded, err := UpgradeLegacyPasswordHash(s.User.Name, pass, matchedHash, s.Config.PasswdFile); err != nil {
					if s.Config.Debug {
						log.Printf("[PASS] User %s legacy hash upgrade failed: %v", s.User.Name, err)
					}
				} else if upgraded && s.Config.Debug {
					log.Printf("[PASS] Upgraded legacy password hash to bcrypt for %s", s.User.Name)
				}
			}

			if !s.User.IPAllowed(remoteIP) {
				reason := "ip_not_allowed"
				if len(s.User.IPs) == 0 {
					reason = "no_ip_masks"
				}
				s.emitLoginFailure(s.User.Name, remoteIP, reason)
				fmt.Fprintf(s.Conn, "530 IP not allowed.\r\n")
				return false
			}

			if s.Config.PluginManager != nil {
				if err := s.Config.PluginManager.ValidateLogin(s.User, remoteIP); err != nil {
					if s.Config.Debug {
						log.Printf("[PASS] User %s rejected by plugin login policy: %v", s.User.Name, err)
					}
					s.emitLoginFailure(s.User.Name, remoteIP, "plugin_rejected")
					fmt.Fprintf(s.Conn, "530 %s.\r\n", err.Error())
					return false
				}
			}

			isTLSExempt := false
			for _, exemptUser := range s.Config.TLSExemptUsers {
				if exemptUser == s.User.Name {
					isTLSExempt = true
					break
				}
			}

			if s.Config.RequireTLSControl && !isTLSExempt && !s.IsTLS {
				if s.Config.Debug {
					log.Printf("[PASS] User %s rejected: TLS required on control channel", s.User.Name)
				}
				s.emitLoginFailure(s.User.Name, remoteIP, "tls_required")
				fmt.Fprintf(s.Conn, "530 TLS required.\r\n")
				return false
			}
			if s.User.LoginSlots > 0 {
				activeSessionsForUser := countSessionsForUser(s.User.Name)
				if activeSessionsForUser >= s.User.LoginSlots {
					s.emitLoginFailure(s.User.Name, remoteIP, "max_logins_reached")
					fmt.Fprintf(s.Conn, "530 Maximum simultaneous logins reached (%d).\r\n", s.User.LoginSlots)
					return false
				}
			}
			if s.User.PrimaryGroup != "" {
				if groupCfg, err := LoadGroupConfig(s.User.PrimaryGroup); err == nil && groupCfg.Simult > 0 {
					if countSessionsForGroup(s.User.PrimaryGroup) >= groupCfg.Simult {
						s.emitLoginFailure(s.User.Name, remoteIP, "group_simult_reached")
						fmt.Fprintf(s.Conn, "530 Group simultaneous login limit reached (%d).\r\n", groupCfg.Simult)
						return false
					}
				}
			}
			if strings.TrimSpace(s.User.CurrentDir) != "" {
				s.CurrentDir = path.Clean(s.User.CurrentDir)
			}
			s.User.LastLogin = time.Now().Unix()
			s.IsLogged = true
			s.PendingUser = ""
			s.PendingReason = ""
			if !s.QuietMode {
				s.emitLoginMOTD()
				fmt.Fprintf(s.Conn, "230-Tagline: %s\r\n", s.User.Tagline)
			}
			s.showGlobalStats("230", false)
			fmt.Fprintf(s.Conn, "230 User logged in.\r\n")
			s.persistLoginStateAsync(s.User.Name, s.User.LastLogin)

		} else {
			remoteIP, _, _ := net.SplitHostPort(s.Conn.RemoteAddr().String())
			reason := s.PendingReason
			if reason == "" {
				reason = "unknown_user"
			}
			s.emitLoginFailure(s.PendingUser, remoteIP, reason)
			fmt.Fprintf(s.Conn, "530 Login incorrect.\r\n")
		}

	case "SYST":
		fmt.Fprintf(s.Conn, "215 UNIX Type: L8\r\n")

	case "TYPE":
		if len(args) == 0 {
			fmt.Fprintf(s.Conn, "501 Syntax error\r\n")
			return false
		}
		transferType, ok := normalizeTransferType(args[0])
		if !ok {
			fmt.Fprintf(s.Conn, "504 Command not implemented for that parameter.\r\n")
			return false
		}
		s.TransferType = transferType
		fmt.Fprintf(s.Conn, "200 Command OK\r\n")

	case "MODE":
		if len(args) == 0 {
			fmt.Fprintf(s.Conn, "501 Syntax error\r\n")
			return false
		}
		if _, ok := normalizeTransferMode(args[0]); !ok {
			fmt.Fprintf(s.Conn, "504 Command not implemented for that parameter.\r\n")
			return false
		}
		fmt.Fprintf(s.Conn, "200 Command OK\r\n")

	case "STRU":
		if len(args) == 0 {
			fmt.Fprintf(s.Conn, "501 Syntax error\r\n")
			return false
		}
		if _, ok := normalizeTransferStructure(args[0]); !ok {
			fmt.Fprintf(s.Conn, "504 Command not implemented for that parameter.\r\n")
			return false
		}
		fmt.Fprintf(s.Conn, "200 Command OK\r\n")

	case "REST":
		if len(args) == 0 {
			fmt.Fprintf(s.Conn, "501 Syntax error\r\n")
			return false
		}
		offset, err := strconv.ParseInt(strings.TrimSpace(args[0]), 10, 64)
		if err != nil || offset < 0 {
			fmt.Fprintf(s.Conn, "501 Invalid REST offset\r\n")
			return false
		}
		s.RestOffset = offset
		fmt.Fprintf(s.Conn, "350 REST position set.\r\n")

	case "PWD":
		fmt.Fprintf(s.Conn, "257 \"%s\" is current directory.\r\n", s.CurrentDir)

	case "CWD":
		target := "/"
		if len(args) > 0 {
			target = args[0]
		}
		if !strings.HasPrefix(target, "/") {
			target = path.Join(s.CurrentDir, target)
		}
		targetPath := path.Clean(target)
		if s.Config.Mode == "master" && s.MasterManager != nil {
			if bridge, ok := s.MasterManager.(MasterBridge); ok {
				targetPath = path.Clean(bridge.ResolvePath(targetPath))
				parent := path.Dir(targetPath)
				name := path.Base(targetPath)
				if resolved := resolveKnownMarkerTarget(bridge, s.Config, parent, name); resolved != "" {
					targetPath = resolved
				}
				if targetPath != "/" {
					entry, ok := bridge.GetPathEntry(targetPath)
					if !ok {
						fmt.Fprintf(s.Conn, "550 %s: no such file or directory\r\n", targetPath)
						return false
					}
					if !entry.IsDir {
						fmt.Fprintf(s.Conn, "550 %s: not a directory\r\n", targetPath)
						return false
					}
				}
			}
		} else {
			localPath := filepath.Join(s.Config.StoragePath, filepath.FromSlash(strings.TrimPrefix(targetPath, "/")))
			info, err := os.Stat(localPath)
			if err != nil {
				if os.IsNotExist(err) {
					fmt.Fprintf(s.Conn, "550 %s: no such file or directory\r\n", targetPath)
				} else {
					fmt.Fprintf(s.Conn, "550 %s: %v\r\n", targetPath, err)
				}
				return false
			}
			if !info.IsDir() {
				fmt.Fprintf(s.Conn, "550 %s: not a directory\r\n", targetPath)
				return false
			}
		}
		if !s.canListPath(targetPath) {
			fmt.Fprintf(s.Conn, "550 %s: no such file or directory\r\n", targetPath)
			return false
		}
		s.CurrentDir = targetPath

		if s.Config.Mode == "master" && s.MasterManager != nil && !s.QuietMode {
			if bridge, ok := s.MasterManager.(MasterBridge); ok {
				emitCWDSectionRules(s, s.CurrentDir)
				emitCWDZipDIZInfo(s, bridge, s.CurrentDir)
				emitCWDAudioInfo(s, bridge, s.CurrentDir)
				if s.Config.ShowDiz != nil {
					for fileName, permission := range s.Config.ShowDiz {
						if fileName == ".message" {
							continue
						}
						if zipscript.ShowZipDIZOnCWDForDir(s.Config.Zipscript, s.CurrentDir) && strings.EqualFold(strings.TrimSpace(fileName), "file_id.diz") {
							continue
						}
						if permission == "*" || s.User.HasFlag(permission) {
							filePath := path.Join(s.CurrentDir, fileName)
							if content, err := bridge.ReadFile(filePath); err == nil && len(content) > 0 {
								text := strings.ReplaceAll(string(content), "\r\n", "\n")
								for _, line := range strings.Split(strings.TrimRight(text, "\n"), "\n") {
									fmt.Fprintf(s.Conn, "250-%s\r\n", line)
								}
							}
						}
					}
				}

				if zipscript.RaceStatusEligibleDir(s.CurrentDir) && zipscript.RaceStatsOnCWDForDir(s.Config.Zipscript, s.CurrentDir) {
					users, groups, totalBytes, present, total := raceStatsForDir(bridge, s.Config, s.CurrentDir)
					users = trimRaceUsers(s.Config, users)
					groups = trimRaceGroups(s.Config, groups)

					if s.Config.Debug {
						log.Printf("[RACESTATS] dir=%s users=%d groups=%d totalBytes=%d present=%d total=%d",
							s.CurrentDir, len(users), len(groups), totalBytes, present, total)
					}

					if shouldRenderCWDRaceBanner(s.Config, users, groups, totalBytes, present, total) {
						var builder strings.Builder
						RenderRaceStats(
							&builder,
							users,
							groups,
							totalBytes,
							present,
							total,
							s.Config.Version,
						)

						for _, line := range strings.Split(strings.TrimRight(builder.String(), "\r\n"), "\n") {
							fmt.Fprintf(s.Conn, "250-%s\r\n", line)
						}
					}
				}
			}
		}

		s.showGlobalStats("250", false)
		fmt.Fprintf(s.Conn, "250 Directory changed to %s\r\n", s.CurrentDir)

	case "CDUP":
		targetPath := path.Clean(path.Join(s.CurrentDir, ".."))
		if !s.canListPath(targetPath) {
			fmt.Fprintf(s.Conn, "550 %s: no such file or directory\r\n", targetPath)
			return false
		}
		s.CurrentDir = targetPath
		fmt.Fprintf(s.Conn, "250 Directory changed to %s\r\n", s.CurrentDir)

	case "MKD":
		if len(args) == 0 {
			fmt.Fprintf(s.Conn, "501 Syntax error\r\n")
			return false
		}

		requestedPath := args[0]
		var targetPath string
		if path.IsAbs(requestedPath) {
			targetPath = path.Clean(requestedPath)
		} else {
			targetPath = path.Join("/", s.CurrentDir, requestedPath)
		}

		if !path.IsAbs(targetPath) {
			targetPath = "/" + targetPath
		}
		targetPath = path.Clean(targetPath)
		if s.Config.Mode == "master" && s.MasterManager != nil {
			if bridge, ok := s.MasterManager.(MasterBridge); ok {
				targetPath = path.Clean(bridge.ResolvePath(targetPath))
			}
		}

		aclPath := path.Join(s.Config.ACLBasePath, targetPath)
		if !s.ACLEngine.CanPerform(s.User, "MKD", aclPath) {
			fmt.Fprintf(s.Conn, "550 Access Denied: Insufficient flags.\r\n")
			return false
		}

		if s.Config.Mode == "master" && s.MasterManager != nil {
			if _, ok := s.MasterManager.(MasterBridge); ok {
				if activeUploadForPath(targetPath) {
					fmt.Fprintf(s.Conn, "550 %s: file is currently being uploaded.\r\n", path.Base(targetPath))
					return false
				}
			}
		} else if activeUploadForPath(targetPath) {
			fmt.Fprintf(s.Conn, "550 %s: file is currently being uploaded.\r\n", path.Base(targetPath))
			return false
		}

		dirName := path.Base(targetPath)

		// Decide whether the new dir participates in dupe-checking. Skip:
		//  - section dirs (parent = root), e.g. /TV-1080P, /X265, /MP3
		//  - known scene subfolders that exist inside many releases
		parent := path.Dir(targetPath)
		isSectionDir := parent == "/" || parent == "."
		isSubFolder := zipscript.IsSceneSubfolder(dirName)
		skipDupeCheck := s.ACLEngine != nil && s.ACLEngine.CanPerformRuleOnly(s.User, "NODUPECHECK", aclPath)
		dupeEligible := !isSectionDir && !isSubFolder && !skipDupeCheck

		if s.Config.PluginManager != nil {
			if err := s.Config.PluginManager.ValidateMKDir(s.User, targetPath); err != nil {
				fmt.Fprintf(s.Conn, "550 %v\r\n", err)
				return false
			}
		}

		if dupeEligible && s.DupeChecker != nil {
			if dc, ok := s.DupeChecker.(interface{ IsDupe(string) (bool, error) }); ok {
				if isDupe, err := dc.IsDupe(dirName); err == nil && isDupe {
					fmt.Fprintf(s.Conn, "550 %s: directory already exists in dupe database.\r\n", dirName)
					return false
				}
			}
		}

		if s.Config.Mode == "master" && s.MasterManager != nil {
			if bridge, ok := s.MasterManager.(MasterBridge); ok {
				if bridge.FileExists(targetPath) {
					fmt.Fprintf(s.Conn, "550 %s: directory already exists.\r\n", dirName)
					return false
				}
				if err := bridge.MakeDir(targetPath, s.User.Name, s.User.PrimaryGroup); err != nil {
					fmt.Fprintf(s.Conn, "550 MKD failed: %v\r\n", err)
					return false
				}
				if shouldStartRaceWindowForDir(s.Config, targetPath) {
					startReleaseRaceWindow(bridge, targetPath, time.Now().UnixMilli())
				}
			}
		}

		if dupeEligible && s.DupeChecker != nil {
			if dc, ok := s.DupeChecker.(interface {
				AddDupe(string, string, string, int, int64) error
			}); ok {
				dc.AddDupe(dirName, s.User.PrimaryGroup, s.User.Name, 0, 0)
			}
		}

		s.emitEvent(EventMKDir, targetPath, dirName, 0, 0, nil)

		fmt.Fprintf(s.Conn, "257 \"%s\" created\r\n", targetPath)

	case "RMD":
		if len(args) == 0 {
			fmt.Fprintf(s.Conn, "501 Syntax error\r\n")
			return false
		}
		dirPath := resolveSessionPath(s.CurrentDir, args[0])
		if !s.canRemoveDirPath(dirPath) {
			fmt.Fprintf(s.Conn, "550 Access Denied: Insufficient flags.\r\n")
			return false
		}
		if s.Config.Mode == "master" && s.MasterManager != nil {
			if bridge, ok := s.MasterManager.(MasterBridge); ok {
				if err := cleanupAudioSortLinksForRelease(bridge, s.Config.Zipscript, dirPath); err != nil && s.Config.Debug {
					log.Printf("[MASTER-ZS] audio sort cleanup skipped for %s: %v", dirPath, err)
				}
				if err := bridge.DeleteFile(dirPath); err != nil {
					fmt.Fprintf(s.Conn, "550 Delete failed: %v\r\n", err)
					return false
				}
			}
		}
		s.emitEvent(EventRMDir, dirPath, path.Base(dirPath), 0, 0, nil)
		fmt.Fprintf(s.Conn, "250 Directory removed.\r\n")

	case "SIZE":
		if len(args) == 0 {
			fmt.Fprintf(s.Conn, "501 Syntax error\r\n")
			return false
		}
		if s.Config.Mode == "master" && s.MasterManager != nil {
			if bridge, ok := s.MasterManager.(MasterBridge); ok {
				filePath := resolveSessionPath(s.CurrentDir, args[0])
				size := bridge.GetFileSize(filePath)
				if size >= 0 {
					fmt.Fprintf(s.Conn, "213 %d\r\n", size)
				} else {
					fmt.Fprintf(s.Conn, "550 File not found.\r\n")
				}
			}
		}

	case "MDTM":
		if len(args) == 0 {
			fmt.Fprintf(s.Conn, "501 Syntax error\r\n")
			return false
		}
		if s.Config.Mode == "master" && s.MasterManager != nil {
			if bridge, ok := s.MasterManager.(MasterBridge); ok {
				filePath := resolveSessionPath(s.CurrentDir, args[0])
				parent := path.Dir(filePath)
				name := path.Base(filePath)
				entries := bridge.ListDir(parent)
				found := false
				for _, e := range entries {
					if e.Name == name {
						fmt.Fprintf(s.Conn, "213 %s\r\n", timeutil.FTPMachineUnix(e.ModTime))
						found = true
						break
					}
				}
				if !found {
					fmt.Fprintf(s.Conn, "550 File not found.\r\n")
				}
			}
		}

	case "DELE":
		if len(args) == 0 {
			fmt.Fprintf(s.Conn, "501 Syntax error\r\n")
			return false
		}
		filePath := resolveSessionPath(s.CurrentDir, args[0])
		if !s.canDeletePath(filePath) {
			fmt.Fprintf(s.Conn, "550 Access Denied: Insufficient flags.\r\n")
			return false
		}
		if s.Config.Mode == "master" && s.MasterManager != nil {
			if bridge, ok := s.MasterManager.(MasterBridge); ok {
				if activeUploadForPath(filePath) {
					fmt.Fprintf(s.Conn, "550 Cannot delete: file is currently being uploaded.\r\n")
					return false
				}
				releasePath := path.Clean(path.Dir(filePath))
				previousMedia := cloneStringMap(bridge.GetDirMediaInfo(releasePath))
				if err := bridge.DeleteFile(filePath); err != nil {
					fmt.Fprintf(s.Conn, "550 Delete failed: %v\r\n", err)
					return false
				}
				if zipscript.IsMediaInfoFile(path.Base(filePath)) {
					if err := maybeRefreshReleaseMediaInfoAndLinks(s.Config, bridge, releasePath, previousMedia); err != nil && s.Config.Debug {
						log.Printf("[MASTER-ZS] media cleanup skipped for %s: %v", releasePath, err)
					}
				}
			}
		}
		fmt.Fprintf(s.Conn, "250 File deleted.\r\n")

	case "RNFR":
		if len(args) == 0 {
			fmt.Fprintf(s.Conn, "501 Syntax error\r\n")
			return false
		}
		renameFrom := resolveSessionPath(s.CurrentDir, args[0])
		if s.Config.Mode == "master" && s.MasterManager != nil {
			if bridge, ok := s.MasterManager.(MasterBridge); ok && !bridge.FileExists(renameFrom) {
				fmt.Fprintf(s.Conn, "550 File not found.\r\n")
				return false
			}
		} else {
			localPath := filepath.Join(s.Config.StoragePath, filepath.FromSlash(strings.TrimPrefix(renameFrom, "/")))
			if _, err := os.Stat(localPath); err != nil {
				fmt.Fprintf(s.Conn, "550 File not found.\r\n")
				return false
			}
		}
		s.RenameFrom = renameFrom
		fmt.Fprintf(s.Conn, "350 File exists, ready for destination name.\r\n")

	case "RNTO":
		if len(args) == 0 || s.RenameFrom == "" {
			fmt.Fprintf(s.Conn, "503 Bad sequence of commands.\r\n")
			return false
		}
		fromPath := resolveSessionPath(s.CurrentDir, s.RenameFrom)
		toPath := resolveSessionPath(s.CurrentDir, args[0])
		toDir := path.Dir(toPath)
		toName := path.Base(toPath)
		if toName == "" || toName == "." || toName == "/" || toName == ".." {
			fmt.Fprintf(s.Conn, "501 Invalid destination name.\r\n")
			return false
		}
		if !s.canRenamePath(fromPath, toPath) {
			fmt.Fprintf(s.Conn, "550 Access Denied: Insufficient flags.\r\n")
			return false
		}
		if s.Config.Mode == "master" && s.MasterManager != nil {
			if bridge, ok := s.MasterManager.(MasterBridge); ok {
				fromRelease := path.Clean(path.Dir(fromPath))
				previousMedia := cloneStringMap(bridge.GetDirMediaInfo(fromRelease))
				if err := bridge.RenameFile(fromPath, toDir, toName); err != nil {
					fmt.Fprintf(s.Conn, "550 Rename failed: %v\r\n", err)
					s.RenameFrom = ""
					return false
				}
				if zipscript.IsMediaInfoFile(path.Base(fromPath)) || zipscript.IsMediaInfoFile(path.Base(toPath)) {
					if err := maybeRefreshReleaseMediaInfoAndLinks(s.Config, bridge, fromRelease, previousMedia); err != nil && s.Config.Debug {
						log.Printf("[MASTER-ZS] media cleanup skipped for %s: %v", fromRelease, err)
					}
				}
			}
		}
		fmt.Fprintf(s.Conn, "250 Rename successful.\r\n")
		s.RenameFrom = ""

	case "SITE":
		return s.DispatchSiteCommand(args)

	case "PRET":
		if s.Config.Debug && len(args) > 0 {
			log.Printf("[PRET] Client preparing for %s", args[0])
		}
		s.clearPreparedTransferState()
		if len(args) == 0 {
			fmt.Fprintf(s.Conn, "501 Syntax error.\r\n")
			return false
		}
		preparedCmd, preparedArg, err := validatePretRequest(s, args[0], args[1:])
		if err != nil {
			fmt.Fprintf(s.Conn, "504 %s\r\n", err.Error())
			return false
		}
		if s.Config.XdupeEnabled && preparedCmd == "STOR" && preparedArg != "" && s.Config.Mode == "master" && s.MasterManager != nil {
			if bridge, ok := s.MasterManager.(MasterBridge); ok {
				pretTarget := path.Clean(path.Join(s.CurrentDir, preparedArg))
				if path.IsAbs(strings.TrimSpace(preparedArg)) {
					pretTarget = path.Clean(preparedArg)
				}
				pretTarget = bridge.ResolvePath(pretTarget)
				if bridge.FileExists(pretTarget) {
					writeDuplicateFileResponse(s, path.Base(pretTarget), existingFileNamesForXDupe(bridge.ListDir(path.Dir(pretTarget))))
					return false
				}
				if uploadPathReserved(pretTarget) || pendingUploadForReply(bridge, pretTarget) {
					writeUploadAlreadyInProgressResponse(s, path.Base(pretTarget), existingFileNamesForXDupe(bridge.ListDir(path.Dir(pretTarget))))
					return false
				}
			}
		}
		s.PretCmd = preparedCmd
		s.PretArg = preparedArg
		fmt.Fprintf(s.Conn, "200 %s\r\n", pretSuccessMessage(preparedCmd))
		return false

	case "ABOR":
		s.abortCurrentTransfer("Transfer aborted")
		fmt.Fprintf(s.Conn, "226 Abort successful\r\n")
		return false

	case "NOOP":
		fmt.Fprintf(s.Conn, "200 NOOP OK\r\n")
		return false

	case "PASV":
		if s.Config.Debug {
			log.Printf("[PASV] Starting passive mode setup (pret=%s, passthrough=%v)", s.PretCmd, s.Config.Passthrough)
		}
		s.clearActiveTransferSetup()
		if !hasPretForPassive(s) {
			s.clearPreparedTransferState()
			fmt.Fprintf(s.Conn, "500 You need to use a client supporting PRET (PRE Transfer) to use PASV\r\n")
			return false
		}

		if s.Config.Passthrough && s.Config.Mode == "master" && s.MasterManager != nil {
			if s.PretCmd == "STOR" || s.PretCmd == "RETR" {
				if bridge, ok := s.MasterManager.(MasterBridge); ok {
					targetPath := s.resolvePretTargetPath(bridge)

					var slaveIP string
					var port int
					var xferIdx int32
					var slaveName string
					var err error
					if s.PretCmd == "RETR" {
						slaveIP, port, xferIdx, slaveName, err = bridge.SlaveListenForDownloadPassthrough(targetPath, s.DataTLS, false)
					} else {
						slaveIP, port, xferIdx, slaveName, err = bridge.SlaveListenForPassthrough(targetPath, s.DataTLS, false)
					}
					if err != nil {
						log.Printf("[PASV] Passthrough slave listen failed: %v", err)
						fmt.Fprintf(s.Conn, "450 No available slave for upcoming transfer.\r\n")
						return false
					}
					s.PassthruSlave = slaveName
					s.PassthruXferIdx = xferIdx
					if s.DataListen != nil {
						s.DataListen.Close()
						s.DataListen = nil
					}
					ip, err := ftpPassiveIPv4(slaveIP)
					if err != nil {
						fmt.Fprintf(s.Conn, "500 Invalid passive address for selected slave.\r\n")
						s.clearPassiveTransferSetup()
						return false
					}
					response := fmt.Sprintf("227 Entering Passive Mode (%s,%d,%d)\r\n", ip, port/256, port%256)
					if s.Config.Debug {
						log.Printf("[PASV] Passthrough to slave %s: %s (port: %d, xferIdx: %d)", slaveName, strings.TrimSpace(response), port, xferIdx)
					}
					fmt.Fprint(s.Conn, response)
					return false
				}
			}
		}

		var l net.Listener
		var port int
		var err error
		for p := s.Config.PasvMin; p <= s.Config.PasvMax; p++ {
			l, err = net.Listen("tcp", fmt.Sprintf(":%d", p))
			if err == nil {
				port = p
				break
			}
		}
		if l == nil {
			if s.Config.Debug {
				log.Printf("[PASV] No available ports (tried %d-%d)", s.Config.PasvMin, s.Config.PasvMax)
			}
			fmt.Fprintf(s.Conn, "425 Can't open passive data connection.\r\n")
			return false
		}
		s.DataListen = l
		s.PassthruSlave = nil
		s.PassthruXferIdx = 0
		s.nextDataTLSClientMode = false
		ip, err := ftpPassiveIPv4(s.Config.PublicIP)
		if err != nil {
			fmt.Fprintf(s.Conn, "500 Invalid passive address configuration.\r\n")
			if s.DataListen != nil {
				s.DataListen.Close()
				s.DataListen = nil
			}
			return false
		}
		response := fmt.Sprintf("227 Entering Passive Mode (%s,%d,%d)\r\n", ip, port/256, port%256)
		if s.Config.Debug {
			log.Printf("[PASV] Sending response: %s (port: %d)", strings.TrimSpace(response), port)
		}
		fmt.Fprint(s.Conn, response)
		return false

	case "PORT":
		if len(args) == 0 {
			return false
		}
		s.clearPassiveTransferSetup()
		ip, port, err := parsePortTarget(args[0])
		if err != nil {
			fmt.Fprintf(s.Conn, "501 Syntax error\r\n")
			return false
		}
		controlHost, _, splitErr := net.SplitHostPort(s.Conn.RemoteAddr().String())
		controlIP := net.ParseIP(controlHost)
		if splitErr == nil && shouldRejectPortTarget(controlIP, ip) {
			fmt.Fprintf(s.Conn, "501 ==YOU'RE BEHIND A NAT ROUTER==\r\n")
			fmt.Fprintf(s.Conn, "501 Configure your FTP client to use your real IP: %s\r\n", controlHost)
			fmt.Fprintf(s.Conn, "501 Or use a PRET-capable passive transfer mode.\r\n")
			return false
		}
		s.ActiveAddr = fmt.Sprintf("%s:%d", ip.String(), port)
		warnings := portTargetWarnings(controlIP, ip)
		if len(warnings) == 0 {
			fmt.Fprintf(s.Conn, "200 PORT command successful.\r\n")
			return false
		}
		for _, warning := range warnings {
			fmt.Fprintf(s.Conn, "200-%s\r\n", warning)
		}
		fmt.Fprintf(s.Conn, "200 PORT command successful.\r\n")

	case "MLST":
		target := s.CurrentDir
		if len(args) > 0 && strings.TrimSpace(args[0]) != "" {
			t := strings.TrimSpace(args[0])
			if strings.HasPrefix(t, "/") {
				target = path.Clean(t)
			} else {
				target = path.Clean(path.Join(s.CurrentDir, t))
			}
		}
		if !s.canListPath(target) {
			fmt.Fprintf(s.Conn, "550 %s: no such file or directory\r\n", target)
			return false
		}

		facts := ""
		found := false
		if s.Config.Mode == "master" && s.MasterManager != nil {
			if bridge, ok := s.MasterManager.(MasterBridge); ok {
				if target == "/" {
					facts = "Type=dir;Perm=elcmp; /"
					found = true
				} else {
					parent := path.Dir(target)
					name := path.Base(target)
					for _, e := range bridge.ListDir(parent) {
						if e.Name == name {
							aclPath := path.Join(s.Config.ACLBasePath, parent, e.Name)
							if !s.ACLEngine.CanPerform(s.User, "LIST", aclPath) {
								break
							}
							ts := timeutil.FTPMachineUnix(e.ModTime)
							var parts []string
							if e.IsSymlink {
								parts = []string{
									fmt.Sprintf("Modify=%s", ts),
									"Perm=el",
									"Type=" + mlsdSymlinkType(e),
								}
							} else if e.IsDir {
								perm := "elcmp"
								if e.Mode == 0555 {
									perm = "el"
								}
								parts = []string{
									fmt.Sprintf("Modify=%s", ts),
									"Perm=" + perm,
									"Type=dir",
								}
							} else {
								parts = []string{
									fmt.Sprintf("Modify=%s", ts),
									"Perm=radfw",
									"Type=file",
									fmt.Sprintf("Size=%d", e.Size),
								}
							}
							facts = strings.Join(parts, ";") + "; " + target
							found = true
							break
						}
					}
				}
			}
		}

		if !found {
			fmt.Fprintf(s.Conn, "550 %s: no such file or directory\r\n", target)
			return false
		}
		fmt.Fprintf(s.Conn, "250- Listing %s\r\n", target)
		fmt.Fprintf(s.Conn, " %s\r\n", facts)
		fmt.Fprintf(s.Conn, "250 End\r\n")

	case "MLSD":
		defer s.clearPreparedTransferState()
		if !s.hasPreparedDataConnection() {
			fmt.Fprintf(s.Conn, "503 Bad sequence of commands.\r\n")
			return false
		}
		targetPath := s.CurrentDir
		if s.Config.Mode == "master" && s.MasterManager != nil {
			if bridge, ok := s.MasterManager.(MasterBridge); ok {
				targetPath = s.resolveListTargetPath("MLSD", args, bridge)
			}
		} else {
			targetPath = s.resolveListTargetPath("MLSD", args, nil)
		}
		if err := s.validateListDirectoryTarget(targetPath, s.masterBridgeOrNil()); err != nil {
			if err.Error() == "504" {
				fmt.Fprintf(s.Conn, "504 Command not implemented for that parameter.\r\n")
			} else {
				fmt.Fprintf(s.Conn, "550 %s: no such file or directory\r\n", targetPath)
			}
			return false
		}
		if s.Config.Debug {
			log.Printf("[MLSD] Client requesting machine list for %s", targetPath)
		}
		fmt.Fprintf(s.Conn, "150 File status okay; about to open data connection.\r\n")

		raw, err := s.getRawDataConn()
		if err != nil {
			fmt.Fprintf(s.Conn, "425 Data connection failed\r\n")
			return false
		}
		dataConn, err := s.upgradeDataTLS(raw, tlsConfig)
		if err != nil {
			raw.Close()
			fmt.Fprintf(s.Conn, "435 Failed TLS negotiation on data channel\r\n")
			return false
		}

		var output strings.Builder

		if s.Config.Mode == "master" && s.MasterManager != nil {
			if bridge, ok := s.MasterManager.(MasterBridge); ok {
				entries := bridge.ListDir(targetPath)

				// Keep MLSD rich for cbftp, but only from already-available state.
				siteName := s.Config.SiteNameShort
				if siteName == "" {
					siteName = "WeaveFTPd"
				}
				if zipscript.ShowStatusBarForDir(s.Config.Zipscript, targetPath) {
					if statusName := dirRaceStatusName(bridge, s.Config, targetPath, siteName); strings.TrimSpace(statusName) != "" {
						nowTs := timeutil.FTPMachine(time.Now())
						entryType := "file"
						if zipscript.StatusBarDirectoryForDir(s.Config.Zipscript, targetPath) {
							entryType = "dir"
						}
						output.WriteString(fmt.Sprintf("Modify=%s;Perm=el;Type=%s; %s\r\n", nowTs, entryType, statusName))
					}
				}

				for _, e := range entries {
					if strings.HasPrefix(e.Name, ".") {
						continue
					}
					aclPath := path.Join(s.Config.ACLBasePath, targetPath, e.Name)
					if !s.ACLEngine.CanPerform(s.User, "LIST", aclPath) {
						continue
					}
					ts := timeutil.FTPMachineUnix(e.ModTime)
					var perm string
					var facts []string
					if e.IsSymlink {
						perm = "el"
						facts = []string{
							fmt.Sprintf("Modify=%s", ts),
							"Perm=" + perm,
							"Type=" + mlsdSymlinkType(e),
						}
					} else if e.IsDir {
						perm = "elcmp" // enter, list, create, mkdir, purge
						if e.Mode == 0555 {
							perm = "el"
						}
						facts = []string{
							fmt.Sprintf("Modify=%s", ts),
							"Perm=" + perm,
							"Type=dir",
						}
					} else {
						perm = "radfw" // read, append, delete, rename, write
						facts = []string{
							fmt.Sprintf("Modify=%s", ts),
							"Perm=" + perm,
							"Type=file",
							fmt.Sprintf("Size=%d", e.Size),
						}
					}
					facts = appendMLSDOwnerGroupFacts(facts, e, s.Config.ShowRealOwnerGroup)
					output.WriteString(strings.Join(facts, ";") + "; " + e.Name + "\r\n")
				}
			}
		} else {
			mlsdPath := filepath.Join(s.Config.StoragePath, targetPath)
			files, err := os.ReadDir(mlsdPath)
			if err != nil {
				if s.Config.Debug {
					log.Printf("[MLSD] ReadDir %s: %v", mlsdPath, err)
				}
			}
			for _, f := range files {
				if strings.HasPrefix(f.Name(), ".") {
					continue
				}
				if !s.Config.ShowSymlinks && f.Type()&fs.ModeSymlink != 0 {
					continue
				}
				if !s.canListPath(path.Join(targetPath, f.Name())) {
					continue
				}
				fileName := f.Name()
				fullPath := filepath.Join(mlsdPath, fileName)
				isSymlink := f.Type()&fs.ModeSymlink != 0
				var info os.FileInfo
				if isSymlink {
					info, err = os.Lstat(fullPath)
				} else {
					info, err = f.Info()
				}
				if err != nil || info == nil {
					continue
				}
				facts := []string{
					fmt.Sprintf("Modify=%s", timeutil.FTPMachine(info.ModTime())),
					fmt.Sprintf("Perm=%s", getMlsdPerm(info, isSymlink)),
				}
				if isSymlink {
					facts = append(facts, "Type=OS.unix=symlink")
				} else if info.IsDir() {
					facts = append(facts, "Type=dir")
				} else {
					facts = append(facts, "Type=file")
					facts = append(facts, fmt.Sprintf("Size=%d", info.Size()))
				}
				output.WriteString(strings.Join(facts, ";") + "; " + fileName + "\r\n")
			}
		}

		dataConn.Write([]byte(output.String()))
		dataConn.Close()
		fmt.Fprintf(s.Conn, "226 Directory listing complete.\r\n")
		return false

	case "NLST":
		defer s.clearPreparedTransferState()
		if !s.hasPreparedDataConnection() {
			fmt.Fprintf(s.Conn, "503 Bad sequence of commands.\r\n")
			return false
		}
		targetPath := s.CurrentDir
		if s.Config.Mode == "master" && s.MasterManager != nil {
			if bridge, ok := s.MasterManager.(MasterBridge); ok {
				targetPath = s.resolveListTargetPath("NLST", args, bridge)
			}
		} else {
			targetPath = s.resolveListTargetPath("NLST", args, nil)
		}
		if err := s.validateListTargetExists(targetPath, s.masterBridgeOrNil()); err != nil {
			fmt.Fprintf(s.Conn, "550 %s: no such file or directory\r\n", targetPath)
			return false
		}
		fmt.Fprintf(s.Conn, "150 Opening ASCII mode data connection.\r\n")

		raw, err := s.getRawDataConn()
		if err != nil {
			fmt.Fprintf(s.Conn, "425 Data connection failed\r\n")
			return false
		}
		dataConn, err := s.upgradeDataTLS(raw, tlsConfig)
		if err != nil {
			raw.Close()
			fmt.Fprintf(s.Conn, "435 Failed TLS negotiation on data channel\r\n")
			return false
		}

		var output strings.Builder

		if s.Config.Mode == "master" && s.MasterManager != nil {
			if bridge, ok := s.MasterManager.(MasterBridge); ok {
				if entry, found := bridge.GetPathEntry(targetPath); found && !entry.IsDir {
					aclPath := path.Join(s.Config.ACLBasePath, targetPath)
					if s.ACLEngine.CanPerform(s.User, "LIST", aclPath) && !strings.HasPrefix(entry.Name, ".") {
						output.WriteString(entry.Name + "\r\n")
					}
				} else {
					for _, e := range bridge.ListDir(targetPath) {
						if strings.HasPrefix(e.Name, ".") {
							continue
						}
						if strings.HasPrefix(e.Name, "[#") || strings.HasPrefix(e.Name, "[:") {
							continue
						}
						if strings.Contains(e.Name, "COMPLETE") && strings.Contains(e.Name, "[") {
							continue
						}
						aclPath := path.Join(s.Config.ACLBasePath, targetPath, e.Name)
						if !s.ACLEngine.CanPerform(s.User, "LIST", aclPath) {
							continue
						}
						output.WriteString(e.Name + "\r\n")
					}
				}
			}
		} else {
			listPath := filepath.Join(s.Config.StoragePath, targetPath)
			if info, statErr := os.Lstat(listPath); statErr == nil && !info.IsDir() {
				name := filepath.Base(listPath)
				if !strings.HasPrefix(name, ".") && s.canListPath(targetPath) {
					output.WriteString(name + "\r\n")
				}
			} else if files, readErr := os.ReadDir(listPath); readErr == nil {
				for _, f := range files {
					if strings.HasPrefix(f.Name(), ".") {
						continue
					}
					if !s.Config.ShowSymlinks && f.Type()&fs.ModeSymlink != 0 {
						continue
					}
					if !s.canListPath(path.Join(targetPath, f.Name())) {
						continue
					}
					output.WriteString(f.Name() + "\r\n")
				}
			}
		}

		dataConn.Write([]byte(output.String()))
		dataConn.Close()

		if s.Config.Mode == "master" && s.MasterManager != nil {
			s.showGlobalStats("226", false)
		}

		fmt.Fprintf(s.Conn, "226 Directory listing complete.\r\n")
		return false

	case "LIST":
		defer s.clearPreparedTransferState()
		if !s.hasPreparedDataConnection() {
			fmt.Fprintf(s.Conn, "503 Bad sequence of commands.\r\n")
			return false
		}
		targetPath := s.CurrentDir
		if s.Config.Mode == "master" && s.MasterManager != nil {
			if bridge, ok := s.MasterManager.(MasterBridge); ok {
				targetPath = s.resolveListTargetPath("LIST", args, bridge)
			}
		} else {
			targetPath = s.resolveListTargetPath("LIST", args, nil)
		}
		if err := s.validateListDirectoryTarget(targetPath, s.masterBridgeOrNil()); err != nil {
			if err.Error() == "504" {
				fmt.Fprintf(s.Conn, "504 Command not implemented for that parameter.\r\n")
			} else {
				fmt.Fprintf(s.Conn, "550 %s: no such file or directory\r\n", targetPath)
			}
			return false
		}
		fmt.Fprintf(s.Conn, "150 Opening ASCII mode data connection.\r\n")

		raw, err := s.getRawDataConn()
		if err != nil {
			fmt.Fprintf(s.Conn, "425 Data connection failed\r\n")
			return false
		}
		dataConn, err := s.upgradeDataTLS(raw, tlsConfig)
		if err != nil {
			raw.Close()
			fmt.Fprintf(s.Conn, "435 Failed TLS negotiation on data channel\r\n")
			return false
		}

		var output strings.Builder

		if s.Config.Mode == "master" && s.MasterManager != nil {
			if bridge, ok := s.MasterManager.(MasterBridge); ok {
				entries := bridge.ListDir(targetPath)
				now := timeutil.Now().Format("Jan _2 15:04")
				siteName := s.Config.SiteNameShort
				if siteName == "" {
					siteName = "WeaveFTPd"
				}

				if zipscript.ShowStatusBarForDir(s.Config.Zipscript, targetPath) {
					if statusName := dirRaceStatusName(bridge, s.Config, targetPath, siteName); strings.TrimSpace(statusName) != "" {
						mode := "drwxr-xr-x"
						size := "4096"
						if !zipscript.StatusBarDirectoryForDir(s.Config.Zipscript, targetPath) {
							mode = "-rw-r--r--"
							size = "0"
						}
						output.WriteString(fmt.Sprintf("%s   1 %-8s %-8s %10s %s %s\r\n",
							mode, "WeaveFTPd", "WeaveFTPd", size, now, statusName))
					}
				}

				for _, e := range entries {
					if strings.HasPrefix(e.Name, ".") {
						continue
					}
					if strings.HasPrefix(e.Name, "[#") || strings.HasPrefix(e.Name, "[:") {
						continue
					}
					if strings.Contains(e.Name, "COMPLETE") && strings.Contains(e.Name, "[") {
						continue
					}

					aclPath := path.Join(s.Config.ACLBasePath, targetPath, e.Name)
					if !s.ACLEngine.CanPerform(s.User, "LIST", aclPath) {
						continue
					}

					mode := ftpListMode(e)
					size := fmt.Sprintf("%d", e.Size)
					name := e.Name
					if e.IsSymlink {
						size = "0"
						name = fmt.Sprintf("%s -> %s", e.Name, e.LinkTarget)
					} else if e.IsDir {
						size = "4096"
					}
					ts := timeutil.Unix(e.ModTime).Format("Jan _2 15:04")
					owner := "WeaveFTPd"
					group := "WeaveFTPd"
					if s.Config.ShowRealOwnerGroup {
						owner = strings.TrimSpace(e.Owner)
						group = strings.TrimSpace(e.Group)
						if owner == "" {
							owner = "WeaveFTPd"
						}
						if group == "" {
							group = "WeaveFTPd"
						}
					}
					output.WriteString(fmt.Sprintf("%s   1 %-8s %-8s %10s %s %s\r\n",
						mode, owner, group, size, ts, name))
				}

			}
		} else {
			// FALLBACK: Standalone mode directory listing for cbftp
			listPath := filepath.Join(s.Config.StoragePath, targetPath)
			files, err := os.ReadDir(listPath)
			if err == nil {

				for _, f := range files {
					if strings.HasPrefix(f.Name(), ".") {
						continue
					}
					if !s.Config.ShowSymlinks && f.Type()&fs.ModeSymlink != 0 {
						continue
					}
					if !s.canListPath(path.Join(targetPath, f.Name())) {
						continue
					}
					info, err := f.Info()
					if err != nil {
						continue
					}
					mode := "-rw-r--r--"
					size := fmt.Sprintf("%d", info.Size())
					if info.IsDir() {
						mode = "drwxr-xr-x"
						size = "4096"
					} else if f.Type()&fs.ModeSymlink != 0 {
						mode = "lrwxrwxrwx"
					}
					ts := timeutil.In(info.ModTime()).Format("Jan _2 15:04")
					output.WriteString(fmt.Sprintf("%s   1 %-8s %-8s %10s %s %s\r\n",
						mode, "WeaveFTPd", "WeaveFTPd", size, ts, f.Name()))
				}
			}
		}

		dataConn.Write([]byte(output.String()))
		dataConn.Close()

		// Only show stats in master mode so we don't crash standalone
		if s.Config.Mode == "master" && s.MasterManager != nil {
			s.showGlobalStats("226", false)
		}

		fmt.Fprintf(s.Conn, "226 Directory listing complete.\r\n")
		return false

	case "STOR":
		if len(args) == 0 {
			return false
		}
		defer s.clearPreparedTransferState()
		if !s.hasPreparedTransferChannel() {
			fmt.Fprintf(s.Conn, "503 Bad sequence of commands.\r\n")
			return false
		}

		isTLSExempt := false
		for _, exemptUser := range s.Config.TLSExemptUsers {
			if exemptUser == s.User.Name {
				isTLSExempt = true
				break
			}
		}
		if s.Config.RequireTLSData && !isTLSExempt && !s.DataTLS {
			fmt.Fprintf(s.Conn, "550 TLS required for data transfers.\r\n")
			return false
		}

		fileName := args[0]
		restOffset := s.RestOffset
		s.RestOffset = 0
		var existingNames []string
		var masterUploadEntries []MasterFileEntry
		masterUploadEntriesLoaded := false
		uploadDir := s.CurrentDir
		uploadPath := path.Clean(path.Join(s.CurrentDir, fileName))
		if path.IsAbs(strings.TrimSpace(fileName)) {
			uploadPath = path.Clean(fileName)
		}
		if s.Config.Mode == "master" && s.MasterManager != nil {
			if bridge, ok := s.MasterManager.(MasterBridge); ok {
				uploadPath = bridge.ResolvePath(uploadPath)
			}
		}
		uploadDir = path.Dir(uploadPath)
		fileName = path.Base(uploadPath)
		getMasterUploadEntries := func(bridge MasterBridge) []MasterFileEntry {
			if !masterUploadEntriesLoaded {
				masterUploadEntries = bridge.ListDir(uploadDir)
				masterUploadEntriesLoaded = true
			}
			return masterUploadEntries
		}

		aclPath := path.Join(s.Config.ACLBasePath, uploadPath)
		if !s.ACLEngine.CanPerform(s.User, "UPLOAD", aclPath) {
			fmt.Fprintf(s.Conn, "550 Access Denied: Cannot upload here.\r\n")
			return false
		}

		var xdupeNames []string
		if s.Config.Mode == "master" && s.MasterManager != nil {
			fileExists := false
			if bridge, ok := s.MasterManager.(MasterBridge); ok {
				if err := ensureUploadDirsForEvent(s, bridge, uploadDir); err != nil {
					fmt.Fprintf(s.Conn, "550 Upload prepare failed: %v\r\n", err)
					return false
				}
				fileExists = bridge.FileExists(uploadPath)
				if s.Config.XdupeEnabled {
					xdupeNames = existingFileNamesForXDupe(getMasterUploadEntries(bridge))
				}
				if fileExists && restOffset == 0 {
					writeDuplicateFileResponse(s, fileName, xdupeNames)
					return false
				}
				if pendingUploadForReply(bridge, uploadPath) {
					writeUploadAlreadyInProgressResponse(s, fileName, xdupeNames)
					return false
				}
			}
			if fileExists && restOffset == 0 {
				writeDuplicateFileResponse(s, fileName, xdupeNames)
				return false
			}
		}
		if restOffset > 0 {
			if !zipscript.AllowResumeForDir(s.Config.Zipscript, uploadDir) {
				fmt.Fprintf(s.Conn, "550 Resume is disabled for this release.\r\n")
				return false
			}
			if s.Config.Mode == "master" && s.MasterManager != nil {
				if bridge, ok := s.MasterManager.(MasterBridge); ok {
					size := bridge.GetFileSize(uploadPath)
					if size < 0 {
						fmt.Fprintf(s.Conn, "550 Resume target not found.\r\n")
						return false
					}
					if restOffset > size {
						fmt.Fprintf(s.Conn, "550 Resume offset beyond end of file.\r\n")
						return false
					}
				}
			}
		}
		if !reserveUploadPath(uploadPath) {
			writeUploadAlreadyInProgressResponse(s, fileName, xdupeNames)
			return false
		}
		defer releaseUploadPath(uploadPath)
		if s.Config.Mode == "master" && s.MasterManager != nil {
			if _, ok := s.MasterManager.(MasterBridge); ok {
				if activeDownloadForPath(uploadPath) {
					writeTemporaryUploadBusyResponse(s.Conn, fileName)
					return false
				}
			}
		} else if activeDownloadForPath(uploadPath) {
			writeTemporaryUploadBusyResponse(s.Conn, fileName)
			return false
		}
		if s.Config.Mode == "master" && s.MasterManager != nil {
			if bridge, ok := s.MasterManager.(MasterBridge); ok {
				entries := getMasterUploadEntries(bridge)
				existingNames = zipscriptExistingNamesFromEntries(entries)
				existingDirs := zipscriptExistingDirNamesFromEntries(entries)
				if s.Config != nil && zipscript.ShouldBlockZipDIZUpload(s.Config.Zipscript, uploadDir, fileName) {
					fmt.Fprintf(s.Conn, "550 zipscript: upload file_id.diz inside the zip, not as a standalone file\r\n")
					return false
				}
				if err := zipscript.ValidateUpload(s.Config.Zipscript, s.User, uploadDir, fileName, existingNames, existingDirs, bridge.GetSFVData(uploadDir)); err != nil {
					fmt.Fprintf(s.Conn, "550 %s\r\n", err)
					return false
				}
			}
		}
		localPath := filepath.Join(s.Config.StoragePath, filepath.FromSlash(strings.TrimPrefix(uploadPath, "/")))
		if s.Config.Mode != "master" || s.MasterManager == nil {
			if s.Config != nil && zipscript.ShouldBlockZipDIZUpload(s.Config.Zipscript, uploadDir, fileName) {
				fmt.Fprintf(s.Conn, "550 zipscript: upload file_id.diz inside the zip, not as a standalone file\r\n")
				return false
			}
			dirEntries, err := os.ReadDir(filepath.Dir(localPath))
			if err == nil {
				localExistingNames := make([]string, 0, len(dirEntries))
				localExistingDirs := make([]string, 0, len(dirEntries))
				for _, entry := range dirEntries {
					localExistingNames = append(localExistingNames, entry.Name())
					if entry.IsDir() {
						localExistingDirs = append(localExistingDirs, entry.Name())
					}
				}
				if err := zipscript.ValidateUpload(s.Config.Zipscript, s.User, uploadDir, fileName, localExistingNames, localExistingDirs, zipscript.LocalSFVEntriesForDir(filepath.Dir(localPath))); err != nil {
					fmt.Fprintf(s.Conn, "550 %s\r\n", err)
					return false
				}
			}
		}
		if s.User != nil && s.User.UploadSlots > 0 {
			activeUploads := countTransfersForUser(s.User.Name, "upload")
			if activeUploads >= s.User.UploadSlots {
				fmt.Fprintf(s.Conn, "550 Maximum simultaneous uploads reached (%d).\r\n", s.User.UploadSlots)
				return false
			}
		}
		if s.User != nil && s.User.MaxSim > 0 {
			activeTransfers := countTransfersForUserAllDirections(s.User.Name)
			if activeTransfers >= s.User.MaxSim {
				fmt.Fprintf(s.Conn, "550 Maximum simultaneous transfers reached (%d).\r\n", s.User.MaxSim)
				return false
			}
		}
		if s.Config.Passthrough && s.Config.Mode == "master" && s.MasterManager != nil && s.ActiveAddr != "" && s.PassthruSlave == nil {
			if bridge, ok := s.MasterManager.(MasterBridge); ok {
				filePath := uploadPath
				portAddr := s.ActiveAddr
				s.ActiveAddr = ""

				log.Printf("[Passthrough] PORT STOR %s → slave connects to %s", filePath, portAddr)
				fmt.Fprintf(s.Conn, "150 Opening %s mode data connection.\r\n", transferTypeReplyName(s.TransferType))
				s.beginTransfer("upload", filePath)
				defer s.endTransfer()
				onTransferReady := func(slaveName string, transferIdx int32) {
					s.attachTransferToSlave(slaveName, transferIdx)
				}

				fileSize, checksum, xferMs, err := bridge.SlaveConnectAndReceive(filePath, portAddr, s.User.Name, s.User.PrimaryGroup, restOffset, s.DataTLS, s.SSCN, s.currentTransferTypeByte(), onTransferReady)
				_ = xferMs

				if err != nil {
					if writeDuplicateUploadResponse(s, bridge, uploadDir, fileName, err) {
						return false
					}
					if s.Config != nil && s.Config.Debug {
						log.Printf("[Passthrough] PORT upload failed for user %s path %s: %s", s.User.Name, filePath, formatTransferFailureLog(err))
					}
					writeTransferFailure(s.Conn, "Upload", err)
					return false
				}
				s.endTransfer()

				if fileSize == 0 {
					if isZeroByteCriticalFile(fileName) {
						if !criticalUploadHasRealContent(bridge, filePath, fileName) {
							bridge.DeleteFile(filePath)
							log.Printf("[MASTER-ZS] Rejected 0-byte critical file %s; requesting re-upload", filePath)
							fmt.Fprintf(s.Conn, "550 Empty %s rejected, please re-upload.\r\n", fileName)
							return false
						}
						// Slave confirms the file has real content despite a 0 measured
						// size; keep it and fall through to the normal SFV parse/track path.
					} else if zipscript.ShouldDeleteZeroByteForDir(s.Config.Zipscript, uploadDir) {
						bridge.DeleteFile(filePath)
						log.Printf("[MASTER-ZS] Deleted 0-byte file: %s", filePath)
						fmt.Fprintf(s.Conn, "226 Transfer complete.\r\n")
						return false
					}
				}
				if handleMasterUploadZipIntegrityAndCleanup(s, bridge, uploadDir, filePath, fileName) {
					return false
				}
				if handleMasterUploadSFVStatusAndCleanup(s, bridge, uploadDir, filePath, fileName, checksum, fileSize) {
					return false
				}

				mediaInfoDir := storReleaseMediaDir(uploadDir, filePath)

				transferredBytes := fileSize
				if restOffset > 0 && fileSize > restOffset {
					transferredBytes = fileSize - restOffset
				}
				speedMB := 0.0
				if xferMs > 0 {
					speedMB = (float64(transferredBytes) / 1024.0 / 1024.0) / (float64(xferMs) / 1000.0)
				}
				fmt.Fprintf(s.Conn, "226 Transfer complete.\r\n")
				queueMasterUploadPostHooks(s, bridge, uploadDir, mediaInfoDir, filePath, fileName, checksum, transferredBytes, fileSize, speedMB, xferMs, existingNames)
				return false
			}
		}

		raw, err := s.getRawDataConn()
		if err != nil {
			if s.PassthruSlave != nil && s.Config.Passthrough {
			} else {
				fmt.Fprintf(s.Conn, "425 Data connection failed\r\n")
				return false
			}
		}

		if s.Config.Mode == "master" && s.MasterManager != nil {
			if bridge, ok := s.MasterManager.(MasterBridge); ok {
				filePath := uploadPath

				var fileSize int64
				var checksum uint32
				var xferMs int64

				if s.PassthruSlave != nil && s.Config.Passthrough {
					slaveName := s.PassthruSlave.(string)
					fmt.Fprintf(s.Conn, "150 Opening %s mode data connection.\r\n", transferTypeReplyName(s.TransferType))
					log.Printf("[Passthrough] STOR %s via slave %s (xferIdx=%d)", filePath, slaveName, s.PassthruXferIdx)
					s.beginTransferOnSlave("upload", filePath, slaveName, s.PassthruXferIdx)
					defer s.endTransfer()

					fileSize, checksum, xferMs, err = bridge.SlaveReceivePassthrough(filePath, s.PassthruXferIdx, slaveName, s.User.Name, s.User.PrimaryGroup, restOffset, s.currentTransferTypeByte())
					s.PassthruSlave = nil
					s.PretCmd = ""
					s.PretArg = ""

					if err != nil {
						if writeDuplicateUploadResponse(s, bridge, uploadDir, fileName, err) {
							return false
						}
						if s.Config != nil && s.Config.Debug {
							log.Printf("[Passthrough] Upload failed for user %s path %s: %s", s.User.Name, filePath, formatTransferFailureLog(err))
						}
						writeTransferFailure(s.Conn, "Upload", err)
						return false
					}
				} else {
					fmt.Fprintf(s.Conn, "150 Opening %s mode data connection.\r\n", transferTypeReplyName(s.TransferType))
					dataConn, err := s.upgradeDataTLS(raw, tlsConfig)
					if err != nil {
						raw.Close()
						return false
					}
					s.beginTransfer("upload", filePath)
					defer s.endTransfer()
					dataConn = trackTransferConn(s, dataConn, "upload")

					// Use the slave-measured transfer time (pure data time) for the
					// announced speed, not wall-clock around the whole call: that
					// would include slave listen/receive RPCs, the master->slave
					// TLS handshake and status round trips, deflating speeds.
					fileSize, checksum, xferMs, err = bridge.UploadFile(filePath, dataConn, s.User.Name, s.User.PrimaryGroup, restOffset, s.currentTransferTypeByte())
					dataConn.Close()

					if err != nil {
						log.Printf("[MASTER] Upload failed: %v", err)
						writeTransferFailure(s.Conn, "Upload", err)
						return false
					}
				}
				s.endTransfer()

				if fileSize == 0 {
					if isZeroByteCriticalFile(fileName) {
						if !criticalUploadHasRealContent(bridge, filePath, fileName) {
							bridge.DeleteFile(filePath)
							log.Printf("[MASTER-ZS] Rejected 0-byte critical file %s; requesting re-upload", filePath)
							fmt.Fprintf(s.Conn, "550 Empty %s rejected, please re-upload.\r\n", fileName)
							return false
						}
						// Slave confirms the file has real content despite a 0 measured
						// size; keep it and fall through to the normal SFV parse/track path.
					} else if zipscript.ShouldDeleteZeroByteForDir(s.Config.Zipscript, uploadDir) {
						bridge.DeleteFile(filePath)
						log.Printf("[MASTER-ZS] Deleted 0-byte file: %s", filePath)
						fmt.Fprintf(s.Conn, "226 Transfer complete.\r\n")
						return false
					}
				}
				if handleMasterUploadZipIntegrityAndCleanup(s, bridge, uploadDir, filePath, fileName) {
					return false
				}
				if handleMasterUploadSFVStatusAndCleanup(s, bridge, uploadDir, filePath, fileName, checksum, fileSize) {
					return false
				}

				mediaInfoDir := storReleaseMediaDir(uploadDir, filePath)

				transferredBytes := fileSize
				if restOffset > 0 && fileSize > restOffset {
					transferredBytes = fileSize - restOffset
				}
				speedMB := 0.0
				if xferMs > 0 {
					speedMB = (float64(transferredBytes) / 1024.0 / 1024.0) / (float64(xferMs) / 1000.0)
				}
				fmt.Fprintf(s.Conn, "226 Transfer complete.\r\n")
				queueMasterUploadPostHooks(s, bridge, uploadDir, mediaInfoDir, filePath, fileName, checksum, transferredBytes, fileSize, speedMB, xferMs, existingNames)
			} else {
				fmt.Fprintf(s.Conn, "550 Master not initialized\r\n")
				if raw != nil {
					raw.Close()
				}
			}
			return false
		}

		if restOffset > 0 {
			info, err := os.Stat(localPath)
			if err != nil {
				fmt.Fprintf(s.Conn, "550 Resume target not found.\r\n")
				return false
			}
			if restOffset > info.Size() {
				fmt.Fprintf(s.Conn, "550 Resume offset beyond end of file.\r\n")
				return false
			}
		} else if info, err := os.Stat(localPath); err == nil && !info.IsDir() {
			var names []string
			if s.Config.XdupeEnabled && s.XDupeMode > 0 {
				dirEntries, readErr := os.ReadDir(filepath.Dir(localPath))
				if readErr == nil {
					for _, entry := range dirEntries {
						names = append(names, entry.Name())
					}
				}
			}
			writeDuplicateFileResponse(s, fileName, names)
			return false
		}

		if err := os.MkdirAll(filepath.Dir(localPath), 0755); err != nil {
			if raw != nil {
				raw.Close()
			}
			fmt.Fprintf(s.Conn, "550 Upload prepare failed: %v\r\n", err)
			return false
		}

		fmt.Fprintf(s.Conn, "150 Opening %s mode data connection.\r\n", transferTypeReplyName(s.TransferType))
		dataConn, err := s.upgradeDataTLS(raw, tlsConfig)
		if err != nil {
			raw.Close()
			return false
		}

		flags := os.O_CREATE | os.O_WRONLY
		if restOffset > 0 {
			flags |= os.O_APPEND
		} else {
			flags |= os.O_EXCL
		}
		file, err := os.OpenFile(localPath, flags, 0644)
		if err != nil {
			dataConn.Close()
			writeTransferFailure(s.Conn, "Upload", err)
			return false
		}
		if restOffset > 0 {
			if _, err := file.Seek(restOffset, io.SeekStart); err != nil {
				file.Close()
				dataConn.Close()
				writeTransferFailure(s.Conn, "Upload", err)
				return false
			}
		}

		s.beginTransfer("upload", uploadPath)
		defer s.endTransfer()
		dataConn = trackTransferConn(s, dataConn, "upload")

		start := time.Now()
		var checksum uint32
		writer := io.Writer(file)
		var checksumHash hash.Hash32
		if restOffset == 0 {
			checksumHash = crc32.NewIEEE()
			writer = io.MultiWriter(file, checksumHash)
		}
		written, err := copyTransferData(writer, dataConn)
		xferMs := time.Since(start).Milliseconds()
		file.Close()
		dataConn.Close()
		if err != nil {
			if restOffset == 0 {
				_ = os.Remove(localPath)
			}
			writeTransferFailure(s.Conn, "Upload", err)
			return false
		}
		s.endTransfer()
		if checksumHash != nil {
			checksum = checksumHash.Sum32()
		}
		fileSize := written
		if restOffset > 0 {
			fileSize += restOffset
		}
		if fileSize == 0 {
			if isZeroByteCriticalFile(fileName) {
				_ = os.Remove(localPath)
				fmt.Fprintf(s.Conn, "550 Empty %s rejected, please re-upload.\r\n", fileName)
				return false
			}
			if zipscript.ShouldDeleteZeroByteForDir(s.Config.Zipscript, uploadDir) {
				_ = os.Remove(localPath)
				fmt.Fprintf(s.Conn, "226 Transfer complete.\r\n")
				return false
			}
		}
		if badZip, err := zipscript.LocalCheckUploadedZipIntegrity(s.Config.Zipscript, uploadDir, localPath, fileName); err != nil && s.Config.Debug {
			log.Printf("[LOCAL-ZS] zip integrity check skipped for %s: %v", uploadPath, err)
		} else if badZip {
			writeZipIntegrityFailureDeleteResponse(s.Conn)
			return false
		}
		if checksum > 0 && zipscript.ShouldDeleteBadCRCForDir(s.Config.Zipscript, uploadDir) && !strings.HasSuffix(strings.ToLower(fileName), ".sfv") {
			if expectedCRC, ok := zipscript.LocalExpectedCRCForFile(localPath); ok && expectedCRC != checksum {
				_ = os.Remove(localPath)
				zipscript.CreateLocalSFVMissingMarker(s.Config.Zipscript, filepath.Dir(localPath), fileName)
				writeChecksumMismatchDeleteResponse(s.Conn, checksum, expectedCRC)
				return false
			}
		}
		if !strings.HasSuffix(strings.ToLower(fileName), ".sfv") {
			sfvEntries := zipscript.LocalSFVEntriesForDir(filepath.Dir(localPath))
			if expectedCRC, ok := zipscript.CachedExpectedCRC(sfvEntries, fileName); ok {
				zipscript.WriteUploadSFVStatus(s.Conn, checksum, expectedCRC, true, fileSize)
				if checksum == expectedCRC && checksum != 0 {
					zipscript.ClearLocalSFVMissingMarker(filepath.Dir(localPath), fileName)
				}
			} else {
				zipscript.WriteUploadNoSFVEntryStatus(s.Conn, sfvEntries, fileName)
			}
		} else {
			zipscript.SyncLocalSFVMissingMarkers(s.Config.Zipscript, filepath.Dir(localPath))
		}

		isSpeedtest := isSpeedtestPath(uploadPath)
		transferredBytes := written
		if transferredBytes > 0 {
			s.User.UpdateStatsWithCredits(transferredBytes, true, !isSpeedtest)
		}
		speedMB := transferSpeedMB(transferredBytes, xferMs)
		fmt.Fprintf(s.Conn, "226 Transfer complete.\r\n")
		go func(uploadPath, fileName, localPath string, transferredBytes int64, speedMB float64) {
			s.emitEvent(EventUpload, uploadPath, fileName, transferredBytes, speedMB, nil)
			if err := zipscript.LocalRefreshZipDIZFromArchive(filepath.Dir(localPath), localPath, fileName); err != nil && s.Config.Debug {
				log.Printf("[LOCAL-ZS] zip diz refresh skipped for %s: %v", uploadPath, err)
			}
		}(uploadPath, fileName, localPath, transferredBytes, speedMB)
		return false

	case "RETR":
		if len(args) == 0 {
			return false
		}
		defer s.clearPreparedTransferState()
		if !s.hasPreparedTransferChannel() {
			fmt.Fprintf(s.Conn, "503 Bad sequence of commands.\r\n")
			return false
		}

		isTLSExempt := false
		for _, exemptUser := range s.Config.TLSExemptUsers {
			if exemptUser == s.User.Name {
				isTLSExempt = true
				break
			}
		}
		if s.Config.RequireTLSData && !isTLSExempt && !s.DataTLS {
			fmt.Fprintf(s.Conn, "550 TLS required for data transfers.\r\n")
			return false
		}

		filePath := path.Clean(path.Join(s.CurrentDir, args[0]))
		if path.IsAbs(strings.TrimSpace(args[0])) {
			filePath = path.Clean(args[0])
		}
		if s.Config.Mode == "master" && s.MasterManager != nil {
			if bridge, ok := s.MasterManager.(MasterBridge); ok {
				filePath = bridge.ResolvePath(filePath)
			}
		}
		aclPath := path.Join(s.Config.ACLBasePath, filePath)
		if !s.ACLEngine.CanPerform(s.User, "DOWNLOAD", aclPath) {
			fmt.Fprintf(s.Conn, "550 Access Denied.\r\n")
			return false
		}
		restOffset := s.RestOffset
		s.RestOffset = 0

		if s.Config.Mode == "master" && s.MasterManager != nil {
			if bridge, ok := s.MasterManager.(MasterBridge); ok {
				fileSize := bridge.GetFileSize(filePath)
				if fileSize < 0 {
					fmt.Fprintf(s.Conn, "550 File not found on any slave.\r\n")
					return false
				}
				if activeUploadForPath(filePath) {
					fmt.Fprintf(s.Conn, "550 No Permission To Download A File Currently Being Uploaded.\r\n")
					return false
				}
				if s.Config != nil && zipscript.ShouldTreatDownloadAsMissing(s.Config.Zipscript, sfvBridge(bridge), filePath, log.Printf) {
					fmt.Fprintf(s.Conn, "550 File is incomplete or failed checksum verification.\r\n")
					return false
				}
				if restOffset > fileSize {
					fmt.Fprintf(s.Conn, "550 Resume offset beyond end of file.\r\n")
					return false
				}
				isSpeedtest := isSpeedtestPath(filePath)
				remainingSize := fileSize
				if restOffset > 0 && restOffset < fileSize {
					remainingSize = fileSize - restOffset
				}
				if !isSpeedtest && !s.User.HasDownloadAccess() {
					fmt.Fprintf(s.Conn, "550 No permission to download.\r\n")
					return false
				}
				if !isSpeedtest && !s.User.HasEnoughCredits(remainingSize) {
					fmt.Fprintf(s.Conn, "550 Not enough credits.\r\n")
					return false
				}
				if s.User != nil && s.User.DownloadSlots > 0 {
					activeDownloads := countTransfersForUser(s.User.Name, "download")
					if activeDownloads >= s.User.DownloadSlots {
						fmt.Fprintf(s.Conn, "550 Maximum simultaneous downloads reached (%d).\r\n", s.User.DownloadSlots)
						return false
					}
				}
				if s.User != nil && s.User.MaxSim > 0 {
					activeTransfers := countTransfersForUserAllDirections(s.User.Name)
					if activeTransfers >= s.User.MaxSim {
						fmt.Fprintf(s.Conn, "550 Maximum simultaneous transfers reached (%d).\r\n", s.User.MaxSim)
						return false
					}
				}
				if !reserveDownloadPath(filePath) {
					fmt.Fprintf(s.Conn, "550 No Permission To Download A File Currently Being Uploaded.\r\n")
					return false
				}
				defer releaseDownloadPath(filePath)
				if s.Config.Passthrough && s.ActiveAddr != "" && s.PassthruSlave == nil {
					portAddr := s.ActiveAddr
					s.ActiveAddr = ""
					fmt.Fprintf(s.Conn, "150 Opening %s mode data connection for %s (%d bytes).\r\n", transferTypeReplyName(s.TransferType), args[0], fileSize)
					log.Printf("[Passthrough] PORT RETR %s by %s -> %s", filePath, s.User.Name, portAddr)
					s.beginTransfer("download", filePath)
					defer s.endTransfer()
					onTransferReady := func(slaveName string, transferIdx int32) {
						s.attachTransferToSlave(slaveName, transferIdx)
					}

					transferChecksum, xferMs, err := bridge.SlaveConnectAndSend(filePath, portAddr, s.User.Name, s.User.PrimaryGroup, restOffset, s.DataTLS, s.SSCN, s.currentTransferTypeByte(), onTransferReady)
					if err != nil {
						if s.Config != nil && s.Config.Debug {
							log.Printf("[Passthrough] PORT download failed for user %s path %s: %s", s.User.Name, filePath, formatTransferFailureLog(err))
						}
						writeTransferFailure(s.Conn, "Download", err)
						return false
					}

					if restOffset == 0 {
						handleMasterDownloadSFVChecksum(s, bridge, filePath, transferChecksum)
					}
					fmt.Fprintf(s.Conn, "226 Transfer complete.\r\n")
					if remainingSize > 0 {
						s.User.UpdateStatsWithCredits(remainingSize, false, !isSpeedtest)
					}
					s.emitEvent(EventDownload, filePath, args[0], remainingSize, transferSpeedMB(remainingSize, xferMs), nil)
					return false
				}

				if s.PassthruSlave != nil && s.Config.Passthrough {
					slaveName := s.PassthruSlave.(string)
					fmt.Fprintf(s.Conn, "150 Opening %s mode data connection for %s (%d bytes).\r\n", transferTypeReplyName(s.TransferType), args[0], fileSize)
					log.Printf("[Passthrough] RETR %s by %s via slave %s (xferIdx=%d)", filePath, s.User.Name, slaveName, s.PassthruXferIdx)
					s.beginTransferOnSlave("download", filePath, slaveName, s.PassthruXferIdx)
					defer s.endTransfer()

					start := time.Now()
					transferChecksum, xferMs, err := bridge.SlaveSendPassthrough(filePath, s.PassthruXferIdx, slaveName, s.User.Name, s.User.PrimaryGroup, restOffset, s.currentTransferTypeByte())
					if xferMs == 0 {
						xferMs = time.Since(start).Milliseconds()
					}
					s.PassthruSlave = nil
					s.PretCmd = ""
					s.PretArg = ""

					if err != nil {
						if s.Config != nil && s.Config.Debug {
							log.Printf("[Passthrough] Download failed for user %s path %s: %s", s.User.Name, filePath, formatTransferFailureLog(err))
						}
						writeTransferFailure(s.Conn, "Download", err)
					} else {
						if restOffset == 0 {
							handleMasterDownloadSFVChecksum(s, bridge, filePath, transferChecksum)
						}
						fmt.Fprintf(s.Conn, "226 Transfer complete.\r\n")
						if remainingSize > 0 {
							s.User.UpdateStatsWithCredits(remainingSize, false, !isSpeedtest)
						}
						s.emitEvent(EventDownload, filePath, args[0], remainingSize, transferSpeedMB(remainingSize, xferMs), nil)
					}
				} else {
					raw, err := s.getRawDataConn()
					if err != nil {
						fmt.Fprintf(s.Conn, "425 Data connection failed\r\n")
						return false
					}
					fmt.Fprintf(s.Conn, "150 Opening %s mode data connection for %s (%d bytes).\r\n", transferTypeReplyName(s.TransferType), args[0], fileSize)
					dataConn, err := s.upgradeDataTLS(raw, tlsConfig)
					if err != nil {
						raw.Close()
						return false
					}
					s.beginTransfer("download", filePath)
					defer s.endTransfer()
					dataConn = trackTransferConn(s, dataConn, "download")
					start := time.Now()
					transferChecksum, err := bridge.DownloadFile(filePath, dataConn, s.User.Name, s.User.PrimaryGroup, restOffset, s.currentTransferTypeByte())
					xferMs := time.Since(start).Milliseconds()
					dataConn.Close()
					s.PretCmd = ""
					s.PretArg = ""
					if err != nil {
						log.Printf("[MASTER] Download failed: %v", err)
						writeTransferFailure(s.Conn, "Download", err)
					} else {
						if restOffset == 0 {
							handleMasterDownloadSFVChecksum(s, bridge, filePath, transferChecksum)
						}
						fmt.Fprintf(s.Conn, "226 Transfer complete.\r\n")
						if remainingSize > 0 {
							s.User.UpdateStatsWithCredits(remainingSize, false, !isSpeedtest)
						}
						s.emitEvent(EventDownload, filePath, args[0], remainingSize, transferSpeedMB(remainingSize, xferMs), nil)
					}
				}
			} else {
				fmt.Fprintf(s.Conn, "550 Master not initialized\r\n")
			}
			return false
		}

		localPath := filepath.Join(s.Config.StoragePath, filepath.FromSlash(strings.TrimPrefix(filePath, "/")))
		info, err := os.Stat(localPath)
		if err != nil {
			fmt.Fprintf(s.Conn, "550 File not found.\r\n")
			return false
		}
		if info.IsDir() {
			fmt.Fprintf(s.Conn, "550 Requested target is not a file.\r\n")
			return false
		}
		fileSize := info.Size()
		if activeUploadForPath(filePath) {
			fmt.Fprintf(s.Conn, "550 No Permission To Download A File Currently Being Uploaded.\r\n")
			return false
		}
		if zipscript.LocalShouldTreatDownloadAsMissing(s.Config.Zipscript, filePath, localPath) {
			fmt.Fprintf(s.Conn, "550 File is incomplete or failed checksum verification.\r\n")
			return false
		}
		if restOffset > fileSize {
			fmt.Fprintf(s.Conn, "550 Resume offset beyond end of file.\r\n")
			return false
		}
		isSpeedtest := isSpeedtestPath(filePath)
		remainingSize := fileSize
		if restOffset > 0 && restOffset < fileSize {
			remainingSize = fileSize - restOffset
		}
		if !isSpeedtest && !s.User.HasDownloadAccess() {
			fmt.Fprintf(s.Conn, "550 No permission to download.\r\n")
			return false
		}
		if !isSpeedtest && !s.User.HasEnoughCredits(remainingSize) {
			fmt.Fprintf(s.Conn, "550 Not enough credits.\r\n")
			return false
		}
		if s.User != nil && s.User.DownloadSlots > 0 {
			activeDownloads := countTransfersForUser(s.User.Name, "download")
			if activeDownloads >= s.User.DownloadSlots {
				fmt.Fprintf(s.Conn, "550 Maximum simultaneous downloads reached (%d).\r\n", s.User.DownloadSlots)
				return false
			}
		}
		if s.User != nil && s.User.MaxSim > 0 {
			activeTransfers := countTransfersForUserAllDirections(s.User.Name)
			if activeTransfers >= s.User.MaxSim {
				fmt.Fprintf(s.Conn, "550 Maximum simultaneous transfers reached (%d).\r\n", s.User.MaxSim)
				return false
			}
		}
		if !reserveDownloadPath(filePath) {
			fmt.Fprintf(s.Conn, "550 No Permission To Download A File Currently Being Uploaded.\r\n")
			return false
		}
		defer releaseDownloadPath(filePath)
		raw, err := s.getRawDataConn()
		if err != nil {
			fmt.Fprintf(s.Conn, "425 Data connection failed\r\n")
			return false
		}
		fmt.Fprintf(s.Conn, "150 Opening %s mode data connection for %s (%d bytes).\r\n", transferTypeReplyName(s.TransferType), args[0], fileSize)
		dataConn, err := s.upgradeDataTLS(raw, tlsConfig)
		if err != nil {
			raw.Close()
			return false
		}

		file, err := os.Open(localPath)
		if err != nil {
			dataConn.Close()
			writeTransferFailure(s.Conn, "Download", err)
			return false
		}
		defer file.Close()
		if restOffset > 0 {
			if _, err := file.Seek(restOffset, io.SeekStart); err != nil {
				dataConn.Close()
				writeTransferFailure(s.Conn, "Download", err)
				return false
			}
		}

		s.beginTransfer("download", filePath)
		defer s.endTransfer()
		dataConn = trackTransferConn(s, dataConn, "download")

		start := time.Now()
		_, err = copyTransferData(dataConn, file)
		xferMs := time.Since(start).Milliseconds()
		dataConn.Close()
		if err != nil {
			writeTransferFailure(s.Conn, "Download", err)
			return false
		}
		fmt.Fprintf(s.Conn, "226 Transfer complete.\r\n")
		if remainingSize > 0 {
			s.User.UpdateStatsWithCredits(remainingSize, false, !isSpeedtest)
		}
		s.emitEvent(EventDownload, filePath, args[0], remainingSize, transferSpeedMB(remainingSize, xferMs), nil)
		return false

	case "STAT":
		// STAT with no args = server status. STAT <path> = listing on control
		// channel (no data connection). cbftp uses STAT -l at login as a
		// cheap way to probe the server without opening a data conn.
		if len(args) == 0 {
			typeName := "ASCII"
			if strings.EqualFold(s.TransferType, "I") {
				typeName = "BINARY"
			}
			siteName := "WeaveFTPd"
			if s.Config != nil && strings.TrimSpace(s.Config.SiteNameShort) != "" {
				siteName = s.Config.SiteNameShort
			}
			remoteAddr := "unknown"
			if s.Conn != nil && s.Conn.RemoteAddr() != nil {
				remoteAddr = s.Conn.RemoteAddr().String()
			}
			fmt.Fprintf(s.Conn, "211- %s server status:\r\n", siteName)
			fmt.Fprintf(s.Conn, " Connected from %s\r\n", remoteAddr)
			if s.User != nil && strings.TrimSpace(s.User.Name) != "" {
				fmt.Fprintf(s.Conn, " Logged in as %s\r\n", s.User.Name)
			} else {
				fmt.Fprintf(s.Conn, " Not logged in\r\n")
			}
			fmt.Fprintf(s.Conn, " TYPE: %s, STRU: F, MODE: S\r\n", typeName)
			fmt.Fprintf(s.Conn, "211 End of status.\r\n")
			return false
		}

		target := s.resolveListTargetPath("LIST", args, s.masterBridgeOrNil())
		if err := s.validateListDirectoryTarget(target, s.masterBridgeOrNil()); err != nil {
			if err.Error() == "504" {
				fmt.Fprintf(s.Conn, "504 Command not implemented for that parameter.\r\n")
			} else {
				fmt.Fprintf(s.Conn, "550 %s: no such file or directory\r\n", target)
			}
			return false
		}

		fmt.Fprintf(s.Conn, "213-STAT\r\n")
		fmt.Fprintf(s.Conn, " total 0\r\n")
		if s.Config.Mode == "master" && s.MasterManager != nil {
			if bridge, ok := s.MasterManager.(MasterBridge); ok {
				entries := bridge.ListDir(target)
				now := timeutil.Now().Format("Jan _2 15:04")
				siteName := s.Config.SiteNameShort
				if siteName == "" {
					siteName = "WeaveFTPd"
				}

				if zipscript.ShowStatusBarForDir(s.Config.Zipscript, target) {
					if statusName := dirRaceStatusName(bridge, s.Config, target, siteName); strings.TrimSpace(statusName) != "" {
						mode := "drwxr-xr-x"
						size := "4096"
						if !zipscript.StatusBarDirectoryForDir(s.Config.Zipscript, target) {
							mode = "-rw-r--r--"
							size = "0"
						}
						fmt.Fprintf(s.Conn, " %s   1 %-8s %-8s %10s %s %s\r\n",
							mode, "WeaveFTPd", "WeaveFTPd", size, now, statusName)
					}
				}

				for _, e := range entries {
					if strings.HasPrefix(e.Name, ".") {
						continue
					}
					if strings.HasPrefix(e.Name, "[#") || strings.HasPrefix(e.Name, "[:") {
						continue
					}
					if strings.Contains(e.Name, "COMPLETE") && strings.Contains(e.Name, "[") {
						continue
					}
					aclPath := path.Join(s.Config.ACLBasePath, target, e.Name)
					if !s.ACLEngine.CanPerform(s.User, "LIST", aclPath) {
						continue
					}

					mode := ftpListMode(e)
					size := fmt.Sprintf("%d", e.Size)
					name := e.Name
					if e.IsSymlink {
						size = "0"
						name = fmt.Sprintf("%s -> %s", e.Name, e.LinkTarget)
					} else if e.IsDir {
						size = "4096"
					}
					ts := timeutil.Unix(e.ModTime).Format("Jan _2 15:04")
					owner := "WeaveFTPd"
					group := "WeaveFTPd"
					if s.Config.ShowRealOwnerGroup {
						owner = strings.TrimSpace(e.Owner)
						group = strings.TrimSpace(e.Group)
						if owner == "" {
							owner = "WeaveFTPd"
						}
						if group == "" {
							group = "WeaveFTPd"
						}
					}
					fmt.Fprintf(s.Conn, " %s   1 %-8s %-8s %10s %s %s\r\n",
						mode, owner, group, size, ts, name)
				}

			}
		} else {
			listPath := filepath.Join(s.Config.StoragePath, target)
			files, err := os.ReadDir(listPath)
			if err == nil {
				for _, f := range files {
					if strings.HasPrefix(f.Name(), ".") {
						continue
					}
					if !s.Config.ShowSymlinks && f.Type()&fs.ModeSymlink != 0 {
						continue
					}
					if !s.canListPath(path.Join(target, f.Name())) {
						continue
					}
					info, err := f.Info()
					if err != nil {
						continue
					}
					mode := "-rw-r--r--"
					size := fmt.Sprintf("%d", info.Size())
					if info.IsDir() {
						mode = "drwxr-xr-x"
						size = "4096"
					} else if f.Type()&fs.ModeSymlink != 0 {
						mode = "lrwxrwxrwx"
					}
					ts := timeutil.In(info.ModTime()).Format("Jan _2 15:04")
					fmt.Fprintf(s.Conn, " %s   1 %-8s %-8s %10s %s %s\r\n",
						mode, "WeaveFTPd", "WeaveFTPd", size, ts, f.Name())
				}
			}
		}
		fmt.Fprintf(s.Conn, "213 End of status.\r\n")
		return false

	case "QUIT":
		fmt.Fprintf(s.Conn, "221 Goodbye.\r\n")
		return true

	default:
		fmt.Fprintf(s.Conn, "502 Command not implemented.\r\n")
	}
	return false
}

func (s *Session) showGlobalStats(code string, final bool) {
	freeSpaceMB := uint64(0)
	if s.Config.Mode == "master" && s.MasterManager != nil {
		if bridge, ok := s.MasterManager.(MasterBridge); ok {
			if freeBytes, _, ok := bridge.GetAggregateDiskUsage(); ok && freeBytes > 0 {
				freeSpaceMB = uint64(freeBytes) / 1024 / 1024
			}
		}
	}
	if freeSpaceMB == 0 {
		var stat syscall.Statfs_t
		wd, _ := os.Getwd()
		if err := syscall.Statfs(s.Config.StoragePath, &stat); err != nil {
			_ = syscall.Statfs(wd, &stat)
		}
		freeSpaceMB = (stat.Bavail * uint64(stat.Bsize)) / 1024 / 1024
	}
	ulGiB := 0.0
	dlGiB := 0.0
	creditsGiB := 0.0
	ratioStr := "UL&DL: Unlimited"

	if s.User != nil {
		ulGiB = float64(s.User.AllUp.Bytes) / (1024 * 1024 * 1024)
		dlGiB = float64(s.User.AllDn.Bytes) / (1024 * 1024 * 1024)
		creditsGiB = float64(s.User.Credits) / (1024 * 1024 * 1024)
		if s.User.Ratio > 0 {
			ratioStr = fmt.Sprintf("1:%d", s.User.Ratio)
		}
	}

	// (Removed the always-0.00 [Speed] field rather than keep misreporting; there
	// is no live aggregate-speed source wired here.)
	fmt.Fprintf(s.Conn, "%s- [Ul: %.1fGiB] [Dl: %.1fGiB] [Free: %dMB]\r\n",
		code, ulGiB, dlGiB, freeSpaceMB)

	if final {
		fmt.Fprintf(s.Conn, "%s  [Credits: %.1fGiB] [Ratio: %s]\r\n",
			code, creditsGiB, ratioStr)
	} else {
		fmt.Fprintf(s.Conn, "%s- [Credits: %.1fGiB] [Ratio: %s]\r\n",
			code, creditsGiB, ratioStr)
	}
}

func (s *Session) persistLoginStateAsync(username string, lastLogin int64) {
	username = strings.TrimSpace(username)
	if username == "" || lastLogin <= 0 {
		return
	}
	groupMap := s.GroupMap
	debug := s.Config != nil && s.Config.Debug
	go func() {
		_, err := user.MutateAndSave(username, groupMap, func(current *user.User) error {
			current.LastLogin = lastLogin
			current.ResetTransferStatPeriodsIfDue(time.Unix(lastLogin, 0))
			return nil
		})
		if err != nil && debug {
			log.Printf("[USER] skipped login-state save for %s: %v", username, err)
		}
	}()
}

func mbString(size int64) string { return fmt.Sprintf("%.0fMB", float64(size)/1024.0/1024.0) }

func isSpeedtestPath(p string) bool {
	clean := strings.ToLower(path.Clean("/" + strings.TrimSpace(p)))
	return clean == "/speedtest" || strings.HasPrefix(clean, "/speedtest/")
}

func transferSpeedMB(size int64, xferMs int64) float64 {
	if size <= 0 || xferMs <= 0 {
		return 0
	}
	return (float64(size) / 1024.0 / 1024.0) / (float64(xferMs) / 1000.0)
}

func ftpListMode(e MasterFileEntry) string {
	switch {
	case e.IsSymlink:
		return "lrwxrwxrwx"
	case e.IsDir:
		if e.Mode == 0555 {
			return "dr-xr-xr-x"
		}
		return "drwxr-xr-x"
	default:
		if e.Mode == 0444 {
			return "-r--r--r--"
		}
		return "-rw-r--r--"
	}
}

func mlsdSymlinkType(e MasterFileEntry) string {
	target := strings.TrimSpace(e.LinkTarget)
	if target == "" {
		return "OS.unix=symlink"
	}
	return "OS.unix=slink:" + target
}

func appendMLSDOwnerGroupFacts(facts []string, e MasterFileEntry, showReal bool) []string {
	if !showReal {
		return facts
	}
	owner := strings.TrimSpace(e.Owner)
	group := strings.TrimSpace(e.Group)
	if owner == "" {
		owner = "WeaveFTPd"
	}
	if group == "" {
		group = "WeaveFTPd"
	}
	return append(facts, "UNIX.owner="+owner, "UNIX.group="+group)
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func emitRaceEndAfter(s *Session, dirPath string, users []VFSRaceUser, groups []VFSRaceGroup, totalBytes int64, total int, raceDurationMs int64, xferMs int64, delay time.Duration) {
	if delay > 0 {
		time.Sleep(delay)
	}
	emitRaceEnd(s, dirPath, users, groups, totalBytes, total, raceDurationMs, xferMs)
}

type releasePostHookQueue struct {
	tasks   chan func()
	pending int // in-flight enqueues, guarded by releasePostHookQueuesMu
}

var (
	releasePostHookQueuesMu sync.Mutex
	releasePostHookQueues   = map[string]*releasePostHookQueue{}
)

func enqueueReleasePostHook(dirPath string, task func()) {
	if task == nil {
		return
	}
	key := path.Clean("/" + dirPath)
	if key == "." || key == "" {
		key = "/"
	}

	// Reserve a slot under the lock (pending++) BEFORE sending outside the lock.
	// The consumer only reaps the queue when pending==0 and the channel is empty,
	// so it cannot delete the queue and exit between our lookup and our send --
	// which would otherwise drop the task (and the COMPLETE announce it carries)
	// into an orphaned channel. We send outside the lock so a full buffer can
	// never stall the STOR hot path while holding the shared mutex.
	releasePostHookQueuesMu.Lock()
	q := releasePostHookQueues[key]
	if q == nil {
		q = &releasePostHookQueue{tasks: make(chan func(), 128)}
		releasePostHookQueues[key] = q
		go runReleasePostHookQueue(key, q)
	}
	q.pending++
	releasePostHookQueuesMu.Unlock()

	q.tasks <- task

	releasePostHookQueuesMu.Lock()
	q.pending--
	releasePostHookQueuesMu.Unlock()
}

func runReleasePostHookQueue(key string, q *releasePostHookQueue) {
	idle := time.NewTimer(30 * time.Second)
	defer idle.Stop()

	for {
		select {
		case task := <-q.tasks:
			if !idle.Stop() {
				select {
				case <-idle.C:
				default:
				}
			}
			if task != nil {
				task()
			}
			idle.Reset(30 * time.Second)
		case <-idle.C:
			releasePostHookQueuesMu.Lock()
			if releasePostHookQueues[key] == q && len(q.tasks) == 0 && q.pending == 0 {
				delete(releasePostHookQueues, key)
				releasePostHookQueuesMu.Unlock()
				return
			}
			releasePostHookQueuesMu.Unlock()
			idle.Reset(30 * time.Second)
		}
	}
}

func existingFileNamesForXDupe(entries []MasterFileEntry) []string {
	out := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir {
			continue
		}
		out = append(out, entry.Name)
	}
	sort.Slice(out, func(i, j int) bool {
		return strings.ToLower(out[i]) < strings.ToLower(out[j])
	})
	return out
}

func xdupeResponseLines(mode int, names []string) []string {
	if mode <= 0 || len(names) == 0 {
		return nil
	}
	const prefix = "X-DUPE: "
	switch mode {
	case 1:
		lines := make([]string, 0, len(names))
		current := ""
		for _, name := range names {
			if len(name) > 66 {
				lines = append(lines, prefix+name[:65])
				continue
			}
			if len(current)+len(name) > 66 {
				if current != "" {
					lines = append(lines, prefix+current)
				}
				current = name
				continue
			}
			if current != "" {
				current += " "
			}
			current += name
		}
		if current != "" {
			lines = append(lines, prefix+current)
		}
		return lines
	case 2:
		lines := make([]string, 0, len(names))
		for _, name := range names {
			if len(name) > 66 {
				lines = append(lines, prefix+name[:65])
			} else {
				lines = append(lines, prefix+name)
			}
		}
		return lines
	case 3:
		lines := make([]string, 0, len(names))
		for _, name := range names {
			lines = append(lines, prefix+name)
		}
		return lines
	case 4:
		current := ""
		for _, name := range names {
			next := name
			if current != "" {
				next = current + " " + name
			}
			if len(next) > 1010 {
				break
			}
			current = next
		}
		if current == "" {
			return nil
		}
		return []string{prefix + current}
	default:
		return nil
	}
}

func isDuplicateUploadErr(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(strings.TrimSpace(err.Error()))
	return strings.Contains(msg, "file exists") || strings.Contains(msg, "already exists") ||
		(strings.HasPrefix(msg, "file ") && strings.HasSuffix(msg, " exists"))
}

func duplicateResponseFileNames(existingNames []string, fileName string) []string {
	out := make([]string, 0, len(existingNames)+1)
	seen := make(map[string]struct{}, len(existingNames)+1)
	for _, name := range existingNames {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		key := strings.ToLower(name)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, name)
	}
	fileName = strings.TrimSpace(fileName)
	if fileName != "" {
		key := strings.ToLower(fileName)
		if _, ok := seen[key]; !ok {
			out = append(out, fileName)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return strings.ToLower(out[i]) < strings.ToLower(out[j])
	})
	return out
}

func writeDuplicateFileResponse(s *Session, fileName string, existingNames []string) {
	if s == nil || s.Conn == nil {
		return
	}
	if s.Config != nil && s.Config.XdupeEnabled && s.XDupeMode > 0 {
		for _, line := range xdupeResponseLines(s.XDupeMode, duplicateResponseFileNames(existingNames, fileName)) {
			fmt.Fprintf(s.Conn, "553-%s\r\n", line)
		}
		fmt.Fprintf(s.Conn, "553 Requested action not taken. File exists.\r\n")
		return
	}
	fmt.Fprintf(s.Conn, "553 Requested action not taken. File exists.\r\n")
}

func writeDuplicateUploadResponse(s *Session, bridge MasterBridge, uploadDir, fileName string, err error) bool {
	if s == nil || s.Conn == nil || bridge == nil || !isDuplicateUploadErr(err) {
		return false
	}
	writeDuplicateFileResponse(s, fileName, existingFileNamesForXDupe(bridge.ListDir(uploadDir)))
	return true
}

func activeIncompleteIndicator(cfg *Config) string {
	if cfg == nil {
		return ""
	}
	return zipscript.IncompleteIndicator(cfg.Zipscript, "")
}

func trimRaceUsers(cfg *Config, users []VFSRaceUser) []VFSRaceUser {
	if cfg != nil && cfg.Zipscript.Race.MaskUserGroupNames {
		masked := make([]VFSRaceUser, len(users))
		copy(masked, users)
		for i := range masked {
			masked[i].Name = maskRaceName(masked[i].Name)
			masked[i].Group = maskRaceName(masked[i].Group)
		}
		users = masked
	}
	if cfg == nil || cfg.Zipscript.Race.MaxUsersInTop <= 0 || len(users) <= cfg.Zipscript.Race.MaxUsersInTop {
		return users
	}
	return users[:cfg.Zipscript.Race.MaxUsersInTop]
}

func trimRaceGroups(cfg *Config, groups []VFSRaceGroup) []VFSRaceGroup {
	if cfg != nil && cfg.Zipscript.Race.MaskUserGroupNames {
		masked := make([]VFSRaceGroup, len(groups))
		copy(masked, groups)
		for i := range masked {
			masked[i].Name = maskRaceName(masked[i].Name)
		}
		groups = masked
	}
	if cfg == nil || cfg.Zipscript.Race.MaxGroupsInTop <= 0 || len(groups) <= cfg.Zipscript.Race.MaxGroupsInTop {
		return groups
	}
	return groups[:cfg.Zipscript.Race.MaxGroupsInTop]
}

func maskRaceName(name string) string {
	runes := []rune(strings.TrimSpace(name))
	switch len(runes) {
	case 0:
		return name
	case 1:
		return string(runes)
	case 2:
		return string(runes[0]) + "*"
	default:
		return string(runes[0]) + strings.Repeat("*", len(runes)-2) + string(runes[len(runes)-1])
	}
}

func raceCRCKey(name string) string {
	name = strings.TrimSpace(path.Base(strings.ReplaceAll(name, "\\", "/")))
	return strings.ToLower(name)
}

// sessionTransferringPath reports whether any live session is transferring
// cleanPath in the given direction.
//
// This scans the session map directly and stops at the first match. It
// deliberately does NOT go through listActiveSessions: that builds a snapshot
// struct for every session (including a RemoteAddr().String() allocation and a
// deferred recover per session) and then sorts the whole slice, which is a lot of
// per-file work for a single yes/no answer. These guards run before the 150 on
// STOR and RETR, so the cost lands directly on race turnaround.
func sessionTransferringPath(cleanPath, direction string) bool {
	found := false
	activeSessions.Range(func(_, value interface{}) bool {
		s, ok := value.(*Session)
		if !ok || s == nil {
			return true
		}
		s.stateMu.RLock()
		dir := s.TransferDirection
		tpath := s.TransferPath
		s.stateMu.RUnlock()
		if dir != direction || tpath == "" {
			return true
		}
		if path.Clean(tpath) == cleanPath {
			found = true
			return false // stop ranging
		}
		return true
	})
	return found
}

func activeUploadForPath(filePath string) bool {
	cleanPath := path.Clean(filePath)
	if uploadPathReserved(cleanPath) {
		return true
	}
	return sessionTransferringPath(cleanPath, "upload")
}

func activeDownloadForPath(filePath string) bool {
	cleanPath := path.Clean(filePath)
	if downloadPathReserved(cleanPath) {
		return true
	}
	return sessionTransferringPath(cleanPath, "download")
}

func mediaInfoPluginSettings(cfg *Config) (sections []string, sampleOnly bool, videoExts map[string]bool) {
	sections = []string{"TV", "X264-HD-1080P", "X264-HD-720P", "X264-SD", "X265", "BLURAY"}
	sampleOnly = true
	videoExts = extensionSetLower([]string{"mkv", "mp4", "avi", "m2ts"})
	if cfg == nil {
		return
	}
	if len(cfg.Zipscript.Media.Sections) > 0 {
		sections = append([]string(nil), cfg.Zipscript.Media.Sections...)
	}
	if cfg.Zipscript.Media.SampleOnly != nil {
		sampleOnly = *cfg.Zipscript.Media.SampleOnly
	}
	if len(cfg.Zipscript.Media.VideoExtensions) > 0 {
		videoExts = extensionSetLower(cfg.Zipscript.Media.VideoExtensions)
	}
	if cfg.Zipscript.Media.Enabled != nil && !*cfg.Zipscript.Media.Enabled {
		sections = nil
		videoExts = map[string]bool{}
		return
	}
	return
}

func interfaceStringSlice(raw interface{}) ([]string, bool) {
	switch v := raw.(type) {
	case []string:
		out := make([]string, 0, len(v))
		for _, s := range v {
			s = strings.TrimSpace(s)
			if s != "" {
				out = append(out, s)
			}
		}
		return out, len(out) > 0
	case []interface{}:
		out := make([]string, 0, len(v))
		for _, item := range v {
			s, ok := item.(string)
			if !ok {
				continue
			}
			s = strings.TrimSpace(s)
			if s != "" {
				out = append(out, s)
			}
		}
		return out, len(out) > 0
	default:
		return nil, false
	}
}

func extensionSetLower(values []string) map[string]bool {
	out := make(map[string]bool, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(value, ".")))
		if value != "" {
			out[value] = true
		}
	}
	return out
}

func mediaInfoSectionMatch(section string, patterns []string) bool {
	section = strings.ToLower(strings.TrimSpace(section))
	for _, pat := range patterns {
		pat = strings.ToLower(strings.TrimSpace(pat))
		if pat != "" && strings.Contains(section, pat) {
			return true
		}
	}
	return false
}

func (s *Session) resolvePretTargetPath(bridge MasterBridge) string {
	targetPath := s.CurrentDir
	if strings.TrimSpace(s.PretArg) != "" {
		if path.IsAbs(strings.TrimSpace(s.PretArg)) {
			targetPath = path.Clean(s.PretArg)
		} else {
			targetPath = path.Clean(path.Join(s.CurrentDir, s.PretArg))
		}
	}
	if bridge != nil {
		targetPath = bridge.ResolvePath(targetPath)
	}
	return targetPath
}
