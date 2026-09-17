package admincommander

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"weaveftpd/sitebot/internal/event"
	"weaveftpd/sitebot/internal/plugin"
	tmpl "weaveftpd/sitebot/internal/template"
)

type Plugin struct {
	host        string
	port        int
	user        string
	password    string
	useTLS      bool
	insecure    bool
	timeout     time.Duration
	replyTarget string

	staffChannels []string
	staffHosts    []string
	allowed       map[string]bool
	theme         *tmpl.Theme
}

func New() *Plugin {
	return &Plugin{
		host:          "127.0.0.1",
		port:          2121,
		user:          "weaveftpd",
		useTLS:        true,
		insecure:      true,
		timeout:       10 * time.Second,
		replyTarget:   "channel",
		staffChannels: []string{"#weaveftpd-staff"},
		allowed:       allowedSet(defaultAllowedCommands()),
	}
}

func (p *Plugin) Name() string { return "AdminCommander" }

func (p *Plugin) Initialize(config map[string]interface{}) error {
	if themeFile, ok := config["theme_file"].(string); ok && strings.TrimSpace(themeFile) != "" {
		th, err := tmpl.LoadTheme(themeFile)
		if err == nil {
			p.theme = th
		}
	}

	cfg := plugin.ConfigSection(config, "admin_commander")
	if s, ok := stringConfig(cfg, config, "host", "admin_commander_host"); ok && strings.TrimSpace(s) != "" {
		p.host = strings.TrimSpace(s)
	}
	if n := intConfig(configValue(cfg, config, "port", "admin_commander_port"), p.port); n > 0 {
		p.port = n
	}
	if s, ok := stringConfig(cfg, config, "user", "admin_commander_user"); ok && strings.TrimSpace(s) != "" {
		p.user = strings.TrimSpace(s)
	}
	if s, ok := stringConfig(cfg, config, "password", "admin_commander_password"); ok {
		p.password = s
	}
	if b, ok := boolConfig(configValue(cfg, config, "tls", "admin_commander_tls")); ok {
		p.useTLS = b
	}
	if b, ok := boolConfig(configValue(cfg, config, "insecure_skip_verify", "admin_commander_insecure_skip_verify")); ok {
		p.insecure = b
	}
	if n := intConfig(configValue(cfg, config, "timeout_seconds", "admin_commander_timeout_seconds"), 0); n > 0 {
		p.timeout = time.Duration(n) * time.Second
	}
	if raw, ok := configValueOK(cfg, config, "staff_channels", "admin_commander_staff_channels"); ok {
		p.staffChannels = plugin.ToStringSlice(raw, p.staffChannels)
	}
	if raw, ok := configValueOK(cfg, config, "staff_hosts", "admin_commander_staff_hosts"); ok {
		p.staffHosts = plugin.ToStringSlice(raw, p.staffHosts)
	}
	if raw, ok := configValueOK(cfg, config, "allowed_commands", "admin_commander_allowed_commands"); ok {
		p.allowed = allowedSet(plugin.ToStringSlice(raw, nil))
	}
	if s, ok := stringConfig(cfg, config, "reply_target", "admin_commander_reply_target"); ok && strings.TrimSpace(s) != "" {
		p.replyTarget = strings.ToLower(strings.TrimSpace(s))
	}
	return nil
}

func (p *Plugin) Close() error { return nil }

func (p *Plugin) OnEvent(evt *event.Event) ([]plugin.Output, error) {
	if evt.Type != event.EventCommand {
		return nil, nil
	}

	cmd := strings.ToLower(strings.TrimSpace(evt.Data["command"]))
	args := strings.TrimSpace(evt.Data["args"])
	siteArgs := ""
	displayArgs := ""
	switch cmd {
	case "site":
		siteArgs = args
		displayArgs = args
	case "nuke":
		if args == "" {
			return p.reply(evt, p.render("ADMINCMD_USAGE", map[string]string{"command": cmd}, "ADMIN: Usage: !site <command> [args], !nuke <release> <multiplier> <reason>, or !unnuke <release> [reason]")), nil
		}
		siteArgs = "NUKE " + args
		displayArgs = siteArgs
	case "unnuke":
		if args == "" {
			return p.reply(evt, p.render("ADMINCMD_USAGE", map[string]string{"command": cmd}, "ADMIN: Usage: !site <command> [args], !nuke <release> <multiplier> <reason>, or !unnuke <release> [reason]")), nil
		}
		siteArgs = "UNNUKE " + args
		displayArgs = siteArgs
	default:
		return nil, nil
	}

	if !p.canStaff(evt) {
		return p.reply(evt, p.render("ADMINCMD_DENIED", map[string]string{"user": evt.User}, "ADMIN: staff command only.")), nil
	}
	siteArgs = normalizeSiteArgs(siteArgs)
	if siteArgs == "" {
		return p.reply(evt, p.render("ADMINCMD_USAGE", map[string]string{"command": cmd}, "ADMIN: Usage: !site <command> [args], !nuke <release> <multiplier> <reason>, or !unnuke <release> [reason]")), nil
	}
	if displayArgs == "" {
		displayArgs = siteArgs
	}
	displayArgs = normalizeSiteArgs(displayArgs)
	displayArgs = sanitizeDisplaySITEArgs(displayArgs)
	siteCommand := firstWord(siteArgs)
	if !p.allowedCommand(siteCommand) {
		return p.reply(evt, p.render("ADMINCMD_BLOCKED", map[string]string{"command": siteCommand}, fmt.Sprintf("ADMIN: SITE %s is not allowed.", siteCommand))), nil
	}

	responseLines, err := p.runSITE(siteArgs)
	response := responseText(responseLines)
	vars := map[string]string{
		"command":  displayArgs,
		"response": response,
		"error":    "",
		"user":     evt.User,
		"channel":  evt.Data["channel"],
	}
	if err != nil {
		vars["error"] = err.Error()
		if response == "" {
			response = err.Error()
		}
		vars["response"] = response
		return p.reply(evt, p.render("ADMINCMD_ERROR", vars, "ADMIN: SITE "+displayArgs+" failed: "+response)), nil
	}
	return p.commandResponse(evt, displayArgs, responseLines), nil
}

func sanitizeDisplaySITEArgs(args string) string {
	fields := strings.Fields(strings.TrimSpace(args))
	if len(fields) == 0 {
		return args
	}
	switch strings.ToUpper(fields[0]) {
	case "ADDUSER", "GADDUSER", "CHPASS", "READD":
		if len(fields) >= 3 {
			fields[2] = "********"
		}
	}
	return strings.Join(fields, " ")
}

func (p *Plugin) runSITE(siteArgs string) ([]string, error) {
	addr := net.JoinHostPort(p.host, strconv.Itoa(p.port))
	rawConn, err := net.DialTimeout("tcp", addr, p.timeout)
	if err != nil {
		return nil, err
	}
	defer rawConn.Close()
	_ = rawConn.SetDeadline(time.Now().Add(p.timeout))

	conn := rawConn
	reader := bufio.NewReader(conn)
	if _, _, err := readFTPResponse(reader); err != nil {
		return nil, err
	}

	if p.useTLS {
		if err := writeFTPCommand(conn, "AUTH TLS"); err != nil {
			return nil, err
		}
		code, lines, err := readFTPResponse(reader)
		if err != nil {
			return nil, err
		}
		if code < 200 || code >= 400 {
			clean := responseLines(lines)
			return clean, fmt.Errorf("AUTH TLS failed: %s", responseText(clean))
		}
		tlsConn := tls.Client(conn, &tls.Config{ServerName: p.host, InsecureSkipVerify: p.insecure})
		if err := tlsConn.Handshake(); err != nil {
			return nil, err
		}
		conn = tlsConn
		reader = bufio.NewReader(conn)
	}

	if err := writeFTPCommand(conn, "USER "+p.user); err != nil {
		return nil, err
	}
	code, lines, err := readFTPResponse(reader)
	if err != nil {
		return nil, err
	}
	if code == 331 {
		if err := writeFTPCommand(conn, "PASS "+p.password); err != nil {
			return nil, err
		}
		code, lines, err = readFTPResponse(reader)
		if err != nil {
			return nil, err
		}
	}
	if code < 200 || code >= 300 {
		clean := responseLines(lines)
		return clean, fmt.Errorf("login failed: %s", responseText(clean))
	}

	if err := writeFTPCommand(conn, "SITE "+siteArgs); err != nil {
		return nil, err
	}
	code, lines, err = readFTPResponse(reader)
	if err != nil {
		return nil, err
	}
	_ = writeFTPCommand(conn, "QUIT")
	clean := responseLines(lines)
	if code >= 400 {
		return clean, errors.New(responseText(clean))
	}
	return clean, nil
}

func readFTPResponse(r *bufio.Reader) (int, []string, error) {
	line, err := readFTPLine(r)
	if err != nil {
		return 0, nil, err
	}
	if len(line) < 3 {
		return 0, []string{line}, fmt.Errorf("short FTP response: %s", line)
	}
	code, err := strconv.Atoi(line[:3])
	if err != nil {
		return 0, []string{line}, err
	}
	lines := []string{line}
	if len(line) > 3 && line[3] == '-' {
		endPrefix := line[:3] + " "
		for {
			next, err := readFTPLine(r)
			if err != nil {
				return code, lines, err
			}
			lines = append(lines, next)
			if strings.HasPrefix(next, endPrefix) {
				break
			}
		}
	}
	return code, lines, nil
}

func readFTPLine(r *bufio.Reader) (string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func writeFTPCommand(conn net.Conn, command string) error {
	_, err := fmt.Fprintf(conn, "%s\r\n", command)
	return err
}

func responseText(lines []string) string {
	return strings.Join(lines, " | ")
}

func responseLines(lines []string) []string {
	parts := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if len(line) >= 4 && isFTPCodePrefix(line) {
			line = strings.TrimSpace(line[4:])
		}
		if line != "" {
			parts = append(parts, line)
		}
	}
	return parts
}

func isFTPCodePrefix(line string) bool {
	if len(line) < 4 {
		return false
	}
	for i := 0; i < 3; i++ {
		if line[i] < '0' || line[i] > '9' {
			return false
		}
	}
	return line[3] == ' ' || line[3] == '-'
}

func normalizeSiteArgs(args string) string {
	fields := strings.Fields(strings.TrimSpace(args))
	if len(fields) == 0 {
		return ""
	}
	fields[0] = strings.ToUpper(fields[0])
	return strings.Join(fields, " ")
}

func firstWord(s string) string {
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return ""
	}
	return strings.ToUpper(fields[0])
}

func allowedSet(commands []string) map[string]bool {
	out := map[string]bool{}
	for _, command := range commands {
		command = strings.ToUpper(strings.TrimSpace(command))
		if command != "" {
			out[command] = true
		}
	}
	if len(out) == 0 {
		return allowedSet(defaultAllowedCommands())
	}
	return out
}

func defaultAllowedCommands() []string {
	return []string{
		"HELP",
		"RULES",
		"WHO",
		"SWHO",
		"USERS",
		"USER",
		"SEEN",
		"LASTLOGIN",
		"GROUPS",
		"GROUP",
		"GINFO",
		"GRPNFO",
		"TRAFFIC",
		"ADDUSER",
		"GADDUSER",
		"DELUSER",
		"READD",
		"RENUSER",
		"CHPASS",
		"ADDIP",
		"DELIP",
		"FLAGS",
		"CHGRP",
		"CHPGRP",
		"GADMIN",
		"GRPADD",
		"GRPDEL",
		"INVITE",
		"NUKE",
		"NUKES",
		"UNNUKE",
		"UNDUPE",
		"WIPE",
		"KICK",
		"REHASH",
		"REMERGE",
		"RACE",
		"SEARCH",
		"RESCAN",
		"CHMOD",
		"XDUPE",
		"GRP",
		"PRE",
		"ADDAFFIL",
		"DELAFFIL",
		"AFFILS",
		"REQUEST",
		"REQUESTS",
		"REQFILL",
		"REQFILLED",
		"REQDEL",
		"REQWIPE",
	}
}

func (p *Plugin) allowedCommand(command string) bool {
	command = strings.ToUpper(strings.TrimSpace(command))
	return p.allowed["*"] || p.allowed[command]
}

func (p *Plugin) canStaff(evt *event.Event) bool {
	channel := strings.ToLower(strings.TrimSpace(evt.Data["channel"]))
	for _, ch := range p.staffChannels {
		if strings.EqualFold(strings.TrimSpace(ch), channel) {
			return true
		}
	}
	host := strings.ToLower(strings.TrimSpace(evt.Data["host"]))
	for _, pattern := range p.staffHosts {
		if wildcardMatch(strings.ToLower(strings.TrimSpace(pattern)), host) {
			return true
		}
	}
	return false
}

func wildcardMatch(pattern, value string) bool {
	if pattern == "" || value == "" {
		return false
	}
	if ok, _ := filepath.Match(pattern, value); ok {
		return true
	}
	return pattern == value
}

func (p *Plugin) replies(evt *event.Event, lines ...string) []plugin.Output {
	target := strings.TrimSpace(evt.Data["channel"])
	noticeReply := false
	if strings.HasPrefix(p.replyTarget, "#") {
		target = p.replyTarget
	} else if p.replyTarget == "notice" || target == "" {
		target = evt.User
		noticeReply = true
	}
	out := make([]plugin.Output, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		out = append(out, plugin.Output{Type: "COMMAND", Target: target, Notice: noticeReply, Text: line})
	}
	return out
}

func (p *Plugin) reply(evt *event.Event, text string) []plugin.Output {
	return p.replies(evt, text)
}

func (p *Plugin) commandResponse(evt *event.Event, command string, lines []string) []plugin.Output {
	if len(lines) <= 1 {
		response := responseText(lines)
		vars := map[string]string{"command": command, "response": response, "user": evt.User, "channel": evt.Data["channel"]}
		return p.reply(evt, p.render("ADMINCMD_OK", vars, "ADMIN: SITE "+command+" -> "+response))
	}
	out := make([]string, 0, len(lines))
	for i, line := range lines {
		vars := map[string]string{
			"command":  command,
			"response": line,
			"line":     line,
			"user":     evt.User,
			"channel":  evt.Data["channel"],
		}
		if i == 0 {
			out = append(out, p.render("ADMINCMD_OK", vars, "ADMIN: SITE "+command+" -> "+line))
			continue
		}
		out = append(out, p.render("ADMINCMD_LINE", vars, "ADMIN: "+line))
	}
	return p.replies(evt, out...)
}

func (p *Plugin) render(key string, vars map[string]string, fallback string) string {
	if p.theme != nil {
		if raw, ok := p.theme.Announces[key]; ok && raw != "" {
			return tmpl.Render(raw, vars)
		}
	}
	return fallback
}

func configValue(section, flat map[string]interface{}, sectionKey, flatKey string) interface{} {
	raw, _ := configValueOK(section, flat, sectionKey, flatKey)
	return raw
}

func configValueOK(section, flat map[string]interface{}, sectionKey, flatKey string) (interface{}, bool) {
	if raw, ok := section[sectionKey]; ok {
		return raw, true
	}
	raw, ok := flat[flatKey]
	return raw, ok
}

func stringConfig(section, flat map[string]interface{}, sectionKey, flatKey string) (string, bool) {
	raw, ok := configValueOK(section, flat, sectionKey, flatKey)
	if !ok {
		return "", false
	}
	s, ok := raw.(string)
	return s, ok
}

func intConfig(raw interface{}, fallback int) int {
	switch v := raw.(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	case string:
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
			return n
		}
	}
	return fallback
}

func boolConfig(raw interface{}) (bool, bool) {
	switch v := raw.(type) {
	case bool:
		return v, true
	case string:
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "true", "yes", "1", "on":
			return true, true
		case "false", "no", "0", "off":
			return false, true
		}
	}
	return false, false
}
