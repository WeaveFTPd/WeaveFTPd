// weaveftpd-setup creates a new bind-mounted Docker runtime, never modifies one.
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
	"unicode"

	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"
)

type values map[string]string

var safeName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,31}$`)

func main() {
	source := flag.String("source", "/source", "read-only public source templates")
	output := flag.String("output", "/output", "host deployment directory")
	issue := flag.String("issue-slave", "", "issue a named slave certificate from this master CA")
	slaveIP := flag.String("slave-ip", "", "public IPv4 address of the slave certificate")
	flag.Parse()
	var err error
	if *issue != "" {
		err = issueSlave(*output, *issue, *slaveIP)
	} else {
		err = setup(os.Stdin, *source, *output)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "Setup:", err)
		os.Exit(1)
	}
}

func readValues(r io.Reader) (values, error) {
	b, err := io.ReadAll(io.LimitReader(r, 65537))
	if err != nil {
		return nil, err
	}
	if len(b) > 65536 {
		return nil, errors.New("input too large")
	}
	v := values{}
	allowed := " role public_ip ftp_port control_port pasv_min pasv_max site_path admin password admin_ip timezone uid gid irc_host irc_port irc_nick irc_channel irc_password fish_key master_host slave_name image sitebot_image bundle sections "
	for _, s := range strings.Split(string(b), "\x00") {
		if s == "" {
			continue
		}
		k, val, ok := strings.Cut(s, "=")
		if !ok || !strings.Contains(allowed, " "+k+" ") {
			return nil, errors.New("unknown setup field")
		}
		if _, ok := v[k]; ok {
			return nil, fmt.Errorf("duplicate field %s", k)
		}
		if strings.ContainsAny(val, "\r\n") {
			return nil, fmt.Errorf("newlines are not allowed in %s", k)
		}
		v[k] = val
	}
	return v, nil
}
func number(v values, k string, min, max int) (int, error) {
	n, e := strconv.Atoi(v[k])
	if e != nil || n < min || n > max {
		return 0, fmt.Errorf("invalid %s (expected %d..%d)", k, min, max)
	}
	return n, nil
}
func validate(v values) error {
	if v["role"] != "master" && v["role"] != "slave" {
		return errors.New("role must be master or slave")
	}
	if net.ParseIP(v["public_ip"]).To4() == nil {
		return errors.New("public_ip must be an IPv4 address for PASV")
	}
	lo, e := number(v, "pasv_min", 1024, 65535)
	if e != nil {
		return e
	}
	hi, e := number(v, "pasv_max", lo, 65535)
	if e != nil {
		return e
	}
	cp, e := number(v, "control_port", 1024, 65535)
	if e != nil {
		return e
	}
	if cp >= lo && cp <= hi {
		return errors.New("control port overlaps passive range")
	}
	for _, k := range []string{"uid", "gid"} {
		if _, e = number(v, k, 0, 2147483647); e != nil {
			return e
		}
	}
	if filepath.Clean(v["site_path"]) == string(filepath.Separator) || !filepath.IsAbs(v["site_path"]) || strings.ContainsAny(v["site_path"], "\x00\r\n") {
		return errors.New("site_path must be absolute")
	}
	if _, e = time.LoadLocation(v["timezone"]); e != nil {
		return errors.New("unknown timezone")
	}
	if v["image"] == "" || v["sitebot_image"] == "" {
		return errors.New("missing image references")
	}
	if v["role"] == "master" {
		if v["sections"] == "" {
			v["sections"] = "TEST"
		}
		for _, section := range strings.Split(v["sections"], ",") {
			if !safeName.MatchString(section) {
				return errors.New("sections must be comma-separated names, using letters, numbers, - or _")
			}
		}
		fp, e := number(v, "ftp_port", 1, 65535)
		if e != nil {
			return e
		}
		if fp == cp || fp >= lo && fp <= hi {
			return errors.New("FTP port overlaps another listener")
		}
		if !safeName.MatchString(v["admin"]) || v["admin"] == "default" {
			return errors.New("invalid administrator name")
		}
		if strings.IndexFunc(v["password"], unicode.IsSpace) >= 0 {
			return errors.New("administrator password cannot contain whitespace: this daemon splits FTP command arguments on whitespace")
		}
		if len(v["password"]) < 12 || len(v["password"]) > 72 {
			return errors.New("password must contain 12..72 bytes")
		}
		if net.ParseIP(v["admin_ip"]) == nil {
			return errors.New("admin_ip must be a trusted IP address")
		}
		if v["irc_host"] != "" {
			if _, e = number(v, "irc_port", 1, 65535); e != nil {
				return e
			}
			if !safeName.MatchString(v["irc_nick"]) {
				return errors.New("invalid IRC nick")
			}
			if !strings.HasPrefix(v["irc_channel"], "#") || strings.ContainsAny(v["irc_channel"], " ,:\t") {
				return errors.New("invalid IRC channel")
			}
		}
	} else {
		if !safeName.MatchString(v["slave_name"]) || strings.EqualFold(v["slave_name"], "LOCAL") {
			return errors.New("use a unique remote slave name (not LOCAL)")
		}
		if v["master_host"] == "" || strings.ContainsAny(v["master_host"], " /\\\t") {
			return errors.New("invalid master hostname")
		}
		if v["bundle"] == "" {
			return errors.New("remote slaves require a CA/client certificate bundle")
		}
	}
	return nil
}

func setup(r io.Reader, source, output string) error {
	v, e := readValues(r)
	if e != nil {
		return e
	}
	if e = validate(v); e != nil {
		return e
	}
	role := v["role"]
	target := filepath.Join(output, "runtime", role)
	env := filepath.Join(output, role+".env")
	// Exclusive guard also prevents two installers racing before the final rename.
	if e = os.MkdirAll(output, 0755); e != nil {
		return e
	}
	guard := filepath.Join(output, ".setup.lock")
	f, e := os.OpenFile(guard, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return errors.New("another setup is running, or .setup.lock needs inspection")
	}
	f.Close()
	defer os.Remove(guard)
	for _, p := range []string{target, env} {
		if _, e = os.Lstat(p); e == nil {
			return fmt.Errorf("%s already exists; existing settings have been preserved", p)
		} else if !os.IsNotExist(e) {
			return e
		}
	}
	parent := filepath.Dir(target)
	if e = os.MkdirAll(parent, 0755); e != nil {
		return e
	}
	stage, e := os.MkdirTemp(parent, ".setup-")
	if e != nil {
		return e
	}
	defer os.RemoveAll(stage)
	// MkdirTemp is 0700; the selected container UID needs traversal.
	if e = os.Chmod(stage, 0750); e != nil {
		return e
	}
	for _, dir := range []string{"etc/certs", "logs", "site"} {
		if e = os.MkdirAll(filepath.Join(stage, dir), 0750); e != nil {
			return e
		}
	}
	certDir := filepath.Join(stage, "etc/certs")
	if role == "master" {
		if e = masterFiles(source, stage, v); e != nil {
			return e
		}
		if e = createCA(certDir, v["public_ip"]); e != nil {
			return e
		}
		// The signing key stays on the host, outside every service bind mount.
		privateCA := filepath.Join(stage, "ca")
		if e = os.Mkdir(privateCA, 0700); e != nil {
			return e
		}
		if e = os.Rename(filepath.Join(certDir, "ca.key"), filepath.Join(privateCA, "ca.key")); e != nil {
			return e
		}
	} else {
		if e = remoteFiles(source, stage, v); e != nil {
			return e
		}
	}
	// Only newly generated files are chowned. Never walk/chown existing site data.
	if runtime.GOOS != "windows" {
		uid, _ := strconv.Atoi(v["uid"])
		gid, _ := strconv.Atoi(v["gid"])
		if e = filepath.WalkDir(stage, func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			return os.Chown(p, uid, gid)
		}); e != nil {
			return e
		}
	}
	body := "WEAVEFTPD_IMAGE=" + envQuote(v["image"]) + "\nWEAVEFTPD_SITEBOT_IMAGE=" + envQuote(v["sitebot_image"]) + "\nWEAVEFTPD_UID=" + v["uid"] + "\nWEAVEFTPD_GID=" + v["gid"] + "\n"
	prefix := "WEAVEFTPD"
	if role == "slave" {
		prefix += "_SLAVE"
	}
	body += prefix + "_RUNTIME=" + envQuote("./runtime/"+role) + "\n" + prefix + "_SITE_PATH=" + envQuote(v["site_path"]) + "\n"
	if role == "master" && v["irc_host"] != "" {
		body += "COMPOSE_PROFILES=sitebot\n"
	}
	// Publish the complete runtime first; a failure writing env leaves a visible
	// runtime for inspection rather than replacing anything on a subsequent run.
	if e = os.Rename(stage, target); e != nil {
		return e
	}
	if e = writeNew(env, []byte(body), 0644); e != nil {
		return e
	}
	fmt.Printf("Created %s runtime. Existing installations are never overwritten.\n", role)
	return nil
}
func envQuote(s string) string {
	return "'" + strings.ReplaceAll(strings.ReplaceAll(s, "\\", "\\\\"), "'", "\\'") + "'"
}
func writeNew(path string, b []byte, mode os.FileMode) error {
	if e := os.MkdirAll(filepath.Dir(path), 0750); e != nil {
		return e
	}
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if e != nil {
		return e
	}
	_, e = f.Write(b)
	ce := f.Close()
	if e != nil {
		return e
	}
	return ce
}
func copyFile(src, dst string) error {
	b, e := os.ReadFile(src)
	if e != nil {
		return e
	}
	return writeNew(dst, b, 0600)
}
func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(p string, d os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if d.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("template symlink refused: %s", p)
		}
		rel, e := filepath.Rel(src, p)
		if e != nil {
			return e
		}
		if d.IsDir() {
			return os.MkdirAll(filepath.Join(dst, rel), 0750)
		}
		return copyFile(p, filepath.Join(dst, rel))
	})
}
func loadYAML(path string) (map[string]any, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return nil, e
	}
	var m map[string]any
	e = yaml.Unmarshal(b, &m)
	return m, e
}
func writeYAML(path string, m map[string]any) error {
	b, e := yaml.Marshal(m)
	if e != nil {
		return e
	}
	return writeNew(path, b, 0600)
}
func block(m map[string]any, k string) map[string]any {
	b, ok := m[k].(map[string]any)
	if !ok {
		b = map[string]any{}
		m[k] = b
	}
	return b
}
func port(v values, k string) int { n, _ := strconv.Atoi(v[k]); return n }
func common(m map[string]any, v values) {
	m["timezone"] = v["timezone"]
	m["tls_enabled"] = true
	m["tls_cert"] = "/app/etc/certs/server.crt"
	m["tls_key"] = "/app/etc/certs/server.key"
	m["log_file"] = "/app/logs/weaveftpd.log"
	m["log_console"] = true
}
func slaveConfig(source string, v values, name, host string) (map[string]any, error) {
	m, e := loadYAML(filepath.Join(source, "etc/config-slave-example.yml"))
	if e != nil {
		return nil, e
	}
	common(m, v)
	s := block(m, "slave")
	s["name"] = name
	s["master_host"] = host
	s["master_port"] = port(v, "control_port")
	s["roots"] = []string{"/app/site"}
	s["bind_ip"] = v["public_ip"]
	s["pasv_port_min"] = port(v, "pasv_min")
	s["pasv_port_max"] = port(v, "pasv_max")
	s["master_ca_cert"] = "/app/etc/certs/ca.crt"
	s["client_cert"] = "/app/etc/certs/client.crt"
	s["client_key"] = "/app/etc/certs/client.key"
	return m, nil
}
func masterFiles(source, stage string, v values) error {
	for _, dir := range []string{"plugins", "userdata", "backup", "logs-local-slave", "etc/users", "etc/groups", "sitebot/etc", "sitebot/plugins", "sitebot/logs"} {
		if e := os.MkdirAll(filepath.Join(stage, dir), 0750); e != nil {
			return e
		}
	}
	m, e := loadYAML(filepath.Join(source, "etc/config-example.yml"))
	if e != nil {
		return e
	}
	common(m, v)
	for k, val := range map[string]any{"mode": "master", "storage_path": "/app/site", "rootpath": "/", "datapath": "/app/userdata", "acl_base_path": "/", "passwd_file": "/app/etc/passwd", "msg_path": "/app/etc/msgs", "event_fifo": "/app/etc/weaveftpd.sitebot.fifo", "sitebot_config": "/app/sitebot/etc/config.yml", "listen_port": port(v, "ftp_port"), "public_ip": v["public_ip"], "pasv_min": port(v, "pasv_min"), "pasv_max": port(v, "pasv_max"), "passthrough": true, "require_tls_control": true, "require_tls_data": true} {
		m[k] = val
	}
	m["sections"] = strings.Split(v["sections"], ",")
	master := block(m, "master")
	master["control_port"] = port(v, "control_port")
	master["listen_host"] = "0.0.0.0"
	master["slave_ca_cert"] = "/app/etc/certs/ca.crt"
	// New installs start without deletion/slow-client enforcement or external API
	// plugins. Enable these deliberately after configuring their policies.
	plugins := block(m, "plugins")
	for name, p := range plugins {
		if cfg, ok := p.(map[string]any); ok {
			cfg["enabled"] = name == "speedtest"
		}
	}
	if e = writeYAML(filepath.Join(stage, "etc/config.yml"), m); e != nil {
		return e
	}
	s, e := slaveConfig(source, v, "LOCAL", "127.0.0.1")
	if e != nil {
		return e
	}
	if e = writeYAML(filepath.Join(stage, "etc/config-slave-local.yml"), s); e != nil {
		return e
	}
	for _, f := range []string{"permissions.yml", "version"} {
		if e = copyFile(filepath.Join(source, "etc", f), filepath.Join(stage, "etc", f)); e != nil {
			return e
		}
	}
	if e = copyTree(filepath.Join(source, "etc/msgs"), filepath.Join(stage, "etc/msgs")); e != nil {
		return e
	}
	// Explicit seed files only: never copy a checkout's active users/passwords.
	hash, e := bcrypt.GenerateFromPassword([]byte(v["password"]), bcrypt.DefaultCost)
	if e != nil {
		return e
	}
	passwd := fmt.Sprintf("%s:%s:1000:100:0:/:/bin/false\n", v["admin"], hash)
	if e = writeNew(filepath.Join(stage, "etc/passwd"), []byte(passwd), 0600); e != nil {
		return e
	}
	user := "USER Docker administrator\nGENERAL 0,120 -1 0 0\nLOGINS 10 0 3 6\nFLAGS 13AB\nHOMEDIR /site\nDIR /\nRATIO 0\nCREDITS 0\nLOGINSLOTS 10\nUPLOADSLOTS 6\nDOWNLOADSLOTS 3\nPRIMARY_GROUP NoGroup\nGROUP NoGroup 0\nIP *@127.0.0.1\nIP *@::1\nIP *@" + v["admin_ip"] + "\n"
	if e = writeNew(filepath.Join(stage, "etc/users", v["admin"]), []byte(user), 0600); e != nil {
		return e
	}
	for path, contents := range map[string]string{"etc/group": "NoGroup:No Group:100:\n", "etc/groups/NoGroup": "GROUP NoGroup\nSLOTS -1 0 0 0\n", "etc/affils.yml": "groups: []\n"} {
		if e = writeNew(filepath.Join(stage, path), []byte(contents), 0600); e != nil {
			return e
		}
	}
	if e = writeNew(filepath.Join(stage, "etc/users/default.user"), []byte("USER Default template\nGENERAL 0,120 -1 0 0\nLOGINS 7 0 3 3\nFLAGS 3\nHOMEDIR /site\nDIR /\nRATIO 3\nCREDITS 0\nLOGINSLOTS 7\nUPLOADSLOTS 3\nDOWNLOADSLOTS 3\nPRIMARY_GROUP NoGroup\nGROUP NoGroup 0\n"), 0600); e != nil {
		return e
	}
	matches, e := filepath.Glob(filepath.Join(source, "plugins/*/config.yml.dist"))
	if e != nil {
		return e
	}
	for _, p := range matches {
		if e = copyFile(p, filepath.Join(stage, "plugins", filepath.Base(filepath.Dir(p)), "config.yml")); e != nil {
			return e
		}
	}
	return sitebotFiles(source, stage, v)
}
func sitebotFiles(source, stage string, v values) error {
	// Announce only: no dummy FTP bot login or privileged IRC command plugins.
	host := v["irc_host"]
	if host == "" {
		host = "localhost"
	}
	channel := v["irc_channel"]
	if channel == "" {
		channel = "#weaveftpd"
	}
	chat := channel + "-chat"
	staff := channel + "-staff"
	irc := map[string]any{"host": host, "port": port(v, "irc_port"), "nick": v["irc_nick"], "user": "sitebot", "realname": "WeaveFTPd sitebot", "password": v["irc_password"], "ssl": true, "tls_verify": "strict", "channels": []string{channel, chat, staff}, "auto_oper": false}
	keys := map[string]string{}
	if v["fish_key"] != "" {
		for _, c := range []string{channel, chat, staff} {
			keys[c] = v["fish_key"]
		}
	}
	m := map[string]any{"debug": false, "log_file": "logs/sitebot.log", "log_console": true, "log_keep_days": 2, "event_fifo": "/app/etc/weaveftpd.sitebot.fifo", "irc": irc, "encryption": map[string]any{"enabled": v["fish_key"] != "", "auto_exchange": true, "keys": keys}, "announce": map[string]any{"config_file": "plugins/announce/config.yml"}, "invite_channels": []any{map[string]any{"channel": staff, "flags": "1"}}, "sections": []any{map[string]any{"name": "DEFAULT", "channels": []string{staff}, "paths": []string{}}}, "plugins": map[string]any{"enabled": map[string]bool{"Announce": true}}}
	if e := writeYAML(filepath.Join(stage, "sitebot/etc/config.yml"), m); e != nil {
		return e
	}
	a, e := loadYAML(filepath.Join(source, "sitebot/plugins/announce/config.yml.dist"))
	if e != nil {
		return e
	}
	a["default_channel"] = staff
	routes := block(a, "type_routes")
	for k := range routes {
		routes[k] = []string{staff}
	}
	routes["SPEEDTEST"] = []string{chat}
	routes["NEWDAY"] = []string{channel}
	routes["TOP"] = []string{chat}
	if e = writeYAML(filepath.Join(stage, "sitebot/plugins/announce/config.yml"), a); e != nil {
		return e
	}
	return copyTree(filepath.Join(source, "sitebot/etc/templates"), filepath.Join(stage, "sitebot/etc/templates"))
}
func remoteFiles(source, stage string, v values) error {
	s, e := slaveConfig(source, v, v["slave_name"], v["master_host"])
	if e != nil {
		return e
	}
	// Validate CA, client identity, key pair, expiry, and trust before installing.
	ca, e := os.ReadFile(filepath.Join(v["bundle"], "ca.crt"))
	if e != nil {
		return e
	}
	cert, e := os.ReadFile(filepath.Join(v["bundle"], "client.crt"))
	if e != nil {
		return e
	}
	key, e := os.ReadFile(filepath.Join(v["bundle"], "client.key"))
	if e != nil {
		return e
	}
	cb, _ := pem.Decode(cert)
	kb, _ := pem.Decode(key)
	if cb == nil || kb == nil {
		return errors.New("invalid client certificate or key")
	}
	c, e := x509.ParseCertificate(cb.Bytes)
	if e != nil {
		return e
	}
	if c.Subject.CommonName != v["slave_name"] {
		return errors.New("client certificate CN does not match slave name")
	}
	k, e := x509.ParsePKCS1PrivateKey(kb.Bytes)
	if e != nil {
		return e
	}
	pub, ok := c.PublicKey.(*rsa.PublicKey)
	if !ok || pub.N.Cmp(k.N) != 0 {
		return errors.New("client key does not match certificate")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return errors.New("invalid CA")
	}
	if _, e = c.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); e != nil {
		return e
	}
	serverCert, e := os.ReadFile(filepath.Join(v["bundle"], "server.crt"))
	if e != nil {
		return e
	}
	serverKey, e := os.ReadFile(filepath.Join(v["bundle"], "server.key"))
	if e != nil {
		return e
	}
	pair, e := tls.X509KeyPair(serverCert, serverKey)
	if e != nil {
		return e
	}
	server, e := x509.ParseCertificate(pair.Certificate[0])
	if e != nil {
		return e
	}
	if _, e = server.Verify(x509.VerifyOptions{Roots: pool, DNSName: v["public_ip"], KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); e != nil {
		return e
	}
	for name, b := range map[string][]byte{"ca.crt": ca, "client.crt": cert, "client.key": key, "server.crt": serverCert, "server.key": serverKey} {
		if e = writeNew(filepath.Join(stage, "etc/certs", name), b, 0600); e != nil {
			return e
		}
	}
	return writeYAML(filepath.Join(stage, "etc/config.yml"), s)
}
func newCert(cn string, ca bool) *x509.Certificate {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	return &x509.Certificate{SerialNumber: n, Subject: pkix.Name{CommonName: cn}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(5, 0, 0), BasicConstraintsValid: true, IsCA: ca, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment}
}
func signCert(dir, stem string, c, parent *x509.Certificate, parentKey *rsa.PrivateKey) (*rsa.PrivateKey, error) {
	k, e := rsa.GenerateKey(rand.Reader, 3072)
	if e != nil {
		return nil, e
	}
	if parent == nil {
		parent = c
		parentKey = k
	}
	b, e := x509.CreateCertificate(rand.Reader, c, parent, &k.PublicKey, parentKey)
	if e != nil {
		return nil, e
	}
	if e = writeNew(filepath.Join(dir, stem+".crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b}), 0600); e != nil {
		return nil, e
	}
	e = writeNew(filepath.Join(dir, stem+".key"), pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}), 0600)
	return k, e
}
func createCA(dir, ip string) error {
	ca := newCert("WeaveFTPd private CA", true)
	ca.KeyUsage |= x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	key, e := signCert(dir, "ca", ca, nil, nil)
	if e != nil {
		return e
	}
	server := newCert("WeaveFTPd", false)
	server.DNSNames = []string{"localhost"}
	server.IPAddresses = []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1"), net.ParseIP(ip)}
	server.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	if _, e = signCert(dir, "server", server, ca, key); e != nil {
		return e
	}
	client := newCert("LOCAL", false)
	client.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	_, e = signCert(dir, "client", client, ca, key)
	return e
}
func issueSlave(output, name, ip string) error {
	if net.ParseIP(ip).To4() == nil {
		return errors.New("slave-ip must be the slave public IPv4 address")
	}
	if !safeName.MatchString(name) || strings.EqualFold(name, "LOCAL") {
		return errors.New("invalid remote slave name")
	}
	dir := filepath.Join(output, "runtime/master/etc/certs")
	cb, e := os.ReadFile(filepath.Join(dir, "ca.crt"))
	if e != nil {
		return e
	}
	kb, e := os.ReadFile(filepath.Join(output, "runtime/master/ca/ca.key"))
	if e != nil {
		return e
	}
	cp, _ := pem.Decode(cb)
	kp, _ := pem.Decode(kb)
	if cp == nil || kp == nil {
		return errors.New("invalid CA files")
	}
	ca, e := x509.ParseCertificate(cp.Bytes)
	if e != nil {
		return e
	}
	key, e := x509.ParsePKCS1PrivateKey(kp.Bytes)
	if e != nil {
		return e
	}
	target := filepath.Join(output, "runtime/master/slave-certs", name)
	if e = os.MkdirAll(filepath.Dir(target), 0700); e != nil {
		return e
	}
	if e = os.Mkdir(target, 0700); e != nil {
		return e
	}
	c := newCert(name, false)
	c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	if _, e = signCert(target, "client", c, ca, key); e != nil {
		return e
	}
	server := newCert(name+" data", false)
	server.IPAddresses = []net.IP{net.ParseIP(ip)}
	server.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	if _, e = signCert(target, "server", server, ca, key); e != nil {
		return e
	}
	if e = writeNew(filepath.Join(target, "ca.crt"), cb, 0600); e != nil {
		return e
	}
	fmt.Printf("Created slave-certs/%s. Copy only this bundle securely to the slave, never ca.key.\n", name)
	return nil
}
