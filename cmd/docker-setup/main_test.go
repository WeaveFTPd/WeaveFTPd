package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func fixture(t *testing.T) (string, string, values) {
	t.Helper()
	source, e := filepath.Abs("../..")
	if e != nil {
		t.Fatal(e)
	}
	out := t.TempDir()
	site := filepath.Join(out, "storage with $dollar and 'quote")
	return source, out, values{"role": "master", "public_ip": "127.0.0.1", "ftp_port": "22121", "control_port": "21099", "pasv_min": "42130", "pasv_max": "42139", "site_path": site, "admin": "TestAdmin", "password": "A-different-test-password!", "admin_ip": "192.0.2.1", "timezone": "UTC", "uid": "0", "gid": "0", "image": "test:daemon", "sitebot_image": "test:sitebot", "irc_host": "irc.example.net", "irc_port": "6697", "irc_nick": "TestBot", "irc_channel": "#test", "irc_password": "server secret", "fish_key": "fish secret"}
}
func input(v values) *bytes.Buffer {
	b := new(bytes.Buffer)
	for k, s := range v {
		b.WriteString(k + "=" + s + "\x00")
	}
	return b
}
func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, e := os.ReadFile(p)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func TestFreshAndPreserve(t *testing.T) {
	source, out, v := fixture(t)
	if e := setup(input(v), source, out); e != nil {
		t.Fatal(e)
	}
	root := filepath.Join(out, "runtime/master")
	if _, err := os.Stat(filepath.Join(root, "etc/certs/ca.key")); !os.IsNotExist(err) {
		t.Fatal("CA signing key would be mounted into running services")
	}
	if len(mustRead(t, filepath.Join(root, "ca/ca.key"))) == 0 {
		t.Fatal("missing host CA signing key")
	}
	passwd := mustRead(t, filepath.Join(root, "etc/passwd"))
	parts := strings.Split(string(passwd), ":")
	if parts[0] != "TestAdmin" || bcrypt.CompareHashAndPassword([]byte(parts[1]), []byte(v["password"])) != nil {
		t.Fatal("administrator hash/login mismatch")
	}
	if _, e := os.Stat(filepath.Join(root, "etc/users/weaveftpd")); !os.IsNotExist(e) {
		t.Fatal("unexpected example account")
	}
	m, e := loadYAML(filepath.Join(root, "etc/config.yml"))
	if e != nil {
		t.Fatal(e)
	}
	if m["listen_port"] != 22121 || m["passwd_file"] != "/app/etc/passwd" || block(m, "master")["slave_ca_cert"] != "/app/etc/certs/ca.crt" {
		t.Fatal("wrong master settings")
	}
	if !strings.Contains(string(mustRead(t, filepath.Join(root, "etc/users/TestAdmin"))), "FLAGS 13AB\n") {
		t.Fatal("administrator cannot download/nuke")
	}
	a, e := loadYAML(filepath.Join(root, "sitebot/plugins/announce/config.yml"))
	if e != nil {
		t.Fatal(e)
	}
	if block(a, "type_routes")["SPEEDTEST"].([]any)[0] != "#test-chat" {
		t.Fatal("speedtest routing")
	}
	ca := x509.NewCertPool()
	ca.AppendCertsFromPEM(mustRead(t, filepath.Join(root, "etc/certs/ca.crt")))
	cert, e := tls.LoadX509KeyPair(filepath.Join(root, "etc/certs/server.crt"), filepath.Join(root, "etc/certs/server.key"))
	if e != nil {
		t.Fatal(e)
	}
	parsed, e := x509.ParseCertificate(cert.Certificate[0])
	if e != nil {
		t.Fatal(e)
	}
	if _, e = parsed.Verify(x509.VerifyOptions{Roots: ca, DNSName: "127.0.0.1"}); e != nil {
		t.Fatal(e)
	}
	// An edited config, users, secrets and certificates must all survive a rerun.
	config := filepath.Join(root, "etc/config.yml")
	if e = os.WriteFile(config, []byte("sentinel custom configuration"), 0600); e != nil {
		t.Fatal(e)
	}
	before := map[string][]byte{}
	filepath.WalkDir(out, func(p string, d os.DirEntry, e error) error {
		if e != nil {
			t.Fatal(e)
		}
		if !d.IsDir() {
			before[p] = mustRead(t, p)
		}
		return nil
	})
	v["password"] = "Should-never-replace-this"
	if e = setup(input(v), source, out); e == nil {
		t.Fatal("existing runtime accepted")
	}
	for p, b := range before {
		if !bytes.Equal(b, mustRead(t, p)) {
			t.Fatalf("changed existing file %s", p)
		}
	}
}
func TestInvalidInputHasNoRuntime(t *testing.T) {
	for name, edit := range map[string]func(values){"short password": func(v values) { v["password"] = "short" },
		"spaced password": func(v values) { v["password"] = "Not a usable password" }, "path username": func(v values) { v["admin"] = "../oops" }, "open admin": func(v values) { v["admin_ip"] = "*" }, "overlap": func(v values) { v["ftp_port"] = v["pasv_min"] }, "reversed range": func(v values) { v["pasv_min"] = "65535" }, "newline": func(v values) { v["fish_key"] = "line\nsecret" }} {
		t.Run(name, func(t *testing.T) {
			source, out, v := fixture(t)
			edit(v)
			if e := setup(input(v), source, out); e == nil {
				t.Fatal("invalid input accepted")
			}
			if _, e := os.Stat(filepath.Join(out, "runtime")); !os.IsNotExist(e) {
				t.Fatal("invalid input created runtime")
			}
		})
	}
}
func TestRemoteCertificate(t *testing.T) {
	source, out, v := fixture(t)
	if e := setup(input(v), source, out); e != nil {
		t.Fatal(e)
	}
	if e := issueSlave(out, "REMOTE1", "192.0.2.20"); e != nil {
		t.Fatal(e)
	}
	bundle := filepath.Join(out, "runtime/master/slave-certs/REMOTE1")
	if _, e := os.Stat(filepath.Join(bundle, "ca.key")); !os.IsNotExist(e) {
		t.Fatal("CA private key leaked into bundle")
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(mustRead(t, filepath.Join(bundle, "ca.crt")))
	clientPair, err := tls.LoadX509KeyPair(filepath.Join(bundle, "client.crt"), filepath.Join(bundle, "client.key"))
	if err != nil {
		t.Fatal(err)
	}
	client, err := x509.ParseCertificate(clientPair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, err = client.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err == nil {
		t.Fatal("slave client identity can impersonate a server")
	}
	v["role"] = "slave"
	v["slave_name"] = "REMOTE1"
	v["master_host"] = "127.0.0.1"
	v["public_ip"] = "192.0.2.20"
	v["bundle"] = bundle
	remote := t.TempDir()
	if e := setup(input(v), source, remote); e != nil {
		t.Fatal(e)
	}
	v["slave_name"] = "WRONG"
	if e := setup(input(v), source, t.TempDir()); e == nil {
		t.Fatal("mismatched certificate accepted")
	}
	if e := issueSlave(out, "REMOTE1", "192.0.2.20"); e == nil {
		t.Fatal("existing bundle replaced")
	}
}
func TestInputProtocol(t *testing.T) {
	for _, s := range []string{"password=one\x00password=two\x00", "unknown=value\x00", strings.Repeat("x", 65537)} {
		if _, e := readValues(strings.NewReader(s)); e == nil {
			t.Fatal("invalid protocol accepted")
		}
	}
}
