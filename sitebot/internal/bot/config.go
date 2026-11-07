package bot

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

type Config struct {
	// Private: source path + mutex for rehash.
	configPath string       `yaml:"-"`
	rehashMu   sync.RWMutex `yaml:"-"`

	Debug              bool           `yaml:"debug"`
	LogFile            string         `yaml:"log_file"`
	LogKeepDays        int            `yaml:"log_keep_days"`
	LogDeleteAfterDays int            `yaml:"log_delete_after_days"`
	LogConsole         bool           `yaml:"log_console"`
	Version            string         `yaml:"version"`
	EventFIFO          string         `yaml:"event_fifo"`
	IRC                IRCConfig      `yaml:"irc"`
	Encryption         EncConfig      `yaml:"encryption"`
	Announce           AnnounceConfig `yaml:"announce"`
	Help               HelpConfig     `yaml:"help"`
	Sections           []SectionRoute `yaml:"sections"`
	Plugins            PluginsConfig  `yaml:"plugins"`
}

type HelpConfig struct {
	Channels    []string `yaml:"channels"`
	ReplyTarget string   `yaml:"reply_target"`
	Lines       []string `yaml:"lines"`
}

type IRCConfig struct {
	Host string `yaml:"host"`
	Port int    `yaml:"port"`
	SSL  bool   `yaml:"ssl"`
	// TLSVerify: "strict" (default) verifies against the system trust store,
	// "custom" verifies against TLSCACert, "insecure" disables verification.
	TLSVerify     string         `yaml:"tls_verify"`
	TLSCACert     string         `yaml:"tls_ca_cert"`
	Nick          string         `yaml:"nick"`
	User          string         `yaml:"user"`
	RealName      string         `yaml:"realname"`
	Password      string         `yaml:"password"`
	Channels      []string       `yaml:"channels"`
	NickServ      NickServConfig `yaml:"nickserv"`
	OperUser      string         `yaml:"operuser"`
	OperPassword  string         `yaml:"operpassword"`
	AutoOper      bool           `yaml:"auto_oper"`
	UserModes     string         `yaml:"user_modes"`
	ChannelModes  string         `yaml:"channel_modes"`
	AutoJoinDelay int            `yaml:"autojoin_delay_ms"`
}

type NickServConfig struct {
	Enabled      bool   `yaml:"enabled"`
	Service      string `yaml:"service"`
	Account      string `yaml:"account"`
	Password     string `yaml:"password"`
	Email        string `yaml:"email"`
	AutoRegister bool   `yaml:"auto_register"`
	DelayMS      int    `yaml:"delay_ms"`
}

type EncConfig struct {
	Enabled      bool              `yaml:"enabled"`
	AutoExchange bool              `yaml:"auto_exchange"`
	PrivateKey   string            `yaml:"private_key"`
	Keys         map[string]string `yaml:"keys"`
}

type AnnounceConfig struct {
	ConfigFile     string                 `yaml:"config_file"`
	DefaultChannel string                 `yaml:"default_channel"`
	TypeRoutes     map[string][]string    `yaml:"type_routes"`
	ThemeFile      string                 `yaml:"theme_file"`
	Pretime        map[string]interface{} `yaml:"pretime"`
}

type SectionRoute struct {
	Name     string   `yaml:"name"`
	Channels []string `yaml:"channels"`
	Paths    []string `yaml:"paths"`
}

type PluginsConfig struct {
	Enabled map[string]bool        `yaml:"enabled"`
	Config  map[string]interface{} `yaml:"config"`
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg := &Config{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}
	modes, err := normalizeChannelModes(cfg.IRC.ChannelModes)
	if err != nil {
		return nil, err
	}
	cfg.IRC.ChannelModes = modes
	cfg.Version = loadVersion(path, cfg.Version)
	if strings.TrimSpace(cfg.Version) == "" {
		if idx := strings.LastIndex(strings.TrimSpace(cfg.IRC.RealName), " v"); idx >= 0 {
			cfg.Version = strings.TrimSpace(cfg.IRC.RealName[idx+2:])
		}
	}
	if strings.TrimSpace(cfg.IRC.RealName) == "" {
		cfg.IRC.RealName = "GoSitebot"
	}
	if strings.TrimSpace(cfg.Version) != "" && strings.TrimSpace(cfg.IRC.RealName) == "GoSitebot" {
		cfg.IRC.RealName = "GoSitebot v" + cfg.Version
	}
	if err := resolveAnnounceConfigFile(&cfg.Announce, filepath.Dir(path)); err != nil {
		return nil, err
	}
	if err := resolvePluginConfigFiles(cfg.Plugins.Config, filepath.Dir(path)); err != nil {
		return nil, err
	}
	if cfg.Announce.TypeRoutes == nil {
		cfg.Announce.TypeRoutes = map[string][]string{}
	}
	if cfg.Encryption.Keys == nil {
		cfg.Encryption.Keys = map[string]string{}
	}
	if !cfg.Encryption.AutoExchange {
		raw := map[string]interface{}{}
		if err := yaml.Unmarshal(data, &raw); err == nil {
			if encRaw, ok := raw["encryption"].(map[string]interface{}); ok {
				if _, exists := encRaw["auto_exchange"]; !exists {
					cfg.Encryption.AutoExchange = true
				}
			}
		}
	}
	if cfg.Plugins.Enabled == nil {
		cfg.Plugins.Enabled = map[string]bool{}
	}
	if cfg.Plugins.Config == nil {
		cfg.Plugins.Config = map[string]interface{}{}
	}
	if len(cfg.Help.Channels) == 0 {
		cfg.Help.Channels = []string{"#weaveftpd"}
	}
	if strings.TrimSpace(cfg.IRC.NickServ.Service) == "" {
		cfg.IRC.NickServ.Service = "NickServ"
	}
	if strings.TrimSpace(cfg.Help.ReplyTarget) == "" {
		cfg.Help.ReplyTarget = "pm"
	}
	if !cfg.LogConsole {
		// default false value from yaml means either unset or explicit false.
		// Keep console logging enabled by default unless user set log_console.
		raw := map[string]interface{}{}
		if err := yaml.Unmarshal(data, &raw); err == nil {
			if _, ok := raw["log_console"]; !ok {
				cfg.LogConsole = true
			}
		} else {
			cfg.LogConsole = true
		}
	}
	if cfg.LogDeleteAfterDays <= 0 && cfg.LogKeepDays > 0 {
		cfg.LogDeleteAfterDays = cfg.LogKeepDays
	}
	if cfg.Announce.ThemeFile == "" {
		cfg.Announce.ThemeFile = "./etc/templates/pzsng.theme"
	}
	cfg.configPath = path
	return cfg, nil
}

func resolveAnnounceConfigFile(cfg *AnnounceConfig, baseDir string) error {
	configFile := strings.TrimSpace(cfg.ConfigFile)
	if configFile == "" {
		return nil
	}
	loaded := AnnounceConfig{}
	data, err := loadConfigFileMap(configFile, baseDir)
	if err != nil {
		return fmt.Errorf("announce: %w", err)
	}
	raw, err := yaml.Marshal(data)
	if err != nil {
		return err
	}
	if err := yaml.Unmarshal(raw, &loaded); err != nil {
		return err
	}
	if cfg.DefaultChannel != "" {
		loaded.DefaultChannel = cfg.DefaultChannel
	}
	if cfg.ThemeFile != "" {
		loaded.ThemeFile = cfg.ThemeFile
	}
	if len(cfg.Pretime) > 0 {
		loaded.Pretime = cfg.Pretime
	}
	if len(cfg.TypeRoutes) > 0 {
		loaded.TypeRoutes = cfg.TypeRoutes
	}
	loaded.ConfigFile = cfg.ConfigFile
	*cfg = loaded
	return nil
}

func loadVersion(configPath, fallback string) string {
	for _, candidate := range versionCandidatePaths(configPath) {
		data, err := os.ReadFile(candidate)
		if err != nil {
			continue
		}
		if version := firstNonEmptyLine(string(data)); version != "" {
			return version
		}
	}
	return strings.TrimSpace(fallback)
}

func versionCandidatePaths(configPath string) []string {
	dir := filepath.Dir(configPath)
	seen := map[string]struct{}{}
	var out []string
	add := func(p string) {
		p = filepath.Clean(p)
		if _, ok := seen[p]; ok {
			return
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}

	add(filepath.Join(dir, "version"))
	for current := filepath.Dir(dir); current != "" && current != "."; {
		add(filepath.Join(current, "etc", "version"))
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		current = parent
	}
	return out
}

func firstNonEmptyLine(s string) string {
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			return line
		}
	}
	return ""
}

func resolvePluginConfigFiles(config map[string]interface{}, baseDir string) error {
	for name, raw := range config {
		section := sectionAsStringMap(raw)
		if len(section) == 0 {
			continue
		}
		configFile, _ := section["config_file"].(string)
		configFile = strings.TrimSpace(configFile)
		if configFile == "" {
			continue
		}
		loaded, err := loadConfigFileMap(configFile, baseDir)
		if err != nil {
			return fmt.Errorf("plugin %s: %w", name, err)
		}
		merged := map[string]interface{}{}
		for k, v := range loaded {
			merged[k] = v
		}
		for k, v := range section {
			merged[k] = v
		}
		config[name] = merged
		if _, ok := raw.(map[string]interface{}); !ok {
			config[name] = merged
		}
	}
	return nil
}

func loadConfigFileMap(path, baseDir string) (map[string]interface{}, error) {
	resolved := path
	checked := []string{}
	if !filepath.IsAbs(path) {
		candidates := []string{
			filepath.Clean(path),
			filepath.Clean(filepath.Join(baseDir, path)),
			filepath.Clean(filepath.Join(filepath.Dir(baseDir), path)),
		}
		for _, candidate := range candidates {
			checked = append(checked, candidate)
			if _, err := os.Stat(candidate); err == nil {
				resolved = candidate
				break
			}
		}
	} else {
		checked = append(checked, filepath.Clean(path))
	}
	data, err := os.ReadFile(filepath.Clean(resolved))
	if err != nil {
		return nil, fmt.Errorf("config_file %q not found; check config", path)
	}
	out := map[string]interface{}{}
	if err := yaml.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func sectionAsStringMap(raw interface{}) map[string]interface{} {
	if section, ok := raw.(map[string]interface{}); ok {
		return section
	}
	if section, ok := raw.(map[interface{}]interface{}); ok {
		out := map[string]interface{}{}
		for k, v := range section {
			if key, ok := k.(string); ok {
				out[key] = v
			}
		}
		return out
	}
	return map[string]interface{}{}
}

// Rehash reloads the config from disk and swaps in fields that are safe
// to change while running. Host/port/SSL/nick/password in `IRC` are NOT
// reloaded — the IRC socket is already established; changing those would
// require a full reconnect. Channels, encryption keys, themes, sections,
// announce routing, and plugin settings all ARE reloaded.
func (c *Config) Rehash() (string, error) {
	if c.configPath == "" {
		return "", fmt.Errorf("no config path recorded; was this loaded via LoadConfig?")
	}
	fresh, err := LoadConfig(c.configPath)
	if err != nil {
		return c.configPath, err
	}

	c.rehashMu.Lock()
	defer c.rehashMu.Unlock()

	c.Debug = fresh.Debug
	c.LogFile = fresh.LogFile
	c.LogKeepDays = fresh.LogKeepDays
	c.LogDeleteAfterDays = fresh.LogDeleteAfterDays
	c.LogConsole = fresh.LogConsole
	// EventFIFO path change requires restart (reader goroutine has it open)
	// IRC connection details: keep old. Only refresh auto-join list + modes.
	c.IRC.Channels = fresh.IRC.Channels
	c.IRC.UserModes = fresh.IRC.UserModes
	c.IRC.ChannelModes = fresh.IRC.ChannelModes
	c.IRC.AutoJoinDelay = fresh.IRC.AutoJoinDelay
	c.IRC.AutoOper = fresh.IRC.AutoOper
	c.IRC.OperUser = fresh.IRC.OperUser
	c.IRC.OperPassword = fresh.IRC.OperPassword

	c.Encryption = fresh.Encryption
	c.Announce = fresh.Announce
	c.Help = fresh.Help
	c.Sections = fresh.Sections
	c.Plugins = fresh.Plugins
	return c.configPath, nil
}
