package core

import (
	"fmt"
	"log"
	"path"
	"strings"
	"sync"

	"weaveftpd/internal/plugin"
	"weaveftpd/internal/user"
)

// PluginManager owns the registered plugins and dispatches events to them.
// It's created at startup, plugins are registered, then initialized with
// per-plugin config sub-maps. After Init, the session/command handlers call
// Dispatch() with a populated Event to notify all plugins.
type PluginManager struct {
	mu      sync.RWMutex
	plugins []plugin.Plugin
	svc     *plugin.Services
	debug   bool
	cfg     *Config
}

// NewPluginManager creates a manager. Call SetServices before registering
// plugins (Init passes the services handle to each plugin).
func NewPluginManager(debug bool) *PluginManager {
	return &PluginManager{
		plugins: make([]plugin.Plugin, 0),
		debug:   debug,
	}
}

func (pm *PluginManager) SetConfig(cfg *Config) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.cfg = cfg
}

// SetServices attaches the Services handle the manager will pass to each
// plugin's Init call. The bridge inside Services must implement
// plugin.MasterBridge — our master.Bridge does, via its WriteFile/ReadFile
// methods.
func (pm *PluginManager) SetServices(svc *plugin.Services) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.svc = svc
}

// RegisterPlugin adds a plugin to the manager (pre-Init). Duplicate names
// are rejected.
func (pm *PluginManager) RegisterPlugin(p plugin.Plugin) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	for _, existing := range pm.plugins {
		if existing.Name() == p.Name() {
			log.Printf("[PLUGIN-MANAGER] Duplicate plugin name %q ignored", p.Name())
			return nil
		}
	}
	pm.plugins = append(pm.plugins, p)
	if pm.debug {
		log.Printf("[PLUGIN-MANAGER] Registered plugin: %s", p.Name())
	}
	return nil
}

// InitializePlugins calls Init on each registered plugin with its config
// sub-map. The outer map is keyed by plugin name (e.g. {"tvmaze": {...}}).
// Plugins without a config entry receive an empty map.
func (pm *PluginManager) InitializePlugins(pluginConfigs map[string]map[string]interface{}) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if pm.svc == nil {
		log.Printf("[PLUGIN-MANAGER] Warning: no Services set, plugins will have nil Bridge")
		pm.svc = &plugin.Services{Debug: pm.debug}
	}

	for _, p := range pm.plugins {
		name := p.Name()
		cfg := pluginConfigs[name]
		if cfg == nil {
			cfg = make(map[string]interface{})
		}
		if err := p.Init(pm.svc, cfg); err != nil {
			log.Printf("[PLUGIN-MANAGER] Init %s failed: %v", name, err)
			return err
		}
		if pm.debug {
			log.Printf("[PLUGIN-MANAGER] Initialized %s", name)
		}
	}
	return nil
}

// Dispatch fires evt to every registered plugin. It populates the Section
// field automatically if empty. Errors from individual plugins are logged
// but don't short-circuit dispatch. This is called from the session/command
// handlers and must be fast — plugins are responsible for offloading work
// to goroutines.
func (pm *PluginManager) Dispatch(evt *plugin.Event) {
	if pm == nil || evt == nil {
		return
	}
	if evt.Section == "" && evt.Path != "" {
		evt.Section = sectionFromPathWithConfig(pm.cfg, evt.Path)
	}

	pm.mu.RLock()
	plugins := make([]plugin.Plugin, len(pm.plugins))
	copy(plugins, pm.plugins)
	pm.mu.RUnlock()

	for _, p := range plugins {
		if err := p.OnEvent(evt); err != nil && pm.debug {
			log.Printf("[PLUGIN-MANAGER] %s.OnEvent(%s) error: %v", p.Name(), evt.Type, err)
		}
	}
}

func (pm *PluginManager) DispatchSiteCommand(ctx plugin.SiteContext, command string, args []string) bool {
	if pm == nil || ctx == nil {
		return false
	}
	command = strings.ToUpper(strings.TrimSpace(command))
	if command == "" {
		return false
	}

	pm.mu.RLock()
	plugins := make([]plugin.Plugin, len(pm.plugins))
	copy(plugins, pm.plugins)
	pm.mu.RUnlock()

	for _, p := range plugins {
		h, ok := p.(plugin.SiteCommandHandler)
		if !ok {
			continue
		}
		for _, handled := range h.SiteCommands() {
			if strings.EqualFold(command, handled) {
				return h.HandleSiteCommand(ctx, command, args)
			}
		}
	}
	return false
}

func (pm *PluginManager) ValidateMKDir(u *user.User, targetPath string) error {
	if pm == nil || u == nil {
		return nil
	}

	pm.mu.RLock()
	plugins := make([]plugin.Plugin, len(pm.plugins))
	copy(plugins, pm.plugins)
	pm.mu.RUnlock()

	for _, p := range plugins {
		v, ok := p.(plugin.MKDirValidator)
		if !ok {
			continue
		}
		if err := v.ValidateMKDir(u, targetPath); err != nil {
			return fmt.Errorf("%s: %w", p.Name(), err)
		}
	}
	return nil
}

func (pm *PluginManager) ValidateLogin(u *user.User, remoteIP string) error {
	if pm == nil || u == nil {
		return nil
	}

	pm.mu.RLock()
	plugins := make([]plugin.Plugin, len(pm.plugins))
	copy(plugins, pm.plugins)
	pm.mu.RUnlock()

	for _, p := range plugins {
		v, ok := p.(plugin.LoginValidator)
		if !ok {
			continue
		}
		if err := v.ValidateLogin(u, remoteIP); err != nil {
			return fmt.Errorf("%s: %w", p.Name(), err)
		}
	}
	return nil
}

func (pm *PluginManager) ValidateUpload(u *user.User, targetPath string) error {
	if pm == nil || u == nil {
		return nil
	}
	pm.mu.RLock()
	plugins := append([]plugin.Plugin(nil), pm.plugins...)
	pm.mu.RUnlock()
	for _, p := range plugins {
		if v, ok := p.(plugin.UploadValidator); ok {
			if err := v.ValidateUpload(u, targetPath); err != nil {
				return fmt.Errorf("%s: %w", p.Name(), err)
			}
		}
	}
	return nil
}

func (pm *PluginManager) ReloadConfigs(pluginConfigs map[string]map[string]interface{}) error {
	if pm == nil {
		return nil
	}

	pm.mu.RLock()
	plugins := make([]plugin.Plugin, len(pm.plugins))
	copy(plugins, pm.plugins)
	pm.mu.RUnlock()

	for _, p := range plugins {
		reloader, ok := p.(plugin.ConfigReloader)
		if !ok {
			continue
		}
		cfg := map[string]interface{}{}
		if pluginConfigs != nil {
			if loaded := pluginConfigs[p.Name()]; loaded != nil {
				cfg = loaded
			}
		}
		if err := reloader.ReloadConfig(cfg); err != nil {
			return fmt.Errorf("%s: %w", p.Name(), err)
		}
	}
	return nil
}

// StopAll calls Stop() on every registered plugin. Called at shutdown.
func (pm *PluginManager) StopAll() error {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	for _, p := range pm.plugins {
		if err := p.Stop(); err != nil {
			log.Printf("[PLUGIN-MANAGER] %s.Stop error: %v", p.Name(), err)
		}
	}
	return nil
}

// GetPlugins returns a snapshot of the plugin list.
func (pm *PluginManager) GetPlugins() []plugin.Plugin {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	out := make([]plugin.Plugin, len(pm.plugins))
	copy(out, pm.plugins)
	return out
}

// sectionFromPluginPath extracts the first path component from p.
// "/TV-1080P/Some.Release" → "TV-1080P", "/" → "", "" → "".
func sectionFromPluginPath(p string) string {
	if p == "" || p == "/" {
		return ""
	}
	clean := path.Clean(p)
	parts := strings.Split(strings.TrimPrefix(clean, "/"), "/")
	if len(parts) == 0 {
		return ""
	}
	return parts[0]
}
