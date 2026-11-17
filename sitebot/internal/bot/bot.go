package bot

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"weaveftpd/sitebot/internal/event"
	"weaveftpd/sitebot/internal/irc"
	"weaveftpd/sitebot/internal/plugin"
	tmpl "weaveftpd/sitebot/internal/template"
	admincommanderplugin "weaveftpd/sitebot/plugins/admincommander"
	affilsplugin "weaveftpd/sitebot/plugins/affils"
	announceplugin "weaveftpd/sitebot/plugins/announce"
	bannedplugin "weaveftpd/sitebot/plugins/banned"
	bncplugin "weaveftpd/sitebot/plugins/bnc"
	bwplugin "weaveftpd/sitebot/plugins/bw"
	freeplugin "weaveftpd/sitebot/plugins/free"
	imdbplugin "weaveftpd/sitebot/plugins/imdb"
	newsplugin "weaveftpd/sitebot/plugins/news"
	quotaplugin "weaveftpd/sitebot/plugins/quota"
	requestplugin "weaveftpd/sitebot/plugins/request"
	rulesplugin "weaveftpd/sitebot/plugins/rules"
	selfipplugin "weaveftpd/sitebot/plugins/selfip"
	topplugin "weaveftpd/sitebot/plugins/top"
	topicplugin "weaveftpd/sitebot/plugins/topic"
	tvmazeplugin "weaveftpd/sitebot/plugins/tvmaze"
)

type Bot struct {
	Config      *Config
	IRC         *irc.Bot
	Plugins     *plugin.Manager
	EventChan   chan *event.Event
	Done        chan bool
	Mutex       sync.RWMutex
	Debug       bool
	ircOper     bool
	operPending bool
}

type controlConfig struct {
	StaffChannels []string
	StaffHosts    []string
	ReplyTarget   string
	RestartDelay  time.Duration
}

func NewBot(cfg *Config) *Bot {
	return &Bot{Config: cfg, Plugins: plugin.NewManager(), EventChan: make(chan *event.Event, 1024), Done: make(chan bool), Debug: cfg.Debug}
}

func (b *Bot) Start() error {
	log.Println("[Bot] Starting GoSitebot")
	log.Printf("[STARTUP] GoSitebot [irc=%s:%d] [nick=%s] [channels=%d]",
		b.Config.IRC.Host, b.Config.IRC.Port, b.Config.IRC.Nick, len(uniqueChannels(b.Config)))
	b.IRC = irc.NewBot(b.Config.IRC.Host, b.Config.IRC.Port, b.Config.IRC.Nick, b.Config.IRC.User, b.Config.IRC.RealName)
	b.IRC.SSL = b.Config.IRC.SSL
	b.IRC.TLSVerify = b.Config.IRC.TLSVerify
	b.IRC.TLSCACert = b.Config.IRC.TLSCACert
	b.IRC.Password = b.Config.IRC.Password
	b.IRC.Debug = b.Debug
	if err := b.IRC.Connect(); err != nil {
		return fmt.Errorf("failed to connect to IRC: %w", err)
	}
	for ch, key := range b.Config.Encryption.Keys {
		_ = b.IRC.SetChannelKey(ch, key)
	}
	b.IRC.SetAutoExchange(b.Config.Encryption.AutoExchange)
	_ = b.IRC.SetPrivateKey(strings.TrimSpace(b.Config.Encryption.PrivateKey))
	if err := b.initializePlugins(); err != nil {
		return err
	}
	go b.listenIRC()
	go b.readEvents()
	go b.processEvents()
	return nil
}

func (b *Bot) registerPlugin(name string, h plugin.Handler) error {
	if err := b.Plugins.Register(h); err != nil {
		return err
	}
	log.Printf("[Bot] Plugin loaded: %s", name)
	return nil
}

func (b *Bot) initializePlugins() error {
	if enabled, ok := b.Config.Plugins.Enabled["Announce"]; !ok || enabled {
		announce := announceplugin.New()
		cfg := map[string]interface{}{
			"debug":           b.Debug,
			"theme_file":      b.Config.Announce.ThemeFile,
			"default_channel": b.Config.Announce.DefaultChannel,
			"type_routes":     b.Config.Announce.TypeRoutes,
			"pretime":         b.Config.Announce.Pretime,
		}
		for k, v := range b.Config.Plugins.Config {
			cfg[k] = v
		}
		if err := announce.Initialize(cfg); err != nil {
			return err
		}
		announce.SetAsyncEmitter(func(outType, text, section, relpath string) {
			fakeEvt := &event.Event{Type: event.EventMKDir, Section: section, Path: relpath}
			b.sendOutputs(fakeEvt, []plugin.Output{{Type: outType, Text: text}})
		})
		if err := b.registerPlugin("Announce", announce); err != nil {
			return err
		}
	}
	if enabled, ok := b.Config.Plugins.Enabled["TVMaze"]; !ok || enabled {
		tv := tvmazeplugin.New()
		cfg := map[string]interface{}{"debug": b.Debug, "theme_file": b.Config.Announce.ThemeFile}
		for k, v := range b.Config.Plugins.Config {
			cfg[k] = v
		}
		if err := tv.Initialize(cfg); err != nil {
			return err
		}
		// Provide an async emitter so TV lookups can post to IRC after the
		// HTTP call returns, without blocking the event loop.
		tv.SetAsyncEmitter(func(outType, text, section, relpath string) {
			fakeEvt := &event.Event{Type: event.EventMKDir, Section: section, Path: relpath}
			channels := b.routeChannels(fakeEvt, outType)
			for _, line := range strings.Split(text, "\n") {
				line = strings.TrimRight(line, "\r")
				if line == "" {
					continue
				}
				for _, ch := range channels {
					_ = b.IRC.SendMessage(ch, line)
				}
			}
		})
		if err := b.registerPlugin("TVMaze", tv); err != nil {
			return err
		}
	}
	if enabled, ok := b.Config.Plugins.Enabled["IMDB"]; !ok || enabled {
		im := imdbplugin.New()
		cfg := map[string]interface{}{"debug": b.Debug, "theme_file": b.Config.Announce.ThemeFile}
		for k, v := range b.Config.Plugins.Config {
			cfg[k] = v
		}
		if err := im.Initialize(cfg); err != nil {
			return err
		}
		im.SetAsyncEmitter(func(outType, text, section, relpath string) {
			fakeEvt := &event.Event{Type: event.EventMKDir, Section: section, Path: relpath}
			channels := b.routeChannels(fakeEvt, outType)
			for _, line := range strings.Split(text, "\n") {
				line = strings.TrimRight(line, "\r")
				if line == "" {
					continue
				}
				for _, ch := range channels {
					_ = b.IRC.SendMessage(ch, line)
				}
			}
		})
		if err := b.registerPlugin("IMDB", im); err != nil {
			return err
		}
	}
	if enabled, ok := b.Config.Plugins.Enabled["News"]; !ok || enabled {
		news := newsplugin.New()
		cfg := map[string]interface{}{"debug": b.Debug}
		for k, v := range b.Config.Plugins.Config {
			cfg[k] = v
		}
		if err := news.Initialize(cfg); err != nil {
			return err
		}
		if err := b.registerPlugin("News", news); err != nil {
			return err
		}
	}
	if enabled, ok := b.Config.Plugins.Enabled["Free"]; ok && enabled {
		free := freeplugin.New()
		cfg := map[string]interface{}{"debug": b.Debug, "theme_file": b.Config.Announce.ThemeFile}
		for k, v := range b.Config.Plugins.Config {
			cfg[k] = v
		}
		if err := free.Initialize(cfg); err != nil {
			return err
		}
		if err := b.registerPlugin("Free", free); err != nil {
			return err
		}
	}
	if enabled, ok := b.Config.Plugins.Enabled["Affils"]; ok && enabled {
		affils := affilsplugin.New()
		cfg := map[string]interface{}{"debug": b.Debug, "theme_file": b.Config.Announce.ThemeFile}
		for k, v := range b.Config.Plugins.Config {
			cfg[k] = v
		}
		if err := affils.Initialize(cfg); err != nil {
			return err
		}
		if err := b.registerPlugin("Affils", affils); err != nil {
			return err
		}
	}
	if enabled, ok := b.Config.Plugins.Enabled["Request"]; ok && enabled {
		requests := requestplugin.New()
		cfg := map[string]interface{}{"debug": b.Debug, "theme_file": b.Config.Announce.ThemeFile}
		for k, v := range b.Config.Plugins.Config {
			cfg[k] = v
		}
		if err := requests.Initialize(cfg); err != nil {
			return err
		}
		if err := b.registerPlugin("Request", requests); err != nil {
			return err
		}
	}
	if enabled, ok := b.Config.Plugins.Enabled["Quota"]; ok && enabled {
		quota := quotaplugin.New()
		quota.SetKicker(func(channel, nick, reason string) {
			channel = strings.TrimSpace(channel)
			nick = strings.TrimSpace(nick)
			reason = strings.TrimSpace(reason)
			if channel == "" || nick == "" {
				return
			}
			if reason == "" {
				reason = "Account disabled."
			}
			if err := b.IRC.SendRaw(fmt.Sprintf("KICK %s %s :%s", channel, nick, reason)); err != nil {
				log.Printf("[Bot] KICK %s %s failed: %v", channel, nick, err)
			}
		})
		cfg := map[string]interface{}{
			"debug":        b.Debug,
			"theme_file":   b.Config.Announce.ThemeFile,
			"irc_channels": b.Config.IRC.Channels,
		}
		for k, v := range b.Config.Plugins.Config {
			cfg[k] = v
		}
		if err := quota.Initialize(cfg); err != nil {
			return err
		}
		if err := b.registerPlugin("Quota", quota); err != nil {
			return err
		}
	}
	if enabled, ok := b.Config.Plugins.Enabled["BNC"]; ok && enabled {
		bnc := bncplugin.New()
		cfg := map[string]interface{}{"debug": b.Debug, "theme_file": b.Config.Announce.ThemeFile}
		for k, v := range b.Config.Plugins.Config {
			cfg[k] = v
		}
		if err := bnc.Initialize(cfg); err != nil {
			return err
		}
		if err := b.registerPlugin("BNC", bnc); err != nil {
			return err
		}
	}
	if enabled, ok := b.Config.Plugins.Enabled["Banned"]; ok && enabled {
		banned := bannedplugin.New()
		cfg := map[string]interface{}{"debug": b.Debug, "theme_file": b.Config.Announce.ThemeFile}
		for k, v := range b.Config.Plugins.Config {
			cfg[k] = v
		}
		if err := banned.Initialize(cfg); err != nil {
			return err
		}
		if err := b.registerPlugin("Banned", banned); err != nil {
			return err
		}
	}
	if enabled, ok := b.Config.Plugins.Enabled["BW"]; ok && enabled {
		bw := bwplugin.New()
		cfg := map[string]interface{}{"debug": b.Debug, "theme_file": b.Config.Announce.ThemeFile}
		for k, v := range b.Config.Plugins.Config {
			cfg[k] = v
		}
		if err := bw.Initialize(cfg); err != nil {
			return err
		}
		if err := b.registerPlugin("BW", bw); err != nil {
			return err
		}
	}
	if enabled, ok := b.Config.Plugins.Enabled["Rules"]; ok && enabled {
		rules := rulesplugin.New()
		cfg := map[string]interface{}{"debug": b.Debug, "theme_file": b.Config.Announce.ThemeFile}
		for k, v := range b.Config.Plugins.Config {
			cfg[k] = v
		}
		if err := rules.Initialize(cfg); err != nil {
			return err
		}
		if err := b.registerPlugin("Rules", rules); err != nil {
			return err
		}
	}
	if enabled, ok := b.Config.Plugins.Enabled["SelfIP"]; ok && enabled {
		selfip := selfipplugin.New()
		cfg := map[string]interface{}{"debug": b.Debug, "theme_file": b.Config.Announce.ThemeFile}
		for k, v := range b.Config.Plugins.Config {
			cfg[k] = v
		}
		if err := selfip.Initialize(cfg); err != nil {
			return err
		}
		if err := b.registerPlugin("SelfIP", selfip); err != nil {
			return err
		}
	}
	if enabled, ok := b.Config.Plugins.Enabled["Top"]; ok && enabled {
		top := topplugin.New()
		top.SetAsyncEmitter(func(outType, text, section, relpath string) {
			fakeEvt := &event.Event{Type: event.EventCommand, Section: section, Path: relpath}
			channels := b.routeChannels(fakeEvt, outType)
			for _, line := range strings.Split(text, "\n") {
				line = strings.TrimRight(line, "\r")
				if line == "" {
					continue
				}
				for _, ch := range channels {
					_ = b.IRC.SendMessage(ch, line)
				}
			}
		})
		cfg := map[string]interface{}{"debug": b.Debug, "theme_file": b.Config.Announce.ThemeFile}
		for k, v := range b.Config.Plugins.Config {
			cfg[k] = v
		}
		if err := top.Initialize(cfg); err != nil {
			return err
		}
		if err := b.registerPlugin("Top", top); err != nil {
			return err
		}
	}
	if enabled, ok := b.Config.Plugins.Enabled["Topic"]; ok && enabled {
		topic := topicplugin.New()
		topic.SetTopicSetter(b.IRC)
		cfg := map[string]interface{}{"debug": b.Debug, "theme_file": b.Config.Announce.ThemeFile}
		for k, v := range b.Config.Plugins.Config {
			cfg[k] = v
		}
		if err := topic.Initialize(cfg); err != nil {
			return err
		}
		if err := b.registerPlugin("Topic", topic); err != nil {
			return err
		}
	}
	if enabled, ok := b.Config.Plugins.Enabled["AdminCommander"]; ok && enabled {
		adminCommander := admincommanderplugin.New()
		cfg := map[string]interface{}{"debug": b.Debug, "theme_file": b.Config.Announce.ThemeFile}
		for k, v := range b.Config.Plugins.Config {
			cfg[k] = v
		}
		if err := adminCommander.Initialize(cfg); err != nil {
			return err
		}
		if err := b.registerPlugin("AdminCommander", adminCommander); err != nil {
			return err
		}
	}
	log.Printf("[Bot] Plugin load complete: %d total", len(b.Plugins.List()))
	return nil
}

func uniqueChannels(cfg *Config) []string {
	set := map[string]bool{}
	add := func(ch string) {
		ch = strings.TrimSpace(ch)
		if ch != "" {
			set[ch] = true
		}
	}
	for _, ch := range cfg.IRC.Channels {
		add(ch)
	}
	add(cfg.Announce.DefaultChannel)
	for _, arr := range cfg.Announce.TypeRoutes {
		for _, ch := range arr {
			add(ch)
		}
	}
	for _, s := range cfg.Sections {
		for _, ch := range s.Channels {
			add(ch)
		}
	}
	out := []string{}
	for ch := range set {
		out = append(out, ch)
	}
	return out
}

func (b *Bot) listenIRC() {
	var registeredOnce sync.Once
	handler := func(line string) {
		b.handleOperReply(line)
		b.handleChannelModes(line)
		if strings.Contains(line, " 004 ") || strings.Contains(line, " 376 ") || strings.Contains(line, " 422 ") {
			registeredOnce.Do(func() {
				b.onRegistered()
			})
			return
		}

		if i := strings.Index(line, " INVITE "); i != -1 {
			parts := strings.Split(line, " ")
			if len(parts) >= 4 {
				channel := strings.TrimPrefix(parts[3], ":")
				if channel != "" {
					if b.Debug {
						log.Printf("[Bot] INVITE received, joining %s", channel)
					}
					_ = b.IRC.Join(channel)
				}
			}
		}
		if handled := b.handleIRCKeyExchange(line); handled {
			return
		}
		if evt := b.commandEventFromPrivmsg(line); evt != nil {
			select {
			case b.EventChan <- evt:
			case <-b.Done:
			}
		}
	}
	if err := b.IRC.Listen(handler); err != nil {
		log.Printf("[Bot] IRC listen error: %v", err)
	}
}

type ircIncomingMessage struct {
	Sender  string
	Host    string
	Command string
	Target  string
	Text    string
}

func parseIRCIncomingMessage(line, command string) (*ircIncomingMessage, bool) {
	token := " " + strings.ToUpper(strings.TrimSpace(command)) + " "
	if !strings.HasPrefix(line, ":") || !strings.Contains(line, token) {
		return nil, false
	}
	withoutPrefix := strings.TrimPrefix(line, ":")
	prefix, rest, ok := strings.Cut(withoutPrefix, token)
	if !ok {
		return nil, false
	}
	sender := prefix
	host := ""
	if nick, userHost, ok := strings.Cut(prefix, "!"); ok {
		sender = nick
		host = userHost
	}
	target, msg, ok := strings.Cut(rest, " :")
	if !ok {
		return nil, false
	}
	return &ircIncomingMessage{
		Sender:  sender,
		Host:    host,
		Command: strings.ToUpper(strings.TrimSpace(command)),
		Target:  strings.TrimSpace(target),
		Text:    strings.TrimSpace(msg),
	}, true
}

func (b *Bot) handleIRCKeyExchange(line string) bool {
	msg, ok := parseIRCIncomingMessage(line, "NOTICE")
	if !ok {
		msg, ok = parseIRCIncomingMessage(line, "PRIVMSG")
		if !ok {
			return false
		}
	}
	handled, err := b.IRC.HandleKeyExchange(msg.Sender, msg.Target, msg.Text)
	if err != nil && b.Debug {
		log.Printf("[Bot] DH1080 exchange with %s failed: %v", msg.Sender, err)
	}
	return handled
}

func (b *Bot) commandEventFromPrivmsg(line string) *event.Event {
	parsed, ok := parseIRCIncomingMessage(line, "PRIVMSG")
	if !ok {
		return nil
	}
	sender := parsed.Sender
	host := parsed.Host
	target := parsed.Target
	msg := parsed.Text
	if strings.HasPrefix(msg, "+OK ") {
		if plain, decrypted := b.IRC.DecryptIncomingMessage(sender, target, msg); decrypted {
			msg = cleanIRCText(plain)
		} else if b.Debug {
			log.Printf("[Bot] Failed to decrypt command from %s in %s", sender, target)
		}
	}
	isChannel := strings.HasPrefix(target, "#")
	isPrivate := strings.EqualFold(strings.TrimSpace(target), strings.TrimSpace(b.Config.IRC.Nick))
	if (!isChannel && !isPrivate) || !strings.HasPrefix(msg, "!") {
		return nil
	}

	fields := strings.Fields(strings.TrimPrefix(msg, "!"))
	if len(fields) == 0 {
		return nil
	}
	command := strings.ToLower(fields[0])
	args := ""
	if len(fields) > 1 {
		args = strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(msg, "!"), fields[0]))
	}
	evt := event.NewEvent(event.EventCommand, sender, "", target, command)
	evt.Data["command"] = command
	evt.Data["args"] = args
	if isChannel {
		evt.Data["channel"] = target
	} else {
		evt.Data["channel"] = ""
		evt.Data["private"] = "true"
		evt.Data["private_target"] = target
	}
	evt.Data["host"] = host
	evt.Data["raw"] = msg
	if b.Debug {
		log.Printf("[Bot] IRC command %q from %s in %s", command, sender, target)
	}
	return evt
}

func cleanIRCText(s string) string {
	return strings.Trim(strings.TrimSpace(s), "\x00")
}

func (b *Bot) nickServDelay() time.Duration {
	delay := b.Config.IRC.NickServ.DelayMS
	if delay <= 0 {
		delay = 800
	}
	return time.Duration(delay) * time.Millisecond
}

func (b *Bot) authWithNickServ() {
	ns := b.Config.IRC.NickServ
	if !ns.Enabled {
		return
	}
	service := strings.TrimSpace(ns.Service)
	if service == "" {
		service = "NickServ"
	}
	password := strings.TrimSpace(ns.Password)
	account := strings.TrimSpace(ns.Account)
	email := strings.TrimSpace(ns.Email)

	if ns.AutoRegister {
		if password == "" || email == "" {
			if b.Debug {
				log.Printf("[Bot] NickServ auto_register enabled but password/email missing; skipping REGISTER")
			}
		} else {
			if err := b.IRC.SendRaw(fmt.Sprintf("PRIVMSG %s :REGISTER %s %s", service, password, email)); err != nil {
				if b.Debug {
					log.Printf("[Bot] NickServ REGISTER failed: %v", err)
				}
			} else {
				time.Sleep(b.nickServDelay())
			}
		}
	}

	if password == "" {
		if b.Debug {
			log.Printf("[Bot] NickServ enabled but no password configured; skipping IDENTIFY")
		}
		return
	}

	identify := password
	if account != "" {
		identify = account + " " + password
	}
	if err := b.IRC.SendRaw(fmt.Sprintf("PRIVMSG %s :IDENTIFY %s", service, identify)); err != nil {
		if b.Debug {
			log.Printf("[Bot] NickServ IDENTIFY failed: %v", err)
		}
		return
	}
	time.Sleep(b.nickServDelay())
}

func (b *Bot) onRegistered() {
	b.authWithNickServ()

	b.ircOper, b.operPending = false, false
	operUser := strings.TrimSpace(b.Config.IRC.OperUser)
	if operUser == "" {
		operUser = b.Config.IRC.Nick
	}
	if b.Config.IRC.AutoOper && strings.TrimSpace(b.Config.IRC.OperPassword) != "" {
		if err := b.IRC.SendRaw(fmt.Sprintf("OPER %s %s", operUser, b.Config.IRC.OperPassword)); err != nil {
			if b.Debug {
				log.Printf("[Bot] OPER failed: %v", err)
			}
		} else {
			b.operPending = true
		}
		// Give server time to process OPER and apply oper privileges before
		// we try SAJOIN. UnrealIRCd's OPER â†’ +o is near-instant but still
		// needs a roundtrip. Default 1500ms, overridable via autojoin_delay_ms.
		delay := b.Config.IRC.AutoJoinDelay
		if delay <= 0 {
			delay = 1500
		}
		time.Sleep(time.Duration(delay) * time.Millisecond)
	}

	if modes := strings.TrimSpace(b.Config.IRC.UserModes); modes != "" {
		modeArg := modes
		if !strings.HasPrefix(modeArg, "+") && !strings.HasPrefix(modeArg, "-") {
			modeArg = "+" + modeArg
		}
		if err := b.IRC.SendRaw(fmt.Sprintf("MODE %s %s", b.Config.IRC.Nick, modeArg)); err != nil && b.Debug {
			log.Printf("[Bot] MODE failed: %v", err)
		}
	}

	if !b.operPending {
		b.joinConfiguredChannels()
	}
}

func (b *Bot) joinConfiguredChannels() {
	// Join all configured channels. When oper'd, use SAJOIN to bypass +i
	// (invite-only) and +R (registered-only) modes â€” this is how scene
	// bots get into staff/ops channels without needing a permanent invite.
	// Follow up with SAMODE +o so the bot has channel ops and can kick/ban
	// / manage the channel later if needed.
	for _, ch := range uniqueChannels(b.Config) {
		if b.ircOper {
			_ = b.IRC.SendRaw(fmt.Sprintf("SAJOIN %s %s", b.Config.IRC.Nick, ch))
			// Small gap so SAJOIN lands before SAMODE hits the same channel.
			time.Sleep(150 * time.Millisecond)
			_ = b.IRC.SendRaw(fmt.Sprintf("SAMODE %s +o %s", ch, b.Config.IRC.Nick))
		} else {
			_ = b.IRC.Join(ch)
		}
		if d := b.Config.IRC.AutoJoinDelay; d > 0 {
			time.Sleep(time.Duration(d) * time.Millisecond)
		}
	}
}

func (b *Bot) readEvents() {
	log.Printf("[Bot] FIFO reader starting, watching %s", b.Config.EventFIFO)
	waited := false
	for {
		for {
			if _, err := os.Stat(b.Config.EventFIFO); err == nil {
				if waited {
					log.Printf("[Bot] FIFO appeared at %s", b.Config.EventFIFO)
				}
				break
			}
			if !waited {
				log.Printf("[Bot] FIFO not present at %s, waiting...", b.Config.EventFIFO)
				waited = true
			}
			time.Sleep(time.Second)
		}
		f, err := os.Open(b.Config.EventFIFO)
		if err != nil {
			log.Printf("[Bot] Failed to open FIFO: %v", err)
			time.Sleep(2 * time.Second)
			continue
		}
		log.Printf("[Bot] FIFO opened, reading events from %s", b.Config.EventFIFO)
		s := bufio.NewScanner(f)
		for s.Scan() {
			line := s.Text()
			evt, err := parseEvent(line)
			if err != nil {
				log.Printf("[Bot] FIFO parse error: %v (raw=%q)", err, line)
				continue
			}
			log.Printf("[Bot] FIFO got event %s section=%s path=%s file=%s", evt.Type, evt.Section, evt.Path, evt.Filename)
			select {
			case b.EventChan <- evt:
			case <-b.Done:
				_ = f.Close()
				return
			}
		}
		if err := s.Err(); err != nil {
			log.Printf("[Bot] FIFO scanner error: %v", err)
		} else {
			log.Printf("[Bot] FIFO writer closed (EOF), reopening...")
		}
		_ = f.Close()
		waited = false
	}
}
func (b *Bot) processEvents() {
	for {
		select {
		case evt := <-b.EventChan:
			b.handleEvent(evt)
		case <-b.Done:
			return
		}
	}
}

func pathMatches(pattern, p string) bool {
	if pattern == "" || p == "" {
		return false
	}
	if ok, _ := filepath.Match(strings.TrimSpace(pattern), p); ok {
		return true
	}
	prefix := strings.TrimRight(strings.TrimSpace(pattern), "*")
	if strings.EqualFold(strings.TrimRight(p, "/"), strings.TrimRight(strings.TrimSuffix(prefix, "/"), "/")) {
		return true
	}
	return strings.HasPrefix(strings.ToLower(p), strings.ToLower(prefix))
}

func (b *Bot) resolveSection(pathValue, fallback string) string {
	best := inferNestedSection(pathValue, fallback)
	bestScore := -1
	for _, sec := range b.Config.Sections {
		for _, pat := range sec.Paths {
			if !pathMatches(pat, pathValue) {
				continue
			}
			score := len(strings.TrimRight(strings.TrimSpace(pat), "*"))
			if score > bestScore {
				best = sec.Name
				bestScore = score
			}
		}
	}
	if strings.TrimSpace(best) == "" {
		return fallback
	}
	return best
}

func inferNestedSection(pathValue, fallback string) string {
	cleaned := filepath.ToSlash(filepath.Clean("/" + strings.TrimSpace(pathValue)))
	if cleaned == "/" || cleaned == "." {
		return strings.TrimSpace(fallback)
	}
	parts := strings.Split(strings.TrimPrefix(cleaned, "/"), "/")
	if len(parts) == 0 || strings.TrimSpace(parts[0]) == "" {
		return strings.TrimSpace(fallback)
	}
	root := strings.ToUpper(strings.TrimSpace(parts[0]))
	switch root {
	case "FOREIGN", "PRE", "ARCHIVE":
		if len(parts) >= 2 && strings.TrimSpace(parts[1]) != "" {
			return strings.ToUpper(strings.TrimSpace(parts[1]))
		}
	}
	if strings.TrimSpace(fallback) == "" {
		return root
	}
	return strings.TrimSpace(fallback)
}

func bestSectionRouteByPath(sections []SectionRoute, pathValue string) *SectionRoute {
	var best *SectionRoute
	bestScore := -1
	for i := range sections {
		sec := &sections[i]
		for _, pat := range sec.Paths {
			if !pathMatches(pat, pathValue) {
				continue
			}
			score := len(strings.TrimRight(strings.TrimSpace(pat), "*"))
			if score > bestScore {
				best = sec
				bestScore = score
			}
		}
	}
	return best
}

func (b *Bot) routeChannels(evt *event.Event, outType string) []string {
	if chs := b.Config.Announce.TypeRoutes[outType]; len(chs) > 0 {
		return nonEmptyChannels(chs)
	}
	if best := bestSectionRouteByPath(b.Config.Sections, evt.Path); best != nil {
		if chs := nonEmptyChannels(best.Channels); len(chs) > 0 {
			return chs
		}
	}
	for _, sec := range b.Config.Sections {
		if strings.EqualFold(sec.Name, evt.Section) {
			if chs := nonEmptyChannels(sec.Channels); len(chs) > 0 {
				return chs
			}
		}
	}
	if strings.TrimSpace(b.Config.Announce.DefaultChannel) != "" {
		return []string{b.Config.Announce.DefaultChannel}
	}
	return nonEmptyChannels(b.Config.IRC.Channels)
}

func nonEmptyChannels(channels []string) []string {
	out := make([]string, 0, len(channels))
	for _, ch := range channels {
		ch = strings.TrimSpace(ch)
		if ch != "" {
			out = append(out, ch)
		}
	}
	return out
}
func (b *Bot) handleEvent(evt *event.Event) {
	// INVITE events still send IRC invites directly, but plugins may observe
	// them too for side effects such as FTP-user to IRC-nick mapping.
	if evt.Type == event.EventInvite {
		b.handleInviteEvent(evt)
	}
	if handled, outs := b.handleHelpCommand(evt); handled {
		b.sendOutputs(evt, outs)
		return
	}
	if handled, outs, after := b.handleControlCommand(evt); handled {
		b.sendOutputs(evt, outs)
		if after != nil {
			go func(command string) {
				time.Sleep(b.controlSettings().RestartDelay)
				if err := after(); err != nil {
					b.sendOutputs(evt, b.controlReply(evt, b.controlSettings(), b.renderControl("CTRLCMD_ERROR", map[string]string{
						"command":  command,
						"response": err.Error(),
					}, "CONTROL: "+err.Error())))
				}
			}(strings.ToLower(strings.TrimSpace(evt.Data["command"])))
		}
		return
	}
	evt.Section = b.resolveSection(evt.Path, evt.Section)
	log.Printf("[Bot] handleEvent %s section=%s path=%s file=%s user=%s", evt.Type, evt.Section, evt.Path, evt.Filename, evt.User)
	outs, err := b.Plugins.ProcessEvent(evt)
	if err != nil {
		log.Printf("[Bot] Plugin processing error for %s: %v", evt.Type, err)
		if len(outs) == 0 {
			return
		}
	}
	if len(outs) == 0 {
		log.Printf("[Bot] %s produced no plugin output", evt.Type)
		return
	}
	log.Printf("[Bot] %s produced %d plugin outputs", evt.Type, len(outs))
	b.sendOutputs(evt, outs)
}

func (b *Bot) sendOutputs(evt *event.Event, outs []plugin.Output) {
	for _, out := range outs {
		if strings.TrimSpace(out.Target) != "" {
			for _, line := range strings.Split(out.Text, "\n") {
				line = strings.TrimRight(line, "\r")
				if line == "" {
					continue
				}
				kind := "PRIVMSG"
				if out.Notice {
					kind = "NOTICE"
				}
				log.Printf("[Bot] -> %s %s: %s", kind, out.Target, line)
				if out.Notice {
					if err := b.IRC.SendNotice(out.Target, line); err != nil {
						log.Printf("[Bot] NOTICE %s failed: %v", out.Target, err)
					}
				} else {
					if err := b.IRC.SendMessage(out.Target, line); err != nil {
						log.Printf("[Bot] PRIVMSG %s failed: %v", out.Target, err)
					}
				}
			}
			continue
		}
		channels := b.routeChannels(evt, out.Type)
		if len(channels) == 0 {
			log.Printf("[Bot] %s output dropped â€” routeChannels returned empty for section=%s outType=%s", evt.Type, evt.Section, out.Type)
			continue
		}
		for _, line := range strings.Split(out.Text, "\n") {
			line = strings.TrimRight(line, "\r")
			if line == "" {
				continue
			}
			for _, ch := range channels {
				log.Printf("[Bot] -> %s %s: %s", out.Type, ch, line)
				if err := b.IRC.SendMessage(ch, line); err != nil {
					log.Printf("[Bot] %s to %s failed: %v", out.Type, ch, err)
				}
			}
		}
	}
}

func (b *Bot) handleControlCommand(evt *event.Event) (bool, []plugin.Output, func() error) {
	if evt.Type != event.EventCommand {
		return false, nil, nil
	}
	cmd := strings.ToLower(strings.TrimSpace(evt.Data["command"]))
	if cmd != "refresh" && cmd != "restart" {
		return false, nil, nil
	}
	if enabled, ok := b.Config.Plugins.Enabled["Control"]; ok && !enabled {
		return false, nil, nil
	}

	ctrl := b.controlSettings()
	if !b.controlCanStaff(evt, ctrl) {
		return true, b.controlReply(evt, ctrl, b.renderControl("CTRLCMD_DENIED", map[string]string{
			"command": cmd,
			"user":    evt.User,
		}, "CONTROL: staff command only.")), nil
	}

	if cmd == "refresh" {
		if err := b.Reload(); err != nil {
			return true, b.controlReply(evt, ctrl, b.renderControl("CTRLCMD_ERROR", map[string]string{
				"command":  cmd,
				"response": err.Error(),
			}, "CONTROL: refresh failed: "+err.Error())), nil
		}
		return true, b.controlReply(evt, ctrl, b.renderControl("CTRLCMD_OK", map[string]string{
			"command":  cmd,
			"response": "sitebot config and plugins reloaded",
		}, "CONTROL: sitebot config and plugins reloaded.")), nil
	}

	return true, b.controlReply(evt, ctrl, b.renderControl("CTRLCMD_OK", map[string]string{
		"command":  cmd,
		"response": "restarting sitebot...",
	}, "CONTROL: restarting sitebot...")), b.RestartProcess
}

func (b *Bot) handleHelpCommand(evt *event.Event) (bool, []plugin.Output) {
	if evt.Type != event.EventCommand || !strings.EqualFold(strings.TrimSpace(evt.Data["command"]), "help") {
		return false, nil
	}
	if !b.helpAllowed(evt) {
		return true, b.helpReplies(evt, b.renderBotLine("HELPCMD_ERROR", map[string]string{
			"response": "command not enabled in this channel.",
		}, "HELP: command not enabled in this channel."))
	}

	lines := b.Config.Help.Lines
	if len(lines) == 0 {
		lines = b.defaultHelpLines()
	}
	rendered := make([]string, 0, len(lines)+1)
	rendered = append(rendered, b.renderBotLine("HELPCMD_HEADER", map[string]string{}, "HELP: available user commands"))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		rendered = append(rendered, b.renderBotLine("HELPCMD_LINE", map[string]string{"line": line}, "HELP: "+line))
	}
	return true, b.helpReplies(evt, rendered...)
}

func (b *Bot) helpAllowed(evt *event.Event) bool {
	if strings.EqualFold(strings.TrimSpace(evt.Data["private"]), "true") {
		return true
	}
	channel := strings.TrimSpace(evt.Data["channel"])
	for _, allowed := range b.Config.Help.Channels {
		if strings.EqualFold(strings.TrimSpace(allowed), channel) {
			return true
		}
	}
	return false
}

func (b *Bot) defaultHelpLines() []string {
	lines := []string{"!help - show this help in PM"}
	enabled := b.Config.Plugins.Enabled
	if enabled["Rules"] {
		lines = append(lines, "!rules - show site rules in PM")
	}
	if enabled["Quota"] {
		lines = append(lines, "!quota - show trial/quota standings")
	}
	if enabled["Top"] {
		lines = append(lines, "!top [5|10|25] - show daily top uploaders")
	}
	if enabled["Request"] {
		lines = append(lines, "!request <release> - add a request")
		lines = append(lines, "!requests - list requests")
		lines = append(lines, "!reqfill <id|release> - mark a request filled")
		lines = append(lines, "!reqtop [count] - show top request fillers")
		lines = append(lines, "!reqdel <id|release> - delete your own request")
	}
	if enabled["Free"] {
		lines = append(lines, "!free / !df - show free disk space")
	}
	if enabled["BNC"] {
		lines = append(lines, "!bnc - show site health checks")
	}
	if enabled["BW"] {
		lines = append(lines, "!bw - show bandwidth summary")
	}
	if enabled["Banned"] {
		lines = append(lines, "!banned [filter] - show banned rules in PM")
	}
	if enabled["SelfIP"] {
		lines = append(lines, "!ip - PM help for self-service IP commands")
	}
	return lines
}

func (b *Bot) helpReplies(evt *event.Event, lines ...string) []plugin.Output {
	target := evt.User
	notice := false
	replyTarget := strings.TrimSpace(b.Config.Help.ReplyTarget)
	switch {
	case strings.HasPrefix(replyTarget, "#"):
		target = replyTarget
	case strings.EqualFold(replyTarget, "notice"):
		notice = true
	default:
		target = evt.User
	}
	out := make([]plugin.Output, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		out = append(out, plugin.Output{Type: "COMMAND", Target: target, Notice: notice, Text: line})
	}
	return out
}

func (b *Bot) Reload() error {
	if _, err := b.Config.Rehash(); err != nil {
		return err
	}
	b.Debug = b.Config.Debug
	if b.IRC != nil {
		b.IRC.Debug = b.Debug
		for ch, key := range b.Config.Encryption.Keys {
			_ = b.IRC.SetChannelKey(ch, key)
		}
		b.IRC.SetAutoExchange(b.Config.Encryption.AutoExchange)
		_ = b.IRC.SetPrivateKey(strings.TrimSpace(b.Config.Encryption.PrivateKey))
		for _, ch := range uniqueChannels(b.Config) {
			_ = b.IRC.Join(ch)
		}
	}
	_ = b.Plugins.Close()
	b.Plugins = plugin.NewManager()
	return b.initializePlugins()
}

func (b *Bot) RestartProcess() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	proc, err := os.StartProcess(exe, os.Args, &os.ProcAttr{
		Dir:   cwd,
		Env:   os.Environ(),
		Files: []*os.File{os.Stdin, os.Stdout, os.Stderr},
	})
	if err != nil {
		return err
	}
	log.Printf("[Bot] Restart spawned pid=%d", proc.Pid)
	_ = b.Stop()
	os.Exit(0)
	return nil
}

func (b *Bot) controlSettings() controlConfig {
	cfg := plugin.ConfigSection(b.Config.Plugins.Config, "control")
	out := controlConfig{
		StaffChannels: []string{"#weaveftpd-staff"},
		StaffHosts:    []string{},
		ReplyTarget:   "channel",
		RestartDelay:  800 * time.Millisecond,
	}
	if raw, ok := cfg["staff_channels"]; ok {
		out.StaffChannels = plugin.ToStringSlice(raw, out.StaffChannels)
	}
	if raw, ok := cfg["staff_hosts"]; ok {
		out.StaffHosts = plugin.ToStringSlice(raw, out.StaffHosts)
	}
	if s, ok := cfg["reply_target"].(string); ok && strings.TrimSpace(s) != "" {
		out.ReplyTarget = strings.ToLower(strings.TrimSpace(s))
	}
	switch v := cfg["restart_delay_ms"].(type) {
	case int:
		if v > 0 {
			out.RestartDelay = time.Duration(v) * time.Millisecond
		}
	case int64:
		if v > 0 {
			out.RestartDelay = time.Duration(v) * time.Millisecond
		}
	case float64:
		if v > 0 {
			out.RestartDelay = time.Duration(int(v)) * time.Millisecond
		}
	}
	return out
}

func (b *Bot) controlCanStaff(evt *event.Event, cfg controlConfig) bool {
	channel := strings.ToLower(strings.TrimSpace(evt.Data["channel"]))
	for _, ch := range cfg.StaffChannels {
		if strings.EqualFold(strings.TrimSpace(ch), channel) {
			return true
		}
	}
	host := strings.ToLower(strings.TrimSpace(evt.Data["host"]))
	for _, pattern := range cfg.StaffHosts {
		if wildcardMatch(strings.ToLower(strings.TrimSpace(pattern)), host) {
			return true
		}
	}
	return false
}

func (b *Bot) controlReply(evt *event.Event, cfg controlConfig, lines ...string) []plugin.Output {
	target := b.commandReplyTarget(evt, cfg.ReplyTarget)
	notice := strings.EqualFold(strings.TrimSpace(cfg.ReplyTarget), "notice")
	out := make([]plugin.Output, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		out = append(out, plugin.Output{Type: "COMMAND", Target: target, Notice: notice, Text: line})
	}
	return out
}

func (b *Bot) commandReplyTarget(evt *event.Event, replyTarget string) string {
	replyTarget = strings.TrimSpace(replyTarget)
	switch {
	case strings.HasPrefix(replyTarget, "#"):
		return replyTarget
	case strings.EqualFold(replyTarget, "notice"):
		return evt.User
	default:
		if ch := strings.TrimSpace(evt.Data["channel"]); ch != "" {
			return ch
		}
		return evt.User
	}
}

func (b *Bot) renderControl(key string, vars map[string]string, fallback string) string {
	themeFile := strings.TrimSpace(b.Config.Announce.ThemeFile)
	if themeFile == "" {
		return fallback
	}
	th, err := tmpl.LoadTheme(themeFile)
	if err != nil {
		return fallback
	}
	if raw, ok := th.Announces[key]; ok && raw != "" {
		return tmpl.Render(raw, vars)
	}
	return fallback
}

func (b *Bot) renderBotLine(key string, vars map[string]string, fallback string) string {
	return b.renderControl(key, vars, fallback)
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
func (b *Bot) Stop() error {
	close(b.Done)
	if b.IRC != nil {
		_ = b.IRC.Quit("Shutting down")
		_ = b.IRC.Close()
	}
	_ = b.Plugins.Close()
	return nil
}

// handleInviteEvent processes an INVITE event from weaveftpd. It sends an IRC
// INVITE command for each channel in evt.Data["channels"] (comma-separated).
// Requires the bot to have ops in those channels (or them to permit non-op
// invites). The bot is typically oper'd via auto_oper, so it can invite
// anywhere network-wide.
func (b *Bot) handleInviteEvent(evt *event.Event) {
	if b.IRC == nil {
		return
	}
	nick := strings.TrimSpace(evt.Data["nick"])
	channels := strings.TrimSpace(evt.Data["channels"])
	if nick == "" || channels == "" {
		if b.Debug {
			log.Printf("[Bot] INVITE event missing nick or channels: %+v", evt.Data)
		}
		return
	}
	for _, ch := range strings.Split(channels, ",") {
		ch = strings.TrimSpace(ch)
		if ch == "" {
			continue
		}
		if err := b.IRC.Invite(nick, ch); err != nil {
			log.Printf("[Bot] INVITE %s %s failed: %v", nick, ch, err)
		} else if b.Debug {
			log.Printf("[Bot] Sent SAJOIN/INVITE %s to %s", nick, ch)
		}
		// Small pacing gap â€” SAJOIN+INVITE per channel is 2 lines, over 3
		// channels that's 6 rapid commands. IRC servers often throttle or
		// drop bursts. 300ms keeps us well under any reasonable flood limit.
		time.Sleep(300 * time.Millisecond)
	}
}

func parseEvent(line string) (*event.Event, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil, fmt.Errorf("empty")
	}
	if strings.HasPrefix(line, "{") {
		var evt event.Event
		if err := json.Unmarshal([]byte(line), &evt); err != nil {
			return nil, err
		}
		if evt.Data == nil {
			evt.Data = map[string]string{}
		}
		return &evt, nil
	}
	parts := strings.Split(line, ":")
	if len(parts) < 4 {
		return nil, fmt.Errorf("invalid")
	}
	evt := event.NewEvent(event.EventType(strings.ToUpper(parts[0])), parts[1], parts[2], parts[3], "")
	if len(parts) > 4 {
		evt.Filename = parts[4]
	}
	if len(parts) > 5 {
		fmt.Sscanf(parts[5], "%d", &evt.Size)
	}
	if len(parts) > 6 {
		fmt.Sscanf(parts[6], "%f", &evt.Speed)
	}
	if len(parts) > 7 {
		evt.Path = parts[7]
	}
	return evt, nil
}
