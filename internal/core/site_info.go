package core

import (
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	"weaveftpd/internal/plugin"
)

type siteHelpEntry struct {
	Command string
	Usage   string
	Summary string
	Area    string
	Aliases []string
}

var baseSiteHelpEntries = []siteHelpEntry{
	{Command: "HELP", Usage: "[command]", Summary: "Show SITE help", Area: "Info"},
	{Command: "RULES", Usage: "", Summary: "Show site rules", Area: "Info"},
	{Command: "WHO", Usage: "", Summary: "Show who's online", Area: "Info", Aliases: []string{"SWHO"}},
	{Command: "BW", Usage: "[user] | SLAVE [name]", Summary: "Show live bandwidth summary", Area: "Info"},
	{Command: "USERS", Usage: "", Summary: "List users", Area: "Info"},
	{Command: "USER", Usage: "<user>", Summary: "Show user details", Area: "Info"},
	{Command: "SEEN", Usage: "<user>", Summary: "Show whether a user is online or when they were last seen", Area: "Info"},
	{Command: "LASTLOGIN", Usage: "<user>", Summary: "Show the stored last login time", Area: "Info"},
	{Command: "GROUPS", Usage: "", Summary: "List groups", Area: "Info"},
	{Command: "GROUP", Usage: "<group>", Summary: "Show group details", Area: "Info", Aliases: []string{"GINFO"}},
	{Command: "GRPNFO", Usage: "<group>", Summary: "Show group file", Area: "Info"},
	{Command: "STAT", Usage: "", Summary: "Show simple account stats for parsing", Area: "Info"},
	{Command: "TRAFFIC", Usage: "", Summary: "Show traffic stats", Area: "Info"},
	{Command: "ALLUP", Usage: "[user|group]", Summary: "Show raw ALLUP stats line", Area: "Info"},
	{Command: "ALLDN", Usage: "[user|group]", Summary: "Show raw ALLDN stats line", Area: "Info"},
	{Command: "WKUP", Usage: "[user|group]", Summary: "Show raw WKUP stats line", Area: "Info"},
	{Command: "WKDN", Usage: "[user|group]", Summary: "Show raw WKDN stats line", Area: "Info"},
	{Command: "DAYUP", Usage: "[user|group]", Summary: "Show raw DAYUP stats line", Area: "Info"},
	{Command: "DAYDN", Usage: "[user|group]", Summary: "Show raw DAYDN stats line", Area: "Info"},
	{Command: "MONTHUP", Usage: "[user|group]", Summary: "Show raw MONTHUP stats line", Area: "Info"},
	{Command: "MONTHDN", Usage: "[user|group]", Summary: "Show raw MONTHDN stats line", Area: "Info"},
	{Command: "ADDUSER", Usage: "<user> <pass> [ident@ip ...]", Summary: "Add a new user", Area: "Users/groups"},
	{Command: "GADDUSER", Usage: "<user> <pass> <group> [ident@ip ...]", Summary: "Add a new user directly to a group", Area: "Users/groups"},
	{Command: "DELUSER", Usage: "<user>", Summary: "Delete a user (restorable with READD)", Area: "Users/groups"},
	{Command: "READD", Usage: "<user> [newpass]", Summary: "Restore a deleted user", Area: "Users/groups"},
	{Command: "RENUSER", Usage: "<olduser> <newuser>", Summary: "Rename a user", Area: "Users/groups"},
	{Command: "CHPASS", Usage: "<user> <newpass>", Summary: "Change a user's password", Area: "Users/groups"},
	{Command: "CHANGE", Usage: "<user|group> <field> <value...>", Summary: "Generic user/group field editor (SITE CHANGE HELP for fields)", Area: "Users/groups"},
	{Command: "CHRATIO", Usage: "<user> <ratio>", Summary: "Change a user's ratio", Area: "Users/groups"},
	{Command: "CHNUMLOGINS", Usage: "<user> <count>", Summary: "Change a user's max concurrent logins", Area: "Users/groups"},
	{Command: "CHMAXSIM", Usage: "<user> <count>", Summary: "Change a user's max concurrent transfers", Area: "Users/groups"},
	{Command: "CHWKLYALLOTMENT", Usage: "<user> <credits>", Summary: "Change a user's weekly credit reset amount", Area: "Users/groups"},
	{Command: "CHUPLOADSLOTS", Usage: "<user> <count>", Summary: "Change a user's upload slot limit", Area: "Users/groups"},
	{Command: "CHDOWNLOADSLOTS", Usage: "<user> <count>", Summary: "Change a user's download slot limit", Area: "Users/groups"},
	{Command: "ADDIP", Usage: "<user> <ident@ip> [ident@ip ...]", Summary: "Add IP(s) to a user", Area: "Users/groups"},
	{Command: "DELIP", Usage: "<user> <ident@ip> [ident@ip ...]", Summary: "Delete IP(s) from a user", Area: "Users/groups"},
	{Command: "SELFIP", Usage: "<LIST|ADD|DEL|CHG> <user> <pass> [args]", Summary: "Self-service user IP management", Area: "Users/groups"},
	{Command: "FLAGS", Usage: "<user> <+|-|=><flags>", Summary: "Change user flags", Area: "Users/groups"},
	{Command: "BAN", Usage: "<user> [reason]", Summary: "Ban an FTP user account", Area: "Users/groups"},
	{Command: "UNBAN", Usage: "<user>", Summary: "Remove an FTP user ban", Area: "Users/groups"},
	{Command: "TAGLINE", Usage: "[user] <text>", Summary: "Set your own or a user's tagline", Area: "Users/groups"},
	{Command: "MSG", Usage: "<user> <message>", Summary: "Send a private offline message", Area: "Mailbox"},
	{Command: "MAIL", Usage: "[page]", Summary: "List your mailbox (20 messages per page)", Area: "Mailbox"},
	{Command: "READ", Usage: "<id>", Summary: "Read a message in your mailbox", Area: "Mailbox"},
	{Command: "DELMSG", Usage: "<id>|ALL", Summary: "Delete messages from your mailbox", Area: "Mailbox"},
	{Command: "CHGRP", Usage: "<user> <group> [group2 ...]", Summary: "Add or remove group membership", Area: "Users/groups"},
	{Command: "CHPGRP", Usage: "<user> <group>", Summary: "Change primary group", Area: "Users/groups"},
	{Command: "GADMIN", Usage: "<group> <user>", Summary: "Make user group admin", Area: "Users/groups"},
	{Command: "GRPADD", Usage: "<group> [description]", Summary: "Add a group", Area: "Users/groups"},
	{Command: "GRPDEL", Usage: "<group>", Summary: "Delete a group", Area: "Users/groups"},
	{Command: "GROUPSLOTS", Usage: "<user> <slots> [leech_slots]", Summary: "Change a gadmin user's group and leech slot allowances", Area: "Users/groups"},
	{Command: "GROUPSIMULT", Usage: "<group> <count>", Summary: "Change group's simultaneous login limit", Area: "Users/groups"},
	{Command: "GRP", Usage: "[user]", Summary: "List groups or a user's groups", Area: "Users/groups"},
	{Command: "NUKE", Usage: "<release> <multiplier> <reason>", Summary: "Nuke a release", Area: "Release/admin"},
	{Command: "NUKES", Usage: "[filter]", Summary: "List nuked releases", Area: "Release/admin"},
	{Command: "UNNUKE", Usage: "<release> [reason]", Summary: "Unnuke a release", Area: "Release/admin"},
	{Command: "UNDUPE", Usage: "<release>", Summary: "Remove a release from the dupe DB", Area: "Release/admin"},
	{Command: "WIPE", Usage: "[-r] <path>", Summary: "Wipe a path", Area: "Release/admin"},
	{Command: "KICK", Usage: "<user>", Summary: "Disconnect a user", Area: "Release/admin"},
	{Command: "REHASH", Usage: "", Summary: "Reload permissions and config-backed state", Area: "Release/admin"},
	{Command: "REMERGE", Usage: "<slave|*>", Summary: "Run configured slave remerge scans", Area: "Release/admin"},
	{Command: "REMERGESTOP", Usage: "<slave|*>", Summary: "Ask active slave remerge jobs to stop", Area: "Release/admin"},
	{Command: "SLAVEBANS", Usage: "", Summary: "Show slave control denylist and active temp bans", Area: "Release/admin"},
	{Command: "SLAVEBAN", Usage: "<ip|cidr>", Summary: "Add an IP or CIDR to the persistent slave control denylist", Area: "Release/admin"},
	{Command: "SLAVEUNBAN", Usage: "<ip|cidr>", Summary: "Remove an IP or CIDR from the persistent slave control denylist and clear matching temp bans", Area: "Release/admin"},
	{Command: "SLAVECLEARBAN", Usage: "<ip|cidr>", Summary: "Clear an active slave control temp ban without changing the persistent denylist", Area: "Release/admin"},
	{Command: "SLAVE", Usage: "MASKS | <name> MASKS | <name> ADDMASK|DELMASK <mask>", Summary: "Manage per-slave IP masks used when mTLS is disabled", Area: "Release/admin"},
	{Command: "SEARCH", Usage: "<pattern>", Summary: "Search releases", Area: "Search/rescan"},
	{Command: "RACE", Usage: "<release>", Summary: "Show race stats for a release", Area: "Search/rescan"},
	{Command: "RESCAN", Usage: "<path>", Summary: "Rescan a path", Area: "Search/rescan"},
	{Command: "RESCANSTATUS", Usage: "[jobid]", Summary: "Show background rescan progress/output", Area: "Search/rescan"},
	{Command: "CHMOD", Usage: "<mode> <path>", Summary: "Change file permissions", Area: "Search/rescan"},
	{Command: "XDUPE", Usage: "", Summary: "Enable XDUPE mode", Area: "Search/rescan"},
	{Command: "INVITE", Usage: "", Summary: "Show site invite channels", Area: "IRC/sitebot"},
	{Command: "BLOWFISH", Usage: "[channel]", Summary: "Show configured sitebot blowfish keys", Area: "IRC/sitebot"},
	{Command: "IRC", Usage: "", Summary: "Show configured sitebot IRC connection info", Area: "IRC/sitebot"},
}

var pluginSiteHelpEntries = map[string]siteHelpEntry{
	"PRE":      {Command: "PRE", Usage: "<release> <section>", Summary: "Pre a release into a section", Area: "Plugins"},
	"ADDAFFIL": {Command: "ADDAFFIL", Usage: "<group>", Summary: "Add an affil group", Area: "Plugins"},
	"DELAFFIL": {Command: "DELAFFIL", Usage: "<group>", Summary: "Remove an affil group", Area: "Plugins"},
	"AFFILS":   {Command: "AFFILS", Usage: "", Summary: "List configured affils", Area: "Plugins"},
	"REQUEST":  {Command: "REQUEST", Usage: "<release> [-for:<user>] [-by:<user>]", Summary: "Create a request", Area: "Plugins"},
	"REQUESTS": {Command: "REQUESTS", Usage: "", Summary: "List current requests", Area: "Plugins"},
	"REQFILL":  {Command: "REQFILL", Usage: "<number|release>", Summary: "Mark a request filled", Area: "Plugins", Aliases: []string{"REQFILLED"}},
	"REQDEL":   {Command: "REQDEL", Usage: "<number|release>", Summary: "Delete a request", Area: "Plugins"},
	"REQWIPE":  {Command: "REQWIPE", Usage: "<number|release>", Summary: "Staff wipe a request", Area: "Plugins"},
	"BANNED":   {Command: "BANNED", Usage: "[filter] | ALLOW [filter]", Summary: "Show releaseguard deny or allow rules", Area: "Plugins"},
}

func (s *Session) HandleSiteWho(detailed bool, args []string) bool {
	label := "WHO"
	if detailed {
		label = "SWHO"
	}
	fmt.Fprintf(s.Conn, "200- Currently Online (%s):\r\n", label)
	for _, snap := range listActiveSessions() {
		user := snap.User
		if user == "" {
			user = "(login)"
		}
		group := snap.PrimaryGroup
		if group == "" {
			group = "-"
		}
		currentDir := snap.CurrentDir
		if currentDir == "" {
			currentDir = "/"
		}
		onlineFor := time.Since(snap.StartedAt).Round(time.Second)
		idleFor := time.Since(lastSessionActivity(snap)).Round(time.Second)

		if !detailed {
			fmt.Fprintf(s.Conn, "200- #%d %-12s %-12s %-18s %-24s online:%s idle:%s\r\n",
				snap.ID, user, group, sessionStateLabel(snap), currentDir, onlineFor, idleFor)
			continue
		}

		flags := snap.Flags
		if flags == "" {
			flags = "-"
		}
		remote := snap.Remote
		if remote == "" {
			remote = "-"
		}
		xferState := sessionTransferLabel(snap)
		fmt.Fprintf(s.Conn, "200- #%d User:%-12s Group:%-12s Flags:%-8s IP:%-22s Dir:%-24s State:%-18s Online:%-8s Idle:%-8s Xfer:%s\r\n",
			snap.ID, user, group, flags, remote, currentDir, sessionStateLabel(snap), onlineFor, idleFor, xferState)
	}
	fmt.Fprintf(s.Conn, "200 End of %s\r\n", label)
	return false
}

func lastSessionActivity(snap sessionSnapshot) time.Time {
	last := snap.LastCommandAt
	if last.IsZero() || snap.StartedAt.After(last) {
		last = snap.StartedAt
	}
	if !snap.TransferStartedAt.IsZero() && snap.TransferStartedAt.After(last) {
		last = snap.TransferStartedAt
	}
	return last
}

func sessionStateLabel(snap sessionSnapshot) string {
	if !snap.LoggedIn {
		return "login"
	}
	if snap.TransferDirection == "upload" {
		return "uploading"
	}
	if snap.TransferDirection == "download" {
		return "downloading"
	}
	return "idle"
}

func sessionTransferLabel(snap sessionSnapshot) string {
	if snap.TransferDirection == "" {
		return "-"
	}
	target := snap.TransferPath
	if strings.TrimSpace(target) == "" {
		target = "-"
	}
	bytesLabel := fmt.Sprintf("%dB", snap.TransferBytes)
	switch snap.TransferDirection {
	case "upload":
		return fmt.Sprintf("upload %s (%s)", target, bytesLabel)
	case "download":
		return fmt.Sprintf("download %s (%s)", target, bytesLabel)
	default:
		return fmt.Sprintf("%s %s (%s)", snap.TransferDirection, target, bytesLabel)
	}
}

func (s *Session) HandleSiteHelp(args []string) bool {
	if s.Config.Debug {
		log.Printf("[SITE HELP] args=%q", args)
	}

	entries := s.siteHelpEntries()
	if len(args) > 0 {
		command := strings.ToUpper(strings.TrimSpace(args[0]))
		if entry, ok := entries[command]; ok {
			s.replySiteHelpEntry(entry)
			return false
		}
		fmt.Fprintf(s.Conn, "504 No help available for SITE %s.\r\n", command)
		return false
	}

	groups := map[string][]siteHelpEntry{}
	order := []string{"Info", "Users/groups", "Release/admin", "Search/rescan", "IRC/sitebot", "Plugins"}
	for _, entry := range entries {
		groups[entry.Area] = append(groups[entry.Area], entry)
	}

	fmt.Fprintf(s.Conn, "214-Available SITE commands:\r\n")
	fmt.Fprintf(s.Conn, "214-\r\n")
	for _, area := range order {
		items := groups[area]
		if len(items) == 0 {
			continue
		}
		sort.Slice(items, func(i, j int) bool {
			return items[i].Command < items[j].Command
		})
		fmt.Fprintf(s.Conn, "214- %s:\r\n", area)
		for _, entry := range items {
			fmt.Fprintf(s.Conn, "214- %-13s - %s\r\n", entry.Command, entry.Summary)
		}
		fmt.Fprintf(s.Conn, "214-\r\n")
	}
	fmt.Fprintf(s.Conn, "214 Use: SITE HELP <command> for more info\r\n")
	return false
}

func (s *Session) HandleSiteRules(args []string) bool {
	vars := map[string]string{
		"sitename": s.Config.SiteName,
		"version":  s.Config.Version,
		"username": s.User.Name,
	}
	rules, err := LoadMessageTemplate("rules.msg", vars, s.Config)
	if err != nil {
		fmt.Fprintf(s.Conn, "550 Rules not available\r\n")
	} else {
		fmt.Fprintf(s.Conn, "214- SITE RULES\r\n")
		for _, line := range strings.Split(rules, "\n") {
			if strings.TrimSpace(line) != "" {
				fmt.Fprintf(s.Conn, "214- %s\r\n", line)
			}
		}
		fmt.Fprintf(s.Conn, "214 End of RULES\r\n")
	}
	return false
}

func (s *Session) siteHelpEntries() map[string]siteHelpEntry {
	entries := make(map[string]siteHelpEntry)
	add := func(entry siteHelpEntry) {
		if entry.Command == "" {
			return
		}
		if !s.canUseSiteCommand(entry.Command) {
			return
		}
		entries[entry.Command] = entry
		for _, alias := range entry.Aliases {
			alias = strings.ToUpper(strings.TrimSpace(alias))
			if alias == "" || !s.canUseSiteCommand(alias) {
				continue
			}
			aliasEntry := entry
			aliasEntry.Command = alias
			aliasEntry.Aliases = nil
			aliasEntry.Area = ""
			if aliasEntry.Usage == "" {
				aliasEntry.Usage = entry.Usage
			}
			entries[alias] = aliasEntry
		}
	}

	for _, entry := range baseSiteHelpEntries {
		add(entry)
	}

	if s.Config != nil && s.Config.PluginManager != nil {
		for _, p := range s.Config.PluginManager.GetPlugins() {
			h, ok := p.(plugin.SiteCommandHandler)
			if !ok {
				continue
			}
			for _, command := range h.SiteCommands() {
				command = strings.ToUpper(strings.TrimSpace(command))
				if command == "" {
					continue
				}
				if entry, ok := pluginSiteHelpEntries[command]; ok {
					add(entry)
					continue
				}
				add(siteHelpEntry{
					Command: command,
					Summary: "Plugin-provided SITE command",
					Area:    "Plugins",
				})
			}
		}
	}
	return entries
}

func (s *Session) replySiteHelpEntry(entry siteHelpEntry) {
	fmt.Fprintf(s.Conn, "214- SITE %s\r\n", entry.Command)
	if entry.Summary != "" {
		fmt.Fprintf(s.Conn, "214- Summary: %s\r\n", entry.Summary)
	}
	if entry.Usage != "" {
		fmt.Fprintf(s.Conn, "214- Usage: SITE %s %s\r\n", entry.Command, entry.Usage)
	} else {
		fmt.Fprintf(s.Conn, "214- Usage: SITE %s\r\n", entry.Command)
	}
	if len(entry.Aliases) > 0 {
		fmt.Fprintf(s.Conn, "214- Aliases: %s\r\n", strings.Join(entry.Aliases, ", "))
	}
	fmt.Fprintf(s.Conn, "214 End of HELP\r\n")
}
