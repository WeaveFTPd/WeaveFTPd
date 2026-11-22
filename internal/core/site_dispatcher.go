package core

import (
	"fmt"
	"log"
	"strings"

	"weaveftpd/internal/plugin"
)

// DispatchSiteCommand routes SITE sub-commands to their specific handlers.
// This keeps commands.go clean and focused on standard FTP/FXP protocol.
func (s *Session) DispatchSiteCommand(args []string) bool {
	if len(args) == 0 {
		fmt.Fprintf(s.Conn, "500 SITE what?\r\n")
		return false
	}

	siteCmd := strings.ToUpper(args[0])
	remainingArgs := args[1:]

	if s.Config.Debug {
		log.Printf("[SITE] siteCmd=%q remainingArgs=%q", siteCmd, sanitizeSiteArgsForLog(siteCmd, remainingArgs))
	}
	if !s.canUseSiteCommand(siteCmd) {
		fmt.Fprintf(s.Conn, "550 Access denied: SITE %s is not allowed.\r\n", siteCmd)
		return false
	}

	switch siteCmd {
	case "MSG", "MAIL", "READ", "DELMSG":
		return s.HandleSiteMail(siteCmd, remainingArgs)
	// Informational Commands (site_info.go)
	case "HELP":
		return s.HandleSiteHelp(remainingArgs)
	case "RULES":
		return s.HandleSiteRules(remainingArgs)
	case "WHO":
		return s.HandleSiteWho(false, remainingArgs)
	case "SWHO":
		return s.HandleSiteWho(true, remainingArgs)
	case "BW":
		return s.HandleSiteBW(remainingArgs)
	case "USERS":
		return s.HandleSiteUsers(remainingArgs)
	case "USER":
		return s.HandleSiteUser(remainingArgs)
	case "SEEN":
		return s.HandleSiteSeen(remainingArgs)
	case "LASTLOGIN":
		return s.HandleSiteLastLogin(remainingArgs)
	case "GROUPS":
		return s.HandleSiteGroups(remainingArgs)
	case "GROUP", "GINFO":
		return s.HandleSiteGroup(remainingArgs)
	case "GRPNFO":
		return s.HandleSiteGrpNfo(remainingArgs)
	case "GROUPSLOTS":
		return s.HandleSiteGroupSlots(remainingArgs)
	case "GROUPSIMULT":
		return s.HandleSiteGroupSimult(remainingArgs)
	case "TRAFFIC":
		return s.HandleSiteTraffic(remainingArgs)
	case "STAT":
		return s.HandleSiteStat(remainingArgs)
	case "ALLUP", "ALLDN", "WKUP", "WKDN", "DAYUP", "DAYDN", "MONTHUP", "MONTHDN":
		return s.HandleSiteUserStatLine(siteCmd, remainingArgs)
	case "TAGLINE":
		return s.HandleSiteTagline(remainingArgs)
	case "BLOWFISH":
		return s.HandleSiteBlowfish(remainingArgs)
	case "IRC":
		return s.HandleSiteIRC(remainingArgs)

	// Admin / User & Group Management (site_admin.go)
	case "ADDUSER":
		return s.HandleSiteAddUser(remainingArgs)
	case "GADDUSER":
		return s.HandleSiteGAddUser(remainingArgs)
	case "DELUSER":
		return s.HandleSiteDelUser(remainingArgs)
	case "READD":
		return s.HandleSiteReAdd(remainingArgs)
	case "RENUSER":
		return s.HandleSiteRenUser(remainingArgs)
	case "CHPASS":
		return s.HandleSiteChPass(remainingArgs)
	case "CHANGE":
		return s.HandleSiteChange(remainingArgs)
	case "CHRATIO":
		return s.HandleSiteChRatio(remainingArgs)
	case "CHNUMLOGINS":
		return s.HandleSiteChNumLogins(remainingArgs)
	case "CHMAXSIM":
		return s.HandleSiteChMaxSim(remainingArgs)
	case "CHWKLYALLOTMENT":
		return s.HandleSiteChWklyAllotment(remainingArgs)
	case "CHUPLOADSLOTS":
		return s.HandleSiteChUploadSlots(remainingArgs)
	case "CHDOWNLOADSLOTS":
		return s.HandleSiteChDownloadSlots(remainingArgs)
	case "ADDIP":
		return s.HandleSiteAddIP(remainingArgs)
	case "DELIP":
		return s.HandleSiteDelIP(remainingArgs)
	case "BAN":
		return s.HandleSiteBan(remainingArgs)
	case "UNBAN":
		return s.HandleSiteUnban(remainingArgs)
	case "SELFIP":
		return s.HandleSiteSelfIP(remainingArgs)
	case "FLAGS":
		return s.HandleSiteFlags(remainingArgs)
	case "CHGRP":
		return s.HandleSiteChGrp(remainingArgs)
	case "CHPGRP":
		return s.HandleSiteChPGrp(remainingArgs)
	case "GADMIN":
		return s.HandleSiteGAdmin(remainingArgs)
	case "GRPADD":
		return s.HandleSiteGrpAdd(remainingArgs)
	case "GRPDEL":
		return s.HandleSiteGrpDel(remainingArgs)
	case "INVITE":
		return s.HandleSiteInvite(remainingArgs)

	// Release Management (site_nuke.go)
	case "NUKE":
		return s.HandleSiteNuke(remainingArgs)
	case "NUKES":
		return s.HandleSiteNukes(remainingArgs)
	case "UNNUKE":
		return s.HandleSiteUnnuke(remainingArgs)
	case "UNDUPE":
		return s.HandleSiteUndupe(remainingArgs)
	case "WIPE":
		return s.HandleSiteWipe(remainingArgs)
	case "KICK":
		return s.HandleSiteKick(remainingArgs)
	case "REHASH":
		return s.HandleSiteRehash(remainingArgs)
	case "REMERGE":
		return s.HandleSiteRemerge(remainingArgs)
	case "REMERGESTOP":
		return s.HandleSiteRemergeStop(remainingArgs)
	case "SLAVEBANS":
		return s.HandleSiteSlaveBans(remainingArgs)
	case "SLAVEBAN":
		return s.HandleSiteSlaveBan(remainingArgs)
	case "SLAVEUNBAN":
		return s.HandleSiteSlaveUnban(remainingArgs)
	case "SLAVECLEARBAN":
		return s.HandleSiteSlaveClearBan(remainingArgs)
	case "SLAVE":
		return s.HandleSiteSlaveMask(remainingArgs)

	// Miscellaneous (site_misc.go / site_race.go)
	case "RACE":
		return s.HandleSiteRace(remainingArgs)
	case "SEARCH":
		return s.HandleSiteSearch(remainingArgs)
	case "RESCAN":
		return s.HandleSiteRescan(remainingArgs)
	case "RESCANSTATUS":
		return s.HandleSiteRescanStatus(remainingArgs)
	case "CHMOD":
		return s.HandleSiteChmod(remainingArgs)
	case "XDUPE":
		return s.HandleSiteXDupe(remainingArgs)
	case "GRP":
		return s.HandleSiteGrp(remainingArgs)

	default:
		if s.Config != nil && s.Config.PluginManager != nil {
			if s.Config.PluginManager.DispatchSiteCommand(pluginSiteContext{s: s}, siteCmd, remainingArgs) {
				return false
			}
		}
		fmt.Fprintf(s.Conn, "504 Unknown SITE command.\r\n")
	}
	return false
}

func (s *Session) canUseSiteCommand(command string) bool {
	command = strings.ToUpper(strings.TrimSpace(command))
	if command == "" {
		return false
	}
	if s != nil && s.ACLEngine != nil && s.ACLEngine.HasRuleType("sitecmd") {
		return s.ACLEngine.CanPerformRuleOnly(s.User, "sitecmd", command)
	}
	if required := requiredSiteCommandFlags(command); required != "" {
		return siteCommandFlagsAllowed(s, required)
	}
	return true
}

// requiredSiteCommandFlags is the daemon-side equivalent of glftpd's
// -addip/-deluser/etc command restrictions. Path ACLs still handle release
// commands such as NUKE/UNNUKE; this table protects account/site admin verbs.
func requiredSiteCommandFlags(command string) string {
	switch strings.ToUpper(strings.TrimSpace(command)) {
	case "WHO",
		"SWHO",
		"SEEN",
		"LASTLOGIN",
		"GROUPS",
		"GROUP",
		"GINFO",
		"GRP",
		"ADDUSER",
		"DELUSER",
		"READD",
		"RENUSER",
		"CHANGE",
		"CHPASS",
		"CHNUMLOGINS",
		"CHMAXSIM",
		"CHWKLYALLOTMENT",
		"CHUPLOADSLOTS",
		"CHDOWNLOADSLOTS",
		"ADDIP",
		"DELIP",
		"BAN",
		"UNBAN",
		"FLAGS",
		"CHGRP",
		"CHPGRP",
		"GADMIN",
		"GRPADD",
		"GRPDEL",
		"GROUPSLOTS",
		"GROUPSIMULT",
		"USERS",
		"GRPNFO",
		"TRAFFIC",
		"NUKES",
		"UNDUPE",
		"WIPE",
		"KICK",
		"CHMOD",
		"RESCANSTATUS",
		"REHASH",
		"REMERGE",
		"REMERGESTOP",
		"SLAVEBANS",
		"SLAVEBAN",
		"SLAVEUNBAN",
		"SLAVECLEARBAN",
		"SLAVE",
		"ADDAFFIL",
		"DELAFFIL":
		return "1"
	default:
		return ""
	}
}

func siteCommandFlagsAllowed(s *Session, required string) bool {
	if s == nil || s.User == nil {
		return false
	}
	for _, flag := range strings.Fields(required) {
		if !s.User.HasFlag(flag) {
			return false
		}
	}
	return true
}

func sanitizeSiteArgsForLog(command string, args []string) []string {
	if len(args) == 0 {
		return args
	}
	command = strings.ToUpper(strings.TrimSpace(command))
	clean := append([]string(nil), args...)
	switch command {
	case "MSG":
		if len(clean) >= 2 {
			return []string{clean[0], "[private message]"}
		}
	case "SELFIP":
		if len(clean) >= 3 {
			clean[2] = "********"
		}
	case "ADDUSER", "GADDUSER", "CHPASS", "READD":
		if len(clean) >= 2 {
			clean[1] = "********"
		}
	}
	return clean
}

type pluginSiteContext struct {
	s *Session
}

var _ plugin.SiteContext = pluginSiteContext{}

func (c pluginSiteContext) Reply(format string, args ...interface{}) {
	if c.s == nil || c.s.Conn == nil {
		return
	}
	fmt.Fprintf(c.s.Conn, format, args...)
}

func (c pluginSiteContext) UserName() string {
	if c.s == nil || c.s.User == nil {
		return ""
	}
	return c.s.User.Name
}

func (c pluginSiteContext) UserFlags() string {
	if c.s == nil || c.s.User == nil {
		return ""
	}
	return c.s.User.Flags
}

func (c pluginSiteContext) UserPrimaryGroup() string {
	if c.s == nil || c.s.User == nil {
		return ""
	}
	return c.s.User.PrimaryGroup
}

func (c pluginSiteContext) UserGroups() []string {
	if c.s == nil || c.s.User == nil {
		return nil
	}
	groups := make([]string, 0, len(c.s.User.Groups)+1)
	if c.s.User.PrimaryGroup != "" {
		groups = append(groups, c.s.User.PrimaryGroup)
	}
	for group := range c.s.User.Groups {
		if !containsStringFold(groups, group) {
			groups = append(groups, group)
		}
	}
	return groups
}

func containsStringFold(values []string, needle string) bool {
	for _, value := range values {
		if strings.EqualFold(value, needle) {
			return true
		}
	}
	return false
}
