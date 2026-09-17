package core

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"weaveftpd/internal/timeutil"
	"weaveftpd/internal/user"
)

func (s *Session) HandleSiteUsers(args []string) bool {
	names, err := listUserNames()
	if err != nil {
		fmt.Fprintf(s.Conn, "550 Could not list users: %v\r\n", err)
		return false
	}
	fmt.Fprintf(s.Conn, "200- Users (%d):\r\n", len(names))
	for _, name := range names {
		u, err := user.LoadUser(name, s.GroupMap)
		if err != nil {
			fmt.Fprintf(s.Conn, "200- %-16s (unreadable: %v)\r\n", name, err)
			continue
		}
		fmt.Fprintf(s.Conn, "200- %-16s Flags:%-8s Group:%-12s Ratio:%-4s Last:%s\r\n",
			u.Name, u.Flags, u.PrimaryGroup, formatRatio(u.Ratio), formatUnixTime(u.LastLogin))
	}
	fmt.Fprintf(s.Conn, "200 End of users.\r\n")
	return false
}

func (s *Session) HandleSiteUser(args []string) bool {
	if len(args) < 1 || strings.TrimSpace(args[0]) == "" {
		fmt.Fprintf(s.Conn, "501 Usage: SITE USER <username>\r\n")
		return false
	}
	u, err := user.LoadUser(args[0], s.GroupMap)
	if err != nil {
		fmt.Fprintf(s.Conn, "550 User %s not found.\r\n", args[0])
		return false
	}
	// Only siteops (flag 1) may inspect another user's account; everyone else is
	// limited to their own. Without this any logged-in user could read anyone's
	// credits, ratio, stats and IPs.
	if !strings.EqualFold(u.Name, s.User.Name) && !s.User.HasFlag("1") {
		fmt.Fprintf(s.Conn, "550 Access denied.\r\n")
		return false
	}
	groups := make([]string, 0, len(u.Groups))
	for group, admin := range u.Groups {
		if admin == 1 {
			group += "(gadmin)"
		}
		groups = append(groups, group)
	}
	sort.Strings(groups)
	fmt.Fprintf(s.Conn, "200- User: %s (UID: %d GID: %d)\r\n", u.Name, u.UID, u.GID)
	fmt.Fprintf(s.Conn, "200- Tagline: %s\r\n", u.Tagline)
	fmt.Fprintf(s.Conn, "200- Flags: %s\r\n", u.Flags)
	fmt.Fprintf(s.Conn, "200- Primary group: %s\r\n", u.PrimaryGroup)
	fmt.Fprintf(s.Conn, "200- Groups: %s\r\n", strings.Join(groups, ", "))
	fmt.Fprintf(s.Conn, "200- Home: %s%s\r\n", u.HomeRoot, u.HomeDir)
	fmt.Fprintf(s.Conn, "200- Ratio: %s Credits: %s\r\n", formatRatio(u.Ratio), formatBytes(u.Credits))
	fmt.Fprintf(s.Conn, "200- Limits: logins=%d maxsim=%d ulslots=%d dlslots=%d wkly_allotment=%s groupslots=%d leechslots=%d\r\n",
		u.LoginSlots, u.MaxSim, u.UploadSlots, u.DownloadSlots, formatBytes(u.WeeklyAllotment), u.GroupSlots, u.LeechSlots)
	fmt.Fprintf(s.Conn, "200- All up:   %6dF / %-10s All dn:   %6dF / %s\r\n",
		u.AllUp.Files, formatBytes(u.AllUp.Bytes), u.AllDn.Files, formatBytes(u.AllDn.Bytes))
	fmt.Fprintf(s.Conn, "200- Month up: %6dF / %-10s Month dn: %6dF / %s\r\n",
		u.MonthUp.Files, formatBytes(u.MonthUp.Bytes), u.MonthDn.Files, formatBytes(u.MonthDn.Bytes))
	fmt.Fprintf(s.Conn, "200- Week up:  %6dF / %-10s Week dn:  %6dF / %s\r\n",
		u.WkUp.Files, formatBytes(u.WkUp.Bytes), u.WkDn.Files, formatBytes(u.WkDn.Bytes))
	fmt.Fprintf(s.Conn, "200- Day up:   %6dF / %-10s Day dn:   %6dF / %s\r\n",
		u.DayUp.Files, formatBytes(u.DayUp.Bytes), u.DayDn.Files, formatBytes(u.DayDn.Bytes))
	if u.NukeStat.Files > 0 {
		fmt.Fprintf(s.Conn, "200- Nuked: %d times / %s (last: %s)\r\n",
			u.NukeStat.Files, formatBytes(u.NukeStat.Bytes), formatUnixTime(u.NukeStat.Meta))
	} else {
		fmt.Fprintf(s.Conn, "200- Nuked: never\r\n")
	}
	addedBy := strings.TrimSpace(u.AddedBy)
	if addedBy == "" {
		addedBy = "unknown"
	}
	fmt.Fprintf(s.Conn, "200- Added: %s by %s\r\n", formatUnixTime(u.Added), addedBy)
	fmt.Fprintf(s.Conn, "200- Last login: %s Expires: %s\r\n",
		formatUnixTime(u.LastLogin), formatUnixTime(u.Expires))
	if len(u.IPs) == 0 {
		fmt.Fprintf(s.Conn, "200- IPs: none\r\n")
	} else {
		for i, ip := range u.IPs {
			fmt.Fprintf(s.Conn, "200- IP%d: %s\r\n", i, ip)
		}
	}
	if ban, ok := FindUserBan(u.Name); ok {
		fmt.Fprintf(s.Conn, "200- Ban: yes (%s by %s at %s)\r\n", ban.Reason, ban.By, formatUnixTime(ban.Added))
	}
	fmt.Fprintf(s.Conn, "200 User end.\r\n")
	return false
}

func (s *Session) HandleSiteSeen(args []string) bool {
	if len(args) < 1 || strings.TrimSpace(args[0]) == "" {
		fmt.Fprintf(s.Conn, "501 Usage: SITE SEEN <username>\r\n")
		return false
	}
	for _, snap := range listActiveSessions() {
		if strings.EqualFold(snap.User, args[0]) {
			fmt.Fprintf(s.Conn, "200 %s is online from %s in %s.\r\n", snap.User, snap.Remote, snap.CurrentDir)
			return false
		}
	}
	u, err := user.LoadUser(args[0], s.GroupMap)
	if err != nil {
		fmt.Fprintf(s.Conn, "550 User %s not found.\r\n", args[0])
		return false
	}
	if u.LastLogin <= 0 {
		fmt.Fprintf(s.Conn, "200 %s has never logged in.\r\n", u.Name)
		return false
	}
	fmt.Fprintf(s.Conn, "200 %s was last seen %s (%s ago).\r\n", u.Name, formatUnixTime(u.LastLogin), formatAge(u.LastLogin))
	return false
}

func (s *Session) HandleSiteLastLogin(args []string) bool {
	if len(args) < 1 || strings.TrimSpace(args[0]) == "" {
		fmt.Fprintf(s.Conn, "501 Usage: SITE LASTLOGIN <username>\r\n")
		return false
	}
	u, err := user.LoadUser(args[0], s.GroupMap)
	if err != nil {
		fmt.Fprintf(s.Conn, "550 User %s not found.\r\n", args[0])
		return false
	}
	if u.LastLogin <= 0 {
		fmt.Fprintf(s.Conn, "200 %s has never logged in.\r\n", u.Name)
		return false
	}
	fmt.Fprintf(s.Conn, "200 %s last logged in at %s (%s ago).\r\n", u.Name, formatUnixTime(u.LastLogin), formatAge(u.LastLogin))
	return false
}

func (s *Session) HandleSiteGroups(args []string) bool {
	groups := make([]string, 0, len(s.GroupMap))
	for group := range s.GroupMap {
		groups = append(groups, group)
	}
	sort.Strings(groups)
	fmt.Fprintf(s.Conn, "200- Groups (%d):\r\n", len(groups))
	for _, group := range groups {
		fmt.Fprintf(s.Conn, "200- %-16s GID:%d Members:%d\r\n", group, s.GroupMap[group], countGroupMembers(group))
	}
	fmt.Fprintf(s.Conn, "200 End of groups.\r\n")
	return false
}

func (s *Session) HandleSiteGroup(args []string) bool {
	if len(args) < 1 || strings.TrimSpace(args[0]) == "" {
		return s.HandleSiteGroups(nil)
	}
	group, err := normalizeSiteGroupName(args[0])
	if err != nil {
		fmt.Fprintf(s.Conn, "550 Invalid group name %q.\r\n", strings.TrimSpace(args[0]))
		return false
	}
	gid, ok := s.GroupMap[group]
	if !ok {
		fmt.Fprintf(s.Conn, "550 Group %s not found.\r\n", group)
		return false
	}
	members, gadmins := groupMembers(group, s.GroupMap)
	fmt.Fprintf(s.Conn, "200- Group: %s (GID: %d)\r\n", group, gid)
	if groupCfg, err := LoadGroupConfig(group); err == nil {
		fmt.Fprintf(s.Conn, "200- Slots: %d %d %d %d\r\n", groupCfg.Slots, groupCfg.LeechSlots, groupCfg.AllotmentSlots, groupCfg.MaxAllotment)
		fmt.Fprintf(s.Conn, "200- Simult: %d\r\n", groupCfg.Simult)
		if strings.TrimSpace(groupCfg.GroupNFO) != "" {
			fmt.Fprintf(s.Conn, "200- GroupNFO: %s\r\n", groupCfg.GroupNFO)
		}
	}
	fmt.Fprintf(s.Conn, "200- Members: %s\r\n", strings.Join(members, ", "))
	fmt.Fprintf(s.Conn, "200- Gadmins: %s\r\n", strings.Join(gadmins, ", "))
	fmt.Fprintf(s.Conn, "200 Group end.\r\n")
	return false
}

func (s *Session) HandleSiteGrpNfo(args []string) bool {
	if len(args) < 1 || strings.TrimSpace(args[0]) == "" {
		fmt.Fprintf(s.Conn, "501 Usage: SITE GRPNFO <group>\r\n")
		return false
	}
	group, err := normalizeSiteGroupName(args[0])
	if err != nil {
		fmt.Fprintf(s.Conn, "550 Invalid group name %q.\r\n", strings.TrimSpace(args[0]))
		return false
	}
	data, err := os.ReadFile(filepath.Join("etc", "groups", group))
	if err != nil {
		fmt.Fprintf(s.Conn, "550 Group file for %s not found.\r\n", group)
		return false
	}
	fmt.Fprintf(s.Conn, "200- Group file: %s\r\n", group)
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) != "" {
			fmt.Fprintf(s.Conn, "200- %s\r\n", line)
		}
	}
	fmt.Fprintf(s.Conn, "200 Group nfo end.\r\n")
	return false
}

func (s *Session) HandleSiteTraffic(args []string) bool {
	target := ""
	if len(args) > 0 {
		target = strings.TrimSpace(args[0])
	}
	if target == "" {
		target = s.User.Name
	}
	if u, err := user.LoadUser(target, s.GroupMap); err == nil {
		fmt.Fprintf(s.Conn, "200- Traffic for user %s\r\n", u.Name)
		writeTrafficLine(s, "All", u.AllUp, u.AllDn)
		writeTrafficLine(s, "Month", u.MonthUp, u.MonthDn)
		writeTrafficLine(s, "Week", u.WkUp, u.WkDn)
		writeTrafficLine(s, "Day", u.DayUp, u.DayDn)
		fmt.Fprintf(s.Conn, "200 Traffic end.\r\n")
		return false
	}
	members, _ := groupMembers(target, s.GroupMap)
	if len(members) == 0 {
		fmt.Fprintf(s.Conn, "550 No user or group named %s.\r\n", target)
		return false
	}
	var up, dn user.StatLine
	for _, member := range members {
		u, err := user.LoadUser(member, s.GroupMap)
		if err != nil {
			continue
		}
		up.Files += u.AllUp.Files
		up.Bytes += u.AllUp.Bytes
		dn.Files += u.AllDn.Files
		dn.Bytes += u.AllDn.Bytes
	}
	fmt.Fprintf(s.Conn, "200- Traffic for group %s\r\n", target)
	writeTrafficLine(s, "All", up, dn)
	fmt.Fprintf(s.Conn, "200 Traffic end.\r\n")
	return false
}

func (s *Session) HandleSiteStat(args []string) bool {
	if len(args) > 0 {
		fmt.Fprintf(s.Conn, "504 Command not implemented for that parameter.\r\n")
		return false
	}
	s.showGlobalStats("200", true)
	return false
}

func (s *Session) HandleSiteUserStatLine(kind string, args []string) bool {
	kind = strings.ToUpper(strings.TrimSpace(kind))
	target := s.User.Name
	if len(args) > 0 && strings.TrimSpace(args[0]) != "" {
		target = strings.TrimSpace(args[0])
	}

	if u, err := user.LoadUser(target, s.GroupMap); err == nil {
		if !strings.EqualFold(u.Name, s.User.Name) && !s.User.HasFlag("1") {
			fmt.Fprintf(s.Conn, "550 Access denied.\r\n")
			return false
		}
		stat, extra := userStatLineByKind(u, kind)
		fmt.Fprintf(s.Conn, "200 %s %d %d %d%s\r\n", kind, stat.Files, stat.Bytes, stat.Meta, suffixWithSpace(extra))
		return false
	}

	members, _ := groupMembers(target, s.GroupMap)
	if len(members) == 0 {
		fmt.Fprintf(s.Conn, "550 No user or group named %s.\r\n", target)
		return false
	}
	if !s.User.HasFlag("1") && !s.User.IsInGroup(target) {
		fmt.Fprintf(s.Conn, "550 Access denied.\r\n")
		return false
	}
	var aggregate user.StatLine
	for _, member := range members {
		u, err := user.LoadUser(member, s.GroupMap)
		if err != nil {
			continue
		}
		stat, _ := userStatLineByKind(u, kind)
		aggregate.Files += stat.Files
		aggregate.Bytes += stat.Bytes
		aggregate.Meta += stat.Meta
	}
	fmt.Fprintf(s.Conn, "200 %s %d %d %d\r\n", kind, aggregate.Files, aggregate.Bytes, aggregate.Meta)
	return false
}

func (s *Session) HandleSiteUndupe(args []string) bool {
	if len(args) < 1 || strings.TrimSpace(args[0]) == "" {
		fmt.Fprintf(s.Conn, "501 Usage: SITE UNDUPE <release|filename>\r\n")
		return false
	}
	query := path.Base(strings.TrimSpace(strings.Join(args, " ")))
	dc, ok := s.DupeChecker.(interface{ Clear(string) error })
	if !ok || dc == nil {
		fmt.Fprintf(s.Conn, "550 Dupe checker is not enabled.\r\n")
		return false
	}
	var lastErr error
	for _, release := range undupeCandidates(query) {
		err := dc.Clear(release)
		if err == nil {
			fmt.Fprintf(s.Conn, "200 Removed %s from dupe database.\r\n", release)
			return false
		}
		lastErr = err
	}
	if lastErr == sql.ErrNoRows {
		fmt.Fprintf(s.Conn, "550 No dupe entry found for %s.\r\n", query)
		return false
	}
	fmt.Fprintf(s.Conn, "550 Could not undupe %s: %v\r\n", query, lastErr)
	return false
}

func (s *Session) HandleSiteWipe(args []string) bool {
	if len(args) < 1 || strings.TrimSpace(strings.Join(args, " ")) == "" {
		fmt.Fprintf(s.Conn, "501 Usage: SITE WIPE [-r] <path>\r\n")
		return false
	}
	if s.Config.Mode != "master" || s.MasterManager == nil {
		fmt.Fprintf(s.Conn, "550 SITE WIPE is only available in master mode.\r\n")
		return false
	}
	bridge, ok := s.MasterManager.(MasterBridge)
	if !ok {
		fmt.Fprintf(s.Conn, "550 Master not initialized.\r\n")
		return false
	}
	filtered := make([]string, 0, len(args))
	for _, arg := range args {
		if strings.EqualFold(strings.TrimSpace(arg), "-r") {
			continue
		}
		filtered = append(filtered, arg)
	}
	if len(filtered) == 0 || strings.TrimSpace(strings.Join(filtered, " ")) == "" {
		fmt.Fprintf(s.Conn, "501 Usage: SITE WIPE [-r] <path>\r\n")
		return false
	}
	target := resolveSitePath(s.CurrentDir, strings.TrimSpace(strings.Join(filtered, " ")))
	if target == "/" {
		fmt.Fprintf(s.Conn, "550 Refusing to wipe root.\r\n")
		return false
	}
	aclPath := path.Join(s.Config.ACLBasePath, target)
	if s.ACLEngine != nil && !s.ACLEngine.CanPerform(s.User, "DELETE", aclPath) {
		fmt.Fprintf(s.Conn, "550 Access Denied: Cannot wipe here.\r\n")
		return false
	}
	if err := cleanupAudioSortLinksForRelease(bridge, s.Config.Zipscript, target); err != nil && s.Config.Debug {
		log.Printf("[MASTER-ZS] audio sort cleanup skipped for %s: %v", target, err)
	}
	if err := bridge.DeleteFile(target); err != nil {
		fmt.Fprintf(s.Conn, "550 Wipe failed: %v\r\n", err)
		return false
	}
	fmt.Fprintf(s.Conn, "200 Wiped %s.\r\n", target)
	return false
}

func (s *Session) HandleSiteKick(args []string) bool {
	if len(args) < 1 || strings.TrimSpace(args[0]) == "" {
		fmt.Fprintf(s.Conn, "501 Usage: SITE KICK <username>\r\n")
		return false
	}
	if strings.EqualFold(args[0], s.User.Name) {
		fmt.Fprintf(s.Conn, "550 Cannot kick yourself.\r\n")
		return false
	}
	kicked := kickActiveUser(args[0])
	if kicked == 0 {
		fmt.Fprintf(s.Conn, "550 User %s is not online.\r\n", args[0])
		return false
	}
	fmt.Fprintf(s.Conn, "200 Kicked %d session(s) for %s.\r\n", kicked, args[0])
	return false
}

func listUserNames() ([]string, error) {
	entries, err := os.ReadDir(filepath.Join("etc", "users"))
	if err != nil {
		return nil, err
	}
	var names []string
	for _, entry := range entries {
		if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") || entry.Name() == "default.user" {
			continue
		}
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	return names, nil
}

func groupMembers(group string, groupMap map[string]int) ([]string, []string) {
	names, err := listUserNames()
	if err != nil {
		return nil, nil
	}
	var members []string
	var gadmins []string
	for _, name := range names {
		u, err := user.LoadUser(name, groupMap)
		if err != nil || !u.IsInGroup(group) {
			continue
		}
		members = append(members, u.Name)
		if u.IsGroupAdmin(group) {
			gadmins = append(gadmins, u.Name)
		}
	}
	sort.Strings(members)
	sort.Strings(gadmins)
	return members, gadmins
}

func countGroupMembers(group string) int {
	members, _ := groupMembers(group, LoadGroupFile("etc/group"))
	return len(members)
}

func countGroupLeechMembers(group string) int {
	members, _ := groupMembers(group, LoadGroupFile("etc/group"))
	count := 0
	for _, name := range members {
		u, err := user.LoadUser(name, LoadGroupFile("etc/group"))
		if err != nil {
			continue
		}
		if u.Ratio == 0 {
			count++
		}
	}
	return count
}

func undupeCandidates(name string) []string {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil
	}
	out := []string{name}
	lower := strings.ToLower(name)
	for _, suffix := range []string{".rar", ".zip", ".sfv", ".nfo", ".diz", ".mkv", ".mp4", ".avi"} {
		if strings.HasSuffix(lower, suffix) && len(name) > len(suffix) {
			out = append(out, name[:len(name)-len(suffix)])
			return uniqueStrings(out)
		}
	}
	if len(name) > 4 && lower[len(lower)-4] == '.' && lower[len(lower)-3] == 'r' &&
		lower[len(lower)-2] >= '0' && lower[len(lower)-2] <= '9' &&
		lower[len(lower)-1] >= '0' && lower[len(lower)-1] <= '9' {
		out = append(out, name[:len(name)-4])
	}
	return uniqueStrings(out)
}

func uniqueStrings(values []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		key := strings.ToLower(strings.TrimSpace(value))
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, strings.TrimSpace(value))
	}
	return out
}

func writeTrafficLine(s *Session, label string, up, dn user.StatLine) {
	fmt.Fprintf(s.Conn, "200- %-5s UL: %dF/%s DL: %dF/%s\r\n",
		label, up.Files, formatBytes(up.Bytes), dn.Files, formatBytes(dn.Bytes))
}

func userStatLineByKind(u *user.User, kind string) (user.StatLine, string) {
	switch strings.ToUpper(strings.TrimSpace(kind)) {
	case "ALLUP":
		return u.AllUp, u.StatExtras["ALLUP"]
	case "ALLDN":
		return u.AllDn, u.StatExtras["ALLDN"]
	case "WKUP":
		return u.WkUp, u.StatExtras["WKUP"]
	case "WKDN":
		return u.WkDn, u.StatExtras["WKDN"]
	case "DAYUP":
		return u.DayUp, u.StatExtras["DAYUP"]
	case "DAYDN":
		return u.DayDn, u.StatExtras["DAYDN"]
	case "MONTHUP":
		return u.MonthUp, u.StatExtras["MONTHUP"]
	case "MONTHDN":
		return u.MonthDn, u.StatExtras["MONTHDN"]
	default:
		return user.StatLine{}, ""
	}
}

func suffixWithSpace(extra string) string {
	extra = strings.TrimSpace(extra)
	if extra == "" {
		return ""
	}
	return " " + extra
}

func formatRatio(ratio int) string {
	if ratio == 0 {
		return "Unlimited"
	}
	return fmt.Sprintf("1:%d", ratio)
}

func formatBytes(bytes int64) string {
	if bytes >= 1<<40 {
		return fmt.Sprintf("%.2fTiB", float64(bytes)/float64(1<<40))
	}
	if bytes >= 1<<30 {
		return fmt.Sprintf("%.2fGiB", float64(bytes)/float64(1<<30))
	}
	if bytes >= 1<<20 {
		return fmt.Sprintf("%.1fMiB", float64(bytes)/float64(1<<20))
	}
	return fmt.Sprintf("%dB", bytes)
}

func formatUnixTime(sec int64) string {
	if sec <= 0 {
		return "never"
	}
	return timeutil.Unix(sec).Format("2006-01-02 15:04:05")
}

func formatAge(sec int64) string {
	if sec <= 0 {
		return "never"
	}
	d := time.Since(time.Unix(sec, 0))
	if d < 0 {
		d = 0
	}
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%dh%02dm", int(d.Hours()), int(d.Minutes())%60)
	}
	return fmt.Sprintf("%dd%02dh", int(d.Hours())/24, int(d.Hours())%24)
}
