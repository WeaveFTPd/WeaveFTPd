package core

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
	"weaveftpd/internal/user"
)

const defaultUserTemplate = "etc/users/default.user"
const deletedUsersDir = "etc/users/.deleted"

func (s *Session) emitUserChange(action, targetType, target, field, oldValue, newValue, detail string) {
	if s == nil || s.Config == nil {
		return
	}
	actor := ""
	if s.User != nil {
		actor = strings.TrimSpace(s.User.Name)
	}
	action = strings.ToUpper(strings.TrimSpace(action))
	targetType = strings.ToLower(strings.TrimSpace(targetType))
	target = strings.TrimSpace(target)
	field = strings.TrimSpace(field)
	oldValue = strings.TrimSpace(oldValue)
	newValue = strings.TrimSpace(newValue)
	detail = strings.TrimSpace(detail)

	parts := []string{}
	if action != "" {
		parts = append(parts, action)
	}
	if targetType != "" {
		parts = append(parts, targetType)
	}
	if target != "" {
		parts = append(parts, target)
	}
	if field != "" {
		parts = append(parts, field)
	}
	switch {
	case oldValue != "" && newValue != "":
		parts = append(parts, oldValue+" -> "+newValue)
	case newValue != "":
		parts = append(parts, newValue)
	case oldValue != "":
		parts = append(parts, oldValue)
	}
	if detail != "" {
		parts = append(parts, "("+detail+")")
	}
	if actor != "" {
		parts = append(parts, "by "+actor)
	}
	message := strings.Join(parts, " ")
	if message == "" {
		message = "user/group settings changed"
	}
	s.emitEvent(EventUserChange, "", "", 0, 0, map[string]string{
		"actor":       actor,
		"action":      action,
		"target_type": targetType,
		"target":      target,
		"field":       field,
		"old_value":   oldValue,
		"new_value":   newValue,
		"detail":      detail,
		"message":     message,
	})
}

func sortedUserGroups(u *user.User) []string {
	if u == nil || len(u.Groups) == 0 {
		return nil
	}
	groups := make([]string, 0, len(u.Groups))
	for group := range u.Groups {
		groups = append(groups, group)
	}
	sort.Strings(groups)
	return groups
}

func deletedUserPath(username string) string {
	return filepath.Join(deletedUsersDir, username)
}

func deletedUserPasswdPath(username string) string {
	return filepath.Join(deletedUsersDir, username+".passwd")
}

func listDeletedUsers() ([]string, error) {
	entries, err := os.ReadDir(deletedUsersDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	users := make([]string, 0, len(entries))
	for _, entry := range entries {
		name := strings.TrimSpace(entry.Name())
		if name == "" || entry.IsDir() || strings.HasSuffix(name, ".passwd") {
			continue
		}
		if _, err := user.NormalizeName(name); err != nil {
			continue
		}
		users = append(users, name)
	}
	sort.Strings(users)
	return users, nil
}

func createUserFromArgs(s *Session, username, plaintextPassword, primaryGroup string, ipArgs []string) (*user.User, string, error) {
	var err error
	username, err = user.NormalizeName(username)
	if err != nil {
		return nil, "", err
	}
	if strings.TrimSpace(primaryGroup) != "" {
		primaryGroup, err = normalizeSiteGroupName(primaryGroup)
		if err != nil {
			return nil, "", err
		}
	}

	hashedPass, err := HashPassword(plaintextPassword)
	if err != nil {
		return nil, "", err
	}

	var ips []string
	for _, rawIP := range ipArgs {
		ip := normalizeUserIP(rawIP)
		if ip == "" {
			return nil, "", fmt.Errorf("invalid IP mask %q", strings.TrimSpace(rawIP))
		}
		ips = append(ips, ip)
	}
	if len(ips) == 0 {
		ips = []string{"*@*"}
	}

	newUser, err := user.LoadTemplate(username, defaultUserTemplate, s.GroupMap)
	if err != nil {
		newUser = &user.User{
			Name:         username,
			Flags:        "3",
			Tagline:      "No Tagline Set",
			HomeRoot:     "/site",
			HomeDir:      "/",
			Groups:       map[string]int{"NoGroup": 0},
			PrimaryGroup: "NoGroup",
			Credits:      15000,
			Ratio:        3,
			LoginSlots:   7,
			MaxSim:       0,
			// Few, fast streams beat many slow ones: a racer's line is fixed, so
			// more upload slots just divide it into thinner streams that each take
			// longer, hold a file locked for longer, and are more likely to trip
			// the slow-transfer floor. 3 matches the drftpd/scene convention.
			UploadSlots:   3,
			DownloadSlots: 3,
			GroupSlots:    0,
			LeechSlots:    0,
		}
	}
	newUser.Name = username
	newUser.Password = hashedPass
	newUser.IPs = ips
	newUser.Added = time.Now().Unix()
	if newUser.Groups == nil {
		newUser.Groups = make(map[string]int)
	}
	if primaryGroup != "" {
		newUser.PrimaryGroup = primaryGroup
		if gid, ok := s.GroupMap[primaryGroup]; ok {
			newUser.GID = gid
		}
		newUser.Groups[primaryGroup] = 0
		dropDefaultNoGroupSecondary(newUser.Groups, primaryGroup)
	} else if newUser.PrimaryGroup != "" {
		if _, ok := newUser.Groups[newUser.PrimaryGroup]; !ok {
			newUser.Groups[newUser.PrimaryGroup] = 0
		}
	}
	return newUser, hashedPass, nil
}

func (s *Session) HandleSiteAddUser(args []string) bool {
	if !s.User.HasFlag("1") {
		fmt.Fprintf(s.Conn, "550 Access denied.\r\n")
		return false
	}
	if len(args) < 2 {
		fmt.Fprintf(s.Conn, "501 Usage: SITE ADDUSER <n> <pass> [ident@ip ...]\r\n")
		return false
	}
	username, err := user.NormalizeName(args[0])
	if err != nil {
		fmt.Fprintf(s.Conn, "550 Invalid username %q.\r\n", strings.TrimSpace(args[0]))
		return false
	}

	// Check if user already exists
	if _, err := user.LoadUser(username, s.GroupMap); err == nil {
		fmt.Fprintf(s.Conn, "550 User %s already exists. Use SITE CHPASS or SITE ADDIP.\r\n", username)
		return false
	}

	newUser, hashedPass, err := createUserFromArgs(s, username, args[1], "", args[2:])
	if err != nil {
		fmt.Fprintf(s.Conn, "550 Failed to create user %s: %v\r\n", username, err)
		return false
	}
	if err := newUser.Save(); err != nil {
		fmt.Fprintf(s.Conn, "550 Failed to save user %s: %v\r\n", username, err)
		return false
	}

	if err := AddUserToPasswd(newUser.Name, hashedPass, s.Config.PasswdFile); err != nil {
		_ = os.Remove(filepath.Join("etc", "users", newUser.Name))
		fmt.Fprintf(s.Conn, "550 Failed to update passwd for %s: %v\r\n", newUser.Name, err)
		return false
	}

	fmt.Fprintf(s.Conn, "200 User %s added with %d IP(s).\r\n", newUser.Name, len(newUser.IPs))
	s.emitUserChange("ADDUSER", "user", newUser.Name, "", "", "", fmt.Sprintf("group=%s ips=%d", newUser.PrimaryGroup, len(newUser.IPs)))
	return false
}

// groupExists reports whether groupName is a known group. It checks the
// session's cached GroupMap first, and on a miss re-reads etc/group from disk
// so that groups created after this session logged in (by GRPADD in another
// session, or an out-of-band edit) are still recognized instead of wrongly
// reported as "not found".
func (s *Session) groupExists(groupName string) bool {
	if _, ok := s.GroupMap[groupName]; ok {
		return true
	}
	fresh := LoadGroupFile("etc/group")
	if gid, ok := fresh[groupName]; ok {
		if s.GroupMap == nil {
			s.GroupMap = fresh
		} else {
			s.GroupMap[groupName] = gid
		}
		return true
	}
	return false
}

func (s *Session) HandleSiteGAddUser(args []string) bool {
	if len(args) < 3 {
		fmt.Fprintf(s.Conn, "501 Usage: SITE GADDUSER <user> <pass> <group> [ident@ip ...]\r\n")
		return false
	}
	username, err := user.NormalizeName(args[0])
	if err != nil {
		fmt.Fprintf(s.Conn, "550 Invalid username %q.\r\n", strings.TrimSpace(args[0]))
		return false
	}
	groupName, err := normalizeSiteGroupName(args[2])
	if err != nil {
		fmt.Fprintf(s.Conn, "550 Invalid group name %q.\r\n", strings.TrimSpace(args[2]))
		return false
	}
	if !s.User.HasFlag("1") && !s.canManageGroup(groupName) {
		fmt.Fprintf(s.Conn, "550 Access denied.\r\n")
		return false
	}
	if !s.groupExists(groupName) {
		fmt.Fprintf(s.Conn, "550 Group %s not found.\r\n", groupName)
		return false
	}
	if !s.User.HasFlag("1") {
		if !s.hasFreeGroupSlot(groupName) {
			fmt.Fprintf(s.Conn, "550 No group slots left for %s.\r\n", groupName)
			return false
		}
	}
	if _, err := user.LoadUser(username, s.GroupMap); err == nil {
		fmt.Fprintf(s.Conn, "550 User %s already exists.\r\n", username)
		return false
	}
	newUser, hashedPass, err := createUserFromArgs(s, username, args[1], groupName, args[3:])
	if err != nil {
		fmt.Fprintf(s.Conn, "550 Failed to create user %s: %v\r\n", username, err)
		return false
	}
	if err := newUser.Save(); err != nil {
		fmt.Fprintf(s.Conn, "550 Failed to save user %s: %v\r\n", username, err)
		return false
	}
	if err := AddUserToPasswd(newUser.Name, hashedPass, s.Config.PasswdFile); err != nil {
		_ = os.Remove(filepath.Join("etc", "users", newUser.Name))
		fmt.Fprintf(s.Conn, "550 Failed to update passwd for %s: %v\r\n", newUser.Name, err)
		return false
	}
	fmt.Fprintf(s.Conn, "200 User %s added to group %s with %d IP(s).\r\n", newUser.Name, groupName, len(newUser.IPs))
	s.emitUserChange("GADDUSER", "user", newUser.Name, "primary_group", "", newUser.PrimaryGroup, fmt.Sprintf("ips=%d", len(newUser.IPs)))
	return false
}

func (s *Session) HandleSiteGrpAdd(args []string) bool {
	if !s.User.HasFlag("1") {
		fmt.Fprintf(s.Conn, "550 Access denied.\r\n")
		return false
	}
	if len(args) < 1 {
		fmt.Fprintf(s.Conn, "501 Usage: SITE GRPADD <groupname> [description]\r\n")
		return false
	}
	groupName, err := normalizeSiteGroupName(args[0])
	if err != nil {
		fmt.Fprintf(s.Conn, "550 Invalid group name %q.\r\n", strings.TrimSpace(args[0]))
		return false
	}
	if s.GroupMap == nil {
		s.GroupMap = LoadGroupFile("etc/group")
	}
	if _, ok := s.GroupMap[groupName]; ok {
		fmt.Fprintf(s.Conn, "550 Group %s already exists.\r\n", groupName)
		return false
	}
	if _, ok := LoadGroupFile("etc/group")[groupName]; ok {
		fmt.Fprintf(s.Conn, "550 Group %s already exists.\r\n", groupName)
		return false
	}
	if _, err := os.Stat(filepath.Join("etc", "groups", groupName)); err == nil {
		fmt.Fprintf(s.Conn, "550 Group %s already exists.\r\n", groupName)
		return false
	} else if !os.IsNotExist(err) {
		fmt.Fprintf(s.Conn, "550 Failed to check group %s: %v\r\n", groupName, err)
		return false
	}
	desc := groupName
	if len(args) > 1 {
		desc = strings.Join(args[1:], " ")
	}
	nextGID := 100
	for _, gid := range s.GroupMap {
		if gid >= nextGID {
			nextGID = gid + 100
		}
	}
	groupCfg := &GroupFile{
		Name:           groupName,
		Slots:          -1,
		LeechSlots:     0,
		AllotmentSlots: 0,
		MaxAllotment:   0,
		GroupNFO:       desc,
		Simult:         0,
	}
	if err := groupCfg.Save(); err != nil {
		fmt.Fprintf(s.Conn, "550 Failed to create group %s: %v\r\n", groupName, err)
		return false
	}
	if err := AddGroupToFile(groupName, desc, nextGID); err != nil {
		_ = os.Remove(filepath.Join("etc", "groups", groupName))
		fmt.Fprintf(s.Conn, "550 Failed to add group %s to etc/group: %v\r\n", groupName, err)
		return false
	}
	s.GroupMap[groupName] = nextGID
	fmt.Fprintf(s.Conn, "200 Group %s added.\r\n", groupName)
	s.emitUserChange("GRPADD", "group", groupName, "description", "", desc, fmt.Sprintf("gid=%d", nextGID))
	return false
}

func (s *Session) HandleSiteGrpDel(args []string) bool {
	if !s.User.HasFlag("1") {
		fmt.Fprintf(s.Conn, "550 Access denied.\r\n")
		return false
	}
	if len(args) < 1 {
		fmt.Fprintf(s.Conn, "501 Usage: SITE GRPDEL <groupname>\r\n")
		return false
	}
	groupName, err := normalizeSiteGroupName(args[0])
	if err != nil {
		fmt.Fprintf(s.Conn, "550 Invalid group name %q.\r\n", strings.TrimSpace(args[0]))
		return false
	}
	groupMap := s.GroupMap
	if groupMap == nil {
		groupMap = LoadGroupFile("etc/group")
	}
	if _, ok := groupMap[groupName]; !ok {
		if _, ok := LoadGroupFile("etc/group")[groupName]; !ok {
			if _, err := os.Stat(filepath.Join("etc", "groups", groupName)); os.IsNotExist(err) {
				fmt.Fprintf(s.Conn, "550 Group %s not found.\r\n", groupName)
				return false
			} else if err != nil {
				fmt.Fprintf(s.Conn, "550 Failed to check group %s: %v\r\n", groupName, err)
				return false
			}
		}
	}
	if members, _ := groupMembers(groupName, groupMap); len(members) > 0 {
		fmt.Fprintf(s.Conn, "550 Group %s still has %d member(s): %s.\r\n", groupName, len(members), formatGroupMemberPreview(members))
		return false
	}
	groupPath := filepath.Join("etc", "groups", groupName)
	groupData, readGroupErr := os.ReadFile(groupPath)
	hadGroupFile := readGroupErr == nil
	groupMode := os.FileMode(0644)
	if st, err := os.Stat(groupPath); err == nil {
		groupMode = st.Mode().Perm()
	}
	if err := os.Remove(groupPath); err != nil && !os.IsNotExist(err) {
		fmt.Fprintf(s.Conn, "550 Failed to remove group file %s: %v\r\n", groupName, err)
		return false
	}
	if err := RemoveGroupFromFile(groupName); err != nil {
		if hadGroupFile {
			_ = atomicWriteFile(groupPath, groupData, groupMode)
		}
		fmt.Fprintf(s.Conn, "550 Failed to remove group from etc/group: %v\r\n", err)
		return false
	}
	delete(s.GroupMap, groupName)
	fmt.Fprintf(s.Conn, "200 Group %s deleted.\r\n", groupName)
	s.emitUserChange("GRPDEL", "group", groupName, "", "", "", "")
	return false
}

func (s *Session) HandleSiteChGrp(args []string) bool {
	if !s.User.HasFlag("1") {
		fmt.Fprintf(s.Conn, "550 Access denied.\r\n")
		return false
	}
	if len(args) < 2 {
		fmt.Fprintf(s.Conn, "501 Usage: SITE CHGRP <user> <group> [group2 ...]\r\n")
		return false
	}
	username, err := user.NormalizeName(args[0])
	if err != nil {
		fmt.Fprintf(s.Conn, "550 Invalid username %q.\r\n", strings.TrimSpace(args[0]))
		return false
	}
	targetUser, err := user.LoadUser(username, s.GroupMap)
	if err != nil {
		fmt.Fprintf(s.Conn, "550 User not found.\r\n")
		return false
	}
	oldGroups := strings.Join(sortedUserGroups(targetUser), ",")
	oldPrimary := targetUser.PrimaryGroup

	nextGroups := make(map[string]int, len(targetUser.Groups))
	for group, admin := range targetUser.Groups {
		nextGroups[group] = admin
	}

	// Toggle group membership (drftpd style): if in group, remove; if not, add.
	// Validate first and apply to a copy so a failing command cannot leave the
	// in-memory user different from what is on disk.
	var added, removed []string
	for _, rawGroup := range args[1:] {
		grp, err := normalizeSiteGroupName(rawGroup)
		if err != nil {
			fmt.Fprintf(s.Conn, "550 Invalid group name %q.\r\n", strings.TrimSpace(rawGroup))
			return false
		}
		if _, inGroup := nextGroups[grp]; inGroup {
			delete(nextGroups, grp)
			removed = append(removed, grp)
		} else {
			if _, ok := s.GroupMap[grp]; !ok {
				fmt.Fprintf(s.Conn, "550 Group %s does not exist.\r\n", grp)
				return false
			}
			nextGroups[grp] = 0
			added = append(added, grp)
		}
	}
	newPrimary := targetUser.PrimaryGroup
	if newPrimary != "" {
		if _, ok := nextGroups[newPrimary]; !ok {
			promoted := pickPrimaryGroupAfterCHGRP(nextGroups, added)
			if promoted == "" {
				fmt.Fprintf(s.Conn, "550 Cannot remove %s from %s because it is the primary group and no other group remains.\r\n", newPrimary, targetUser.Name)
				return false
			}
			newPrimary = promoted
		}
	}
	targetUser.Groups = nextGroups
	targetUser.PrimaryGroup = newPrimary
	if gid, ok := s.GroupMap[newPrimary]; ok {
		targetUser.GID = gid
	}
	if err := targetUser.Save(); err != nil {
		fmt.Fprintf(s.Conn, "550 Failed to save user %s: %v\r\n", targetUser.Name, err)
		return false
	}

	msg := fmt.Sprintf("200 %s:", targetUser.Name)
	if len(added) > 0 {
		msg += " added " + strings.Join(added, ",")
	}
	if len(removed) > 0 {
		msg += " removed " + strings.Join(removed, ",")
	}
	if oldPrimary != targetUser.PrimaryGroup {
		msg += " primary " + oldPrimary + "->" + targetUser.PrimaryGroup
	}
	fmt.Fprintf(s.Conn, "%s.\r\n", msg)
	detailParts := []string{}
	if len(added) > 0 {
		detailParts = append(detailParts, "added="+strings.Join(added, ","))
	}
	if len(removed) > 0 {
		detailParts = append(detailParts, "removed="+strings.Join(removed, ","))
	}
	if oldPrimary != targetUser.PrimaryGroup {
		detailParts = append(detailParts, "primary="+oldPrimary+"->"+targetUser.PrimaryGroup)
	}
	s.emitUserChange("CHGRP", "user", targetUser.Name, "groups", oldGroups, strings.Join(sortedUserGroups(targetUser), ","), strings.Join(detailParts, " "))
	return false
}

func pickPrimaryGroupAfterCHGRP(groups map[string]int, preferred []string) string {
	for _, group := range preferred {
		if _, ok := groups[group]; ok {
			return group
		}
	}
	names := make([]string, 0, len(groups))
	for group := range groups {
		names = append(names, group)
	}
	sort.Strings(names)
	if len(names) == 0 {
		return ""
	}
	return names[0]
}

// HandleSiteFlags adds or removes flags from a user.
// Usage: SITE FLAGS <user> <+|-><flags>
// Examples:
//   SITE FLAGS N0pe +1      (add siteop flag)
//   SITE FLAGS N0pe -1      (remove siteop flag)
//   SITE FLAGS N0pe +1G     (add siteop and gadmin)
//   SITE FLAGS N0pe =13     (replace all flags with 1 and 3)

func (s *Session) HandleSiteFlags(args []string) bool {

	if s.Config.Debug {
		log.Printf("[SITE FLAGS] args=%q len=%d", args, len(args))
	}

	if !s.User.HasFlag("1") {
		fmt.Fprintf(s.Conn, "550 Access denied.\r\n")
		return false
	}
	if len(args) < 2 {
		fmt.Fprintf(s.Conn, "501 Usage: SITE FLAGS <user> <+|-|=><flags>\r\n")
		return false
	}

	targetUser, err := user.LoadUser(args[0], s.GroupMap)
	if err != nil {
		fmt.Fprintf(s.Conn, "550 User %s not found.\r\n", args[0])
		return false
	}

	op := args[1][0]
	if op != '+' && op != '-' && op != '=' {
		fmt.Fprintf(s.Conn, "501 First char must be +, -, or =\r\n")
		return false
	}
	flags := args[1][1:]
	oldFlags := targetUser.Flags

	switch op {
	case '=':
		targetUser.Flags = flags
	case '+':
		for _, f := range flags {
			if !strings.ContainsRune(targetUser.Flags, f) {
				targetUser.Flags += string(f)
			}
		}
	case '-':
		for _, f := range flags {
			targetUser.Flags = strings.ReplaceAll(targetUser.Flags, string(f), "")
		}
	}

	if err := targetUser.Save(); err != nil {
		fmt.Fprintf(s.Conn, "550 Failed to save flags for %s: %v\r\n", args[0], err)
		return false
	}
	fmt.Fprintf(s.Conn, "200 Flags for %s: %s\r\n", args[0], targetUser.Flags)
	s.emitUserChange("FLAGS", "user", targetUser.Name, "flags", oldFlags, targetUser.Flags, "op="+string(op)+flags)
	return false
}

func (s *Session) HandleSiteChPGrp(args []string) bool {
	if !s.User.HasFlag("1") {
		fmt.Fprintf(s.Conn, "550 Access denied.\r\n")
		return false
	}
	if len(args) < 2 {
		fmt.Fprintf(s.Conn, "501 Usage: SITE CHPGRP <user> <group>\r\n")
		return false
	}
	username, err := user.NormalizeName(args[0])
	if err != nil {
		fmt.Fprintf(s.Conn, "550 Invalid username %q.\r\n", strings.TrimSpace(args[0]))
		return false
	}
	groupName, err := normalizeSiteGroupName(args[1])
	if err != nil {
		fmt.Fprintf(s.Conn, "550 Invalid group name %q.\r\n", strings.TrimSpace(args[1]))
		return false
	}
	targetUser, err := user.LoadUser(username, s.GroupMap)
	if err != nil {
		fmt.Fprintf(s.Conn, "550 User not found.\r\n")
		return false
	}
	gid, ok := s.GroupMap[groupName]
	if !ok {
		fmt.Fprintf(s.Conn, "550 Group %s does not exist.\r\n", groupName)
		return false
	}
	oldPrimary := targetUser.PrimaryGroup
	targetUser.PrimaryGroup = groupName
	targetUser.GID = gid
	if targetUser.Groups == nil {
		targetUser.Groups = make(map[string]int)
	}
	targetUser.Groups[groupName] = 0
	dropDefaultNoGroupSecondary(targetUser.Groups, targetUser.PrimaryGroup)
	if err := targetUser.Save(); err != nil {
		fmt.Fprintf(s.Conn, "550 Failed to save primary group for %s: %v\r\n", targetUser.Name, err)
		return false
	}
	fmt.Fprintf(s.Conn, "200 Primary group changed.\r\n")
	s.emitUserChange("CHPGRP", "user", targetUser.Name, "primary_group", oldPrimary, targetUser.PrimaryGroup, "")
	return false
}

func dropDefaultNoGroupSecondary(groups map[string]int, primaryGroup string) {
	if groups == nil || isDefaultNoGroup(primaryGroup) {
		return
	}
	for group := range groups {
		if isDefaultNoGroup(group) {
			delete(groups, group)
		}
	}
}

func isDefaultNoGroup(group string) bool {
	return strings.EqualFold(strings.TrimSpace(group), "NoGroup")
}

func formatGroupMemberPreview(members []string) string {
	if len(members) == 0 {
		return ""
	}
	const maxShown = 5
	shown := members
	if len(shown) > maxShown {
		shown = shown[:maxShown]
	}
	out := strings.Join(shown, ",")
	if len(members) > maxShown {
		out += fmt.Sprintf(",+%d more", len(members)-maxShown)
	}
	return out
}

func (s *Session) HandleSiteGAdmin(args []string) bool {
	if !s.User.HasFlag("1") {
		fmt.Fprintf(s.Conn, "550 Access denied.\r\n")
		return false
	}
	if len(args) < 2 {
		fmt.Fprintf(s.Conn, "501 Usage: SITE GADMIN <group> <user>\r\n")
		return false
	}
	groupName, err := normalizeSiteGroupName(args[0])
	if err != nil {
		fmt.Fprintf(s.Conn, "550 Invalid group name %q.\r\n", strings.TrimSpace(args[0]))
		return false
	}
	targetUser, err := user.LoadUser(args[1], s.GroupMap)
	if err != nil {
		fmt.Fprintf(s.Conn, "550 User not found.\r\n")
		return false
	}
	if _, ok := s.GroupMap[groupName]; !ok {
		fmt.Fprintf(s.Conn, "550 Group %s does not exist.\r\n", groupName)
		return false
	}
	// The user must actually belong to the group before being made its admin;
	// previously this silently added them to an arbitrary group as admin.
	_, isMember := targetUser.Groups[groupName]
	if !isMember && !strings.EqualFold(targetUser.PrimaryGroup, groupName) {
		fmt.Fprintf(s.Conn, "550 %s is not a member of group %s.\r\n", targetUser.Name, groupName)
		return false
	}
	// Toggle: grant gadmin if not set, revoke it (keeping membership) if already set.
	oldAdmin := targetUser.Groups[groupName]
	newAdmin := 1
	if oldAdmin == 1 {
		newAdmin = 0
	}
	targetUser.Groups[groupName] = newAdmin
	if err := targetUser.Save(); err != nil {
		fmt.Fprintf(s.Conn, "550 Failed to save gadmin for %s: %v\r\n", args[1], err)
		return false
	}
	verb := "granted"
	if newAdmin == 0 {
		verb = "revoked"
	}
	fmt.Fprintf(s.Conn, "200 Gadmin %s for %s on group %s.\r\n", verb, targetUser.Name, groupName)
	s.emitUserChange("GADMIN", "user", targetUser.Name, "group_admin", fmt.Sprintf("%d", oldAdmin), fmt.Sprintf("%s=%d", groupName, newAdmin), "")
	return false
}

// HandleSiteChPass changes a user's password.
// Usage: SITE CHPASS <user> <newpass>
func (s *Session) HandleSiteChPass(args []string) bool {
	if !s.User.HasFlag("1") {
		fmt.Fprintf(s.Conn, "550 Access denied.\r\n")
		return false
	}
	if len(args) < 2 {
		fmt.Fprintf(s.Conn, "501 Usage: SITE CHPASS <user> <newpass>\r\n")
		return false
	}

	username, err := user.NormalizeName(args[0])
	if err != nil {
		fmt.Fprintf(s.Conn, "550 Invalid username %q.\r\n", strings.TrimSpace(args[0]))
		return false
	}

	u, err := user.LoadUser(username, s.GroupMap)
	if err != nil {
		fmt.Fprintf(s.Conn, "550 User %s not found.\r\n", username)
		return false
	}

	hashedPass, err := HashPassword(args[1])
	if err != nil {
		fmt.Fprintf(s.Conn, "550 Failed to hash password: %v\r\n", err)
		return false
	}

	if err := AddUserToPasswd(u.Name, hashedPass, s.Config.PasswdFile); err != nil {
		fmt.Fprintf(s.Conn, "550 Failed to update passwd for %s: %v\r\n", u.Name, err)
		return false
	}

	fmt.Fprintf(s.Conn, "200 Password changed for %s.\r\n", u.Name)
	s.emitUserChange("CHPASS", "user", u.Name, "password", "", "changed", "")
	return false
}

// HandleSiteChRatio changes a user's ratio.
// Usage: SITE CHRATIO <user> <ratio>
func (s *Session) HandleSiteChRatio(args []string) bool {
	if len(args) < 2 {
		fmt.Fprintf(s.Conn, "501 Usage: SITE CHRATIO <user> <ratio>\r\n")
		return false
	}

	u, err := user.LoadUser(args[0], s.GroupMap)
	if err != nil {
		fmt.Fprintf(s.Conn, "550 User %s not found.\r\n", args[0])
		return false
	}

	ratio, err := parseSiteRatio(args[1])
	if err != nil {
		fmt.Fprintf(s.Conn, "550 Invalid ratio %q. Use a whole number >= 0.\r\n", args[1])
		return false
	}

	if !s.User.HasFlag("1") {
		if ratio != 0 {
			fmt.Fprintf(s.Conn, "550 Access denied.\r\n")
			return false
		}
		if !s.canGrantManagedLeech(u) {
			fmt.Fprintf(s.Conn, "550 No free leech slots available for that group.\r\n")
			return false
		}
	}

	oldRatio := u.Ratio
	u.Ratio = ratio
	if err := u.Save(); err != nil {
		fmt.Fprintf(s.Conn, "550 Failed to save ratio for %s: %v\r\n", args[0], err)
		return false
	}

	fmt.Fprintf(s.Conn, "200 Ratio changed for %s: %d.\r\n", args[0], ratio)
	s.emitUserChange("CHRATIO", "user", u.Name, "ratio", fmt.Sprintf("%d", oldRatio), fmt.Sprintf("%d", ratio), "")
	return false
}

func (s *Session) HandleSiteChange(args []string) bool {
	if len(args) == 1 {
		switch strings.ToUpper(strings.TrimSpace(args[0])) {
		case "HELP", "?":
			fmt.Fprintf(s.Conn, "200 Usage: SITE CHANGE <user|group> <field> <value...>\r\n")
			fmt.Fprintf(s.Conn, "200 Supported CHANGE fields: %s\r\n", siteChangeFieldSummary())
			return false
		}
	}
	if len(args) < 3 {
		fmt.Fprintf(s.Conn, "501 Usage: SITE CHANGE <user|group> <field> <value...>\r\n")
		fmt.Fprintf(s.Conn, "501 Supported CHANGE fields: %s\r\n", siteChangeFieldSummary())
		return false
	}
	field := strings.ToUpper(strings.TrimSpace(args[1]))
	switch field {
	case "RATIO":
		return s.HandleSiteChRatio([]string{args[0], args[2]})
	case "NUM_LOGINS":
		return s.HandleSiteChNumLogins([]string{args[0], args[2]})
	case "MAX_SIM":
		return s.HandleSiteChMaxSim([]string{args[0], args[2]})
	case "WKLY_ALLOTMENT":
		return s.HandleSiteChWklyAllotment([]string{args[0], args[2]})
	case "UPLOADSLOTS":
		return s.HandleSiteChUploadSlots([]string{args[0], args[2]})
	case "DOWNLOADSLOTS":
		return s.HandleSiteChDownloadSlots([]string{args[0], args[2]})
	case "GROUP_SLOTS":
		groupArgs := append([]string{args[0]}, args[2:]...)
		return s.HandleSiteGroupSlots(groupArgs)
	case "GROUP_SIMULT":
		return s.HandleSiteGroupSimult([]string{args[0], args[2]})
	case "TAGLINE":
		taglineArgs := append([]string{args[0]}, args[2:]...)
		return s.HandleSiteTagline(taglineArgs)
	default:
		fmt.Fprintf(s.Conn, "550 Unknown CHANGE field %s.\r\n", field)
		fmt.Fprintf(s.Conn, "550 Supported CHANGE fields: %s\r\n", siteChangeFieldSummary())
		return false
	}
}

func siteChangeFieldSummary() string {
	return "RATIO, NUM_LOGINS, MAX_SIM, WKLY_ALLOTMENT, UPLOADSLOTS, DOWNLOADSLOTS, GROUP_SLOTS, GROUP_SIMULT, TAGLINE"
}

func (s *Session) HandleSiteBan(args []string) bool {
	if !s.User.HasFlag("1") {
		fmt.Fprintf(s.Conn, "550 Access denied.\r\n")
		return false
	}
	if len(args) < 1 {
		fmt.Fprintf(s.Conn, "501 Usage: SITE BAN <user> [reason]\r\n")
		return false
	}
	target := strings.TrimSpace(args[0])
	if target == "" {
		fmt.Fprintf(s.Conn, "550 User is required.\r\n")
		return false
	}
	if _, err := user.LoadUser(target, s.GroupMap); err != nil {
		fmt.Fprintf(s.Conn, "550 User %s not found.\r\n", target)
		return false
	}
	reason := ""
	if len(args) > 1 {
		reason = strings.TrimSpace(strings.Join(args[1:], " "))
	}
	if reason == "" {
		reason = "Banned by siteop"
	}
	if err := AddUserBan(target, s.User.Name, reason); err != nil {
		fmt.Fprintf(s.Conn, "550 Failed to ban %s: %v\r\n", target, err)
		return false
	}
	fmt.Fprintf(s.Conn, "200 User %s banned.\r\n", target)
	s.emitUserChange("BAN", "user", target, "ban", "", "banned", reason)
	return false
}

func (s *Session) HandleSiteUnban(args []string) bool {
	if !s.User.HasFlag("1") {
		fmt.Fprintf(s.Conn, "550 Access denied.\r\n")
		return false
	}
	if len(args) < 1 {
		fmt.Fprintf(s.Conn, "501 Usage: SITE UNBAN <user>\r\n")
		return false
	}
	target := strings.TrimSpace(args[0])
	removed, err := RemoveUserBan(target)
	if err != nil {
		fmt.Fprintf(s.Conn, "550 Failed to unban %s: %v\r\n", target, err)
		return false
	}
	if !removed {
		fmt.Fprintf(s.Conn, "550 User %s is not banned.\r\n", target)
		return false
	}
	fmt.Fprintf(s.Conn, "200 User %s unbanned.\r\n", target)
	s.emitUserChange("UNBAN", "user", target, "ban", "banned", "unbanned", "")
	return false
}

type sitebotBlowfishConfig struct {
	IRC struct {
		Host     string `yaml:"host"`
		Port     int    `yaml:"port"`
		Nick     string `yaml:"nick"`
		Password string `yaml:"password"`
		SSL      bool   `yaml:"ssl"`
	} `yaml:"irc"`
	Encryption struct {
		PrivateKey string            `yaml:"private_key"`
		Keys       map[string]string `yaml:"keys"`
	} `yaml:"encryption"`
}

func (s *Session) loadSitebotBlowfishConfig() (*sitebotBlowfishConfig, error) {
	cfg := &sitebotBlowfishConfig{}
	if len(s.Config.BlowfishKeys) > 0 || strings.TrimSpace(s.Config.BlowfishPrivateKey) != "" {
		cfg.Encryption.PrivateKey = s.Config.BlowfishPrivateKey
		cfg.Encryption.Keys = s.Config.BlowfishKeys
	}
	if strings.TrimSpace(s.Config.SitebotConfig) == "" {
		if len(cfg.Encryption.Keys) == 0 && strings.TrimSpace(cfg.Encryption.PrivateKey) == "" {
			return nil, fmt.Errorf("neither blowfish_keys nor sitebot_config is configured")
		}
		return cfg, nil
	}
	data, err := os.ReadFile(filepath.Clean(s.Config.SitebotConfig))
	if err != nil {
		return nil, fmt.Errorf("could not read sitebot config: %w", err)
	}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("could not parse sitebot config: %w", err)
	}
	return cfg, nil
}

func renderSiteInfoBlock(w io.Writer, version, title string, lines []string) {
	width := 70

	infoRaw(w, infoLine(infoCpTL, infoCpHZ, infoCpTR, width))
	infoText(w, " __        __                    _____ _____ ____      _ ", width)
	infoText(w, " \\ \\      / /__  __ ___   _____ |  ___|_   _|  _ \\  __| | ", width)
	infoText(w, "  \\ \\ /\\ / / _ \\/ _` \\ \\ / / _ \\| |_    | | | |_) |/ _` | ", width)
	infoText(w, "   \\ V  V /  __/ (_| |\\ V /  __/|  _|   | | |  __/| (_| | ", width)
	infoText(w, "    \\_/\\_/ \\___|\\__,_| \\_/ \\___||_|     |_| |_|    \\__,_| ", width)
	infoText(w, fmt.Sprintf(" You are using WeaveFTPd v%s ", version), width)
	infoRaw(w, infoLine(infoCpLT, infoCpHZ, infoCpRT, width))
	infoText(w, fmt.Sprintf(" %s ", title), width)
	infoRaw(w, infoLine(infoCpLT, infoCpHZ, infoCpRT, width))
	for _, lineText := range lines {
		infoText(w, " "+strings.TrimSpace(lineText), width)
	}
	infoRaw(w, infoLine(infoCpBL, infoCpHZ, infoCpBR, width))
}

const (
	infoCpTL = byte(0xDA)
	infoCpTR = byte(0xBF)
	infoCpBL = byte(0xC0)
	infoCpBR = byte(0xD9)
	infoCpHZ = byte(0xC4)
	infoCpVT = byte(0xB3)
	infoCpLT = byte(0xC3)
	infoCpRT = byte(0xB4)
)

func infoLine(l, fill, r byte, n int) []byte {
	b := make([]byte, 0, n+2)
	b = append(b, l)
	for i := 0; i < n; i++ {
		b = append(b, fill)
	}
	b = append(b, r)
	return b
}

func infoRaw(w io.Writer, b []byte) {
	w.Write(append(b, '\r', '\n'))
}

func infoText(w io.Writer, s string, width int) {
	buf := []byte{infoCpVT}
	buf = append(buf, []byte(fmt.Sprintf("%-*s", width, s))...)
	buf = append(buf, infoCpVT, '\r', '\n')
	w.Write(buf)
}

func (s *Session) HandleSiteBlowfish(args []string) bool {
	cfg, err := s.loadSitebotBlowfishConfig()
	if err != nil {
		fmt.Fprintf(s.Conn, "550 %v\r\n", err)
		return false
	}
	filter := ""
	if len(args) > 0 {
		filter = strings.TrimSpace(args[0])
	}
	var lines []string
	if cfg.Encryption.PrivateKey != "" && (filter == "" || strings.EqualFold(filter, "PM") || strings.EqualFold(filter, "PRIVATE")) {
		lines = append(lines, fmt.Sprintf("PM/NOTICE  %s", cfg.Encryption.PrivateKey))
	}
	channels := make([]string, 0, len(cfg.Encryption.Keys))
	for channel := range cfg.Encryption.Keys {
		channels = append(channels, channel)
	}
	sort.Strings(channels)
	for _, channel := range channels {
		if filter != "" && !strings.EqualFold(filter, channel) {
			continue
		}
		lines = append(lines, fmt.Sprintf("%-12s %s", channel, cfg.Encryption.Keys[channel]))
	}
	if len(lines) == 0 {
		lines = append(lines, "No matching blowfish keys configured.")
	}
	RenderFTPReplyBlock(s.Conn, 200, "End of blowfish keys.", func(w io.Writer) {
		renderSiteInfoBlock(w, s.Config.Version, "Blowfish Keys", lines)
	})
	return false
}

func (s *Session) HandleSiteIRC(args []string) bool {
	cfg, err := s.loadSitebotBlowfishConfig()
	if err != nil {
		fmt.Fprintf(s.Conn, "550 %v\r\n", err)
		return false
	}
	password := cfg.IRC.Password
	if strings.TrimSpace(password) == "" {
		password = "(none)"
	}
	sslMode := "off"
	if cfg.IRC.SSL {
		sslMode = "on"
	}
	lines := []string{
		fmt.Sprintf("Server     %s", fallbackSiteInfoValue(cfg.IRC.Host)),
		fmt.Sprintf("Port       %s", fallbackSiteInfoValue(fmt.Sprintf("%d", cfg.IRC.Port))),
		fmt.Sprintf("SSL        %s", sslMode),
		fmt.Sprintf("Nick       %s", fallbackSiteInfoValue(cfg.IRC.Nick)),
		fmt.Sprintf("Password   %s", password),
	}
	RenderFTPReplyBlock(s.Conn, 200, "End of IRC info.", func(w io.Writer) {
		renderSiteInfoBlock(w, s.Config.Version, "IRC Info", lines)
	})
	return false
}

func fallbackSiteInfoValue(v string) string {
	v = strings.TrimSpace(v)
	if v == "" || v == "0" {
		return "(unset)"
	}
	return v
}

// HandleSiteAddIP adds one or more IPs to an existing user.
// Usage: SITE ADDIP <user> <ident@ip> [ident@ip ...]
func (s *Session) HandleSiteAddIP(args []string) bool {
	if !s.User.HasFlag("1") {
		fmt.Fprintf(s.Conn, "550 Access denied.\r\n")
		return false
	}
	if len(args) < 2 {
		fmt.Fprintf(s.Conn, "501 Usage: SITE ADDIP <user> <ident@ip> [ident@ip ...]\r\n")
		return false
	}

	u, err := user.LoadUser(args[0], s.GroupMap)
	if err != nil {
		fmt.Fprintf(s.Conn, "550 User %s not found.\r\n", args[0])
		return false
	}

	added := 0
	addedIPs := []string{}
	for _, rawIP := range args[1:] {
		ip := normalizeUserIP(rawIP)
		if ip == "" {
			fmt.Fprintf(s.Conn, "550 Invalid IP mask %q.\r\n", strings.TrimSpace(rawIP))
			return false
		}
		// Skip if already present
		exists := false
		for _, existing := range u.IPs {
			if existing == ip {
				exists = true
				break
			}
		}
		if !exists {
			u.IPs = append(u.IPs, ip)
			added++
			addedIPs = append(addedIPs, ip)
		}
	}

	if err := saveUserIPsOnly(u.Name, u.IPs); err != nil {
		fmt.Fprintf(s.Conn, "550 Failed to save IPs for %s: %v\r\n", args[0], err)
		return false
	}
	fmt.Fprintf(s.Conn, "200 Added %d IP(s) to %s (total: %d).\r\n", added, args[0], len(u.IPs))
	if added > 0 {
		s.emitUserChange("ADDIP", "user", u.Name, "ip", "", strings.Join(addedIPs, ","), fmt.Sprintf("total=%d", len(u.IPs)))
	}
	return false
}

// HandleSiteDelIP removes one or more IPs from a user.
// Usage: SITE DELIP <user> <ident@ip> [ident@ip ...]
func (s *Session) HandleSiteDelIP(args []string) bool {
	if !s.User.HasFlag("1") {
		fmt.Fprintf(s.Conn, "550 Access denied.\r\n")
		return false
	}
	if len(args) < 2 {
		fmt.Fprintf(s.Conn, "501 Usage: SITE DELIP <user> <ident@ip> [ident@ip ...]\r\n")
		return false
	}

	u, err := user.LoadUser(args[0], s.GroupMap)
	if err != nil {
		fmt.Fprintf(s.Conn, "550 User %s not found.\r\n", args[0])
		return false
	}

	removed := 0
	removedIPs := []string{}
	for _, rawIP := range args[1:] {
		ip := normalizeUserIP(rawIP)
		if ip == "" {
			fmt.Fprintf(s.Conn, "550 Invalid IP mask %q.\r\n", strings.TrimSpace(rawIP))
			return false
		}
		for i, existing := range u.IPs {
			if existing == ip {
				u.IPs = append(u.IPs[:i], u.IPs[i+1:]...)
				removed++
				removedIPs = append(removedIPs, ip)
				break
			}
		}
	}

	if err := saveUserIPsOnly(u.Name, u.IPs); err != nil {
		fmt.Fprintf(s.Conn, "550 Failed to save IPs for %s: %v\r\n", args[0], err)
		return false
	}
	fmt.Fprintf(s.Conn, "200 Removed %d IP(s) from %s (remaining: %d).\r\n", removed, args[0], len(u.IPs))
	if removed > 0 {
		s.emitUserChange("DELIP", "user", u.Name, "ip", strings.Join(removedIPs, ","), "", fmt.Sprintf("remaining=%d", len(u.IPs)))
	}
	return false
}

func (s *Session) HandleSiteSelfIP(args []string) bool {
	// No flag gate: SELFIP is self-service and authenticates the caller with the
	// target account's own password below (authenticateSelfIPUser). Requiring the
	// siteop flag made it unusable for the ordinary users it exists for.
	if len(args) < 3 {
		fmt.Fprintf(s.Conn, "501 Usage: SITE SELFIP <LIST|ADD|DEL|CHG> <user> <pass> [args]\r\n")
		return false
	}

	action := strings.ToUpper(strings.TrimSpace(args[0]))
	username := strings.TrimSpace(args[1])
	password := args[2]

	targetUser, authReason := s.authenticateSelfIPUser(username, password)
	if targetUser == nil {
		fmt.Fprintf(s.Conn, "550 Authentication failed: %s.\r\n", authReason)
		return false
	}

	switch action {
	case "LIST":
		fmt.Fprintf(s.Conn, "200- IPs for %s:\r\n", targetUser.Name)
		if len(targetUser.IPs) == 0 {
			fmt.Fprintf(s.Conn, "200- No IPs configured.\r\n")
		}
		for i, ip := range targetUser.IPs {
			fmt.Fprintf(s.Conn, "200- [%02d] %s\r\n", i+1, ip)
		}
		fmt.Fprintf(s.Conn, "200 End of IP list.\r\n")
		return false
	case "ADD":
		if len(args) < 4 {
			fmt.Fprintf(s.Conn, "501 Usage: SITE SELFIP ADD <user> <pass> <ident@ip> [ident@ip ...]\r\n")
			return false
		}
		added := 0
		for _, ip := range args[3:] {
			ip = normalizeUserIP(ip)
			if ip == "" || containsExact(targetUser.IPs, ip) {
				continue
			}
			targetUser.IPs = append(targetUser.IPs, ip)
			added++
		}
		if err := saveUserIPsOnly(targetUser.Name, targetUser.IPs); err != nil {
			fmt.Fprintf(s.Conn, "550 Failed to save IPs for %s: %v\r\n", targetUser.Name, err)
			return false
		}
		if added > 0 {
			s.emitSelfIPChange(targetUser.Name, "ADD", "", strings.Join(args[3:], ", "), added)
		}
		fmt.Fprintf(s.Conn, "200 Added %d IP(s) to %s (total: %d).\r\n", added, targetUser.Name, len(targetUser.IPs))
		return false
	case "DEL":
		if len(args) < 4 {
			fmt.Fprintf(s.Conn, "501 Usage: SITE SELFIP DEL <user> <pass> <ident@ip> [ident@ip ...]\r\n")
			return false
		}
		removed := 0
		for _, ip := range args[3:] {
			ip = normalizeUserIP(ip)
			for i, existing := range targetUser.IPs {
				if existing == ip {
					targetUser.IPs = append(targetUser.IPs[:i], targetUser.IPs[i+1:]...)
					removed++
					break
				}
			}
		}
		if err := saveUserIPsOnly(targetUser.Name, targetUser.IPs); err != nil {
			fmt.Fprintf(s.Conn, "550 Failed to save IPs for %s: %v\r\n", targetUser.Name, err)
			return false
		}
		if removed > 0 {
			s.emitSelfIPChange(targetUser.Name, "DEL", strings.Join(args[3:], ", "), "", removed)
		}
		fmt.Fprintf(s.Conn, "200 Removed %d IP(s) from %s (remaining: %d).\r\n", removed, targetUser.Name, len(targetUser.IPs))
		return false
	case "CHG", "CHANGE":
		if len(args) < 5 {
			fmt.Fprintf(s.Conn, "501 Usage: SITE SELFIP CHG <user> <pass> <oldip> <newip>\r\n")
			return false
		}
		oldIP := normalizeUserIP(args[3])
		newIP := normalizeUserIP(args[4])
		if oldIP == "" || newIP == "" {
			fmt.Fprintf(s.Conn, "550 Invalid IP argument.\r\n")
			return false
		}
		replaced := false
		for i, existing := range targetUser.IPs {
			if existing == oldIP {
				targetUser.IPs[i] = newIP
				replaced = true
				break
			}
		}
		if !replaced {
			fmt.Fprintf(s.Conn, "550 IP %s not found on %s.\r\n", oldIP, targetUser.Name)
			return false
		}
		if err := saveUserIPsOnly(targetUser.Name, targetUser.IPs); err != nil {
			fmt.Fprintf(s.Conn, "550 Failed to save IPs for %s: %v\r\n", targetUser.Name, err)
			return false
		}
		s.emitSelfIPChange(targetUser.Name, "CHG", oldIP, newIP, 1)
		fmt.Fprintf(s.Conn, "200 Changed IP for %s: %s -> %s.\r\n", targetUser.Name, oldIP, newIP)
		return false
	default:
		fmt.Fprintf(s.Conn, "501 Usage: SITE SELFIP <LIST|ADD|DEL|CHG> <user> <pass> [args]\r\n")
		return false
	}
}

func saveUserIPsOnly(username string, ips []string) error {
	username = strings.TrimSpace(username)
	if username == "" {
		return fmt.Errorf("empty username")
	}
	normalized := make([]string, 0, len(ips))
	seen := make(map[string]struct{}, len(ips))
	for _, ip := range ips {
		ip = strings.TrimSpace(ip)
		if ip == "" {
			continue
		}
		if _, ok := seen[ip]; ok {
			continue
		}
		seen[ip] = struct{}{}
		normalized = append(normalized, ip)
	}
	sort.Strings(normalized)

	return user.WithFileLock(username, func() error {
		userPath := filepath.Join("etc", "users", username)
		data, err := os.ReadFile(userPath)
		if err != nil {
			return err
		}
		mode := os.FileMode(0600)
		if st, statErr := os.Stat(userPath); statErr == nil {
			mode = st.Mode().Perm()
		}

		text := strings.ReplaceAll(string(data), "\r\n", "\n")
		hadTrailingNewline := strings.HasSuffix(text, "\n")
		lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
		if len(lines) == 1 && lines[0] == "" {
			lines = nil
		}

		out := make([]string, 0, len(lines)+len(normalized))
		insertedIPs := false
		appendIPs := func() {
			if insertedIPs {
				return
			}
			for _, ip := range normalized {
				out = append(out, "IP "+ip)
			}
			insertedIPs = true
		}
		for _, line := range lines {
			fields := strings.Fields(strings.TrimSpace(line))
			if len(fields) > 0 && strings.EqualFold(fields[0], "IP") {
				appendIPs()
				continue
			}
			out = append(out, line)
		}
		if !insertedIPs {
			appendIPs()
		}

		result := strings.Join(out, "\n")
		if hadTrailingNewline || result != "" {
			result += "\n"
		}

		dir := filepath.Dir(userPath)
		tmp, err := os.CreateTemp(dir, "."+filepath.Base(userPath)+".tmp-*")
		if err != nil {
			return err
		}
		tmpPath := tmp.Name()
		cleanup := true
		defer func() {
			if cleanup {
				_ = os.Remove(tmpPath)
			}
		}()
		if _, err := tmp.WriteString(result); err != nil {
			_ = tmp.Close()
			return err
		}
		if err := tmp.Chmod(mode); err != nil {
			_ = tmp.Close()
			return err
		}
		if err := tmp.Close(); err != nil {
			return err
		}
		if err := os.Rename(tmpPath, userPath); err != nil {
			_ = os.Remove(userPath)
			if renameErr := os.Rename(tmpPath, userPath); renameErr != nil {
				return err
			}
		}
		cleanup = false
		return nil
	})
}

func (s *Session) authenticateSelfIPUser(username, password string) (*user.User, string) {
	u, err := user.LoadUser(username, s.GroupMap)
	if err != nil {
		if _, statErr := os.Stat(deletedUserPath(username)); statErr == nil {
			return nil, "user deleted"
		}
		return nil, "user not found"
	}

	passwordOK := false
	matchedHash := ""
	passwds, err := LoadPasswdFile(s.Config.PasswdFile)
	if err == nil {
		if hash, ok := passwds[u.Name]; ok {
			matchedHash = hash
			passwordOK = VerifyPassword(password, hash)
		}
	}
	if !passwordOK && u.Password != "" {
		passwordOK = (u.Password == password)
	}
	if !passwordOK {
		return nil, "password not accepted"
	}
	if matchedHash != "" {
		if upgraded, err := UpgradeLegacyPasswordHash(u.Name, password, matchedHash, s.Config.PasswdFile); err != nil {
			if s.Config.Debug {
				log.Printf("[SELFIP] User %s legacy hash upgrade failed: %v", u.Name, err)
			}
		} else if upgraded && s.Config.Debug {
			log.Printf("[SELFIP] Upgraded legacy password hash to bcrypt for %s", u.Name)
		}
	}
	return u, ""
}

func normalizeUserIP(ip string) string {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return ""
	}
	if !strings.Contains(ip, "@") {
		ip = "*@" + ip
	}
	if !looksLikeUserIPMask(ip) {
		return ""
	}
	return ip
}

func looksLikeUserIPMask(ip string) bool {
	if !strings.Contains(ip, "@") {
		return false
	}
	host := strings.TrimSpace(strings.SplitN(ip, "@", 2)[1])
	if host == "" {
		return false
	}
	return strings.ContainsAny(host, ".*:") || strings.EqualFold(host, "*")
}

func containsExact(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}

func parseSiteRatio(raw string) (int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, fmt.Errorf("empty ratio")
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return 0, err
	}
	if value < 0 {
		return 0, fmt.Errorf("negative ratio")
	}
	return value, nil
}

func (s *Session) canManageGroup(group string) bool {
	if s == nil || s.User == nil {
		return false
	}
	if s.User.HasFlag("1") {
		return true
	}
	return s.User.IsGroupAdmin(group)
}

func (s *Session) hasFreeGroupSlot(group string) bool {
	if s == nil || s.User == nil {
		return false
	}
	if s.User.HasFlag("1") {
		return true
	}
	if s.User.GroupSlots <= 0 {
		return false
	}
	return countGroupMembers(group) < s.User.GroupSlots
}

func (s *Session) managedGroups() []string {
	if s == nil || s.User == nil || s.User.Groups == nil {
		return nil
	}
	var groups []string
	for group, val := range s.User.Groups {
		if val == 1 {
			groups = append(groups, group)
		}
	}
	sort.Strings(groups)
	return groups
}

func (s *Session) canGrantManagedLeech(target *user.User) bool {
	if s == nil || s.User == nil || target == nil {
		return false
	}
	if s.User.HasFlag("1") {
		return true
	}
	if target.Ratio == 0 {
		for _, group := range s.managedGroups() {
			if target.IsInGroup(group) {
				return true
			}
		}
		return false
	}
	if s.User.LeechSlots <= 0 {
		return false
	}
	for _, group := range s.managedGroups() {
		if !target.IsInGroup(group) {
			continue
		}
		if countGroupLeechMembers(group) < s.User.LeechSlots {
			return true
		}
	}
	return false
}

func parseNonNegativeInt(raw string) (int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, fmt.Errorf("empty value")
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return 0, err
	}
	if value < 0 {
		return 0, fmt.Errorf("negative value")
	}
	return value, nil
}

func parseLimitInt(raw string) (int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, fmt.Errorf("empty value")
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return 0, err
	}
	if value < -1 {
		return 0, fmt.Errorf("value below -1")
	}
	return value, nil
}

func parseInt64Value(raw string) (int64, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, fmt.Errorf("empty value")
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0, err
	}
	if value < 0 {
		return 0, fmt.Errorf("negative value")
	}
	return value, nil
}

func (s *Session) HandleSiteTagline(args []string) bool {
	if len(args) == 0 {
		fmt.Fprintf(s.Conn, "501 Usage: SITE TAGLINE [user] <text>\r\n")
		return false
	}

	targetUserName := s.User.Name
	textArgs := args
	if len(args) > 1 && s.User.HasFlag("1") {
		if _, err := user.LoadUser(args[0], s.GroupMap); err == nil {
			targetUserName = args[0]
			textArgs = args[1:]
		}
	}
	if len(textArgs) == 0 {
		fmt.Fprintf(s.Conn, "501 Usage: SITE TAGLINE [user] <text>\r\n")
		return false
	}
	targetUser, err := user.LoadUser(targetUserName, s.GroupMap)
	if err != nil {
		fmt.Fprintf(s.Conn, "550 User %s not found.\r\n", targetUserName)
		return false
	}
	if !strings.EqualFold(targetUser.Name, s.User.Name) && !s.User.HasFlag("1") {
		fmt.Fprintf(s.Conn, "550 Access denied.\r\n")
		return false
	}
	oldTagline := targetUser.Tagline
	targetUser.Tagline = strings.TrimSpace(strings.Join(textArgs, " "))
	if targetUser.Tagline == "" {
		targetUser.Tagline = "No Tagline Set"
	}
	if err := targetUser.Save(); err != nil {
		fmt.Fprintf(s.Conn, "550 Failed to save tagline for %s: %v\r\n", targetUser.Name, err)
		return false
	}
	fmt.Fprintf(s.Conn, "200 Tagline changed for %s.\r\n", targetUser.Name)
	s.emitUserChange("TAGLINE", "user", targetUser.Name, "tagline", oldTagline, targetUser.Tagline, "")
	return false
}

func (s *Session) HandleSiteChNumLogins(args []string) bool {
	if !s.User.HasFlag("1") {
		fmt.Fprintf(s.Conn, "550 Access denied.\r\n")
		return false
	}
	if len(args) < 2 {
		fmt.Fprintf(s.Conn, "501 Usage: SITE CHNUMLOGINS <user> <count>\r\n")
		return false
	}
	u, err := user.LoadUser(args[0], s.GroupMap)
	if err != nil {
		fmt.Fprintf(s.Conn, "550 User %s not found.\r\n", args[0])
		return false
	}
	value, err := parseLimitInt(args[1])
	if err != nil {
		fmt.Fprintf(s.Conn, "550 Invalid num_logins value %q.\r\n", args[1])
		return false
	}
	oldValue := u.LoginSlots
	u.LoginSlots = value
	u.LoginSlotsSet = true
	if err := u.Save(); err != nil {
		fmt.Fprintf(s.Conn, "550 Failed to save user %s: %v\r\n", u.Name, err)
		return false
	}
	fmt.Fprintf(s.Conn, "200 Num logins changed for %s: %d.\r\n", u.Name, value)
	s.emitUserChange("CHNUMLOGINS", "user", u.Name, "num_logins", fmt.Sprintf("%d", oldValue), fmt.Sprintf("%d", value), "")
	return false
}

func (s *Session) HandleSiteChMaxSim(args []string) bool {
	if !s.User.HasFlag("1") {
		fmt.Fprintf(s.Conn, "550 Access denied.\r\n")
		return false
	}
	if len(args) < 2 {
		fmt.Fprintf(s.Conn, "501 Usage: SITE CHMAXSIM <user> <count>\r\n")
		return false
	}
	u, err := user.LoadUser(args[0], s.GroupMap)
	if err != nil {
		fmt.Fprintf(s.Conn, "550 User %s not found.\r\n", args[0])
		return false
	}
	value, err := parseLimitInt(args[1])
	if err != nil {
		fmt.Fprintf(s.Conn, "550 Invalid max_sim value %q.\r\n", args[1])
		return false
	}
	oldValue := u.MaxSim
	u.MaxSim = value
	u.MaxSimSet = true
	if err := u.Save(); err != nil {
		fmt.Fprintf(s.Conn, "550 Failed to save user %s: %v\r\n", u.Name, err)
		return false
	}
	fmt.Fprintf(s.Conn, "200 Max sim changed for %s: %d.\r\n", u.Name, value)
	s.emitUserChange("CHMAXSIM", "user", u.Name, "max_sim", fmt.Sprintf("%d", oldValue), fmt.Sprintf("%d", value), "")
	return false
}

func (s *Session) HandleSiteChWklyAllotment(args []string) bool {
	if !s.User.HasFlag("1") {
		fmt.Fprintf(s.Conn, "550 Access denied.\r\n")
		return false
	}
	if len(args) < 2 {
		fmt.Fprintf(s.Conn, "501 Usage: SITE CHWKLYALLOTMENT <user> <credits>\r\n")
		return false
	}
	u, err := user.LoadUser(args[0], s.GroupMap)
	if err != nil {
		fmt.Fprintf(s.Conn, "550 User %s not found.\r\n", args[0])
		return false
	}
	value, err := parseInt64Value(args[1])
	if err != nil {
		fmt.Fprintf(s.Conn, "550 Invalid wkly_allotment value %q.\r\n", args[1])
		return false
	}
	oldValue := u.WeeklyAllotment
	u.WeeklyAllotment = value
	u.WeeklyAllotmentSet = true
	if err := u.Save(); err != nil {
		fmt.Fprintf(s.Conn, "550 Failed to save user %s: %v\r\n", u.Name, err)
		return false
	}
	fmt.Fprintf(s.Conn, "200 Weekly allotment changed for %s: %s.\r\n", u.Name, formatBytes(value))
	s.emitUserChange("CHWKLYALLOTMENT", "user", u.Name, "wkly_allotment", formatBytes(oldValue), formatBytes(value), "")
	return false
}

func (s *Session) HandleSiteChUploadSlots(args []string) bool {
	if !s.User.HasFlag("1") {
		fmt.Fprintf(s.Conn, "550 Access denied.\r\n")
		return false
	}
	if len(args) < 2 {
		fmt.Fprintf(s.Conn, "501 Usage: SITE CHUPLOADSLOTS <user> <count>\r\n")
		return false
	}
	u, err := user.LoadUser(args[0], s.GroupMap)
	if err != nil {
		fmt.Fprintf(s.Conn, "550 User %s not found.\r\n", args[0])
		return false
	}
	value, err := parseLimitInt(args[1])
	if err != nil {
		fmt.Fprintf(s.Conn, "550 Invalid upload slot value %q.\r\n", args[1])
		return false
	}
	oldValue := u.UploadSlots
	u.UploadSlots = value
	u.UploadSlotsSet = true
	if err := u.Save(); err != nil {
		fmt.Fprintf(s.Conn, "550 Failed to save user %s: %v\r\n", u.Name, err)
		return false
	}
	fmt.Fprintf(s.Conn, "200 Upload slots changed for %s: %d.\r\n", u.Name, value)
	s.emitUserChange("CHUPLOADSLOTS", "user", u.Name, "upload_slots", fmt.Sprintf("%d", oldValue), fmt.Sprintf("%d", value), "")
	return false
}

func (s *Session) HandleSiteChDownloadSlots(args []string) bool {
	if !s.User.HasFlag("1") {
		fmt.Fprintf(s.Conn, "550 Access denied.\r\n")
		return false
	}
	if len(args) < 2 {
		fmt.Fprintf(s.Conn, "501 Usage: SITE CHDOWNLOADSLOTS <user> <count>\r\n")
		return false
	}
	u, err := user.LoadUser(args[0], s.GroupMap)
	if err != nil {
		fmt.Fprintf(s.Conn, "550 User %s not found.\r\n", args[0])
		return false
	}
	value, err := parseLimitInt(args[1])
	if err != nil {
		fmt.Fprintf(s.Conn, "550 Invalid download slot value %q.\r\n", args[1])
		return false
	}
	oldValue := u.DownloadSlots
	u.DownloadSlots = value
	u.DownloadSlotsSet = true
	if err := u.Save(); err != nil {
		fmt.Fprintf(s.Conn, "550 Failed to save user %s: %v\r\n", u.Name, err)
		return false
	}
	fmt.Fprintf(s.Conn, "200 Download slots changed for %s: %d.\r\n", u.Name, value)
	s.emitUserChange("CHDOWNLOADSLOTS", "user", u.Name, "download_slots", fmt.Sprintf("%d", oldValue), fmt.Sprintf("%d", value), "")
	return false
}

func (s *Session) HandleSiteGroupSlots(args []string) bool {
	if !s.User.HasFlag("1") {
		fmt.Fprintf(s.Conn, "550 Access denied.\r\n")
		return false
	}
	if len(args) < 2 {
		fmt.Fprintf(s.Conn, "501 Usage: SITE GROUPSLOTS <user> <slots> [leech_slots]\r\n")
		return false
	}
	u, err := user.LoadUser(args[0], s.GroupMap)
	if err != nil {
		fmt.Fprintf(s.Conn, "550 User %s not found.\r\n", args[0])
		return false
	}
	value, err := parseLimitInt(args[1])
	if err != nil {
		fmt.Fprintf(s.Conn, "550 Invalid group slot value %q.\r\n", args[1])
		return false
	}
	oldGroupSlots := u.GroupSlots
	oldLeechSlots := u.LeechSlots
	u.GroupSlots = value
	u.GroupSlotsSet = true
	if len(args) > 2 {
		if u.LeechSlots, err = parseNonNegativeInt(args[2]); err != nil {
			fmt.Fprintf(s.Conn, "550 Invalid leech slot value %q.\r\n", args[2])
			return false
		}
		u.LeechSlotsSet = true
	}
	if err := u.Save(); err != nil {
		fmt.Fprintf(s.Conn, "550 Failed to save user %s: %v\r\n", u.Name, err)
		return false
	}
	fmt.Fprintf(s.Conn, "200 Group slots changed for %s: %d %d.\r\n", u.Name, u.GroupSlots, u.LeechSlots)
	s.emitUserChange("GROUPSLOTS", "user", u.Name, "group_slots", fmt.Sprintf("%d/%d", oldGroupSlots, oldLeechSlots), fmt.Sprintf("%d/%d", u.GroupSlots, u.LeechSlots), "")
	return false
}

func (s *Session) HandleSiteGroupSimult(args []string) bool {
	if !s.User.HasFlag("1") {
		fmt.Fprintf(s.Conn, "550 Access denied.\r\n")
		return false
	}
	if len(args) < 2 {
		fmt.Fprintf(s.Conn, "501 Usage: SITE GROUPSIMULT <group> <count>\r\n")
		return false
	}
	group, err := normalizeSiteGroupName(args[0])
	if err != nil {
		fmt.Fprintf(s.Conn, "550 Invalid group name %q.\r\n", strings.TrimSpace(args[0]))
		return false
	}
	if !s.canManageGroup(group) {
		fmt.Fprintf(s.Conn, "550 Access denied.\r\n")
		return false
	}
	groupCfg, err := LoadGroupConfig(group)
	if err != nil {
		fmt.Fprintf(s.Conn, "550 Group %s not found.\r\n", group)
		return false
	}
	value, err := parseLimitInt(args[1])
	if err != nil {
		fmt.Fprintf(s.Conn, "550 Invalid simult value %q.\r\n", args[1])
		return false
	}
	oldValue := groupCfg.Simult
	groupCfg.Simult = value
	if err := groupCfg.Save(); err != nil {
		fmt.Fprintf(s.Conn, "550 Failed to save group %s: %v\r\n", group, err)
		return false
	}
	fmt.Fprintf(s.Conn, "200 Group simult changed for %s: %d.\r\n", groupCfg.Name, value)
	s.emitUserChange("GROUPSIMULT", "group", groupCfg.Name, "simult", fmt.Sprintf("%d", oldValue), fmt.Sprintf("%d", value), "")
	return false
}

// HandleSiteDelUser deletes a user account.
// Usage: SITE DELUSER <user>
func (s *Session) HandleSiteDelUser(args []string) bool {
	if !s.User.HasFlag("1") {
		fmt.Fprintf(s.Conn, "550 Access denied.\r\n")
		return false
	}
	if len(args) < 1 {
		fmt.Fprintf(s.Conn, "501 Usage: SITE DELUSER <user>\r\n")
		return false
	}
	username, err := user.NormalizeName(args[0])
	if err != nil {
		fmt.Fprintf(s.Conn, "550 Invalid username %q.\r\n", strings.TrimSpace(args[0]))
		return false
	}
	if username == s.User.Name {
		fmt.Fprintf(s.Conn, "550 Cannot delete yourself.\r\n")
		return false
	}

	userPath := filepath.Join("etc", "users", username)
	if _, err := os.Stat(userPath); err != nil {
		fmt.Fprintf(s.Conn, "550 User %s not found.\r\n", username)
		return false
	}
	if err := os.MkdirAll(deletedUsersDir, 0755); err != nil {
		fmt.Fprintf(s.Conn, "550 Failed to prepare deleted-user store: %v\r\n", err)
		return false
	}
	if passwds, err := LoadPasswdFile(s.Config.PasswdFile); err == nil {
		if hash, ok := passwds[username]; ok && hash != "" {
			_ = os.WriteFile(deletedUserPasswdPath(username), []byte(hash+"\n"), 0600)
		}
	}
	if err := os.Rename(userPath, deletedUserPath(username)); err != nil {
		fmt.Fprintf(s.Conn, "550 Failed to delete user %s: %v\r\n", username, err)
		return false
	}
	if err := RemoveUserFromPasswd(username, s.Config.PasswdFile); err != nil {
		_ = os.Rename(deletedUserPath(username), userPath)
		fmt.Fprintf(s.Conn, "550 Failed to update passwd for %s: %v\r\n", username, err)
		return false
	}
	fmt.Fprintf(s.Conn, "200 User %s deleted (can be restored with SITE READD).\r\n", username)
	s.emitUserChange("DELUSER", "user", username, "", "", "", "stored for READD")
	return false
}

func (s *Session) HandleSiteReAdd(args []string) bool {
	if !s.User.HasFlag("1") {
		fmt.Fprintf(s.Conn, "550 Access denied.\r\n")
		return false
	}
	if len(args) < 1 {
		users, err := listDeletedUsers()
		if err != nil {
			fmt.Fprintf(s.Conn, "550 Failed to read deleted users: %v\r\n", err)
			return false
		}
		if len(users) == 0 {
			fmt.Fprintf(s.Conn, "200 No deleted users stored.\r\n")
			return false
		}
		fmt.Fprintf(s.Conn, "200- Deleted users:\r\n")
		for _, name := range users {
			fmt.Fprintf(s.Conn, "200- %s\r\n", name)
		}
		fmt.Fprintf(s.Conn, "200 %d deleted user(s) stored.\r\n", len(users))
		return false
	}
	username, err := user.NormalizeName(args[0])
	if err != nil {
		fmt.Fprintf(s.Conn, "550 Invalid username %q.\r\n", strings.TrimSpace(args[0]))
		return false
	}
	if _, err := user.LoadUser(username, s.GroupMap); err == nil {
		fmt.Fprintf(s.Conn, "550 User %s already exists.\r\n", username)
		return false
	}
	deletedPath := deletedUserPath(username)
	if _, err := os.Stat(deletedPath); err != nil {
		fmt.Fprintf(s.Conn, "550 Deleted user %s not found.\r\n", username)
		return false
	}

	hash := ""
	passwdPath := deletedUserPasswdPath(username)
	if data, err := os.ReadFile(passwdPath); err == nil {
		hash = strings.TrimSpace(string(data))
	}
	if hash == "" && len(args) > 1 {
		var err error
		hash, err = HashPassword(args[1])
		if err != nil {
			fmt.Fprintf(s.Conn, "550 Failed to hash password: %v\r\n", err)
			return false
		}
	}
	if hash == "" {
		fmt.Fprintf(s.Conn, "550 No stored password available. Use SITE READD <user> <newpass>.\r\n")
		return false
	}
	userPath := filepath.Join("etc", "users", username)
	if err := os.Rename(deletedPath, userPath); err != nil {
		fmt.Fprintf(s.Conn, "550 Failed to restore user %s: %v\r\n", username, err)
		return false
	}
	if err := AddUserToPasswd(username, hash, s.Config.PasswdFile); err != nil {
		_ = os.Rename(userPath, deletedPath)
		fmt.Fprintf(s.Conn, "550 Failed to restore passwd entry for %s: %v\r\n", username, err)
		return false
	}
	_ = os.Remove(passwdPath)
	fmt.Fprintf(s.Conn, "200 User %s restored.\r\n", username)
	s.emitUserChange("READD", "user", username, "", "", "", "restored deleted user")
	return false
}

func (s *Session) HandleSiteRenUser(args []string) bool {
	if !s.User.HasFlag("1") {
		fmt.Fprintf(s.Conn, "550 Access denied.\r\n")
		return false
	}
	if len(args) < 2 {
		fmt.Fprintf(s.Conn, "501 Usage: SITE RENUSER <olduser> <newuser>\r\n")
		return false
	}
	oldName, err := user.NormalizeName(args[0])
	if err != nil {
		fmt.Fprintf(s.Conn, "550 Invalid username %q.\r\n", strings.TrimSpace(args[0]))
		return false
	}
	newName, err := user.NormalizeName(args[1])
	if err != nil {
		fmt.Fprintf(s.Conn, "550 Invalid username %q.\r\n", strings.TrimSpace(args[1]))
		return false
	}
	u, err := user.LoadUser(oldName, s.GroupMap)
	if err != nil {
		fmt.Fprintf(s.Conn, "550 User %s not found.\r\n", oldName)
		return false
	}
	if _, err := user.LoadUser(newName, s.GroupMap); err == nil {
		fmt.Fprintf(s.Conn, "550 User %s already exists.\r\n", newName)
		return false
	}
	oldPath := filepath.Join("etc", "users", oldName)
	newPath := filepath.Join("etc", "users", newName)
	u.Name = newName
	if err := u.Save(); err != nil {
		fmt.Fprintf(s.Conn, "550 Failed to save renamed user: %v\r\n", err)
		return false
	}
	if err := RenameUserInPasswd(oldName, newName, s.Config.PasswdFile); err != nil {
		_ = os.Remove(newPath)
		fmt.Fprintf(s.Conn, "550 Failed to rename passwd entry: %v\r\n", err)
		return false
	}
	if err := os.Remove(oldPath); err != nil {
		_ = RenameUserInPasswd(newName, oldName, s.Config.PasswdFile)
		_ = os.Remove(newPath)
		fmt.Fprintf(s.Conn, "550 Failed to remove old user file: %v\r\n", err)
		return false
	}
	fmt.Fprintf(s.Conn, "200 User %s renamed to %s.\r\n", oldName, newName)
	s.emitUserChange("RENUSER", "user", newName, "username", oldName, newName, "")
	return false
}
