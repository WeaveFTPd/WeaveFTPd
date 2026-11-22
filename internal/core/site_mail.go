package core

import (
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"weaveftpd/internal/user"
)

// Identity is kept in the userfile, not derived from a reusable username or UID.
func mailboxFor(name string, groups map[string]int, create bool) (string, error) {
	u, err := user.LoadUser(name, groups)
	if err != nil {
		return "", err
	}
	if u.MailboxID == "" && create {
		u, err = user.MutateAndSave(name, groups, func(current *user.User) error {
			if current.MailboxID == "" {
				current.MailboxID, err = newMailboxID()
				return err
			}
			return nil
		})
		if err != nil {
			return "", err
		}
	}
	if u.MailboxID != "" && !validMailboxID(u.MailboxID) {
		return "", errors.New("invalid mailbox identity")
	}
	return u.MailboxID, nil
}

func (s *Session) mailFailure(err error) {
	switch {
	case errors.Is(err, errMailNotFound):
		fmt.Fprint(s.Conn, "550 Message not found in your mailbox.\r\n")
	case errors.Is(err, errMailboxFull):
		fmt.Fprint(s.Conn, "452 Recipient mailbox is full.\r\n")
	case errors.Is(err, errMailRate):
		fmt.Fprint(s.Conn, "450 Send limit reached (5 per minute). Try again later.\r\n")
	default:
		// Do not log parser errors: a corrupt mailbox may contain private text.
		log.Print("[MAIL] Mailbox operation failed; check account and mailbox storage")
		fmt.Fprint(s.Conn, "451 Mailbox unavailable. Please contact a site operator.\r\n")
	}
}

func (s *Session) HandleSiteMail(command string, args []string) bool {
	if !s.IsLogged || s.User == nil {
		fmt.Fprint(s.Conn, "530 Please log in first.\r\n")
		return false
	}
	if command == "MSG" {
		if len(args) < 2 {
			fmt.Fprint(s.Conn, "501 Usage: SITE MSG <user> <message>\r\n")
			return false
		}
		name, err := user.NormalizeName(args[0])
		if err != nil {
			fmt.Fprint(s.Conn, "550 Invalid recipient.\r\n")
			return false
		}
		body := strings.Join(args[1:], " ")
		if strings.TrimSpace(body) == "" || len(body) > mailBodyLimit || !validMailText(body) {
			fmt.Fprintf(s.Conn, "501 Message must contain 1-%d bytes without control characters.\r\n", mailBodyLimit)
			return false
		}
		if s.Config == nil {
			s.mailFailure(errors.New("missing config"))
			return false
		}
		accounts, err := LoadPasswdFile(s.Config.PasswdFile)
		if err != nil {
			s.mailFailure(err)
			return false
		}
		if _, ok := accounts[name]; !ok {
			fmt.Fprint(s.Conn, "550 Recipient does not exist.\r\n")
			return false
		}
		id, err := mailboxFor(name, s.GroupMap, true)
		if err != nil {
			s.mailFailure(err)
			return false
		}
		number, err := privateMail.send(id, s.User.Name, body, time.Now())
		if err != nil {
			s.mailFailure(err)
			return false
		}
		fmt.Fprintf(s.Conn, "200 Message %d delivered to %s.\r\n", number, name)
		return false
	}
	page := 1
	var number int64
	all := false
	if command == "MAIL" {
		if len(args) > 1 {
			fmt.Fprint(s.Conn, "501 Usage: SITE MAIL [page]\r\n")
			return false
		}
		if len(args) == 1 {
			var err error
			page, err = strconv.Atoi(args[0])
			if err != nil || page < 1 || page > (mailLimit+19)/20 {
				fmt.Fprint(s.Conn, "501 Invalid mailbox page.\r\n")
				return false
			}
		}
	} else {
		if len(args) != 1 {
			suffix := ""
			if command == "DELMSG" {
				suffix = "|ALL"
			}
			fmt.Fprintf(s.Conn, "501 Usage: SITE %s <id>%s\r\n", command, suffix)
			return false
		}
		all = command == "DELMSG" && strings.EqualFold(args[0], "ALL")
		if !all {
			var err error
			number, err = strconv.ParseInt(args[0], 10, 64)
			if err != nil || number < 1 {
				fmt.Fprint(s.Conn, "501 Invalid message ID.\r\n")
				return false
			}
		}
	}
	id, err := mailboxFor(s.User.Name, s.GroupMap, false)
	if err != nil {
		s.mailFailure(err)
		return false
	}
	if id == "" {
		if command == "MAIL" || all {
			fmt.Fprint(s.Conn, "200 Mailbox is empty.\r\n")
		} else {
			s.mailFailure(errMailNotFound)
		}
		return false
	}
	switch command {
	case "MAIL":
		messages, err := privateMail.list(id)
		if err != nil {
			s.mailFailure(err)
			return false
		}
		start := (page - 1) * 20
		if start >= len(messages) {
			fmt.Fprint(s.Conn, "200 No messages on this page.\r\n")
			return false
		}
		fmt.Fprintf(s.Conn, "200-Mailbox: %d message(s), page %d\r\n", len(messages), page)
		for _, msg := range messages[start:min(start+20, len(messages))] {
			state := "READ"
			if !msg.Read {
				state = "NEW"
			}
			fmt.Fprintf(s.Conn, "200- %d %s from %s at %s\r\n", msg.ID, state, msg.Sender, time.Unix(msg.SentAt, 0).UTC().Format(time.RFC3339))
		}
		fmt.Fprint(s.Conn, "200 End of mailbox. SITE READ <id> to read.\r\n")
	case "READ":
		msg, err := privateMail.read(id, number)
		if err != nil {
			s.mailFailure(err)
			return false
		}
		fmt.Fprintf(s.Conn, "200-Message %d from %s at %s\r\n", msg.ID, msg.Sender, time.Unix(msg.SentAt, 0).UTC().Format(time.RFC3339))
		// Bound each FTP reply line without splitting UTF-8 characters.
		text := []rune(msg.Body)
		for len(text) > 0 {
			n := min(len(text), 100)
			fmt.Fprintf(s.Conn, "200- %s\r\n", string(text[:n]))
			text = text[n:]
		}
		fmt.Fprint(s.Conn, "200 End of message.\r\n")
	case "DELMSG":
		if err := privateMail.delete(id, number, all); err != nil {
			s.mailFailure(err)
			return false
		}
		fmt.Fprint(s.Conn, "200 Message(s) deleted.\r\n")
	}
	return false
}

func (s *Session) emitMailNotice() {
	if s.User == nil || !s.canUseSiteCommand("MAIL") {
		return
	}
	id, err := mailboxFor(s.User.Name, s.GroupMap, false)
	if err != nil {
		log.Print("[MAIL] Could not check mailbox at login")
		return
	}
	if id == "" {
		return
	}
	messages, err := privateMail.list(id)
	if err != nil {
		log.Print("[MAIL] Could not check mailbox at login")
		return
	}
	unread := 0
	for _, msg := range messages {
		if !msg.Read {
			unread++
		}
	}
	if unread > 0 {
		fmt.Fprintf(s.Conn, "230-You have %d unread message(s). Use SITE MAIL.\r\n", unread)
	}
}
