package bot

import (
	"fmt"
	"log"
	"strings"
)

func normalizeChannelModes(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", nil
	}
	flags := strings.TrimPrefix(value, "+")
	if flags == "" || strings.Trim(flags, "is") != "" {
		return "", fmt.Errorf("irc.channel_modes accepts only +i, +s, +is, or an empty string")
	}
	modes := "+"
	for _, flag := range "is" {
		if strings.ContainsRune(flags, flag) {
			modes += string(flag)
		}
	}
	return modes, nil
}

func (b *Bot) handleChannelModes(line string) {
	modes, err := normalizeChannelModes(b.Config.IRC.ChannelModes)
	if err != nil || modes == "" {
		return
	}
	fields := strings.Fields(line)
	if len(fields) > 0 && strings.HasPrefix(fields[0], "@") {
		fields = fields[1:]
	}
	if len(fields) < 3 || !strings.HasPrefix(fields[0], ":") {
		return
	}
	channel := ""
	reportedModes := ""
	switch fields[1] {
	case "324":
		if len(fields) < 5 {
			return
		}
		channel, reportedModes = fields[3], fields[4]
	case "JOIN":
		sender := strings.SplitN(strings.TrimPrefix(fields[0], ":"), "!", 2)[0]
		if strings.EqualFold(sender, b.IRC.Nick) {
			channel = strings.TrimPrefix(fields[2], ":")
		}
	case "MODE":
		if len(fields) < 5 {
			return
		}
		adding := true
		argument := 4
		for _, mode := range fields[3] {
			switch mode {
			case '+':
				adding = true
			case '-':
				adding = false
			default:
				if strings.ContainsRune("qaohvbekI", mode) || (mode == 'l' && adding) {
					if argument >= len(fields) {
						return
					}
					if adding && strings.ContainsRune("qao", mode) && strings.EqualFold(strings.TrimPrefix(fields[argument], ":"), b.IRC.Nick) {
						channel = fields[2]
					}
					argument++
				}
			}
		}
	}
	if channel == "" {
		return
	}
	configured := false
	for _, candidate := range uniqueChannels(b.Config) {
		if strings.EqualFold(candidate, channel) {
			configured = true
			break
		}
	}
	if !configured {
		return
	}
	if reportedModes != "" {
		for _, flag := range strings.TrimPrefix(modes, "+") {
			if !strings.ContainsRune(reportedModes, flag) {
				log.Printf("[Bot] Channel %s is missing requested mode +%c; check channel privileges or ChanServ MLOCK", channel, flag)
				return
			}
		}
		log.Printf("[Bot] Confirmed channel modes %s for %s", modes, channel)
		return
	}
	command := "MODE"
	if b.ircOper {
		command = "SAMODE"
	}
	if err := b.IRC.SendRaw(fmt.Sprintf("%s %s %s", command, channel, modes)); err != nil {
		log.Printf("[Bot] Channel modes %s for %s failed: %v", modes, channel, err)
		return
	}
	log.Printf("[Bot] Requested channel modes %s for %s", modes, channel)
	_ = b.IRC.SendRaw("MODE " + channel)
}

func (b *Bot) handleOperReply(line string) {
	fields := strings.Fields(line)
	if len(fields) > 0 && strings.HasPrefix(fields[0], "@") {
		fields = fields[1:]
	}
	if !b.operPending || len(fields) < 3 || !strings.EqualFold(fields[2], b.IRC.Nick) {
		return
	}
	switch fields[1] {
	case "381":
		b.ircOper, b.operPending = true, false
		log.Printf("[Bot] IRC operator login confirmed")
		b.joinConfiguredChannels()
	case "491", "464":
		b.ircOper, b.operPending = false, false
		log.Printf("[Bot] IRC operator login failed (%s); falling back to normal JOIN", fields[1])
		b.joinConfiguredChannels()
	}
}
