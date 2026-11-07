package bot

import (
	"strings"
	"testing"

	"weaveftpd/sitebot/internal/irc"
)

func TestNormalizeChannelModes(t *testing.T) {
	for _, value := range []string{"", "+i", "+s", "+is", "si", " +ssi "} {
		got, err := normalizeChannelModes(value)
		if err != nil {
			t.Fatalf("%q: %v", value, err)
		}
		if strings.Contains(value, "i") && !strings.Contains(got, "i") {
			t.Fatalf("lost invite-only mode: %q", got)
		}
	}
	for _, value := range []string{"+", "-is", "+o nick", "+isk secret", "+is\r\nQUIT", "+n"} {
		if _, err := normalizeChannelModes(value); err == nil {
			t.Errorf("accepted invalid modes %q", value)
		}
	}
}

func TestOperatorReplyControlsJoin(t *testing.T) {
	for _, code := range []string{"381", "491", "464"} {
		t.Run(code, func(t *testing.T) {
			connection := &recordingConn{}
			client := irc.NewBot("localhost", 6667, "bot", "bot", "bot")
			client.Conn, client.Connected, client.Debug = connection, true, false
			instance := &Bot{Config: &Config{IRC: IRCConfig{Nick: "bot", Channels: []string{"#private"}, AutoOper: true, OperPassword: "test", AutoJoinDelay: 1}}, IRC: client}
			instance.onRegistered()
			if len(connection.writes) != 1 || !instance.operPending || instance.ircOper {
				t.Fatalf("joined before OPER reply: %v", connection.writes)
			}
			connection.writes = nil
			instance.handleOperReply(":server " + code + " bot :reply")
			want := "JOIN #private"
			if code == "381" {
				want = "SAJOIN bot #private"
			}
			if len(connection.writes) == 0 || strings.TrimSpace(connection.writes[0]) != want || instance.operPending || instance.ircOper != (code == "381") {
				t.Fatalf("unexpected operator result: writes=%v oper=%v pending=%v", connection.writes, instance.ircOper, instance.operPending)
			}
		})
	}
}

func TestChannelModesAfterJoinAndOperatorGrant(t *testing.T) {
	for _, check := range []struct {
		name, line, modes, want string
		oper                    bool
	}{
		{"disabled", ":bot!u@h JOIN :#private", "", "", false},
		{"mode confirmation", ":server 324 bot #private +inst", "+is", "", false},
		{"self join", ":bot!u@h JOIN :#private", "+is", "MODE #private +is", false},
		{"oper join", ":bot!u@h JOIN :#private", "+is", "SAMODE #private +is", true},
		{"extended join", "@time=now :bot!u@h JOIN #private account :Real Name", "+s", "MODE #private +s", false},
		{"other user", ":other!u@h JOIN :#private", "+is", "", false},
		{"unconfigured", ":bot!u@h JOIN :#public", "+is", "", false},
		{"ops later", ":ChanServ MODE #private +o bot", "+is", "MODE #private +is", false},
		{"multiple grants", ":ChanServ MODE #private +vo other bot", "+is", "MODE #private +is", false},
		{"ops removed", ":ChanServ MODE #private -o bot", "+is", "", false},
		{"other ops", ":ChanServ MODE #private +o other", "+is", "", false},
		{"no feedback loop", ":bot MODE #private +is", "+is", "", true},
		{"malformed", ":ChanServ MODE #private +oo bot", "+is", "", false},
	} {
		t.Run(check.name, func(t *testing.T) {
			connection := &recordingConn{}
			client := irc.NewBot("localhost", 6667, "bot", "bot", "bot")
			client.Conn, client.Connected, client.Debug = connection, true, false
			instance := &Bot{Config: &Config{IRC: IRCConfig{Channels: []string{"#private"}, ChannelModes: check.modes, AutoOper: check.oper, OperPassword: "test"}}, IRC: client, ircOper: check.oper}
			instance.handleChannelModes(check.line)
			if check.want == "" {
				if len(connection.writes) != 0 {
					t.Fatalf("unexpected writes: %v", connection.writes)
				}
				return
			}
			if len(connection.writes) != 2 || strings.TrimSpace(connection.writes[0]) != check.want || strings.TrimSpace(connection.writes[1]) != "MODE #private" {
				t.Fatalf("writes = %v; want %q followed by mode query", connection.writes, check.want)
			}
		})
	}
}
