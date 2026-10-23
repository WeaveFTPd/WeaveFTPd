package core

import (
	"strings"
	"unicode"
)

func parseFTPCommand(line string) (string, []string) {
	line = strings.TrimSpace(line)
	parts := strings.Fields(line)
	if len(parts) == 0 {
		return "", nil
	}
	cmd := strings.ToUpper(parts[0])
	// CWD takes one pathname, not whitespace-separated arguments. Keep even
	// repeated interior spaces; SITE and other multi-argument commands are unchanged.
	if cmd == "CWD" && len(parts) > 1 {
		return cmd, []string{strings.TrimLeft(line[len(parts[0]):], " \t")}
	}
	if cmd == "STAT" && len(parts) > 1 {
		// Only leading listing options are separate arguments. Once a pathname
		// starts, keep its remaining bytes, including repeated interior spaces.
		rest := strings.TrimLeftFunc(line[len(parts[0]):], unicode.IsSpace)
		args := make([]string, 0, 2)
		for strings.HasPrefix(rest, "-") {
			end := strings.IndexFunc(rest, unicode.IsSpace)
			if end < 0 {
				return cmd, append(args, rest)
			}
			args = append(args, rest[:end])
			rest = strings.TrimLeftFunc(rest[end:], unicode.IsSpace)
		}
		if rest != "" {
			args = append(args, rest)
		}
		return cmd, args
	}
	return cmd, parts[1:]
}
