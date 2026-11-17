package core

import (
	"fmt"
	"path"
	"strings"
)

// ValidateSectionWritePath does not rewrite paths: existing differently cased
// directories may contain different files and must remain readable for recovery.
func (c *Config) ValidateSectionWritePath(p string) error {
	if c == nil || !c.StrictSectionCase {
		return nil
	}
	p = path.Clean("/" + strings.TrimPrefix(p, "/"))
	best, exact := "", false
	for _, raw := range c.Sections {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		section := path.Clean("/" + strings.TrimPrefix(strings.TrimSpace(raw), "/"))
		if section == "/" || len(p) < len(section) {
			continue
		}
		prefix := p[:len(section)]
		if (len(p) != len(section) && p[len(section)] != '/') || !strings.EqualFold(prefix, section) {
			continue
		}
		if len(section) > len(best) {
			best, exact = section, prefix == section
		} else if len(section) == len(best) && prefix == section {
			best, exact = section, true
		}
	}
	if best != "" && !exact {
		return fmt.Errorf("section path case mismatch: use %s", best)
	}
	return nil
}
