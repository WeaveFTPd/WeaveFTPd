package bot

import (
	"path"
	"strings"
	"weaveftpd/sitebot/internal/event"
)

func (b *Bot) resolveEventSection(evt *event.Event) string {
	section := b.resolveSection(evt.Path, evt.Section)
	// Generic archive channel routes must not hide the release's own category.
	// Channel selection still uses the original path and configured type routes.
	if (evt.Type == event.EventNuke || evt.Type == event.EventUnnuke) && strings.EqualFold(section, "ARCHIVE") && strings.HasPrefix(strings.ToUpper(evt.Path), "/ARCHIVE/") {
		parts := strings.Split(strings.TrimPrefix(path.Clean(evt.Path), "/"), "/")
		if len(parts) >= 2 && strings.EqualFold(parts[0], "ARCHIVE") {
			return strings.ToUpper(parts[1])
		}
	}
	return section
}
