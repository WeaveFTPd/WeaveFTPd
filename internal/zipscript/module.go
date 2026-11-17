package zipscript

import (
	"errors"
	"fmt"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"weaveftpd/internal/user"
)

type MediaInfoProvider interface {
	GetDirMediaInfo(dirPath string) map[string]string
}

type AudioSortLink struct {
	DirPath  string
	LinkPath string
	Target   string
}

type StatusMarkerRelease struct {
	Name         string
	Path         string
	ModTime      int64
	VisibleCount int
	FileCount    int
	HasSFV       bool
	HasNFO       bool
	Present      int
	Total        int
}

type StatusMarkerEntry struct {
	Name       string
	LinkTarget string
	ModTime    int64
}

// ZIP-style sections also carry native Amiga archives. Format-specific ZIP
// validation and DIZ extraction must still use IsZipRecoverableArchiveName.
var zipPayloadNameRE = regexp.MustCompile(`(?i)\.(zip|z\d\d|dms|lha)$`)
var multiDiscReleaseDirRE = regexp.MustCompile(`(?i)^(?:cd|disc|disk|dvd)[0-9]{1,2}$`)
var discDirNameRE = regexp.MustCompile(`(?i)^(?:cd|disc|disk|dvd)[0-9]+$`)

var scenePayloadExts = map[string]bool{
	"rar":  true,
	"zip":  true,
	"sfv":  true,
	"nfo":  true,
	"diz":  true,
	"txt":  true,
	"log":  true,
	"m3u":  true,
	"cue":  true,
	"jpg":  true,
	"jpeg": true,
	"png":  true,
	"gif":  true,
}

var defaultAllowedOutsideSFVExts = map[string]bool{
	"nfo":  true,
	"txt":  true,
	"jpg":  true,
	"jpeg": true,
	"png":  true,
	"diz":  true,
	"avi":  true,
	"vob":  true,
	"m2ts": true,
	"mkv":  true,
	"mp4":  true,
	"zip":  true,
	"m3u":  true,
}

func Enabled(cfg Config) bool {
	return cfg.Enabled
}

func UsesSFV(cfg Config, dirPath string) bool {
	if !cfg.Enabled {
		return false
	}
	if pathMatchesAny(dirPath, cfg.Sections.NoCheck) {
		return false
	}
	if len(cfg.Sections.SFV) == 0 {
		return true
	}
	return pathMatchesAny(dirPath, cfg.Sections.SFV) || requestContainerMatchesChildPattern(dirPath, cfg.Sections.SFV)
}

func UsesZip(cfg Config, dirPath string) bool {
	if !cfg.Enabled {
		return false
	}
	if pathMatchesAny(dirPath, cfg.Sections.NoCheck) {
		return false
	}
	return pathMatchesAny(dirPath, cfg.Sections.Zip) || requestContainerMatchesChildPattern(dirPath, cfg.Sections.Zip)
}

func UsesRace(cfg Config, dirPath string) bool {
	return UsesSFV(cfg, dirPath) || UsesZip(cfg, dirPath)
}

func UsesReleaseCheck(cfg Config, dirPath string) bool {
	if !cfg.Enabled {
		return false
	}
	if pathMatchesAny(dirPath, cfg.Sections.NoCheck) {
		return false
	}
	if len(cfg.Sections.ReleaseCheck) == 0 {
		return UsesRace(cfg, dirPath)
	}
	return pathMatchesAny(dirPath, cfg.Sections.ReleaseCheck) || requestContainerMatchesChildPattern(dirPath, cfg.Sections.ReleaseCheck)
}

// UsesReleaseCheckEntry reports whether dirPath matches a configured
// release_check pattern as an actual release entry, not merely as a parent or
// descendant covered by the broader pathMatchesAny semantics.
func UsesReleaseCheckEntry(cfg Config, dirPath string) bool {
	if !cfg.Enabled {
		return false
	}
	if pathMatchesAny(dirPath, cfg.Sections.NoCheck) {
		return false
	}
	if len(cfg.Sections.ReleaseCheck) == 0 {
		return UsesRaceEntry(cfg, dirPath)
	}
	return pathMatchesAnyExact(dirPath, cfg.Sections.ReleaseCheck) || requestContainerMatchesChildPattern(dirPath, cfg.Sections.ReleaseCheck)
}

func UsesCleanup(cfg Config, dirPath string) bool {
	return UsesReleaseCheck(cfg, dirPath)
}

func UsesRaceEntry(cfg Config, dirPath string) bool {
	return UsesSFVEntry(cfg, dirPath) || UsesZipEntry(cfg, dirPath)
}

func UsesSFVEntry(cfg Config, dirPath string) bool {
	if !cfg.Enabled {
		return false
	}
	if pathMatchesAny(dirPath, cfg.Sections.NoCheck) {
		return false
	}
	if len(cfg.Sections.SFV) == 0 {
		return true
	}
	return pathMatchesAnyExact(dirPath, cfg.Sections.SFV) || requestContainerMatchesChildPattern(dirPath, cfg.Sections.SFV)
}

func UsesZipEntry(cfg Config, dirPath string) bool {
	if !cfg.Enabled {
		return false
	}
	if pathMatchesAny(dirPath, cfg.Sections.NoCheck) {
		return false
	}
	return pathMatchesAnyExact(dirPath, cfg.Sections.Zip) || requestContainerMatchesChildPattern(dirPath, cfg.Sections.Zip)
}

func AnnounceReleaseSubdirs(cfg Config) bool {
	if cfg.Race.AnnounceSubdirs == nil {
		return true
	}
	return *cfg.Race.AnnounceSubdirs
}

func IsIgnoredReleaseSubdir(cfg Config, dirPath string) bool {
	name := strings.TrimSpace(path.Base(path.Clean(dirPath)))
	if name == "" || name == "." || name == "/" {
		return false
	}
	items := cfg.Sections.IgnoredReleaseSubdirs
	if len(items) == 0 {
		items = []string{"Sample", "Proof", "Subs", "Subtitles", "Covers", "Spam"}
	}
	for _, item := range items {
		if strings.EqualFold(strings.TrimSpace(item), name) {
			return true
		}
	}
	return false
}

func ReleaseSubdirLabel(cfg Config, dirPath string) string {
	if !IsIgnoredReleaseSubdir(cfg, dirPath) {
		return ""
	}
	return strings.TrimSpace(path.Base(path.Clean(dirPath)))
}

// IsMultiDiscReleaseSubdir matches the numbered disc directories that pzs-ng
// treats as children of the parent release for announce display purposes.
func IsMultiDiscReleaseSubdir(dirPath string) bool {
	name := strings.TrimSpace(path.Base(path.Clean(dirPath)))
	return multiDiscReleaseDirRE.MatchString(name)
}

// ReleaseDisplayName keeps each disc as an independent race while including
// its parent release in announces, for example Release-GRP/DISC1.
func ReleaseDisplayName(dirPath string) string {
	clean := path.Clean("/" + strings.TrimSpace(dirPath))
	name := strings.TrimSpace(path.Base(clean))
	if name == "" || name == "." || name == "/" {
		return ""
	}
	if !IsMultiDiscReleaseSubdir(clean) {
		return name
	}
	parent := strings.TrimSpace(path.Base(path.Dir(clean)))
	if parent == "" || parent == "." || parent == "/" {
		return name
	}
	return parent + "/" + name
}

func IncompleteEnabled(cfg Config) bool {
	return cfg.Enabled && cfg.Incomplete.Enabled
}

func IncompleteIndicator(cfg Config, fallback string) string {
	if !cfg.Enabled {
		return fallback
	}
	if strings.TrimSpace(cfg.Incomplete.Indicator) != "" {
		return strings.TrimSpace(cfg.Incomplete.Indicator)
	}
	return fallback
}

func NFOIndicator(cfg Config) string {
	if !IncompleteEnabled(cfg) {
		return ""
	}
	return strings.TrimSpace(cfg.Incomplete.NFOIndicator)
}

func NoSFVIndicator(cfg Config) string {
	if !IncompleteEnabled(cfg) {
		return ""
	}
	return strings.TrimSpace(cfg.Incomplete.NoSFVIndicator)
}

func IgnoreNoSFVMarker(cfg Config, releasePath, releaseName string) bool {
	return matchesNameOrPathPatternList(releasePath, releaseName, cfg.Incomplete.NoSFVIgnore)
}

func CDIndicator(cfg Config) string {
	if !IncompleteEnabled(cfg) {
		return ""
	}
	return strings.TrimSpace(cfg.Incomplete.CDIndicator)
}

func IsStatusMarkerName(cfg Config, name string) bool {
	name = strings.TrimSpace(name)
	if name == "" {
		return false
	}
	patterns := []string{
		IncompleteIndicator(cfg, ""),
		NoSFVIndicator(cfg),
		NFOIndicator(cfg),
		CDIndicator(cfg),
	}
	for _, pattern := range patterns {
		if isStatusMarkerName(pattern, name) {
			return true
		}
	}
	return false
}

func StatusMarkerName(pattern, relname string) string {
	return statusMarkerName(pattern, relname)
}

func StatusMarkerNameForChild(pattern, relname, child string) string {
	return statusMarkerNameForChild(pattern, relname, child)
}

func BuildStatusMarkerEntries(cfg Config, parentDir string, releases []StatusMarkerRelease) []StatusMarkerEntry {
	parentDir = normalizePath(parentDir)
	if parentDir == "/" {
		return nil
	}
	incompletePattern := strings.TrimSpace(IncompleteIndicator(cfg, ""))
	noSFVPattern := strings.TrimSpace(NoSFVIndicator(cfg))
	nfoPattern := strings.TrimSpace(NFOIndicator(cfg))
	cdPattern := strings.TrimSpace(CDIndicator(cfg))
	markEmptyDirs := MarkEmptyDirsOnRescan(cfg)

	out := make([]StatusMarkerEntry, 0, len(releases)*2)
	seen := make(map[string]struct{}, len(releases)*2)
	for _, rel := range releases {
		name := strings.TrimSpace(rel.Name)
		releasePath := normalizePath(rel.Path)
		if name == "" || releasePath == "/" {
			continue
		}
		if !UsesReleaseCheckEntry(cfg, releasePath) || IsIgnoredReleaseSubdir(cfg, releasePath) {
			continue
		}

		hasContent := rel.FileCount > 0 || rel.Present > 0 || rel.HasSFV || rel.HasNFO
		if !hasContent && !isRequestContainerPath(releasePath) {
			hasContent = rel.VisibleCount > 0
		}
		expectsSFV := UsesSFVEntry(cfg, releasePath) && !UsesZipEntry(cfg, releasePath)
		if hasContent && expectsSFV && noSFVPattern != "" && !rel.HasSFV && !IgnoreNoSFVMarker(cfg, releasePath, name) {
			appendStatusMarker(&out, seen, statusMarkerName(noSFVPattern, name), releasePath, rel.ModTime)
		}
		if hasContent && nfoPattern != "" && !rel.HasNFO {
			appendStatusMarker(&out, seen, statusMarkerName(nfoPattern, name), releasePath, rel.ModTime)
		}

		emptyDir := false
		if rel.Total <= 0 {
			if markEmptyDirs {
				emptyDir = rel.VisibleCount == 0
			}
			if !emptyDir {
				continue
			}
		}

		if hasContent && rel.Total > 0 && rel.Present < rel.Total && incompletePattern != "" {
			appendStatusMarker(&out, seen, statusMarkerName(incompletePattern, name), releasePath, rel.ModTime)
		}
		if cdPattern != "" && isDiscDirName(name) && rel.Total > 0 && rel.Present < rel.Total {
			appendStatusMarker(&out, seen, statusMarkerNameForChild(cdPattern, path.Base(parentDir), name), releasePath, rel.ModTime)
		}
	}
	return out
}

func appendStatusMarker(out *[]StatusMarkerEntry, seen map[string]struct{}, name, target string, modTime int64) {
	name = strings.TrimSpace(path.Base(name))
	target = normalizePath(target)
	if name == "" || target == "/" {
		return
	}
	if _, ok := seen[name]; ok {
		return
	}
	seen[name] = struct{}{}
	*out = append(*out, StatusMarkerEntry{
		Name:       name,
		LinkTarget: target,
		ModTime:    modTime,
	})
}

func matchesNameOrPathPatternList(releasePath, releaseName string, patterns []string) bool {
	releasePath = strings.ToLower(normalizePath(releasePath))
	releaseName = strings.ToLower(strings.TrimSpace(releaseName))
	for _, pattern := range patterns {
		pattern = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(pattern), "\\", "/"))
		if pattern == "" {
			continue
		}
		if strings.Contains(pattern, "/") {
			if !strings.HasPrefix(pattern, "/") {
				pattern = "/" + pattern
			}
			if ok, _ := path.Match(pattern, releasePath); ok {
				return true
			}
			continue
		}
		if ok, _ := path.Match(pattern, releaseName); ok {
			return true
		}
	}
	return false
}

func isDiscDirName(name string) bool {
	lower := strings.ToLower(strings.TrimSpace(name))
	return discDirNameRE.MatchString(lower)
}

func isStatusMarkerName(pattern, name string) bool {
	pattern = strings.TrimSpace(pattern)
	name = strings.TrimSpace(name)
	if pattern == "" || name == "" {
		return false
	}
	if strings.Contains(pattern, "%0") {
		prefix := path.Base(strings.SplitN(pattern, "%0", 2)[0])
		return prefix != "" && strings.HasPrefix(strings.ToLower(name), strings.ToLower(prefix))
	}
	return strings.EqualFold(name, path.Base(pattern))
}

func statusMarkerName(pattern, relname string) string {
	pattern = strings.TrimSpace(pattern)
	relname = strings.TrimSpace(relname)
	if pattern == "" || relname == "" {
		return ""
	}
	if strings.Contains(pattern, "%0") {
		return path.Base(strings.ReplaceAll(pattern, "%0", relname))
	}
	return path.Base(pattern)
}

func statusMarkerNameForChild(pattern, relname, child string) string {
	pattern = statusMarkerName(pattern, relname)
	if strings.Contains(pattern, "%1") {
		pattern = strings.ReplaceAll(pattern, "%1", strings.TrimSpace(child))
	}
	return path.Base(pattern)
}

func MarkEmptyDirsOnRescan(cfg Config) bool {
	return cfg.Enabled && cfg.Incomplete.Enabled && cfg.Incomplete.MarkEmptyDirsOnRescan
}

func ValidateUpload(cfg Config, uploadUser *user.User, dirPath, fileName string, existingNames []string, existingDirs []string, sfvEntries map[string]uint32) error {
	if isConfiguredRaceContainerUpload(cfg, dirPath, fileName) {
		return errors.New("zipscript: upload files inside a release directory, not the section or dated folder")
	}
	if !UsesRace(cfg, dirPath) {
		if isConfiguredRaceContainerDir(cfg, dirPath) {
			return errors.New("zipscript: upload files inside a release directory, not the section or dated folder")
		}
		return nil
	}
	if !UsesRaceEntry(cfg, dirPath) && !isRaceReleaseChildUploadDir(cfg, dirPath) {
		return errors.New("zipscript: upload files inside a release directory, not the section or dated folder")
	}

	lowerName := strings.ToLower(strings.TrimSpace(fileName))
	isSFV := strings.HasSuffix(lowerName, ".sfv")
	if isSFV && denySFVForExistingSubdirs(cfg, existingDirs) {
		return errors.New("zipscript: cannot upload .sfv while matching subdirs already exist in this release")
	}
	listedInSFV := false
	if sfvEntries != nil {
		_, listedInSFV = sfvEntries[raceEntryKey(fileName)]
	}
	isPayload := IsRacePayloadFileForDir(cfg, dirPath, fileName) || listedInSFV
	allowedOutsideSFV := AllowedOutsideSFVForDir(cfg, dirPath, fileName)
	if UsesZipUploadMode(cfg, dirPath, fileName, existingNames) {
		if strings.EqualFold(path.Base(strings.ReplaceAll(strings.TrimSpace(fileName), "\\", "/")), "file_id.diz") {
			return errors.New("zipscript: diz-file is not allowed here")
		}
		if !IsAllowedTypeForDir(cfg, dirPath, fileName) {
			return fmt.Errorf("zipscript: file type %q is not allowed here", normalizedExt(fileName))
		}
		return nil
	}
	hasReadableSFV := sfvEntries != nil
	hasNamedSFV := false
	sfvPolicyApplies := sfvPolicyAppliesToUpload(cfg, uploadUser, dirPath)
	for _, name := range existingNames {
		if strings.HasSuffix(strings.ToLower(strings.TrimSpace(name)), ".sfv") {
			hasNamedSFV = true
			if isSFV && cfg.SFV.DenyDoubleSFV && hasReadableSFV {
				return errors.New("zipscript: .sfv already exists in this release")
			}
		}
	}

	// Do not let globally allowed sample/archive types bypass the release manifest.
	// Child directories and ZIP-style releases keep their own upload policies.
	if cfg.SFV.StrictReleaseRoot && sfvRestrictFiles(cfg) && sfvPolicyApplies &&
		UsesSFVEntry(cfg, dirPath) && !UsesZip(cfg, dirPath) && !IsIgnoredReleaseSubdir(cfg, dirPath) &&
		!isSFV && !isSFVRootSidecar(fileName) {
		if len(sfvEntries) == 0 {
			return errors.New("zipscript: upload a valid .sfv before payload files in this release")
		}
		if !listedInSFV {
			return fmt.Errorf("zipscript: %q is not listed in the .sfv", fileName)
		}
	}

	if !hasReadableSFV && !hasNamedSFV && cfg.SFV.ForceFirst && sfvPolicyApplies && isPayload && !allowedOutsideSFV && !isSFV {
		return errors.New("zipscript: upload the .sfv before payload files in this release")
	}

	if hasReadableSFV && sfvPolicyApplies && !isSFV && isPayload && !allowedOutsideSFV {
		if sfvRestrictFiles(cfg) && !listedInSFV {
			return fmt.Errorf("zipscript: %q is not listed in the .sfv", fileName)
		}
	}

	if listedInSFV {
		return nil
	}

	if !IsAllowedTypeForDir(cfg, dirPath, fileName) {
		return fmt.Errorf("zipscript: file type %q is not allowed here", normalizedExt(fileName))
	}

	return nil
}

func isSFVRootSidecar(fileName string) bool {
	switch normalizedExt(fileName) {
	case "nfo", "txt", "jpg", "jpeg", "png", "gif", "cue", "m3u", "log", "diz",
		"debug", "message", "imdb", "html", "url", "metadata":
		return true
	default:
		return false
	}
}

func isConfiguredRaceContainerUpload(cfg Config, dirPath, fileName string) bool {
	if !isConfiguredRaceContainerDir(cfg, dirPath) {
		return false
	}
	ext := normalizedExt(fileName)
	return ext != "" && !IsIgnoredType(cfg, fileName)
}

func isRaceReleaseChildUploadDir(cfg Config, dirPath string) bool {
	cleanPath := normalizePath(dirPath)
	parent := path.Dir(cleanPath)
	return parent != "." && parent != "/" && UsesRaceEntry(cfg, parent)
}

func isConfiguredRaceContainerDir(cfg Config, dirPath string) bool {
	if !cfg.Enabled {
		return false
	}
	if pathMatchesAny(dirPath, cfg.Sections.NoCheck) {
		return false
	}
	cleanPath := normalizePath(dirPath)
	if isRequestContainerPath(cleanPath) {
		return false
	}
	if isTopLevelPath(cleanPath) && UsesRace(cfg, cleanPath) {
		return true
	}
	candidates := []string{
		path.Join(cleanPath, "_release_"),
		path.Join(cleanPath, "_date_", "_release_"),
	}
	for _, candidate := range candidates {
		if len(cfg.Sections.SFV) > 0 && pathMatchesAnyExact(candidate, cfg.Sections.SFV) {
			return true
		}
		if len(cfg.Sections.Zip) > 0 && pathMatchesAnyExact(candidate, cfg.Sections.Zip) {
			return true
		}
	}
	return false
}

func isTopLevelPath(dirPath string) bool {
	clean := strings.Trim(path.Clean("/"+strings.TrimSpace(dirPath)), "/")
	return clean != "" && !strings.Contains(clean, "/")
}

func sfvPolicyAppliesToUpload(cfg Config, uploadUser *user.User, dirPath string) bool {
	if !cfg.Enabled {
		return false
	}
	cleanPath := normalizePath(dirPath)
	if !scopePathMatchesAny(cleanPath, cfg.SFV.PathCheck) {
		return false
	}
	if scopePathMatchesAny(cleanPath, cfg.SFV.PathIgnore) {
		return false
	}
	return sfvUserMatches(uploadUser, cfg.SFV.Users)
}

func sfvUserMatches(uploadUser *user.User, specs []string) bool {
	if len(specs) == 0 {
		return true
	}
	allow := false
	for _, spec := range specs {
		spec = strings.TrimSpace(spec)
		if spec == "" {
			continue
		}
		if spec == "*" {
			allow = true
			continue
		}
		if strings.HasPrefix(spec, "!=") {
			target := strings.TrimSpace(spec[2:])
			if target != "" && userMatchesToken(uploadUser, target) {
				return false
			}
			continue
		}
		if userMatchesToken(uploadUser, spec) {
			allow = true
		}
	}
	return allow
}

func userMatchesToken(uploadUser *user.User, token string) bool {
	if uploadUser == nil {
		return false
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return false
	}
	if strings.EqualFold(uploadUser.Name, token) {
		return true
	}
	if strings.EqualFold(uploadUser.PrimaryGroup, token) {
		return true
	}
	for group := range uploadUser.Groups {
		if strings.EqualFold(group, token) {
			return true
		}
	}
	return false
}

func scopePathMatchesAny(dirPath string, patterns []string) bool {
	cleanPath := normalizePath(dirPath)
	for _, pattern := range patterns {
		if scopePathMatches(cleanPath, pattern) {
			return true
		}
	}
	return false
}

func scopePathMatches(dirPath, pattern string) bool {
	pattern = normalizePattern(strings.TrimSuffix(strings.TrimSpace(pattern), "/"))
	if pattern == "" {
		return false
	}
	if pattern == "/*" || pattern == "*" {
		return true
	}
	regex := globToPathRegex(pattern)
	matched, err := regexp.MatchString(regex, dirPath)
	return err == nil && matched
}

func globToPathRegex(pattern string) string {
	var b strings.Builder
	b.WriteString("^")
	for i := 0; i < len(pattern); i++ {
		ch := pattern[i]
		switch ch {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteByte('.')
		case '.', '+', '(', ')', '|', '^', '$', '{', '}', '[', ']', '\\':
			b.WriteByte('\\')
			b.WriteByte(ch)
		default:
			b.WriteByte(ch)
		}
	}
	b.WriteString("$")
	return b.String()
}

func denySFVForExistingSubdirs(cfg Config, existingDirs []string) bool {
	if !cfg.SFV.DenySubdir || len(existingDirs) == 0 {
		return false
	}
	include := strings.TrimSpace(cfg.SFV.DenySubdirInclude)
	if include == "" {
		include = ".*"
	}
	exclude := strings.TrimSpace(cfg.SFV.DenySubdirExclude)
	for _, dirName := range existingDirs {
		name := strings.TrimSpace(dirName)
		if name == "" {
			continue
		}
		if exclude != "" {
			if matched, err := regexp.MatchString(exclude, name); err == nil && matched {
				continue
			}
		}
		if matched, err := regexp.MatchString(include, name); err == nil && matched {
			return true
		}
	}
	return false
}

func sfvAllowNoExt(cfg Config) bool {
	if cfg.SFV.AllowNoExt == nil {
		return true
	}
	return *cfg.SFV.AllowNoExt
}

func sfvRestrictFiles(cfg Config) bool {
	if cfg.SFV.RestrictFiles == nil {
		return true
	}
	return *cfg.SFV.RestrictFiles
}

func IsIgnoredType(cfg Config, fileName string) bool {
	ext := normalizedExt(fileName)
	if ext == "" {
		return false
	}
	for _, item := range cfg.AllowedFiles.IgnoredTypes {
		if strings.EqualFold(strings.TrimSpace(item), ext) {
			return true
		}
	}
	return false
}

func IsAllowedType(cfg Config, fileName string) bool {
	return IsAllowedTypeForDir(cfg, "", fileName)
}

func AllowedOutsideSFVForDir(cfg Config, dirPath, fileName string) bool {
	ext := normalizedExt(fileName)
	if ext == "" {
		return sfvAllowNoExt(cfg)
	}
	if IsIgnoredType(cfg, fileName) {
		return true
	}
	if len(cfg.AllowedFiles.AllowedTypes) > 0 {
		for _, item := range cfg.AllowedFiles.AllowedTypes {
			if strings.EqualFold(strings.TrimSpace(item), ext) {
				return true
			}
		}
		return false
	}
	return defaultAllowedOutsideSFVExts[ext]
}

func IsAllowedTypeForDir(cfg Config, dirPath, fileName string) bool {
	ext := normalizedExt(fileName)
	if UsesZip(cfg, dirPath) && IsZipPayloadName(fileName) {
		return true
	}
	if ext == "" {
		return sfvAllowNoExt(cfg)
	}
	if isPrimaryAudioPayload(dirPath, ext) {
		return true
	}
	if scenePayloadExts[ext] || isSceneMultipartExt(ext) {
		return true
	}
	if IsIgnoredType(cfg, fileName) {
		return true
	}
	if len(cfg.AllowedFiles.AllowedTypes) == 0 {
		return true
	}
	for _, item := range cfg.AllowedFiles.AllowedTypes {
		if strings.EqualFold(strings.TrimSpace(item), ext) {
			return true
		}
	}
	return false
}

func isPrimaryAudioPayload(dirPath, ext string) bool {
	section := strings.ToUpper(strings.Trim(path.Clean(dirPath), "/"))
	if idx := strings.Index(section, "/"); idx >= 0 {
		section = section[:idx]
	}
	switch section {
	case "MP3":
		return ext == "mp3"
	case "FLAC":
		return ext == "flac"
	case "REQUESTS":
		return isRequestReleasePath(dirPath) && isAudioPayloadExt(ext)
	default:
		return false
	}
}

func isAudioPayloadExt(ext string) bool {
	switch strings.ToLower(strings.TrimSpace(ext)) {
	case "mp3", "flac", "m4a", "wav":
		return true
	default:
		return false
	}
}

func isRequestReleasePath(dirPath string) bool {
	clean := strings.Trim(path.Clean("/"+strings.TrimSpace(dirPath)), "/")
	if clean == "" {
		return false
	}
	parts := strings.Split(clean, "/")
	return len(parts) >= 2 && strings.EqualFold(parts[0], "REQUESTS") && isRequestWrapperName(parts[1])
}

func requestContainerMatchesChildPattern(dirPath string, patterns []string) bool {
	if len(patterns) == 0 || !isRequestContainerPath(dirPath) {
		return false
	}
	return pathMatchesAnyExact(path.Join(normalizePath(dirPath), "_request_payload_"), patterns)
}

func isRequestContainerPath(dirPath string) bool {
	clean := strings.Trim(path.Clean("/"+strings.TrimSpace(dirPath)), "/")
	if clean == "" {
		return false
	}
	parts := strings.Split(clean, "/")
	return len(parts) == 2 && strings.EqualFold(parts[0], "REQUESTS") && isRequestWrapperName(parts[1])
}

func isRequestWrapperName(name string) bool {
	upper := strings.ToUpper(strings.TrimSpace(name))
	return strings.HasPrefix(upper, "REQ-") || strings.HasPrefix(upper, "FILLED-")
}

func ExpectedFileLabel(cfg Config, dirPath string) string {
	if !RaceEnabled(cfg, dirPath) {
		return "file(s)"
	}
	section := strings.ToUpper(strings.Trim(path.Clean(dirPath), "/"))
	if idx := strings.Index(section, "/"); idx >= 0 {
		section = section[:idx]
	}
	switch section {
	case "MP3", "FLAC":
		return "track(s)"
	default:
		return "file(s)"
	}
}

func IsRacePayloadFile(cfg Config, fileName string) bool {
	return IsRacePayloadFileForDir(cfg, "", fileName)
}

func IsRacePayloadFileForDir(cfg Config, dirPath, fileName string) bool {
	if dirPath != "" && !UsesRace(cfg, dirPath) {
		return false
	}
	if dirPath == "" && !cfg.Enabled {
		return false
	}
	name := strings.ToLower(strings.TrimSpace(fileName))
	if strings.HasSuffix(name, ".rar") || isSceneMultipartExt(normalizedExt(name)) {
		return true
	}
	if UsesZip(cfg, dirPath) && IsZipPayloadName(name) {
		return true
	}
	return IsMediaInfoFile(name)
}

func IsZipPayloadName(name string) bool {
	return zipPayloadNameRE.MatchString(strings.ToLower(strings.TrimSpace(name)))
}

func IsZipRecoverableArchiveName(name string) bool {
	return strings.HasSuffix(strings.ToLower(strings.TrimSpace(name)), ".zip")
}

func IsZipManifestName(name string) bool {
	return strings.EqualFold(path.Base(strings.ReplaceAll(strings.TrimSpace(name), "\\", "/")), "file_id.diz")
}

var zipDIZTotalRE = regexp.MustCompile(`[][()<>:[:space:]][[:space:]]*[0-9oOxX*]*[[:space:]]*/[[:space:]]*([0-9oOxX]*[0-9oO])[[:space:]]*[][()<>[:space:]]`)

func ParseZipExpectedPartsFromDIZ(content []byte) int {
	if len(content) == 0 {
		return 0
	}
	match := zipDIZTotalRE.FindSubmatch(content)
	if len(match) < 2 {
		return 0
	}
	raw := strings.TrimSpace(string(match[1]))
	if raw == "" {
		return 0
	}
	raw = strings.NewReplacer("o", "0", "O", "0", "x", "0", "X", "0").Replace(raw)
	total, err := strconv.Atoi(raw)
	if err != nil || total <= 0 {
		return 0
	}
	return total
}

func ShouldBlockZipDIZUpload(cfg Config, dirPath, fileName string) bool {
	if !UsesZip(cfg, dirPath) {
		return false
	}
	return IsZipManifestName(fileName)
}

func UsesZipUploadMode(cfg Config, dirPath, fileName string, existingNames []string) bool {
	if !UsesZip(cfg, dirPath) {
		return false
	}
	if !UsesSFV(cfg, dirPath) {
		return true
	}
	if IsZipPayloadName(fileName) || IsZipManifestName(fileName) {
		return true
	}
	for _, name := range existingNames {
		if IsZipPayloadName(name) || IsZipManifestName(name) {
			return true
		}
	}
	return false
}

func isSceneMultipartExt(ext string) bool {
	ext = strings.ToLower(strings.TrimSpace(ext))
	return len(ext) == 3 && ext[0] >= 'r' && ext[0] <= 'z' && ext[1] >= '0' && ext[1] <= '9' && ext[2] >= '0' && ext[2] <= '9'
}

func CanTriggerRaceEnd(cfg Config, sfvEntries map[string]uint32, fileName string) bool {
	return CanTriggerRaceEndForDir(cfg, "", sfvEntries, fileName)
}

// raceEndDirGuardsPass reports whether dirPath (or, for the "" legacy
// no-dir callers, cfg as a whole) is allowed to emit a race COMPLETE at all.
// Shared by RaceEndDirEligible and CanTriggerRaceEndForDir so the two guard
// sets can't drift apart the way the completeness-check duplicates in
// vfs.go/zipscript_runtime.go did.
func raceEndDirGuardsPass(cfg Config, dirPath string) bool {
	if dirPath != "" && IsIgnoredReleaseSubdir(cfg, dirPath) {
		return false
	}
	if dirPath != "" && !RaceEnabled(cfg, dirPath) {
		return false
	}
	if dirPath == "" && (!cfg.Enabled || !cfg.Race.Enabled) {
		return false
	}
	return true
}

// RaceEndDirEligible reports whether dirPath is a race directory that may emit a
// COMPLETE (the dir-level guards from CanTriggerRaceEndForDir, without requiring
// the triggering file to be SFV-listed). Used so a verified-complete release can
// announce on any trailing file (cover/.m3u/.nfo) instead of only on the SFV file
// that happened to flip completeness -- otherwise a flap on that one file loses
// the COMPLETE permanently. Duplicate emits are still prevented by markRaceCompleteOnce.
func RaceEndDirEligible(cfg Config, dirPath string) bool {
	return raceEndDirGuardsPass(cfg, dirPath)
}

func CanTriggerRaceEndForDir(cfg Config, dirPath string, sfvEntries map[string]uint32, fileName string) bool {
	if !raceEndDirGuardsPass(cfg, dirPath) {
		return false
	}
	name := raceEntryKey(fileName)
	if UsesZip(cfg, dirPath) && (!UsesSFV(cfg, dirPath) || IsZipPayloadName(name)) {
		return IsZipPayloadName(name)
	}
	if strings.HasSuffix(name, ".sfv") {
		return true
	}
	_, ok := sfvEntries[name]
	return ok
}

func MediaInfoGraceDelay(cfg Config, fileName string) time.Duration {
	return MediaInfoGraceDelayForDir(cfg, "", fileName)
}

func MediaInfoGraceDelayForDir(cfg Config, dirPath, fileName string) time.Duration {
	if dirPath != "" && !RaceEnabled(cfg, dirPath) {
		return 0
	}
	if dirPath == "" && (!cfg.Enabled || !cfg.Race.Enabled) {
		return 0
	}
	return 0
}

func CompleteStatusName(cfg Config, siteName, dirPath string, totalMB float64, totalFiles int, media MediaInfoProvider) string {
	if !cfg.Enabled || !cfg.Race.CompleteBanner {
		return ""
	}
	extra := ""
	if cfg.Race.MusicCompleteGenre {
		extra = musicCompleteExtra(dirPath, media)
	}
	if extra != "" {
		return fmt.Sprintf("[%s] - ( %.0fM %dF - COMPLETE - %s ) - [%s]",
			siteName, totalMB, totalFiles, extra, siteName)
	}
	return fmt.Sprintf("[%s] - ( %.0fM %dF - COMPLETE ) - [%s]",
		siteName, totalMB, totalFiles, siteName)
}

func ShouldDeleteZeroByte(cfg Config) bool {
	return ShouldDeleteZeroByteForDir(cfg, "")
}

func ShouldDeleteBadCRC(cfg Config) bool {
	return ShouldDeleteBadCRCForDir(cfg, "")
}

func ShouldDeleteZeroByteForDir(cfg Config, dirPath string) bool {
	if dirPath != "" && !UsesRace(cfg, dirPath) {
		return false
	}
	return cfg.Enabled && cfg.SFV.IgnoreZeroSize
}

func ShouldDeleteBadCRCForDir(cfg Config, dirPath string) bool {
	if dirPath != "" && !UsesSFV(cfg, dirPath) {
		return false
	}
	return cfg.Enabled && cfg.SFV.DeleteBadCRC
}

func AllowResumeForDir(cfg Config, dirPath string) bool {
	if dirPath != "" && !UsesRace(cfg, dirPath) {
		return true
	}
	return !cfg.Enabled || cfg.SFV.AllowResume
}

func CheckZipIntegrityForDir(cfg Config, dirPath string) bool {
	if dirPath != "" && !UsesZip(cfg, dirPath) {
		return false
	}
	if !cfg.Enabled {
		return false
	}
	if cfg.Zip.IntegrityCheck == nil {
		return true
	}
	return *cfg.Zip.IntegrityCheck
}

func ShowZipDIZOnCWDForDir(cfg Config, dirPath string) bool {
	if !UsesZipEntry(cfg, dirPath) || cfg.Zip.CWDDIZInfo == nil {
		return false
	}
	return *cfg.Zip.CWDDIZInfo
}

func RaceStatsOnCWDForDir(cfg Config, dirPath string) bool {
	if !cfg.Enabled {
		return false
	}
	if UsesZipEntry(cfg, dirPath) {
		return cfg.Race.CWDZipRaceStats != nil && *cfg.Race.CWDZipRaceStats
	}
	if UsesSFVEntry(cfg, dirPath) {
		return cfg.Race.CWDRaceStats != nil && *cfg.Race.CWDRaceStats
	}
	return false
}

func RaceStatsOnSTORForDir(cfg Config, dirPath string) bool {
	if !cfg.Enabled {
		return false
	}
	if UsesZip(cfg, dirPath) {
		return cfg.Race.STORZipRaceStats != nil && *cfg.Race.STORZipRaceStats
	}
	if UsesSFV(cfg, dirPath) {
		return cfg.Race.STORRaceStats != nil && *cfg.Race.STORRaceStats
	}
	return false
}

func ShowStatusBarForDir(cfg Config, dirPath string) bool {
	if cfg.List.StatusBarEnabled == nil || !cfg.Enabled {
		return false
	}
	if !*cfg.List.StatusBarEnabled {
		return false
	}
	return UsesRaceEntry(cfg, dirPath) || audioStatusBarEligibleDir(cfg, dirPath)
}

func StatusBarDirectoryForDir(cfg Config, dirPath string) bool {
	if !ShowStatusBarForDir(cfg, dirPath) || cfg.List.StatusBarDirectory == nil {
		return false
	}
	return *cfg.List.StatusBarDirectory
}

func ShowMissingFilesForDir(cfg Config, dirPath string) bool {
	if !UsesSFV(cfg, dirPath) || cfg.List.MissingFiles == nil {
		return false
	}
	return *cfg.List.MissingFiles
}

func audioStatusBarEligibleDir(cfg Config, dirPath string) bool {
	if !cfg.Audio.Enabled {
		return false
	}
	if !UsesReleaseCheckEntry(cfg, dirPath) {
		return false
	}
	section, _ := SectionInfoFromPath(dirPath)
	switch strings.ToUpper(strings.TrimSpace(section)) {
	case "MP3", "FLAC":
		return true
	default:
		return false
	}
}

func RaceEnabled(cfg Config, dirPath string) bool {
	return cfg.Enabled && cfg.Race.Enabled && UsesRace(cfg, dirPath)
}

func AudioCheckEnabled(cfg Config, dirPath, fileName string) bool {
	if !cfg.Enabled || !cfg.Audio.Enabled {
		return false
	}
	section, _ := SectionInfoFromPath(dirPath)
	requestAudio := isRequestReleasePath(dirPath) && isAudioPayloadExt(normalizedExt(fileName))
	if len(cfg.Audio.Sections) > 0 && !matchesAnySectionName(section, cfg.Audio.Sections) && !requestAudio {
		return false
	}
	ext := normalizedExt(fileName)
	for _, allowed := range cfg.Audio.Extensions {
		if strings.EqualFold(strings.TrimSpace(allowed), ext) {
			return true
		}
	}
	return false
}

func matchesAnySectionName(section string, patterns []string) bool {
	section = strings.ToLower(strings.TrimSpace(section))
	for _, pat := range patterns {
		pat = strings.ToLower(strings.TrimSpace(pat))
		if pat != "" && strings.Contains(section, pat) {
			return true
		}
	}
	return false
}

func ShowAudioInfoOnCWDForDir(cfg Config, dirPath string, fields map[string]string) bool {
	switch audioInfoReleaseType(dirPath, fields) {
	case "mp3":
		return cfg.Enabled && cfg.Audio.Enabled && cfg.Audio.CWDMP3Info != nil && *cfg.Audio.CWDMP3Info
	case "flac":
		return cfg.Enabled && cfg.Audio.Enabled && cfg.Audio.CWDFLACInfo != nil && *cfg.Audio.CWDFLACInfo
	default:
		return false
	}
}

func ShowAudioInfoOnSTORForDir(cfg Config, dirPath string, fields map[string]string) bool {
	switch audioInfoReleaseType(dirPath, fields) {
	case "mp3":
		return cfg.Enabled && cfg.Audio.Enabled && cfg.Audio.STORMP3Info != nil && *cfg.Audio.STORMP3Info
	case "flac":
		return cfg.Enabled && cfg.Audio.Enabled && cfg.Audio.STORFLACInfo != nil && *cfg.Audio.STORFLACInfo
	default:
		return false
	}
}

func ValidateAudioRelease(cfg Config, fields map[string]string) []string {
	if !cfg.Enabled || !cfg.Audio.Enabled || len(fields) == 0 {
		return nil
	}
	var reasons []string

	if cfg.Audio.CBRCheck {
		mode := strings.ToUpper(strings.TrimSpace(firstNonEmpty(fields, "bitrate_mode")))
		if mode != "CBR" {
			reasons = append(reasons, "audio is not CBR")
		}
		if len(cfg.Audio.AllowedConstantBitrates) > 0 {
			bitrate := parseBitrateKbps(firstNonEmpty(fields, "bitrate"))
			if bitrate > 0 && !intInSlice(bitrate, cfg.Audio.AllowedConstantBitrates) {
				reasons = append(reasons, fmt.Sprintf("bitrate %dkbps is not allowed", bitrate))
			}
		}
	}

	if cfg.Audio.YearCheck && len(cfg.Audio.AllowedYears) > 0 {
		year := normalizeYearForBanner(firstNonEmpty(fields, "year"))
		if year != "" {
			if n, err := strconv.Atoi(year); err == nil && !intInSlice(n, cfg.Audio.AllowedYears) {
				reasons = append(reasons, fmt.Sprintf("year %d is not allowed", n))
			}
		}
	}

	genre := strings.TrimSpace(firstNonEmpty(fields, "genre", "g_genre"))
	if cfg.Audio.BannedGenreCheck && genre != "" && stringInSliceFold(genre, cfg.Audio.BannedGenres) {
		reasons = append(reasons, fmt.Sprintf("genre %q is banned", genre))
	}
	if cfg.Audio.AllowedGenreCheck && len(cfg.Audio.AllowedGenres) > 0 && genre != "" && !stringInSliceFold(genre, cfg.Audio.AllowedGenres) {
		reasons = append(reasons, fmt.Sprintf("genre %q is not allowed", genre))
	}

	return reasons
}

func AudioInfoLooksUsable(fields map[string]string) bool {
	if len(fields) == 0 {
		return false
	}
	genre := strings.TrimSpace(firstNonEmpty(fields, "genre", "g_genre"))
	year := strings.TrimSpace(normalizeYearForBanner(firstNonEmpty(fields, "year", "g_recordeddate", "g_recorded_date")))
	return genre != "" && year != ""
}

func AudioSortLinks(cfg Config, releasePath string, fields map[string]string) []AudioSortLink {
	if !cfg.Enabled || !cfg.Audio.Enabled || len(fields) == 0 {
		return nil
	}
	relName := strings.TrimSpace(path.Base(path.Clean(releasePath)))
	if relName == "" || relName == "." || relName == "/" {
		return nil
	}
	var out []AudioSortLink
	add := func(enabled bool, basePath, bucket string) {
		basePath = audioSortBasePath(cfg, releasePath, basePath)
		bucket = sanitizeSortBucket(bucket)
		if !enabled || basePath == "/" || bucket == "" {
			return
		}
		dirPath := path.Join(basePath, bucket)
		out = append(out, AudioSortLink{
			DirPath:  dirPath,
			LinkPath: path.Join(dirPath, relName),
			Target:   normalizePath(releasePath),
		})
	}

	add(cfg.Audio.Sort.Genre, cfg.Audio.GenrePath, firstNonEmpty(fields, "genre", "g_genre"))
	add(cfg.Audio.Sort.Artist, cfg.Audio.ArtistPath, firstNonEmpty(fields, "artist", "g_performer", "g_album_performer", "g_track_name"))
	add(cfg.Audio.Sort.Year, cfg.Audio.YearPath, normalizeYearForBanner(firstNonEmpty(fields, "year", "g_recordeddate", "g_recorded_date")))
	add(cfg.Audio.Sort.Group, cfg.Audio.GroupPath, releaseGroupName(relName))
	return out
}

func audioSortBasePath(cfg Config, releasePath, basePath string) string {
	basePath = normalizePath(basePath)
	if basePath == "/" {
		return basePath
	}
	if cfg.Audio.Sort.SeparateBySection == nil || *cfg.Audio.Sort.SeparateBySection {
		if section, _ := SectionInfoFromPath(releasePath); strings.TrimSpace(section) != "" {
			basePath = path.Join(basePath, strings.ToUpper(strings.TrimSpace(section)))
		}
	}
	return basePath
}

func IsMediaInfoFile(fileName string) bool {
	name := strings.ToLower(strings.TrimSpace(fileName))
	for _, suffix := range []string{".mp3", ".flac", ".m4a", ".wav", ".mkv", ".mp4", ".avi", ".m2ts"} {
		if strings.HasSuffix(name, suffix) {
			return true
		}
	}
	return false
}

func raceEntryKey(fileName string) string {
	name := strings.TrimSpace(strings.ReplaceAll(fileName, "\\", "/"))
	name = strings.TrimPrefix(name, "\ufeff")
	for strings.HasPrefix(name, "./") {
		name = strings.TrimPrefix(name, "./")
	}
	name = strings.TrimSpace(path.Base(name))
	name = strings.TrimPrefix(name, "\ufeff")
	return strings.ToLower(name)
}

func musicCompleteExtra(dirPath string, media MediaInfoProvider) string {
	if media == nil {
		return ""
	}
	info := media.GetDirMediaInfo(dirPath)
	if !AudioInfoLooksUsable(info) {
		return ""
	}
	if !isMusicSection(dirPath) && !looksLikeMusicReleaseInfo(info) {
		return ""
	}
	genre := firstNonEmpty(info, "genre", "g_genre")
	year := firstNonEmpty(info, "year", "g_recordeddate", "g_recorded_date", "g_originalreleaseddate", "g_original_released_date")
	year = normalizeYearForBanner(year)
	switch {
	case genre != "" && year != "":
		return genre + " " + year
	case genre != "":
		return genre
	default:
		return year
	}
}

func looksLikeMusicReleaseInfo(info map[string]string) bool {
	for _, key := range []string{"filename", "filepath", "path"} {
		name := strings.ToLower(strings.TrimSpace(info[key]))
		switch {
		case strings.HasSuffix(name, ".mp3"),
			strings.HasSuffix(name, ".flac"),
			strings.HasSuffix(name, ".m4a"),
			strings.HasSuffix(name, ".wav"):
			return true
		}
	}
	return false
}

func isMusicSection(dirPath string) bool {
	section := strings.ToUpper(strings.Trim(path.Clean(dirPath), "/"))
	if idx := strings.Index(section, "/"); idx >= 0 {
		section = section[:idx]
	}
	return section == "MP3" || section == "FLAC"
}

func audioInfoReleaseType(dirPath string, fields map[string]string) string {
	section := strings.ToUpper(strings.Trim(path.Clean(dirPath), "/"))
	if idx := strings.Index(section, "/"); idx >= 0 {
		section = section[:idx]
	}
	switch section {
	case "MP3":
		return "mp3"
	case "FLAC":
		return "flac"
	}
	for _, key := range []string{"filename", "filepath", "path"} {
		name := strings.ToLower(strings.TrimSpace(fields[key]))
		switch {
		case strings.HasSuffix(name, ".mp3"):
			return "mp3"
		case strings.HasSuffix(name, ".flac"):
			return "flac"
		}
	}
	return ""
}

func firstNonEmpty(values map[string]string, keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(values[key]); value != "" {
			return value
		}
	}
	return ""
}

func normalizeYearForBanner(value string) string {
	value = strings.TrimSpace(value)
	if len(value) >= 4 {
		year := value[:4]
		allDigits := true
		for _, r := range year {
			if r < '0' || r > '9' {
				allDigits = false
				break
			}
		}
		if allDigits {
			return year
		}
	}
	return value
}

func pathMatchesAny(dirPath string, patterns []string) bool {
	cleanPath := normalizePath(dirPath)
	for _, pattern := range patterns {
		pattern = normalizePattern(pattern)
		if pattern == "" {
			continue
		}
		if ok, _ := path.Match(pattern, cleanPath); ok {
			return true
		}
		if strings.HasSuffix(pattern, "/*") {
			base := strings.TrimSuffix(pattern, "/*")
			if cleanPath == base || strings.HasPrefix(cleanPath, base+"/") {
				return true
			}
		}
	}
	return false
}

func pathMatchesAnyExact(dirPath string, patterns []string) bool {
	cleanPath := normalizePath(dirPath)
	for _, pattern := range patterns {
		pattern = normalizePattern(pattern)
		if pattern == "" {
			continue
		}
		if ok, _ := path.Match(pattern, cleanPath); ok {
			return true
		}
	}
	return false
}

func normalizePath(p string) string {
	p = strings.ReplaceAll(strings.TrimSpace(p), "\\", "/")
	if p == "" {
		return "/"
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return path.Clean(p)
}

func normalizePattern(p string) string {
	p = strings.ReplaceAll(strings.TrimSpace(p), "\\", "/")
	if p == "" {
		return ""
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return p
}

func sanitizeSortBucket(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	var b strings.Builder
	lastUnderscore := false
	for _, r := range name {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
			lastUnderscore = false
		case r == '-' || r == '_' || r == '.' || r == ' ':
			if !lastUnderscore {
				b.WriteByte('_')
				lastUnderscore = true
			}
		}
	}
	return strings.Trim(b.String(), "_")
}

func normalizedExt(name string) string {
	base := strings.ToLower(strings.TrimSpace(path.Base(name)))
	if base == "" {
		return ""
	}
	if strings.HasPrefix(base, ".") && strings.Count(base, ".") == 1 {
		return strings.TrimPrefix(base, ".")
	}
	if idx := strings.LastIndexByte(base, '.'); idx >= 0 && idx < len(base)-1 {
		return base[idx+1:]
	}
	return ""
}

func parseBitrateKbps(value string) int {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return 0
	}
	replacer := strings.NewReplacer(" ", "", ",", "", "kbps", "", "kbit/s", "", "kb/s", "", "bps", "", "bit/s", "")
	value = replacer.Replace(value)
	if n, err := strconv.Atoi(value); err == nil {
		if n >= 1000 {
			return n / 1000
		}
		return n
	}
	return 0
}

func intInSlice(v int, values []int) bool {
	for _, item := range values {
		if item == v {
			return true
		}
	}
	return false
}

func stringInSliceFold(v string, values []string) bool {
	v = strings.TrimSpace(v)
	for _, item := range values {
		if strings.EqualFold(v, strings.TrimSpace(item)) {
			return true
		}
	}
	return false
}

func releaseGroupName(relName string) string {
	relName = strings.TrimSpace(relName)
	if idx := strings.LastIndex(relName, "-"); idx >= 0 && idx < len(relName)-1 {
		return relName[idx+1:]
	}
	return ""
}
