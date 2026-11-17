package zipscript

type Config struct {
	Enabled bool `yaml:"enabled"`
	Debug   bool `yaml:"debug"`

	Sections     SectionsConfig     `yaml:"sections"`
	Race         RaceConfig         `yaml:"race"`
	SFV          SFVConfig          `yaml:"sfv"`
	Zip          ZipConfig          `yaml:"zip"`
	List         ListConfig         `yaml:"list"`
	Incomplete   IncompleteConfig   `yaml:"incomplete"`
	AllowedFiles AllowedFilesConfig `yaml:"allowed_files"`
	SectionRules SectionRulesConfig `yaml:"section_rules"`
	Audio        AudioConfig        `yaml:"audio"`
	Media        MediaConfig        `yaml:"media"`
	Hooks        HooksConfig        `yaml:"hooks"`

	// Legacy flat keys kept for compatibility with the first pass.
	LegacyRaceStats          bool `yaml:"race_stats"`
	LegacyCompleteBanner     bool `yaml:"complete_banner"`
	LegacyMusicCompleteGenre bool `yaml:"music_complete_genre"`
	LegacyDeleteBadCRC       bool `yaml:"delete_bad_crc"`
	LegacyIgnoreZeroSize     bool `yaml:"ignore_zero_size"`
}

type SectionsConfig struct {
	SFV                   []string `yaml:"sfv"`
	Zip                   []string `yaml:"zip"`
	NoCheck               []string `yaml:"nocheck"`
	ReleaseCheck          []string `yaml:"release_check"`
	IgnoredReleaseSubdirs []string `yaml:"ignored_release_subdirs"`
	LegacyCleanupPath     []string `yaml:"cleanup"`
}

type RaceConfig struct {
	Enabled            bool  `yaml:"enabled"`
	MaxUsersInTop      int   `yaml:"max_users_in_top"`
	MaxGroupsInTop     int   `yaml:"max_groups_in_top"`
	MaskUserGroupNames bool  `yaml:"mask_user_group_names"`
	CompleteBanner     bool  `yaml:"complete_banner"`
	MusicCompleteGenre bool  `yaml:"music_complete_genre"`
	AnnounceNoRace     bool  `yaml:"announce_norace"`
	AnnounceSubdirs    *bool `yaml:"announce_subdirs"`
	CWDRaceStats       *bool `yaml:"cwd_race_stats"`
	STORRaceStats      *bool `yaml:"stor_race_stats"`
	CWDZipRaceStats    *bool `yaml:"cwd_zip_race_stats"`
	STORZipRaceStats   *bool `yaml:"stor_zip_race_stats"`
}

type SFVConfig struct {
	StrictReleaseRoot bool     `yaml:"strict_release_root"`
	ForceFirst        bool     `yaml:"force_first"`
	DenyDoubleSFV     bool     `yaml:"deny_double_sfv"`
	DeleteBadCRC      bool     `yaml:"delete_bad_crc"`
	IgnoreZeroSize    bool     `yaml:"ignore_zero_size"`
	AllowResume       bool     `yaml:"allow_resume"`
	PathCheck         []string `yaml:"path_check"`
	PathIgnore        []string `yaml:"path_ignore"`
	Users             []string `yaml:"users"`
	DenySubdir        bool     `yaml:"deny_subdir"`
	DenySubdirInclude string   `yaml:"deny_subdir_include"`
	DenySubdirExclude string   `yaml:"deny_subdir_exclude"`
	AllowNoExt        *bool    `yaml:"allow_no_ext"`
	RestrictFiles     *bool    `yaml:"restrict_files"`
}

type IncompleteConfig struct {
	Enabled               bool     `yaml:"enabled"`
	Indicator             string   `yaml:"indicator"`
	NoSFVIndicator        string   `yaml:"no_sfv_indicator"`
	NoSFVIgnore           []string `yaml:"no_sfv_ignore"`
	NFOIndicator          string   `yaml:"nfo_indicator"`
	CDIndicator           string   `yaml:"cd_indicator"`
	MarkEmptyDirsOnRescan bool     `yaml:"mark_empty_dirs_on_rescan"`
}

type ZipConfig struct {
	IntegrityCheck *bool `yaml:"integrity_check"`
	CWDDIZInfo     *bool `yaml:"cwd_diz_info"`
}

type ListConfig struct {
	StatusBarEnabled   *bool `yaml:"statusbar_enabled"`
	StatusBarDirectory *bool `yaml:"statusbar_directory"`
	MissingFiles       *bool `yaml:"missing_files_enabled"`
}

type AllowedFilesConfig struct {
	AllowedTypes []string `yaml:"allowed_types"`
	IgnoredTypes []string `yaml:"ignored_types"`
}

type SectionRulesConfig struct {
	CWD       bool   `yaml:"cwd"`
	Directory string `yaml:"directory"`
}

type AudioConfig struct {
	Enabled                 bool            `yaml:"enabled"`
	Sections                []string        `yaml:"sections"`
	Extensions              []string        `yaml:"extensions"`
	CBRCheck                bool            `yaml:"cbr_check"`
	YearCheck               bool            `yaml:"year_check"`
	BannedGenreCheck        bool            `yaml:"banned_genre_check"`
	AllowedGenreCheck       bool            `yaml:"allowed_genre_check"`
	AllowedConstantBitrates []int           `yaml:"allowed_constant_bitrates"`
	AllowedYears            []int           `yaml:"allowed_years"`
	BannedGenres            []string        `yaml:"banned_genres"`
	AllowedGenres           []string        `yaml:"allowed_genres"`
	GenrePath               string          `yaml:"genre_path"`
	ArtistPath              string          `yaml:"artist_path"`
	YearPath                string          `yaml:"year_path"`
	GroupPath               string          `yaml:"group_path"`
	Sort                    AudioSortConfig `yaml:"sort"`
	CreateM3U               *bool           `yaml:"create_m3u"`
	CWDMP3Info              *bool           `yaml:"cwd_mp3_info"`
	STORMP3Info             *bool           `yaml:"stor_mp3_info"`
	CWDFLACInfo             *bool           `yaml:"cwd_flac_info"`
	STORFLACInfo            *bool           `yaml:"stor_flac_info"`
}

type AudioSortConfig struct {
	Genre             bool  `yaml:"genre"`
	Artist            bool  `yaml:"artist"`
	Year              bool  `yaml:"year"`
	Group             bool  `yaml:"group"`
	SeparateBySection *bool `yaml:"separate_by_section"`
}

type MediaConfig struct {
	Enabled         *bool    `yaml:"enabled"`
	Sections        []string `yaml:"sections"`
	SampleOnly      *bool    `yaml:"sample_only"`
	VideoExtensions []string `yaml:"video_extensions"`
}

type HooksConfig struct {
	OnComplete CommandHookConfig `yaml:"on_complete"`
}

type CommandHookConfig struct {
	Enabled        bool              `yaml:"enabled"`
	RunOn          string            `yaml:"run_on"`
	SlaveName      string            `yaml:"slave_name"`
	Command        string            `yaml:"command"`
	Args           []string          `yaml:"args"`
	TimeoutSeconds int               `yaml:"timeout_seconds"`
	ExtraEnv       map[string]string `yaml:"extra_env"`
}

func (c *Config) ApplyDefaults() {
	if c == nil {
		return
	}

	// Map legacy flat keys into the nested layout.
	if c.LegacyRaceStats {
		c.Race.Enabled = true
	}
	if c.LegacyCompleteBanner {
		c.Race.CompleteBanner = true
	}
	if c.LegacyMusicCompleteGenre {
		c.Race.MusicCompleteGenre = true
	}
	if c.LegacyDeleteBadCRC {
		c.SFV.DeleteBadCRC = true
	}
	if c.LegacyIgnoreZeroSize {
		c.SFV.IgnoreZeroSize = true
	}
	if len(c.Sections.ReleaseCheck) == 0 && len(c.Sections.LegacyCleanupPath) > 0 {
		c.Sections.ReleaseCheck = append([]string(nil), c.Sections.LegacyCleanupPath...)
	}

	// Preserve current behavior unless explicitly configured otherwise.
	if !c.Enabled &&
		!c.Race.Enabled &&
		!c.Race.CompleteBanner &&
		!c.Race.MusicCompleteGenre &&
		!c.SFV.DeleteBadCRC &&
		!c.SFV.IgnoreZeroSize {
		c.Enabled = true
		c.Race.Enabled = true
		c.Race.CompleteBanner = true
		c.Race.MusicCompleteGenre = true
		c.SFV.DeleteBadCRC = true
		c.SFV.IgnoreZeroSize = true
	}

	if c.Enabled &&
		!c.Race.Enabled &&
		!c.Race.CompleteBanner &&
		!c.Race.MusicCompleteGenre &&
		!c.SFV.DeleteBadCRC &&
		!c.SFV.IgnoreZeroSize {
		c.Race.Enabled = true
		c.Race.CompleteBanner = true
		c.Race.MusicCompleteGenre = true
		c.SFV.DeleteBadCRC = true
		c.SFV.IgnoreZeroSize = true
	}

	if c.Race.Enabled {
		if !c.Race.CompleteBanner {
			c.Race.CompleteBanner = true
		}
		if !c.Race.MusicCompleteGenre {
			c.Race.MusicCompleteGenre = true
		}
	}

	// Keep music sort trees MP3/FLAC-aware by default unless explicitly disabled.
	if c.Audio.Sort.SeparateBySection == nil {
		enabled := true
		c.Audio.Sort.SeparateBySection = &enabled
	}
	if c.SFV.AllowNoExt == nil {
		enabled := true
		c.SFV.AllowNoExt = &enabled
	}
	if c.SFV.RestrictFiles == nil {
		enabled := true
		c.SFV.RestrictFiles = &enabled
	}
	if c.Zip.IntegrityCheck == nil {
		enabled := true
		c.Zip.IntegrityCheck = &enabled
	}
	if c.Zip.CWDDIZInfo == nil {
		enabled := true
		c.Zip.CWDDIZInfo = &enabled
	}
	if c.List.StatusBarEnabled == nil {
		enabled := true
		c.List.StatusBarEnabled = &enabled
	}
	if c.List.StatusBarDirectory == nil {
		enabled := true
		c.List.StatusBarDirectory = &enabled
	}
	if c.List.MissingFiles == nil {
		enabled := true
		c.List.MissingFiles = &enabled
	}
	if c.SectionRules.Directory == "" {
		c.SectionRules.Directory = "etc/section-rules"
	}
	if c.Race.CWDRaceStats == nil {
		enabled := true
		c.Race.CWDRaceStats = &enabled
	}
	if c.Race.STORRaceStats == nil {
		enabled := true
		c.Race.STORRaceStats = &enabled
	}
	if c.Race.CWDZipRaceStats == nil {
		enabled := true
		c.Race.CWDZipRaceStats = &enabled
	}
	if c.Race.STORZipRaceStats == nil {
		enabled := true
		c.Race.STORZipRaceStats = &enabled
	}
	if c.Audio.CWDMP3Info == nil {
		enabled := true
		c.Audio.CWDMP3Info = &enabled
	}
	if c.Audio.STORMP3Info == nil {
		enabled := true
		c.Audio.STORMP3Info = &enabled
	}
	if c.Audio.CWDFLACInfo == nil {
		enabled := true
		c.Audio.CWDFLACInfo = &enabled
	}
	if c.Audio.STORFLACInfo == nil {
		enabled := true
		c.Audio.STORFLACInfo = &enabled
	}
	if c.Audio.CreateM3U == nil {
		enabled := true
		c.Audio.CreateM3U = &enabled
	}
	if len(c.Audio.Sections) == 0 {
		c.Audio.Sections = []string{"FLAC", "MP3"}
	}
	if len(c.Audio.Extensions) == 0 {
		c.Audio.Extensions = []string{"flac", "mp3", "m4a", "wav"}
	}
	if c.Media.Enabled == nil {
		enabled := true
		c.Media.Enabled = &enabled
	}
	if c.Media.SampleOnly == nil {
		enabled := true
		c.Media.SampleOnly = &enabled
	}
	if len(c.Media.Sections) == 0 {
		c.Media.Sections = []string{"TV", "X264-HD-1080P", "X264-HD-720P", "X264-SD", "X265", "BLURAY"}
	}
	if len(c.Media.VideoExtensions) == 0 {
		c.Media.VideoExtensions = []string{"mkv", "mp4", "avi", "m2ts"}
	}
	if len(c.SFV.PathCheck) == 0 {
		c.SFV.PathCheck = []string{"*"}
	}
	if len(c.SFV.PathIgnore) == 0 {
		c.SFV.PathIgnore = []string{"/PRE/*", "/REQUESTS/*", "*/Subs", "*/Cover", "*/Covers", "/SPEEDTEST/*"}
	}
	if len(c.SFV.Users) == 0 {
		c.SFV.Users = []string{"*"}
	}
}
