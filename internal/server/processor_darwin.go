//go:build darwin

package server

// Common macOS-specific arg patterns.
var (
	// longDirArgs uses --dir instead of -d for tools that expect it.
	longDirArgs = func(input, output string) []string {
		return []string{"--dir", input, "--out", output}
	}
	// fileArgs passes a single file via -f.
	fileArgs = func(input, output string) []string {
		return []string{"-f", input, "--out", output}
	}
)

// platformTools returns the macOS AS-Tools processor definitions.
func platformTools() []toolDef {
	return []toolDef{
		// System
		{"accountsx", "accountsx", "macOS user account parser (dslocal plist, accounts.db)", "System",
			func(input, output string) []string { return []string{"--dslocal", input, "--out", output} }},
		{"sysinfoX", "sysinfoX", "macOS system information parser (SystemVersion, SPHardwareDataType)", "System", longDirArgs},

		// User Activity
		{"airdropx", "airdropx", "AirDrop transfer history parser (Discoveryd plist)", "UserActivity", fileArgs},
		{"calendarx", "calendarx", "macOS Calendar.sqlitedb event parser", "UserActivity", fileArgs},
		{"contactsx", "contactsx", "macOS AddressBook contacts database parser", "UserActivity", fileArgs},
		{"docrevisionsx", "docrevisionsx", "macOS document revision history parser (.DocumentRevisions-V100)", "UserActivity", fileArgs},
		{"knowledgex", "knowledgex", "macOS KnowledgeC.db application usage parser", "UserActivity", fileArgs},
		{"mailx", "mailx", "macOS Mail.app Envelope Index parser", "UserActivity", fileArgs},
		{"messagesx", "messagesx", "macOS iMessage / SMS chat.db parser", "UserActivity", fileArgs},
		{"notesx", "notesx", "macOS Notes.app NoteStore.sqlite parser", "UserActivity", fileArgs},
		{"quicklookx", "quicklookx", "macOS QuickLook thumbnail cache parser (com.apple.QuickLook.thumbnailcache)", "UserActivity", fileArgs},
		{"recentx", "recentx", "macOS recent items and MRU parser", "UserActivity", dirArgs},
		{"savedstatex", "savedstatex", "macOS Saved Application State parser (windows.plist)", "UserActivity", dirArgs},
		{"screentimex", "screentimex", "macOS Screen Time usage database parser (RMAdminStore)", "UserActivity", dirArgs},
		{"spotlightx", "spotlightx", "macOS Spotlight metadata index parser (.Spotlight-V100)", "UserActivity", dirArgs},
		{"trashx", "trashx", "macOS Trash metadata and .DS_Store parser", "UserActivity", longDirArgs},

		// Security
		{"biomex", "biomex", "macOS biometric (Touch ID) enrollment database parser", "Security", dirArgs},
		{"gatekeeperx", "gatekeeperx", "macOS Gatekeeper and XProtect assessment parser", "Security", dirArgs},
		{"keychainx", "keychainx", "macOS Keychain item metadata parser (login.keychain-db)", "Security", longDirArgs},
		{"quarantinex", "quarantinex", "macOS quarantine events database parser (com.apple.LaunchServices)", "Security", fileArgs},
		{"tccx", "tccx", "macOS TCC.db privacy permission grant parser", "Security", fileArgs},

		// File System
		{"exifx", "exifx", "Image EXIF / GPS metadata extractor", "FileSystem", dirArgs},
		{"fseventsx", "fseventsx", "macOS FSEvents log parser (.fseventsd)", "FileSystem", dirArgs},
		{"wherefromsx", "wherefromsx", "macOS kMDItemWhereFroms download origin parser", "FileSystem", dirArgs},

		// Logs
		{"openbsmx", "openbsmx", "macOS OpenBSM audit trail parser (/var/audit)", "Logs", dirArgs},
		{"sysdiagx", "sysdiagx", "macOS sysdiagnose archive parser", "Logs", dirArgs},
		{"unifiedlogsx", "unifiedlogsx", "macOS Unified Log (tracev3) parser", "Logs", dirArgs},

		// Persistence
		{"persistencex", "persistencex", "macOS persistence mechanism parser (LaunchAgents, LaunchDaemons, login items)", "Persistence", dirArgs},

		// Network
		{"wifihistoryx", "wifihistoryx", "macOS Wi-Fi connection history parser (com.apple.wifi.known-networks)", "Network", dirArgs},

		// Hardware
		{"usbx", "usbx", "macOS USB device connection history parser", "Hardware", dirArgs},

		// Applications
		{"cachex", "cachex", "macOS application cache parser (NSURLCache, Caches)", "Applications", longDirArgs},
		{"webx", "webx", "Browser history analyzer (Safari, Chrome, Firefox, Edge, Brave, Arc)", "Applications", scanArgs},
		{"iosbackupx", "iosbackupx", "iOS backup manifest and artifact parser (iTunes/Finder backups)", "Applications",
			func(input, output string) []string { return []string{"parse", "--backup", input, "--out", output} }},
	}
}
