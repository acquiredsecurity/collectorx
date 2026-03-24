//go:build windows

package server

// platformTools returns the Windows AS-Tools processor definitions.
func platformTools() []toolDef {
	return []toolDef{
		{"evtx", "evtx", "Windows Event Log parser (.evtx) with Sigma rule support", "EventLogs", dirArgs},
		{"mftx", "mftx", "NTFS Master File Table parser ($MFT) with timestomp detection", "FileSystem", dirArgs},
		{"pfx", "pfx", "Windows Prefetch execution evidence parser (.pf)", "Execution", scanArgs},
		{"regx", "regx", "Windows Registry parser (SAM, SYSTEM, SOFTWARE, NTUSER)", "Registry", dirArgs},
		{"usnx", "usnx", "NTFS USN Change Journal parser ($UsnJrnl:$J)", "FileSystem", dirArgs},
		{"lnkx", "lnkx", "LNK shortcut and Jump List parser", "FileSystem", dirArgs},
		{"srumx", "srumx", "System Resource Usage Monitor parser (SRUDB.dat)", "SystemActivity", scanArgs},
		{"amcachex", "amcachex", "Amcache.hve application execution evidence parser", "Execution", scanArgs},
		{"rbx", "rbx", "Recycle Bin $I file deletion evidence parser", "FileSystem", scanArgs},
		{"etlx", "etlx", "Windows ETL trace log parser (kernel + ETW events)", "EventLogs", dirArgs},
		{"aix", "aix", "AI chat history parser (Claude Code, ChatGPT)", "Applications",
			func(input, output string) []string { return []string{"scan", "-d", input, "-o", output} }},
		{"defx", "defx", "Windows Defender log parser (MPLog, MPDetection)", "Antivirus", dirArgs},
		{"ntdsx", "ntdsx", "Active Directory NTDS.dit hash extractor", "ActiveDirectory", scanArgs},
		{"wmix", "wmix", "WMI repository persistence artifact parser (OBJECTS.DATA)", "Persistence", dirArgs},
		{"schtskx", "schtskx", "Scheduled Tasks XML parser", "Persistence", dirArgs},
		{"shellbagx", "shellbagx", "Registry shellbag navigation history parser", "Registry", dirArgs},
		{"webx", "webx", "Browser history analyzer (Chrome, Firefox, Edge, Brave, Arc)", "Applications", scanArgs},
		{"pshx", "pshx", "PowerShell ConsoleHost_history parser", "Applications",
			func(input, output string) []string { return []string{input, "-o", output} }},
		{"vpnx", "vpnx", "SSL VPN log parser (Fortinet, Cisco, SonicWall, Ivanti)", "Network", dirArgs},
		{"wtlx", "wtlx", "Windows Timeline and Search Index parser", "UserActivity", scanArgs},
		{"carverx", "carverx", "Forensic file carving tool (E01, raw/dd images)", "FileSystem",
			func(input, output string) []string { return []string{"-i", input, "--out", output} }},
	}
}
