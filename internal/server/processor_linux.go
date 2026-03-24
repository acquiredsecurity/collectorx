//go:build linux

package server

// platformTools returns the Linux AS-Tools processor definitions.
func platformTools() []toolDef {
	return []toolDef{
		{"auditx", "auditx", "Linux auditd log forensic parser (audit.log)", "Logs", dirArgs},
		{"authlogx", "authlogx", "Linux auth.log / secure log parser (SSH, sudo, sessions)", "Logs", dirArgs},
		{"bodyx", "bodyx", "Sleuth Kit bodyfile forensic parser (timeline metadata)", "FileSystem",
			func(input, output string) []string { return []string{"-f", input, "--out", output} }},
		{"dockerx", "dockerx", "Docker container config and metadata parser", "Containers", dirArgs},
		{"journalx", "journalx", "systemd journal binary log parser (.journal)", "Logs", dirArgs},
		{"networkx", "networkx", "Linux network config parser (interfaces, hosts, firewall)", "Network", dirArgs},
		{"packagex", "packagex", "Linux package manager parser (dpkg, rpm, pacman, yum)", "System", dirArgs},
		{"persistlinuxx", "persistlinuxx", "Linux persistence mechanism parser (systemd, cron, init, shell RC)", "Persistence", dirArgs},
		{"recentlinuxx", "recentlinuxx", "Linux recent files parser (XBEL, Trash)", "UserActivity", dirArgs},
		{"shellhistx", "shellhistx", "Shell history parser (bash, zsh, fish, python, node)", "UserActivity", dirArgs},
		{"sshx", "sshx", "SSH artifact parser (authorized_keys, known_hosts, sshd_config)", "Network", dirArgs},
		{"syslogx", "syslogx", "Linux syslog/messages parser (rsyslog, kern, daemon)", "Logs", dirArgs},
		{"usersx", "usersx", "Linux user account parser (passwd, shadow, group)", "System", dirArgs},
		{"wtmpx", "wtmpx", "Linux wtmp/utmp/btmp binary login record parser", "Logs", dirArgs},
	}
}
