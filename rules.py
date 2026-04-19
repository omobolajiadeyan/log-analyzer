"""
Detection rules for the Log Analyzer.
Each rule defines a regex pattern, event type, severity, and description.
"""

RULES = [
    # Authentication failures
    {
        "id": "AUTH-001",
        "name": "Failed Login Attempt",
        "regex": r"(?i)(failed password|authentication failure|invalid user|failed login|login failed)",
        "severity": "MEDIUM",
        "category": "Authentication",
        "description": "A login attempt failed — could indicate a brute-force attack if repeated.",
        "mitre": "T1110 - Brute Force",
    },
    {
        "id": "AUTH-002",
        "name": "Multiple Failed Logins (Brute Force)",
        "regex": r"(?i)(maximum authentication attempts|too many authentication failures|account locked)",
        "severity": "HIGH",
        "category": "Authentication",
        "description": "Account locked or too many failed attempts — possible brute-force attack.",
        "mitre": "T1110 - Brute Force",
    },
    {
        "id": "AUTH-003",
        "name": "Root Login",
        "regex": r"(?i)(accepted password for root|session opened for user root|sudo.*root)",
        "severity": "HIGH",
        "category": "Authentication",
        "description": "Root account was accessed — should be audited carefully.",
        "mitre": "T1078 - Valid Accounts",
    },

    # Network threats
    {
        "id": "NET-001",
        "name": "Port Scan Detected",
        "regex": r"(?i)(port scan|nmap|masscan|SYN flood|half-open)",
        "severity": "HIGH",
        "category": "Network",
        "description": "Potential port scanning activity detected.",
        "mitre": "T1046 - Network Service Discovery",
    },
    {
        "id": "NET-002",
        "name": "SQL Injection Attempt",
        "regex": r"(?i)(union\s+select|select\s+\*\s+from|or\s+1=1|drop\s+table|' or '|;--|\bxp_cmdshell\b)",
        "severity": "CRITICAL",
        "category": "Web Attack",
        "description": "SQL injection string detected in request.",
        "mitre": "T1190 - Exploit Public-Facing Application",
    },
    {
        "id": "NET-003",
        "name": "XSS Attempt",
        "regex": r"(?i)(<script>|javascript:|onerror\s*=|onload\s*=|alert\s*\(|document\.cookie)",
        "severity": "HIGH",
        "category": "Web Attack",
        "description": "Cross-site scripting (XSS) attempt detected.",
        "mitre": "T1059.007 - JavaScript",
    },
    {
        "id": "NET-004",
        "name": "Directory Traversal",
        "regex": r"(\.\./){2,}|(%2e%2e%2f){2,}|(%252e%252e%252f)",
        "severity": "HIGH",
        "category": "Web Attack",
        "description": "Path traversal attempt to access files outside web root.",
        "mitre": "T1083 - File and Directory Discovery",
    },

    # System events
    {
        "id": "SYS-001",
        "name": "Privilege Escalation",
        "regex": r"(?i)(sudo.*command|privilege escalat|setuid|chmod\s+[0-7]*[4-7]777|pkexec)",
        "severity": "HIGH",
        "category": "Privilege Escalation",
        "description": "A process attempted to escalate privileges.",
        "mitre": "T1548 - Abuse Elevation Control Mechanism",
    },
    {
        "id": "SYS-002",
        "name": "Suspicious Command Execution",
        "regex": r"(?i)(wget\s+http|curl\s+http|bash\s+-i|nc\s+-e|/dev/tcp|python\s+-c|perl\s+-e)",
        "severity": "CRITICAL",
        "category": "Execution",
        "description": "Potentially malicious command execution detected.",
        "mitre": "T1059 - Command and Scripting Interpreter",
    },
    {
        "id": "SYS-003",
        "name": "File Deletion",
        "regex": r"(?i)(rm\s+-rf|shred\s+|unlink.*\/var\/log|del\s+/f|format\s+c:)",
        "severity": "HIGH",
        "category": "Defense Evasion",
        "description": "Destructive file deletion command detected.",
        "mitre": "T1070.004 - File Deletion",
    },
    {
        "id": "SYS-004",
        "name": "Cron Job Modified",
        "regex": r"(?i)(crontab\s+-e|cron\.d|/etc/cron|CRON.*CMD)",
        "severity": "MEDIUM",
        "category": "Persistence",
        "description": "Cron job added or modified — could be persistence mechanism.",
        "mitre": "T1053.003 - Cron",
    },

    # Malware indicators
    {
        "id": "MAL-001",
        "name": "Reverse Shell Indicator",
        "regex": r"(?i)(/bin/bash.*>&|bash\s+-i\s+>&|0>&1|mkfifo|/tmp/[a-z0-9]{8,})",
        "severity": "CRITICAL",
        "category": "Malware",
        "description": "Reverse shell or backdoor indicator found.",
        "mitre": "T1059.004 - Unix Shell",
    },
    {
        "id": "MAL-002",
        "name": "Known Malicious IP Pattern",
        "regex": r"(?i)(tor2web|\.onion|\.i2p)",
        "severity": "HIGH",
        "category": "Malware",
        "description": "Connection to Tor or I2P anonymization network.",
        "mitre": "T1090.003 - Multi-hop Proxy",
    },
]

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
