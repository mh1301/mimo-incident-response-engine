"""Configuration for MiMo Incident Response Engine."""

# ── Server ─────────────────────────────────────────────────────
HOST = "0.0.0.0"
PORT = 80

# ── MiMo LLM ───────────────────────────────────────────────────
MIMO_API = "http://43.153.206.68:20128/v1/chat/completions"
MIMO_MODEL = "xmtp/mimo-v2.5-pro"

# ── Agent Intervals (seconds) ──────────────────────────────────
TELEMETRY_INTERVAL = 10
CORRELATION_INTERVAL = 5
TRIAGE_INTERVAL = 15
FORENSIC_INTERVAL = 30
CONTAINMENT_INTERVAL = 20
REMEDIATION_INTERVAL = 25
REPORT_INTERVAL = 60

# ── Database ────────────────────────────────────────────────────
DB_PATH = "/root/mimo-incident-response-engine/data/incidents.db"

# ── Severity Levels ────────────────────────────────────────────
SEVERITY = {
    "CRITICAL": {"color": "#ef4444", "score": 10, "response_time": 60},
    "HIGH": {"color": "#f97316", "score": 8, "response_time": 300},
    "MEDIUM": {"color": "#eab308", "score": 5, "response_time": 1800},
    "LOW": {"color": "#22c55e", "score": 2, "response_time": 3600},
    "INFO": {"color": "#3b82f6", "score": 1, "response_time": 86400},
}

# ── Sigma Detection Rules ──────────────────────────────────────
SIGMA_RULES = {
    "ssh_brute_force": {
        "name": "SSH Brute Force",
        "description": "Multiple failed SSH login attempts from same source",
        "condition": "failed_ssh_count >= 5 within 60s",
        "severity": "HIGH",
        "category": "credential_access",
    },
    "port_scan": {
        "name": "Port Scan",
        "description": "Sequential port connection attempts",
        "condition": "unique_ports >= 20 within 30s",
        "severity": "MEDIUM",
        "category": "reconnaissance",
    },
    "malware_execution": {
        "name": "Malware Execution",
        "description": "Suspicious process execution pattern",
        "condition": "suspicious_process AND network_connection",
        "severity": "CRITICAL",
        "category": "execution",
    },
    "data_exfiltration": {
        "name": "Data Exfiltration",
        "description": "Large outbound data transfer to unknown destination",
        "condition": "outbound_bytes >= 100MB within 300s",
        "severity": "CRITICAL",
        "category": "exfiltration",
    },
    "privilege_escalation": {
        "name": "Privilege Escalation",
        "description": "User gained elevated privileges",
        "condition": "sudo_or_su AND new_group_membership",
        "severity": "HIGH",
        "category": "privilege_escalation",
    },
    "lateral_movement": {
        "name": "Lateral Movement",
        "description": "Internal network scanning after initial compromise",
        "condition": "internal_port_scan AND credential_use",
        "severity": "HIGH",
        "category": "lateral_movement",
    },
    "dns_tunneling": {
        "name": "DNS Tunneling",
        "description": "DNS queries with unusually long subdomain labels",
        "condition": "dns_label_length >= 50 AND high_query_rate",
        "severity": "MEDIUM",
        "category": "command_and_control",
    },
    "ransomware_activity": {
        "name": "Ransomware Activity",
        "description": "Mass file encryption pattern detected",
        "condition": "file_rename_count >= 100 within 60s",
        "severity": "CRITICAL",
        "category": "impact",
    },
}

# ── Attack Simulation ──────────────────────────────────────────
ATTACK_SCENARIOS = [
    {
        "id": "ssh_brute",
        "name": "SSH Brute Force Attack",
        "severity": "HIGH",
        "events": [
            {"type": "auth_failure", "source_ip": "185.220.101.34", "dest_ip": "10.0.1.15", "port": 22, "user": "root"},
            {"type": "auth_failure", "source_ip": "185.220.101.34", "dest_ip": "10.0.1.15", "port": 22, "user": "admin"},
            {"type": "auth_failure", "source_ip": "185.220.101.34", "dest_ip": "10.0.1.15", "port": 22, "user": "root"},
            {"type": "auth_failure", "source_ip": "185.220.101.34", "dest_ip": "10.0.1.15", "port": 22, "user": "test"},
            {"type": "auth_failure", "source_ip": "185.220.101.34", "dest_ip": "10.0.1.15", "port": 22, "user": "root"},
            {"type": "auth_success", "source_ip": "185.220.101.34", "dest_ip": "10.0.1.15", "port": 22, "user": "root"},
        ],
    },
    {
        "id": "port_scan",
        "name": "Port Scanning",
        "severity": "MEDIUM",
        "events": [
            {"type": "connection_attempt", "source_ip": "45.33.32.156", "dest_ip": "10.0.1.10", "port": p}
            for p in [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 8080, 8443]
        ],
    },
    {
        "id": "malware",
        "name": "Malware Execution + C2",
        "severity": "CRITICAL",
        "events": [
            {"type": "process_create", "source_ip": "10.0.1.25", "process": "powershell.exe", "args": "-enc SQBFAFgA"},
            {"type": "network_connect", "source_ip": "10.0.1.25", "dest_ip": "185.56.83.83", "port": 443},
            {"type": "dns_query", "source_ip": "10.0.1.25", "query": "c2.malware-domain.xyz"},
            {"type": "file_create", "source_ip": "10.0.1.25", "path": "C:\\Users\\Public\\svchost.exe"},
            {"type": "registry_modify", "source_ip": "10.0.1.25", "key": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"},
        ],
    },
    {
        "id": "data_exfil",
        "name": "Data Exfiltration",
        "severity": "CRITICAL",
        "events": [
            {"type": "file_access", "source_ip": "10.0.1.30", "path": "/data/customer_db.sql"},
            {"type": "file_compress", "source_ip": "10.0.1.30", "path": "/tmp/backup.tar.gz", "size_mb": 850},
            {"type": "network_upload", "source_ip": "10.0.1.30", "dest_ip": "91.215.85.142", "port": 443, "bytes": 850000000},
            {"type": "dns_query", "source_ip": "10.0.1.30", "query": "exfil.data-harvest.xyz"},
        ],
    },
    {
        "id": "priv_esc",
        "name": "Privilege Escalation",
        "severity": "HIGH",
        "events": [
            {"type": "process_create", "source_ip": "10.0.1.20", "process": "sudo", "args": "su -"},
            {"type": "auth_success", "source_ip": "10.0.1.20", "user": "www-data", "method": "su"},
            {"type": "file_access", "source_ip": "10.0.1.20", "path": "/etc/shadow"},
            {"type": "process_create", "source_ip": "10.0.1.20", "process": "nc", "args": "-e /bin/sh 10.0.1.20 4444"},
        ],
    },
]

# ── Containment Actions ────────────────────────────────────────
CONTAINMENT_ACTIONS = {
    "block_ip": {
        "name": "Block IP Address",
        "description": "Add IP to firewall block list",
        "auto": True,
    },
    "isolate_host": {
        "name": "Isolate Host",
        "description": "Disconnect host from network",
        "auto": True,
    },
    "disable_account": {
        "name": "Disable User Account",
        "description": "Disable compromised user account",
        "auto": True,
    },
    "kill_process": {
        "name": "Kill Malicious Process",
        "description": "Terminate suspicious process",
        "auto": True,
    },
    "quarantine_file": {
        "name": "Quarantine File",
        "description": "Move suspicious file to quarantine",
        "auto": True,
    },
}
