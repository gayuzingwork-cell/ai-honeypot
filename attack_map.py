"""Maps attacker commands to MITRE ATT&CK techniques (simple rule engine)."""
import re

RULES = [
    (r"\b(whoami|id|w|who|last)\b", "T1033", "System Owner/User Discovery"),
    (r"\b(uname|lscpu|hostnamectl|cat /etc/os-release|lsb_release)\b", "T1082", "System Information Discovery"),
    (r"\b(ifconfig|ip a|ip addr|netstat|ss -)", "T1016", "System Network Configuration Discovery"),
    (r"\b(ps|top)\b", "T1057", "Process Discovery"),
    (r"\bls\b|\bfind\b", "T1083", "File and Directory Discovery"),
    (r"/etc/(passwd|shadow)", "T1003.008", "OS Credential Dumping: /etc/passwd and /etc/shadow"),
    (r"\.ssh|id_rsa|authorized_keys", "T1552.004", "Unsecured Credentials: Private Keys"),
    (r"\b(wget|curl|tftp|scp)\b", "T1105", "Ingress Tool Transfer"),
    (r"chmod\s+\+?[0-7]*x|chmod 7", "T1222.002", "File Permissions Modification"),
    (r"\b(crontab|/etc/cron)", "T1053.003", "Scheduled Task: Cron"),
    (r"history\s+-c|unset HISTFILE|rm .*(\.bash_history|/var/log)", "T1070.003", "Indicator Removal: Clear Command History"),
    (r"\b(nc|ncat|netcat)\b.*-e|bash -i|/dev/tcp/", "T1059.004", "Command and Scripting Interpreter: Unix Shell (reverse shell)"),
    (r"\b(sudo|su)\b", "T1548.003", "Abuse Elevation Control: Sudo"),
    (r"\b(xmrig|minerd|stratum\+tcp)", "T1496", "Resource Hijacking (cryptomining)"),
    (r"\b(useradd|adduser)\b|(?<![/\w])passwd\b", "T1136.001", "Create Account: Local Account"),
    (r"\b(iptables|ufw|systemctl (stop|disable))", "T1562.004", "Impair Defenses: Disable Firewall"),
]

def map_command(cmd: str):
    """Return list of (technique_id, name) matched by the command."""
    hits = []
    for pattern, tid, name in RULES:
        if re.search(pattern, cmd):
            hits.append({"id": tid, "name": name})
    return hits
