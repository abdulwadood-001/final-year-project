"""
HoneyBot-IoT — MITRE ATT&CK tagging (Enterprise + ICS matrices).  Scope M4.

Two levels:
  * every detection type maps to one or more techniques  (TECHNIQUES_BY_TYPE)
  * individual shell commands are tagged too            (tag_command)
"""

import re

NAMES = {
    # Enterprise
    "T1110":     "Brute Force",
    "T1110.001": "Brute Force: Password Guessing",
    "T1110.004": "Brute Force: Credential Stuffing",
    "T1078":     "Valid Accounts",
    "T1078.001": "Valid Accounts: Default Accounts",
    "T1046":     "Network Service Discovery",
    "T1595":     "Active Scanning",
    "T1595.002": "Active Scanning: Vulnerability Scanning",
    "T1190":     "Exploit Public-Facing Application",
    "T1059.004": "Command and Scripting Interpreter: Unix Shell",
    "T1105":     "Ingress Tool Transfer",
    "T1204.002": "User Execution: Malicious File",
    "T1082":     "System Information Discovery",
    "T1083":     "File and Directory Discovery",
    "T1016":     "System Network Configuration Discovery",
    "T1057":     "Process Discovery",
    "T1033":     "System Owner/User Discovery",
    "T1222.002": "File and Directory Permissions Modification: Linux",
    "T1070.004": "Indicator Removal: File Deletion",
    "T1053.003": "Scheduled Task/Job: Cron",
    "T1098":     "Account Manipulation",
    "T1489":     "Service Stop",
    "T1071":     "Application Layer Protocol",
    "T1071.001": "Application Layer Protocol: Web Protocols",
    "T1125":     "Video Capture",
    "T1552.001": "Unsecured Credentials: Credentials In Files",
    "T1499":     "Endpoint Denial of Service",
    "T1584.005": "Compromise Infrastructure: Botnet",
    "T1027":     "Obfuscated Files or Information",
    # ICS
    "T0812": "ICS: Default Credentials",
    "T0855": "ICS: Unauthorized Command Message",
    "T0836": "ICS: Modify Parameter",
    "T0801": "ICS: Monitor Process State",
    "T0846": "ICS: Remote System Discovery",
    "T0815": "ICS: Denial of View",
    "T0883": "ICS: Internet Accessible Device",
    "T0866": "ICS: Exploitation of Remote Services",
    "T0869": "ICS: Standard Application Layer Protocol",
}

TECHNIQUES_BY_TYPE = {
    "BRUTE_FORCE":             ["T1110", "T1110.001"],
    "CREDENTIAL_STUFFING":     ["T1110.004"],
    "CREDENTIAL_COMPROMISE":   ["T1078", "T1078.001", "T0812"],
    "RECONNAISSANCE":          ["T1046", "T0846"],
    "WEB_SCAN":                ["T1595.002", "T1595"],
    "RTSP_ROUTE_ENUM":         ["T1595", "T0846"],
    "MALWARE_DELIVERY":        ["T1105", "T1059.004", "T1204.002"],
    "MIRAI_SIGNATURE":         ["T1584.005", "T1059.004", "T1078.001"],
    "MALWARE_FAMILY":          ["T1105", "T1204.002", "T1584.005"],
    "BOTNET_C2":               ["T1071", "T0869", "T1584.005"],
    "ICS_UNAUTHORIZED_COMMAND": ["T0855", "T0836"],
    "ICS_PROCESS_MONITORING":  ["T0801", "T0883"],
    "PROTOCOL_EXPLOIT":        ["T1190", "T0866"],
    "POST_EXPLOITATION":       ["T1082", "T1033", "T1057", "T1016"],
    "MULTI_PROTOCOL_ATTACK":   ["T1046", "T1110"],
    "VIDEO_STREAM_ACCESS":     ["T1125", "T1078.001"],
    "DENIAL_OF_VIEW":          ["T0815"],
}

COMMAND_RULES = [
    (r"\b(wget|curl|tftp|ftpget)\b",                    "T1105"),
    (r"\bchmod\b",                                      "T1222.002"),
    (r"(^|[;&|\s])\./|/tmp/\S+\s*$|\bsh\s+\S+\.sh",      "T1204.002"),
    (r"\b(uname|/proc/cpuinfo|/proc/version|nproc|free|df)\b", "T1082"),
    (r"\b(ls|find)\b",                                  "T1083"),
    (r"\b(ifconfig|ip\s+a|route|netstat|/etc/resolv)\b", "T1016"),
    (r"\b(ps|top)\b",                                   "T1057"),
    (r"\b(whoami|id|w)\b",                              "T1033"),
    (r"\brm\s+-rf?\b|\bhistory\s+-c\b",                 "T1070.004"),
    (r"\bcrontab\b|/etc/cron",                          "T1053.003"),
    (r"\b(passwd|chpasswd|useradd)\b",                  "T1098"),
    (r"\b(kill|killall|pkill)\b",                       "T1489"),
    (r"/etc/shadow|/etc/passwd|config\.json",           "T1552.001"),
    (r"/bin/busybox\s+[A-Z]{4,}",                       "T1584.005"),
    (r"echo\s+-e\s+['\"]?\\\\x",                        "T1027"),
    (r"\b(lockctl|sensorctl)\b",                        "T0855"),
]
_COMPILED = [(re.compile(rx), tid) for rx, tid in COMMAND_RULES]


def techniques_for(attack_type):
    ids = TECHNIQUES_BY_TYPE.get(attack_type, [])
    return ids, [NAMES.get(i, i) for i in ids]


def tag_command(cmd):
    if not cmd:
        return []
    found = ["T1059.004"]
    for rx, tid in _COMPILED:
        if rx.search(cmd) and tid not in found:
            found.append(tid)
    return found


def name(tid):
    return NAMES.get(tid, tid)
