"""
AegisX — MITRE ATT&CK mapping.

Compact, curated subset of ATT&CK Enterprise techniques that AegisX uses to
classify infrastructure behaviour. Mapping is rule/tag based and always
presents the mapping as *evidence-driven association*, never as attribution.
"""

from __future__ import annotations

# technique_id -> (name, tactic)
ATTACK_TECHNIQUES: dict[str, tuple[str, str]] = {
    "T1071":    ("Application Layer Protocol", "Command and Control"),
    "T1071.001":("Web Protocols", "Command and Control"),
    "T1071.004":("DNS", "Command and Control"),
    "T1090":    ("Proxy", "Command and Control"),
    "T1090.003":("Proxy: Multi-hop Proxy", "Command and Control"),
    "T1105":    ("Ingress Tool Transfer", "Command and Control"),
    "T1568":    ("Dynamic Resolution", "Command and Control"),
    "T1568.002":("Dynamic Resolution: Domain Generation Algorithms", "Command and Control"),
    "T1583":    ("Acquire Infrastructure", "Resource Development"),
    "T1583.001":("Acquire Infrastructure: Domains", "Resource Development"),
    "T1584":    ("Compromise Infrastructure", "Resource Development"),
    "T1585":    ("Establish Accounts", "Resource Development"),
    "T1586":    ("Compromise Accounts", "Resource Development"),
    "T1587":    ("Develop Capabilities", "Resource Development"),
    "T1588":    ("Obtain Capabilities", "Resource Development"),
    "T1566":    ("Phishing", "Initial Access"),
    "T1566.002":("Phishing: Spearphishing Link", "Initial Access"),
    "T1190":    ("Exploit Public-Facing Application", "Initial Access"),
    "T1203":    ("Exploitation for Client Execution", "Execution"),
    "T1204":    ("User Execution", "Execution"),
    "T1059":    ("Command and Scripting Interpreter", "Execution"),
    "T1110":    ("Brute Force", "Credential Access"),
    "T1555":    ("Credentials from Password Stores", "Credential Access"),
    "T1539":    ("Steal Web Session Cookie", "Credential Access"),
    "T1557":    ("Adversary-in-the-Middle", "Credential Access"),
    "T1046":    ("Network Service Scanning", "Discovery"),
    "T1595":    ("Active Scanning", "Reconnaissance"),
    "T1595.002":("Active Scanning: Vulnerability Scanning", "Reconnaissance"),
    "T1041":    ("Exfiltration Over C2 Channel", "Exfiltration"),
    "T1048":    ("Exfiltration Over Alternative Protocol", "Exfiltration"),
    "T1486":    ("Data Encrypted for Impact", "Impact"),
    "T1498":    ("Network Denial of Service", "Impact"),
    "T1499":    ("Endpoint Denial of Service", "Impact"),
}

# tag -> technique ids (order matters: first match listed first)
TAG_TO_TECHNIQUE: dict[str, list[str]] = {
    "c2":            ["T1071", "T1071.001"],
    "c2-server":     ["T1071", "T1071.001"],
    "command-and-control": ["T1071"],
    "dga":           ["T1568.002", "T1568"],
    "fast-flux":     ["T1568", "T1090"],
    "proxy":         ["T1090"],
    "tor-exit":      ["T1090.003", "T1090"],
    "vpn":           ["T1090"],
    "botnet":        ["T1584", "T1583"],
    "bulletproof-hosting": ["T1583", "T1584"],
    "phishing":      ["T1566.002", "T1566"],
    "credential-phishing": ["T1566.002", "T1566"],
    "ransomware":    ["T1486", "T1588.001"],
    "ddos":          ["T1498", "T1499"],
    "booter":        ["T1498"],
    "bruteforce":    ["T1110"],
    "brute-force":   ["T1110"],
    "scanner":       ["T1595", "T1046"],
    "scanning":      ["T1595", "T1046"],
    "exploit":       ["T1190", "T1203"],
    "exploit-kit":   ["T1203", "T1190"],
    "loader":        ["T1204", "T1105"],
    "malware-delivery": ["T1204", "T1566.002"],
    "stealer":       ["T1555", "T1539"],
    "mitm":          ["T1557"],
    "spam":          ["T1586.002", "T1586"],
    "backdoor":      ["T1505.003"],
    "rat":           ["T1219"],
    "mining":        ["T1496"],
    "exfiltration":  ["T1041", "T1048"],
}


def techniques_for_tags(tags: list[str]) -> list[str]:
    """Return the ordered, de-duplicated technique ids suggested by tags."""
    out: list[str] = []
    for tag in tags or []:
        key = str(tag).lower().strip()
        for tid in TAG_TO_TECHNIQUE.get(key, []):
            if tid not in out and tid in ATTACK_TECHNIQUES:
                out.append(tid)
    return out


def describe(technique_id: str) -> tuple[str, str]:
    return ATTACK_TECHNIQUES.get(technique_id, ("Unknown technique", "Unknown tactic"))
