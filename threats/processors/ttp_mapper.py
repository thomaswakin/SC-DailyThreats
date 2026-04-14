"""Map text content to MITRE ATT&CK TTPs via keyword/ID matching."""

import re
from threats.models.ttp import TTP, MITRETactic

# ── Technique ID pattern ──────────────────────────────────────────────────────
_TECHNIQUE_ID = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

# ── Keyword → (technique_id, tactic, name) ───────────────────────────────────
# A representative subset for common threat intel topics
_KEYWORD_MAP: list[tuple[re.Pattern, str, MITRETactic, str]] = [
    # Initial Access
    (re.compile(r"spear.?phish|spearphish", re.I), "T1566.001", MITRETactic.INITIAL_ACCESS, "Spearphishing Attachment"),
    (re.compile(r"phish(?:ing)?", re.I), "T1566", MITRETactic.INITIAL_ACCESS, "Phishing"),
    (re.compile(r"exploit(?:ed|ing)?\s+public.?facing", re.I), "T1190", MITRETactic.INITIAL_ACCESS, "Exploit Public-Facing Application"),
    (re.compile(r"valid\s+account|stolen\s+credential|credential\s+reuse", re.I), "T1078", MITRETactic.INITIAL_ACCESS, "Valid Accounts"),
    (re.compile(r"supply.?chain", re.I), "T1195", MITRETactic.INITIAL_ACCESS, "Supply Chain Compromise"),
    (re.compile(r"drive.by\s+download|watering.hole", re.I), "T1189", MITRETactic.INITIAL_ACCESS, "Drive-by Compromise"),

    # Execution
    (re.compile(r"powershell", re.I), "T1059.001", MITRETactic.EXECUTION, "PowerShell"),
    (re.compile(r"\bwscript\b|\bcscript\b|vb.?script", re.I), "T1059.005", MITRETactic.EXECUTION, "Visual Basic"),
    (re.compile(r"\bbash\b|shell\s+script|linux\s+shell", re.I), "T1059.004", MITRETactic.EXECUTION, "Unix Shell"),
    (re.compile(r"\bpython\b.*(?:malware|dropper|loader|stager)", re.I), "T1059.006", MITRETactic.EXECUTION, "Python"),
    (re.compile(r"\bmshta\b", re.I), "T1218.005", MITRETactic.EXECUTION, "Mshta"),
    (re.compile(r"\bregsvr32\b", re.I), "T1218.010", MITRETactic.EXECUTION, "Regsvr32"),
    (re.compile(r"\bwmic\b", re.I), "T1047", MITRETactic.EXECUTION, "Windows Management Instrumentation"),
    (re.compile(r"macro|vba\s+macro|office\s+macro", re.I), "T1137", MITRETactic.EXECUTION, "Office Application Startup"),

    # Persistence
    (re.compile(r"scheduled\s+task|schtask|cron\s+job", re.I), "T1053", MITRETactic.PERSISTENCE, "Scheduled Task/Job"),
    (re.compile(r"registry\s+run\s+key|HKCU.+Run|HKLM.+Run", re.I), "T1547.001", MITRETactic.PERSISTENCE, "Registry Run Keys"),
    (re.compile(r"autostart|boot\s+persistence", re.I), "T1547", MITRETactic.PERSISTENCE, "Boot or Logon Autostart Execution"),
    (re.compile(r"web\s*shell", re.I), "T1505.003", MITRETactic.PERSISTENCE, "Web Shell"),
    (re.compile(r"dll\s+hijack|search.order\s+hijack", re.I), "T1574.001", MITRETactic.PERSISTENCE, "DLL Search Order Hijacking"),

    # Privilege Escalation
    (re.compile(r"uac\s+bypass|bypass\s+uac", re.I), "T1548.002", MITRETactic.PRIVILEGE_ESCALATION, "Bypass User Account Control"),
    (re.compile(r"token\s+impersonat|access\s+token", re.I), "T1134", MITRETactic.PRIVILEGE_ESCALATION, "Access Token Manipulation"),

    # Defense Evasion
    (re.compile(r"obfuscat", re.I), "T1027", MITRETactic.DEFENSE_EVASION, "Obfuscated Files or Information"),
    (re.compile(r"living.off.the.land|lolbin|lolbas", re.I), "T1218", MITRETactic.DEFENSE_EVASION, "System Binary Proxy Execution"),
    (re.compile(r"process\s+hollow|process\s+inject", re.I), "T1055", MITRETactic.DEFENSE_EVASION, "Process Injection"),
    (re.compile(r"timestomp", re.I), "T1070.006", MITRETactic.DEFENSE_EVASION, "Timestomp"),
    (re.compile(r"disable\s+(?:av|antivirus|defender|security)", re.I), "T1562", MITRETactic.DEFENSE_EVASION, "Impair Defenses"),
    (re.compile(r"sign(?:ed)?\s+(?:binary|executable|code)", re.I), "T1553.002", MITRETactic.DEFENSE_EVASION, "Code Signing"),

    # Credential Access
    (re.compile(r"mimikatz|lsass\s+dump|credential\s+dump", re.I), "T1003", MITRETactic.CREDENTIAL_ACCESS, "OS Credential Dumping"),
    (re.compile(r"kerberoast", re.I), "T1558.003", MITRETactic.CREDENTIAL_ACCESS, "Kerberoasting"),
    (re.compile(r"pass.the.hash|pth\b", re.I), "T1550.002", MITRETactic.CREDENTIAL_ACCESS, "Pass the Hash"),
    (re.compile(r"brute.forc", re.I), "T1110", MITRETactic.CREDENTIAL_ACCESS, "Brute Force"),

    # Discovery
    (re.compile(r"network\s+scan|port\s+scan|nmap", re.I), "T1046", MITRETactic.DISCOVERY, "Network Service Discovery"),
    (re.compile(r"active\s+directory\s+enum|ldap\s+enum", re.I), "T1087.002", MITRETactic.DISCOVERY, "Domain Account Discovery"),

    # Lateral Movement
    (re.compile(r"\bpsexec\b|lateral\s+movement.*smb", re.I), "T1021.002", MITRETactic.LATERAL_MOVEMENT, "SMB/Windows Admin Shares"),
    (re.compile(r"\brdp\b.*lateral|lateral.*\brdp\b", re.I), "T1021.001", MITRETactic.LATERAL_MOVEMENT, "Remote Desktop Protocol"),
    (re.compile(r"wmi.*lateral|lateral.*wmi", re.I), "T1021.006", MITRETactic.LATERAL_MOVEMENT, "Windows Remote Management"),

    # Command and Control
    (re.compile(r"c2|c&c|command.and.control", re.I), "T1071", MITRETactic.COMMAND_AND_CONTROL, "Application Layer Protocol"),
    (re.compile(r"beacon|cobalt\s+strike", re.I), "T1071.001", MITRETactic.COMMAND_AND_CONTROL, "Web Protocols C2"),
    (re.compile(r"domain\s+fronting", re.I), "T1090.004", MITRETactic.COMMAND_AND_CONTROL, "Domain Fronting"),
    (re.compile(r"dns\s+tunnel(?:ing)?", re.I), "T1071.004", MITRETactic.COMMAND_AND_CONTROL, "DNS C2"),
    (re.compile(r"fast.?flux", re.I), "T1568.001", MITRETactic.COMMAND_AND_CONTROL, "Fast Flux DNS"),

    # Exfiltration
    (re.compile(r"exfiltrat", re.I), "T1041", MITRETactic.EXFILTRATION, "Exfiltration Over C2 Channel"),
    (re.compile(r"data\s+theft|steal.*data|data.*stolen", re.I), "T1567", MITRETactic.EXFILTRATION, "Exfiltration Over Web Service"),

    # Impact
    (re.compile(r"ransomware|encrypt.*files|file.*encrypt", re.I), "T1486", MITRETactic.IMPACT, "Data Encrypted for Impact"),
    (re.compile(r"wiper|wipe\s+disk|destroy.*data", re.I), "T1485", MITRETactic.IMPACT, "Data Destruction"),
    (re.compile(r"ddos|denial.of.service", re.I), "T1498", MITRETactic.IMPACT, "Network Denial of Service"),
]


def map_ttps(text: str) -> list[TTP]:
    """Extract TTPs from text via explicit T-IDs and keyword matching."""
    found: dict[str, TTP] = {}

    # Direct technique ID references (e.g. T1059.001)
    for m in _TECHNIQUE_ID.finditer(text):
        tid = m.group().upper()
        if tid not in found:
            found[tid] = TTP(technique_id=tid)

    # Keyword matching
    for pattern, tid, tactic, name in _KEYWORD_MAP:
        if pattern.search(text) and tid not in found:
            found[tid] = TTP(technique_id=tid, tactic=tactic, name=name)

    return list(found.values())
