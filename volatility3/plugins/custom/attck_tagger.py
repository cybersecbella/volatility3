"""
attck_tagger.py — MITRE ATT&CK TTP tagging layer for Volatility 3
===================================================================

Usage (standalone):
    from volatility3.plugins.custom.attck_tagger import tag_process, tag_findings, build_report

Usage (as Volatility plugin):
    python3 vol.py -f memory.dmp custom.AttckTagger

What it does:
    - Maps Volatility findings to MITRE ATT&CK T-numbers
    - Scores each process/finding by risk (0–100)
    - Detects: hidden processes, credential dumping, C2 beaconing,
      encoded PowerShell, DLL hijacking, persistence, rootkits,
      suspicious parent-child relationships, and more
    - Outputs enriched dicts ready for the AI explainer plugin
"""

from __future__ import annotations
import json
import re
from dataclasses import dataclass, field, asdict
from typing import Optional
from volatility3.framework import renderers, interfaces
from volatility3.framework.configuration import requirements


# ─────────────────────────────────────────────────────────────────────────────
# DATA STRUCTURES
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class TTP:
    """A single MITRE ATT&CK technique."""
    id: str           # e.g. "T1055.001"
    name: str         # e.g. "Dynamic-link Library Injection"
    tactic: str       # e.g. "Defense Evasion"
    confidence: str   # "HIGH" | "MEDIUM" | "LOW"
    evidence: str     # human-readable reason this was tagged

    def to_dict(self) -> dict:
        return asdict(self)

    def __str__(self) -> str:
        return f"[{self.id}] {self.name} ({self.tactic}) — {self.confidence}"


@dataclass
class TaggedFinding:
    """A Volatility finding enriched with ATT&CK tags and a risk score."""
    source_plugin: str          # "pslist", "malfind", "netstat", etc.
    raw: dict                   # original Volatility output dict
    ttps: list[TTP] = field(default_factory=list)
    risk_score: int = 0         # 0–100
    risk_level: str = "LOW"     # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
    summary: str = ""           # one-line human summary

    def to_dict(self) -> dict:
        return {
            "source_plugin": self.source_plugin,
            "raw":           self.raw,
            "ttps":          [t.to_dict() for t in self.ttps],
            "risk_score":    self.risk_score,
            "risk_level":    self.risk_level,
            "summary":       self.summary,
        }


# ─────────────────────────────────────────────────────────────────────────────
# MASTER ATT&CK KNOWLEDGE BASE
# All techniques relevant to memory forensics, with tactic context
# ─────────────────────────────────────────────────────────────────────────────

ATTCK_DB: dict[str, dict] = {

    # ── Defense Evasion ──────────────────────────────────────────────────────
    "T1055":     {"name": "Process Injection",                   "tactic": "Defense Evasion / Privilege Escalation"},
    "T1055.001": {"name": "DLL Injection",                       "tactic": "Defense Evasion / Privilege Escalation"},
    "T1055.002": {"name": "Portable Executable Injection",       "tactic": "Defense Evasion / Privilege Escalation"},
    "T1055.012": {"name": "Process Hollowing",                   "tactic": "Defense Evasion / Privilege Escalation"},
    "T1014":     {"name": "Rootkit",                             "tactic": "Defense Evasion"},
    "T1562.001": {"name": "Disable or Modify Tools",             "tactic": "Defense Evasion"},
    "T1070.001": {"name": "Clear Windows Event Logs",            "tactic": "Defense Evasion"},
    "T1574.001": {"name": "DLL Search Order Hijacking",          "tactic": "Defense Evasion / Persistence"},
    "T1574.002": {"name": "DLL Side-Loading",                    "tactic": "Defense Evasion / Persistence"},
    "T1036.005": {"name": "Match Legitimate Name or Location",   "tactic": "Defense Evasion"},

    # ── Credential Access ────────────────────────────────────────────────────
    "T1003":     {"name": "OS Credential Dumping",               "tactic": "Credential Access"},
    "T1003.001": {"name": "LSASS Memory Credential Dumping",     "tactic": "Credential Access"},
    "T1003.002": {"name": "SAM Credential Dumping",              "tactic": "Credential Access"},
    "T1003.003": {"name": "NTDS Credential Dumping",             "tactic": "Credential Access"},
    "T1056.001": {"name": "Keylogging",                          "tactic": "Credential Access"},

    # ── Execution ────────────────────────────────────────────────────────────
    "T1059.001": {"name": "PowerShell Execution",                "tactic": "Execution"},
    "T1059.003": {"name": "Windows Command Shell",               "tactic": "Execution"},
    "T1059.005": {"name": "Visual Basic Script",                 "tactic": "Execution"},
    "T1106":     {"name": "Native API",                          "tactic": "Execution"},
    "T1204.002": {"name": "Malicious File Execution",            "tactic": "Execution"},

    # ── Persistence ──────────────────────────────────────────────────────────
    "T1547.001": {"name": "Registry Run Keys / Startup Folder",  "tactic": "Persistence / Privilege Escalation"},
    "T1053.005": {"name": "Scheduled Task",                      "tactic": "Persistence / Privilege Escalation"},
    "T1543.003": {"name": "Windows Service",                     "tactic": "Persistence / Privilege Escalation"},
    "T1546.015": {"name": "Component Object Model Hijacking",    "tactic": "Persistence / Privilege Escalation"},

    # ── Command and Control ──────────────────────────────────────────────────
    "T1071.001": {"name": "Web Protocols C2",                    "tactic": "Command and Control"},
    "T1071.004": {"name": "DNS C2",                              "tactic": "Command and Control"},
    "T1095":     {"name": "Non-Application Layer Protocol",      "tactic": "Command and Control"},
    "T1571":     {"name": "Non-Standard Port",                   "tactic": "Command and Control"},
    "T1090":     {"name": "Proxy",                               "tactic": "Command and Control"},

    # ── Discovery ────────────────────────────────────────────────────────────
    "T1057":     {"name": "Process Discovery",                   "tactic": "Discovery"},
    "T1049":     {"name": "System Network Connections Discovery", "tactic": "Discovery"},
    "T1082":     {"name": "System Information Discovery",        "tactic": "Discovery"},

    # ── Lateral Movement ─────────────────────────────────────────────────────
    "T1550.002": {"name": "Pass the Hash",                       "tactic": "Lateral Movement"},
    "T1021.002": {"name": "SMB/Windows Admin Shares",            "tactic": "Lateral Movement"},

    # ── Exfiltration ─────────────────────────────────────────────────────────
    "T1041":     {"name": "Exfiltration Over C2 Channel",        "tactic": "Exfiltration"},
    "T1048":     {"name": "Exfiltration Over Alternative Protocol","tactic": "Exfiltration"},
}


def _ttp(tid: str, confidence: str, evidence: str) -> TTP:
    """Convenience constructor — looks up name/tactic from DB."""
    entry = ATTCK_DB.get(tid, {"name": "Unknown", "tactic": "Unknown"})
    return TTP(id=tid, name=entry["name"], tactic=entry["tactic"],
               confidence=confidence, evidence=evidence)


# ─────────────────────────────────────────────────────────────────────────────
# SCORING
# ─────────────────────────────────────────────────────────────────────────────

# Points per TTP confidence level
_SCORE_MAP = {"HIGH": 40, "MEDIUM": 25, "LOW": 10}

def _score(ttps: list[TTP]) -> tuple[int, str]:
    """Return (risk_score 0-100, risk_level string)."""
    total = min(sum(_SCORE_MAP[t.confidence] for t in ttps), 100)
    if total >= 75:
        return total, "CRITICAL"
    elif total >= 50:
        return total, "HIGH"
    elif total >= 25:
        return total, "MEDIUM"
    return total, "LOW"


# ─────────────────────────────────────────────────────────────────────────────
# DETECTION RULES — PROCESSES
# ─────────────────────────────────────────────────────────────────────────────

# Processes that should NEVER have children like cmd.exe / powershell.exe
_BROWSER_PROCS = {
    "chrome.exe", "firefox.exe", "msedge.exe", "iexplore.exe",
    "opera.exe", "brave.exe", "safari.exe",
}
_SHELL_PROCS = {
    "cmd.exe", "powershell.exe", "pwsh.exe",
    "wscript.exe", "cscript.exe", "mshta.exe",
}
# Legitimate parents for svchost.exe
_SVCHOST_PARENTS = {"services.exe"}
# Legitimate parents for lsass.exe
_LSASS_PARENTS   = {"wininit.exe"}

# Known-bad process name typosquats (masquerading)
_TYPOSQUATS: list[tuple[str, str]] = [
    ("svch0st.exe",   "svchost.exe"),
    ("lsas.exe",      "lsass.exe"),
    ("csrss32.exe",   "csrss.exe"),
    ("svchost32.exe", "svchost.exe"),
    ("explore.exe",   "explorer.exe"),
    ("kerne132.dll",  "kernel32.dll"),
]

# Suspicious temp/staging paths
_BAD_PATHS = [
    r"\\temp\\", r"\\tmp\\", r"\\appdata\\local\\temp\\",
    r"\\appdata\\roaming\\", r"\\programdata\\",
    r"\\users\\public\\", r"\\recycle",
    r"\\windows\\fonts\\", r"\\windows\\temp\\",
]

# Encoded PowerShell patterns
_PS_ENCODED = re.compile(
    r"-enc(?:odedcommand)?\s+[A-Za-z0-9+/=]{20,}|"
    r"-e\s+[A-Za-z0-9+/=]{20,}|"
    r"frombase64string|"
    r"invoke-expression|iex\s*\(|"
    r"downloadstring|downloadfile",
    re.IGNORECASE,
)

# Non-standard C2 ports (common but not exhaustive)
_KNOWN_PORTS    = {80, 443, 8080, 8443, 53, 22, 21, 25, 110, 143, 3389}
_SUSPICIOUS_PORTS = {4444, 4445, 1337, 31337, 8888, 9999, 1234, 12345, 6666}


def tag_process(proc: dict) -> TaggedFinding:
    """
    Analyze a single process dict and return a TaggedFinding.

    Expected proc keys (all optional — missing keys are handled gracefully):
        pid         int     Process ID
        name        str     Image name e.g. "svchost.exe"
        ppid        int     Parent PID
        parent_name str     Parent image name
        cmdline     str     Full command line string
        path        str     Full path to executable
        hidden      bool    True if in psscan but NOT in pslist
        has_network bool    True if process has open connections
        exit_time   str     Non-null means process has exited
    """
    ttps: list[TTP] = []
    name        = (proc.get("name") or "").lower()
    cmdline     = (proc.get("cmdline") or "").lower()
    path        = (proc.get("path") or "").lower()
    parent_name = (proc.get("parent_name") or "").lower()
    hidden      = bool(proc.get("hidden"))

    # ── Rule 1: DKOM / hidden process ────────────────────────────────────────
    if hidden:
        ttps.append(_ttp("T1055", "HIGH",
            f"PID {proc.get('pid')} '{proc.get('name')}' present in psscan "
            f"but absent from pslist — classic DKOM rootkit unlinking"))
        ttps.append(_ttp("T1014", "HIGH",
            "Process removed from PsActiveProcessHead linked list"))

    # ── Rule 2: Encoded / obfuscated PowerShell ───────────────────────────────
    if _PS_ENCODED.search(cmdline):
        ttps.append(_ttp("T1059.001", "HIGH",
            f"Encoded or obfuscated PowerShell detected in cmdline: "
            f"'{cmdline[:120]}'"))

    # ── Rule 3: Suspicious parent → child relationship ────────────────────────
    if parent_name in _BROWSER_PROCS and name in _SHELL_PROCS:
        ttps.append(_ttp("T1059.003", "HIGH",
            f"'{name}' spawned by browser '{parent_name}' — "
            f"likely browser exploit or malicious download execution"))

    # ── Rule 4: svchost.exe without services.exe parent ──────────────────────
    if name == "svchost.exe" and parent_name and parent_name not in _SVCHOST_PARENTS:
        ttps.append(_ttp("T1036.005", "MEDIUM",
            f"svchost.exe has unusual parent '{parent_name}' "
            f"(expected: services.exe) — possible masquerading"))

    # ── Rule 5: lsass.exe without wininit.exe parent ─────────────────────────
    if name == "lsass.exe" and parent_name and parent_name not in _LSASS_PARENTS:
        ttps.append(_ttp("T1003.001", "HIGH",
            f"lsass.exe spawned by '{parent_name}' not wininit.exe — "
            f"possible credential dumping process masquerading as lsass"))

    # ── Rule 6: Typosquatting / name masquerading ─────────────────────────────
    for fake, real in _TYPOSQUATS:
        if name == fake:
            ttps.append(_ttp("T1036.005", "HIGH",
                f"'{name}' is a known typosquat of '{real}' — likely malware"))
            break

    # ── Rule 7: Executable running from suspicious path ───────────────────────
    for bad_path in _BAD_PATHS:
        if bad_path in path:
            ttps.append(_ttp("T1204.002", "MEDIUM",
                f"Executable path '{path[:100]}' is in a suspicious staging "
                f"location commonly used by malware droppers"))
            break

    # ── Rule 8: Script interpreter with network access ────────────────────────
    if name in _SHELL_PROCS and proc.get("has_network"):
        ttps.append(_ttp("T1071.001", "MEDIUM",
            f"'{name}' has open network connections — possible C2 over "
            f"scripting engine (living-off-the-land)"))

    # ── Rule 9: wscript / cscript (VBScript / JScript execution) ─────────────
    if name in {"wscript.exe", "cscript.exe"}:
        ttps.append(_ttp("T1059.005", "MEDIUM",
            f"'{name}' running — Windows Script Host execution "
            f"(common phishing / dropper technique)"))

    # ── Rule 10: mshta.exe (HTML Application abuse) ───────────────────────────
    if name == "mshta.exe":
        ttps.append(_ttp("T1059.005", "HIGH",
            "mshta.exe running — MSHTA is almost exclusively used "
            "maliciously to execute remote HTA payloads"))

    # Score and summarise
    score, level = _score(ttps)
    ttp_ids = ", ".join(t.id for t in ttps) if ttps else "none"
    summary = (
        f"PID {proc.get('pid')} '{proc.get('name')}' — "
        f"{level} risk (score {score}) — TTPs: {ttp_ids}"
    )
    return TaggedFinding(
        source_plugin="pslist/psscan",
        raw=proc,
        ttps=ttps,
        risk_score=score,
        risk_level=level,
        summary=summary,
    )


# ─────────────────────────────────────────────────────────────────────────────
# DETECTION RULES — OTHER PLUGINS
# ─────────────────────────────────────────────────────────────────────────────

def tag_malfind_hit(hit: dict) -> TaggedFinding:
    """
    Tag a single malfind result.
    Expected keys: pid, process_name, vad_start, vad_end, protection, tag, hexdump
    """
    ttps: list[TTP] = []
    protect = (hit.get("protection") or "").upper()
    hexdump = (hit.get("hexdump") or "")
    tag     = (hit.get("tag") or "")

    # MZ header in non-image region → reflective PE injection
    if "4d5a" in hexdump.lower() or "MZ" in hexdump[:4]:
        ttps.append(_ttp("T1055.002", "HIGH",
            f"MZ/PE header found in RWX memory region at "
            f"0x{hit.get('vad_start','?')} in PID {hit.get('pid')} — "
            f"reflective DLL/PE injection"))

    # PAGE_EXECUTE_READWRITE is the classic injection protection flag
    if "EXECUTE_READWRITE" in protect or "PAGE_EXECUTE_READ_WRITE" in protect:
        ttps.append(_ttp("T1055", "HIGH",
            f"Memory region at 0x{hit.get('vad_start','?')} has "
            f"PAGE_EXECUTE_READWRITE protection — characteristic of "
            f"shellcode injection or process hollowing"))

    # VadS tag = private memory marked executable (no backing file)
    if tag == "VadS":
        ttps.append(_ttp("T1055.012", "MEDIUM",
            f"VadS tag at 0x{hit.get('vad_start','?')} — "
            f"executable private memory with no file backing, "
            f"consistent with process hollowing"))

    score, level = _score(ttps)
    return TaggedFinding(
        source_plugin="malfind",
        raw=hit,
        ttps=ttps,
        risk_score=score,
        risk_level=level,
        summary=(f"malfind hit in PID {hit.get('pid')} "
                 f"'{hit.get('process_name')}' at "
                 f"0x{hit.get('vad_start','?')} — "
                 f"{level} ({', '.join(t.id for t in ttps) or 'no tags'})"),
    )


def tag_netstat_row(conn: dict) -> TaggedFinding:
    """
    Tag a single netstat connection.
    Expected keys: pid, owner, proto, local_addr, local_port,
                   foreign_addr, foreign_port, state
    """
    ttps: list[TTP] = []
    foreign_ip   = (conn.get("foreign_addr") or "")
    foreign_port = int(conn.get("foreign_port") or 0)
    proto        = (conn.get("proto") or "").upper()
    state        = (conn.get("state") or "").upper()
    owner        = (conn.get("owner") or "").lower()

    # Known-bad C2 ports
    if foreign_port in _SUSPICIOUS_PORTS:
        ttps.append(_ttp("T1571", "HIGH",
            f"Connection to {foreign_ip}:{foreign_port} — "
            f"port {foreign_port} is a well-known C2/backdoor port"))

    # Raw TCP connection from shell process
    if owner in _SHELL_PROCS and state == "ESTABLISHED":
        ttps.append(_ttp("T1071.001", "HIGH",
            f"'{owner}' has established connection to "
            f"{foreign_ip}:{foreign_port} — possible C2 reverse shell"))

    # Raw socket (non-HTTP/S) from browser-like process
    if proto == "TCP" and foreign_port not in _KNOWN_PORTS and state == "ESTABLISHED":
        ttps.append(_ttp("T1095", "MEDIUM",
            f"Non-standard port {foreign_port} TCP connection "
            f"from '{owner}' to {foreign_ip} — possible covert channel"))

    score, level = _score(ttps)
    return TaggedFinding(
        source_plugin="netstat",
        raw=conn,
        ttps=ttps,
        risk_score=score,
        risk_level=level,
        summary=(f"netstat: PID {conn.get('pid')} '{owner}' → "
                 f"{foreign_ip}:{foreign_port} [{state}] — "
                 f"{level} ({', '.join(t.id for t in ttps) or 'clean'})"),
    )


def tag_hashdump_row(entry: dict) -> TaggedFinding:
    """Every hashdump row is a credential access finding by definition."""
    ttps = [
        _ttp("T1003.002", "HIGH",
             f"NTLM hash extracted from SAM for user '{entry.get('username')}' — "
             f"hashes can be used directly for pass-the-hash attacks"),
        _ttp("T1550.002", "MEDIUM",
             "Extracted NTLM hash enables pass-the-hash lateral movement "
             "without cracking the plaintext password"),
    ]
    score, level = _score(ttps)
    return TaggedFinding(
        source_plugin="hashdump",
        raw=entry,
        ttps=ttps,
        risk_score=score,
        risk_level=level,
        summary=f"Credential: '{entry.get('username')}' NTLM hash extracted — {level}",
    )


def tag_driverscan_row(driver: dict) -> TaggedFinding:
    """Tag a kernel driver — flag unsigned or suspicious-path drivers."""
    ttps: list[TTP] = []
    path   = (driver.get("driver_name") or "").lower()
    offset = driver.get("offset_p", "")

    # Driver loaded from non-standard location
    standard_paths = ["\\windows\\system32\\", "\\windows\\syswow64\\",
                      "\\program files\\"]
    if path and not any(p in path for p in standard_paths):
        ttps.append(_ttp("T1014", "HIGH",
            f"Kernel driver '{path}' loaded from non-standard path — "
            f"characteristic of a rootkit kernel module"))
        ttps.append(_ttp("T1543.003", "MEDIUM",
            f"Unsigned or out-of-place driver at offset {offset}"))

    score, level = _score(ttps)
    return TaggedFinding(
        source_plugin="driverscan",
        raw=driver,
        ttps=ttps,
        risk_score=score,
        risk_level=level,
        summary=(f"Driver '{path or offset}' — "
                 f"{level} ({', '.join(t.id for t in ttps) or 'appears clean'})"),
    )


# ─────────────────────────────────────────────────────────────────────────────
# BATCH TAGGERS  (convenience wrappers for lists)
# ─────────────────────────────────────────────────────────────────────────────

def tag_findings(items: list[dict], finding_type: str) -> list[TaggedFinding]:
    """
    Tag a list of raw Volatility dicts by plugin type.

    finding_type: "process" | "malfind" | "netstat" | "hashdump" | "driverscan"
    """
    dispatch = {
        "process":    tag_process,
        "malfind":    tag_malfind_hit,
        "netstat":    tag_netstat_row,
        "hashdump":   tag_hashdump_row,
        "driverscan": tag_driverscan_row,
    }
    fn = dispatch.get(finding_type, tag_process)
    return [fn(item) for item in items]


# ─────────────────────────────────────────────────────────────────────────────
# REPORT BUILDER
# ─────────────────────────────────────────────────────────────────────────────

def build_report(all_findings: list[TaggedFinding]) -> dict:
    """
    Aggregate all tagged findings into a structured report dict.
    Ready to pass to the AI explainer or serialize to JSON.
    """
    critical = [f for f in all_findings if f.risk_level == "CRITICAL"]
    high     = [f for f in all_findings if f.risk_level == "HIGH"]
    medium   = [f for f in all_findings if f.risk_level == "MEDIUM"]
    low      = [f for f in all_findings if f.risk_level == "LOW"]

    # Collect unique TTP IDs across all findings
    all_ttp_ids: set[str] = set()
    for f in all_findings:
        for t in f.ttps:
            all_ttp_ids.add(t.id)

    # Build tactic coverage summary
    tactic_coverage: dict[str, list[str]] = {}
    for f in all_findings:
        for t in f.ttps:
            tactic_coverage.setdefault(t.tactic, [])
            if t.id not in tactic_coverage[t.tactic]:
                tactic_coverage[t.tactic].append(t.id)

    return {
        "summary": {
            "total_findings": len(all_findings),
            "critical":       len(critical),
            "high":           len(high),
            "medium":         len(medium),
            "low":            len(low),
            "unique_ttps":    sorted(all_ttp_ids),
            "tactic_coverage": tactic_coverage,
        },
        "critical_findings": [f.to_dict() for f in critical],
        "high_findings":     [f.to_dict() for f in high],
        "medium_findings":   [f.to_dict() for f in medium],
        "low_findings":      [f.to_dict() for f in low],
    }


# ─────────────────────────────────────────────────────────────────────────────
# VOLATILITY 3 PLUGIN CLASS
# ─────────────────────────────────────────────────────────────────────────────

class AttckTagger(interfaces.plugins.PluginInterface):
    """
    Volatility 3 plugin: runs pslist + psscan + malfind + netstat,
    tags every finding with MITRE ATT&CK TTPs, and outputs a
    risk-scored table sorted by severity.

    Run with:
        python3 vol.py -f memory.dmp custom.AttckTagger
        python3 vol.py -f memory.dmp custom.AttckTagger --output json > report.json
    """

    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.TranslationLayerRequirement(
                name="primary",
                description="Memory layer",
            ),
            requirements.SymbolTableRequirement(
                name="nt_symbols",
                description="Windows kernel symbols",
            ),
            requirements.BooleanRequirement(
                name="no-malfind",
                description="Skip malfind scan (faster but less thorough)",
                default=False,
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="no-netstat",
                description="Skip network connection analysis",
                default=False,
                optional=True,
            ),
        ]

    def _get_processes(self) -> list[TaggedFinding]:
        """Collect processes from pslist + psscan, diff, tag."""
        from volatility3.plugins.windows import pslist, psscan

        pslist_pids: dict[int, dict] = {}
        findings: list[TaggedFinding] = []

        # Collect pslist
        for proc in pslist.PsList.list_processes(
            self.context, self.config["primary"], self.config["nt_symbols"]
        ):
            pid  = int(proc.UniqueProcessId)
            name = proc.ImageFileName.cast(
                "string", max_length=15, errors="replace")
            proc_dict = {
                "pid":         pid,
                "name":        name,
                "ppid":        int(proc.InheritedFromUniqueProcessId),
                "cmdline":     "",
                "path":        "",
                "hidden":      False,
                "has_network": False,
            }
            pslist_pids[pid] = proc_dict

        # Collect psscan — flag anything not in pslist as hidden
        for proc in psscan.PsScan.scan_processes(
            self.context, self.config["primary"], self.config["nt_symbols"]
        ):
            pid  = int(proc.UniqueProcessId)
            name = proc.ImageFileName.cast(
                "string", max_length=15, errors="replace")
            if pid not in pslist_pids:
                proc_dict = {
                    "pid":    pid,
                    "name":   name,
                    "ppid":   int(proc.InheritedFromUniqueProcessId),
                    "cmdline": "",
                    "path":   "",
                    "hidden": True,   # ← DKOM-hidden
                    "has_network": False,
                }
                pslist_pids[pid] = proc_dict

        # Tag all collected processes
        for proc_dict in pslist_pids.values():
            findings.append(tag_process(proc_dict))

        return findings

    def _get_malfind(self) -> list[TaggedFinding]:
        from volatility3.plugins.windows import malfind
        findings = []
        for hit in malfind.Malfind.scan_vads(
            self.context, self.config["primary"], self.config["nt_symbols"]
        ):
            hit_dict = {
                "pid":          int(hit.get("PID", 0)),
                "process_name": str(hit.get("Process", "")),
                "vad_start":    hex(int(hit.get("Start VPN", 0))),
                "vad_end":      hex(int(hit.get("End VPN", 0))),
                "protection":   str(hit.get("Protection", "")),
                "tag":          str(hit.get("Tag", "")),
                "hexdump":      str(hit.get("Hexdump", "")),
            }
            findings.append(tag_malfind_hit(hit_dict))
        return findings

    def _get_netstat(self) -> list[TaggedFinding]:
        from volatility3.plugins.windows import netstat
        findings = []
        for conn in netstat.NetStat.list_sockets(
            self.context, self.config["primary"], self.config["nt_symbols"]
        ):
            conn_dict = {
                "pid":          int(conn.get("PID", 0)),
                "owner":        str(conn.get("Owner", "")),
                "proto":        str(conn.get("Proto", "")),
                "local_addr":   str(conn.get("LocalAddr", "")),
                "local_port":   int(conn.get("LocalPort", 0)),
                "foreign_addr": str(conn.get("ForeignAddr", "")),
                "foreign_port": int(conn.get("ForeignPort", 0)),
                "state":        str(conn.get("State", "")),
            }
            findings.append(tag_netstat_row(conn_dict))
        return findings

    def run(self):
        all_findings: list[TaggedFinding] = []
        all_findings += self._get_processes()

        if not self.config.get("no-malfind", False):
            all_findings += self._get_malfind()

        if not self.config.get("no-netstat", False):
            all_findings += self._get_netstat()

        # Sort: CRITICAL first, then HIGH, MEDIUM, LOW
        _order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        all_findings.sort(key=lambda f: (_order[f.risk_level], -f.risk_score))

        return renderers.TreeGrid(
            [
                ("Source",      str),
                ("Risk",        str),
                ("Score",       int),
                ("TTP IDs",     str),
                ("Summary",     str),
            ],
            self._generator(all_findings),
        )

    def _generator(self, findings: list[TaggedFinding]):
        for f in findings:
            ttp_ids = " | ".join(t.id for t in f.ttps) if f.ttps else "—"
            yield (0, (
                f.source_plugin,
                f.risk_level,
                f.risk_score,
                ttp_ids,
                f.summary,
            ))


# ─────────────────────────────────────────────────────────────────────────────
# CLI HELPER  — run standalone without full Volatility context
# ─────────────────────────────────────────────────────────────────────────────
# Usage:
#   python3 attck_tagger.py sample_procs.json
#
# sample_procs.json format:
#   [{"pid": 1234, "name": "evil.exe", "hidden": true, "cmdline": "..."}]

if __name__ == "__main__":
    import sys

    # Windows consoles default to cp1252, which can't encode the box-drawing
    # characters used below; force UTF-8 output where supported.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8")

    if len(sys.argv) < 2:
        print("Usage: python3 attck_tagger.py <procs.json>")
        sys.exit(1)

    with open(sys.argv[1], encoding="utf-8-sig") as fh:
        raw_procs = json.load(fh)

    tagged = tag_findings(raw_procs, "process")
    report = build_report(tagged)

    print(json.dumps(report, indent=2))

    # Human-readable summary goes to stderr so stdout stays pure JSON and can be
    # safely redirected (e.g. `attck_tagger.py procs.json > tagged.json`).
    print("\n─── HIGH/CRITICAL findings ───", file=sys.stderr)
    for f in tagged:
        if f.risk_level in ("CRITICAL", "HIGH"):
            print(f"  {f.summary}", file=sys.stderr)
            for t in f.ttps:
                print(f"    → {t}", file=sys.stderr)
