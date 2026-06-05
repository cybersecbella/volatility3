"""
vol_langchain.py — LangChain natural language wrapper for Volatility 3
=======================================================================
Place this file at: the ROOT of your volatility3 fork (alongside vol.py)

Requires:
    pip install langchain>=0.2.0 langchain-anthropic>=0.1.0 anthropic>=0.25.0

Environment variables:
    ANTHROPIC_API_KEY   Your Anthropic API key (required)
    VOL_DUMP            Path to memory dump (or pass --dump on CLI)
    VOL_AI_MODEL        Claude model (default: claude-opus-4-6)

Usage — interactive REPL:
    export ANTHROPIC_API_KEY=sk-ant-...
    export VOL_DUMP=/path/to/memory.dmp
    python3 vol_langchain.py

Usage — single query:
    python3 vol_langchain.py --query "show me all hidden processes"
    python3 vol_langchain.py --dump memory.dmp --query "any C2 connections?"

Usage — batch mode (run all queries from a file):
    python3 vol_langchain.py --batch queries.txt --out report.json

Example queries the agent handles:
    "Show me all hidden processes"
    "Are there any suspicious network connections?"
    "What persistence mechanisms did the attacker install?"
    "Dump and analyze PID 2744"
    "Give me a full investigation summary"
    "What credentials were stolen?"
    "Show me injected code"
    "Map all findings to ATT&CK techniques"
    "Write me an executive summary of this incident"
    "What should I do next?"
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import textwrap
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from dotenv import load_dotenv
load_dotenv()   # loads .env file automatically

# ── LangChain imports ─────────────────────────────────────────────────────────
try:
    from langchain_anthropic import ChatAnthropic
    from langchain_core.tools import tool
    # AgentExecutor / create_tool_calling_agent and ConversationBufferWindowMemory
    # were moved out of core `langchain` into `langchain-classic` in LangChain 1.0.
    from langchain_classic.agents import AgentExecutor, create_tool_calling_agent
    from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
    from langchain_core.messages import AIMessage, HumanMessage, SystemMessage
    from langchain_core.callbacks import BaseCallbackHandler
    from langchain_classic.memory import ConversationBufferWindowMemory
except ImportError as e:
    print(f"[ERROR] Missing LangChain package: {e}")
    print("Run: pip install langchain langchain-classic langchain-anthropic langchain-core")
    sys.exit(1)

# ── Anthropic (for direct calls when needed) ──────────────────────────────────
try:
    import anthropic as _anthropic_sdk
except ImportError:
    print("[ERROR] anthropic package not found. Run: pip install anthropic")
    sys.exit(1)


# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────

DEFAULT_MODEL  = os.environ.get("VOL_AI_MODEL", "claude-opus-4-6")
DEFAULT_DUMP   = os.environ.get("VOL_DUMP", "")
VOL_SCRIPT     = Path(__file__).parent / "vol.py"

# Conversation memory window (how many past exchanges the agent remembers)
MEMORY_WINDOW = 10


# ─────────────────────────────────────────────────────────────────────────────
# VOLATILITY RUNNER
# Low-level helper that runs vol.py as a subprocess and parses output.
# All tools call this instead of importing vol3 directly so the wrapper
# works even if vol3 is not installed as a Python package.
# ─────────────────────────────────────────────────────────────────────────────

class VolatilityRunner:
    """
    Runs Volatility 3 plugins as subprocesses and returns structured output.
    Caches results so repeated queries don't re-run expensive plugins.
    """

    def __init__(self, dump_path: str, vol_script: Path = VOL_SCRIPT):
        if not dump_path:
            raise ValueError(
                "No memory dump path provided.\n"
                "Set the VOL_DUMP environment variable or pass --dump on the CLI."
            )
        self.dump_path  = dump_path
        self.vol_script = str(vol_script)
        self._cache: dict[str, Any] = {}

    def run(
        self,
        plugin:     str,
        extra_args: list[str] = None,
        use_cache:  bool = True,
    ) -> list[dict] | str:
        """
        Run a Volatility plugin and return parsed output.
        Returns list[dict] when JSON parsing succeeds, raw string otherwise.
        """
        cache_key = f"{plugin}::{' '.join(extra_args or [])}"
        if use_cache and cache_key in self._cache:
            return self._cache[cache_key]

        cmd = [
            sys.executable, self.vol_script,
            "-f", self.dump_path,
            "--renderer", "json",
            plugin,
        ] + (extra_args or [])

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
            )
        except subprocess.TimeoutExpired:
            return [{"error": f"Plugin {plugin} timed out after 120s"}]
        except FileNotFoundError:
            return [{"error": f"vol.py not found at {self.vol_script}. "
                               f"Run from the root of your volatility3 fork."}]

        raw = result.stdout.strip()
        if not raw:
            stderr = result.stderr.strip()
            return [{"error": f"No output from {plugin}. stderr: {stderr[:300]}"}]

        try:
            parsed = json.loads(raw)
            output = parsed if isinstance(parsed, list) else [parsed]
        except json.JSONDecodeError:
            # Some plugins output non-JSON — return as string
            output = raw

        if use_cache:
            self._cache[cache_key] = output
        return output

    def clear_cache(self):
        self._cache.clear()

    def dump_info(self) -> dict:
        """Return basic info about the loaded dump."""
        result = self.run("windows.info")
        if isinstance(result, list) and result:
            return result[0]
        return {"path": self.dump_path}


# ─────────────────────────────────────────────────────────────────────────────
# TOOL FACTORY
# Builds LangChain tools bound to a specific VolatilityRunner instance.
# We use a factory (not module-level @tool decorators) so the dump path
# can be set at runtime rather than at import time.
# ─────────────────────────────────────────────────────────────────────────────

def build_tools(runner: VolatilityRunner) -> list:
    """
    Build all LangChain tools bound to the given VolatilityRunner.
    Returns a list of @tool-decorated functions ready for the agent.
    """

    # ── Known bad C2 / backdoor ports ────────────────────────────────────────
    _C2_PORTS = {4444, 4445, 1337, 31337, 8888, 9999, 1234, 12345, 6666, 5555}
    _STD_PORTS = {80, 443, 8080, 8443, 53, 22, 21, 25, 110, 143, 3389, 445}

    # ── Suspicious parent → child relationships ───────────────────────────────
    _BAD_PARENTS  = {"chrome.exe", "firefox.exe", "msedge.exe", "iexplore.exe"}
    _SHELL_PROCS  = {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe",
                     "cscript.exe", "mshta.exe"}

    @tool
    def get_dump_info() -> str:
        """
        Get basic information about the memory dump: OS version,
        build number, kernel base address. Always run this first
        to confirm the dump loaded correctly.
        """
        result = runner.run("windows.info")
        if isinstance(result, list):
            return json.dumps(result[:3], indent=2)
        return str(result)

    @tool
    def list_processes(show_hidden: bool = True) -> str:
        """
        List all running processes from the memory dump.
        Set show_hidden=True (default) to also detect rootkit-hidden
        processes by comparing pslist vs psscan output.
        Returns process name, PID, PPID, and hidden status.
        """
        pslist_result = runner.run("windows.pslist")
        pslist_pids: set[int] = set()
        procs: list[dict] = []

        if isinstance(pslist_result, list):
            for p in pslist_result:
                pid = p.get("PID") or p.get("pid")
                if pid:
                    pslist_pids.add(int(pid))
                    procs.append({
                        "pid":    int(pid),
                        "name":   p.get("ImageFileName") or p.get("name", "?"),
                        "ppid":   p.get("PPID") or p.get("ppid", 0),
                        "hidden": False,
                        "exit":   bool(p.get("ExitTime") or p.get("exit_time")),
                    })

        hidden_procs: list[dict] = []
        if show_hidden:
            psscan_result = runner.run("windows.psscan")
            if isinstance(psscan_result, list):
                for p in psscan_result:
                    pid = p.get("PID") or p.get("pid")
                    if pid and int(pid) not in pslist_pids:
                        hidden_procs.append({
                            "pid":    int(pid),
                            "name":   p.get("ImageFileName") or p.get("name", "?"),
                            "ppid":   p.get("PPID") or p.get("ppid", 0),
                            "hidden": True,
                            "note":   "NOT in pslist — possible DKOM rootkit (T1014, T1055)",
                        })

        output = {
            "running_processes": procs,
            "hidden_processes":  hidden_procs,
            "summary": (
                f"{len(procs)} visible processes, "
                f"{len(hidden_procs)} hidden (DKOM) processes detected"
            ),
        }
        return json.dumps(output, indent=2)

    @tool
    def get_process_tree() -> str:
        """
        Show the parent-child process hierarchy.
        Highlights suspicious relationships such as browsers spawning
        cmd.exe or PowerShell (common exploit/malware behavior).
        """
        result = runner.run("windows.pstree")
        if not isinstance(result, list):
            return str(result)

        suspicious: list[dict] = []
        for proc in result:
            name   = (proc.get("ImageFileName") or proc.get("name") or "").lower()
            parent = (proc.get("__children") or [])
            # Check children for suspicious spawns
            for child_entry in result:
                child_name   = (child_entry.get("ImageFileName") or "").lower()
                child_ppid   = child_entry.get("PPID") or child_entry.get("ppid")
                parent_pid   = proc.get("PID") or proc.get("pid")
                if (child_ppid == parent_pid
                        and name in _BAD_PARENTS
                        and child_name in _SHELL_PROCS):
                    suspicious.append({
                        "finding":     "Suspicious parent-child relationship",
                        "parent":      f"{proc.get('ImageFileName')} (PID {parent_pid})",
                        "child":       f"{child_entry.get('ImageFileName')} "
                                       f"(PID {child_entry.get('PID')})",
                        "attck":       "T1059.003 — Windows Command Shell (Execution)",
                        "action":      "Run get_cmdlines() on child PID immediately",
                    })

        output = {
            "process_tree": result[:40],
            "suspicious_relationships": suspicious,
        }
        return json.dumps(output, indent=2)

    @tool
    def get_cmdlines(pid: int = None) -> str:
        """
        Get command line arguments for all processes, or a specific PID.
        Reveals obfuscated/encoded PowerShell, C2 URLs passed as arguments,
        and how malicious processes were launched.
        Pass pid=None to get all processes.
        """
        args = ["--pid", str(pid)] if pid else []
        result = runner.run("windows.cmdline", args)
        if not isinstance(result, list):
            return str(result)

        import re
        encoded_ps = re.compile(
            r"-enc(?:odedcommand)?\s+[A-Za-z0-9+/=]{20,}|"
            r"frombase64string|invoke-expression|iex\s*\(|"
            r"downloadstring|downloadfile|hidden.*bypass",
            re.IGNORECASE,
        )
        flagged: list[dict] = []
        for entry in result:
            cmdline = str(entry.get("Args") or entry.get("cmdline") or "")
            if encoded_ps.search(cmdline):
                flagged.append({
                    "pid":     entry.get("PID") or entry.get("pid"),
                    "name":    entry.get("ImageFileName") or entry.get("name"),
                    "cmdline": cmdline,
                    "flag":    "Obfuscated/encoded PowerShell detected (T1059.001)",
                })

        output = {
            "all_cmdlines":         result[:30],
            "flagged_cmdlines":     flagged,
            "flagged_count":        len(flagged),
        }
        return json.dumps(output, indent=2)

    @tool
    def check_network_connections() -> str:
        """
        Show all active and recently closed network connections from the dump.
        Highlights connections to suspicious ports (4444, 1337, 31337, etc.)
        and shell processes with outbound connections (reverse shells).
        """
        result = runner.run("windows.netstat")
        if not isinstance(result, list):
            return str(result)

        suspicious: list[dict] = []
        for conn in result:
            foreign_port = int(conn.get("ForeignPort") or conn.get("foreign_port") or 0)
            foreign_addr = str(conn.get("ForeignAddr") or conn.get("foreign_addr") or "")
            owner        = str(conn.get("Owner") or conn.get("owner") or "").lower()
            state        = str(conn.get("State") or conn.get("state") or "").upper()
            proto        = str(conn.get("Proto") or conn.get("proto") or "").upper()

            reasons: list[str] = []
            if foreign_port in _C2_PORTS:
                reasons.append(f"Port {foreign_port} is a known C2/backdoor port (T1571)")
            if owner in _SHELL_PROCS and state == "ESTABLISHED":
                reasons.append(f"Shell process '{owner}' has live connection — possible reverse shell (T1071.001)")
            if proto == "TCP" and foreign_port not in _STD_PORTS and state == "ESTABLISHED":
                reasons.append(f"Non-standard port {foreign_port} TCP to {foreign_addr} (T1095)")
            # Private/loopback exclusion
            if foreign_addr.startswith(("127.", "0.0.0.0", "::")):
                reasons = []

            if reasons:
                suspicious.append({
                    "pid":          conn.get("PID") or conn.get("pid"),
                    "owner":        owner,
                    "proto":        proto,
                    "foreign_addr": foreign_addr,
                    "foreign_port": foreign_port,
                    "state":        state,
                    "reasons":      reasons,
                })

        output = {
            "all_connections": result[:30],
            "suspicious_connections": suspicious,
            "summary": (
                f"{len(result)} total connections, "
                f"{len(suspicious)} suspicious"
            ),
        }
        return json.dumps(output, indent=2)

    @tool
    def find_injected_code(pid: int = None) -> str:
        """
        Scan for process injection, shellcode, and malicious memory regions
        using the malfind plugin. Detects PAGE_EXECUTE_READWRITE regions
        and PE headers (MZ) in unexpected memory locations.
        Pass pid to target a specific process, or leave None to scan all.
        """
        args = ["--pid", str(pid)] if pid else []
        result = runner.run("windows.malfind", args)
        if not isinstance(result, list):
            return str(result)

        enriched: list[dict] = []
        for hit in result[:20]:  # cap at 20 to avoid LLM token overflow
            protect  = str(hit.get("Protection") or hit.get("protection") or "")
            hexdump  = str(hit.get("Hexdump") or hit.get("hexdump") or "")
            tag      = str(hit.get("Tag") or hit.get("tag") or "")
            pid_hit  = hit.get("PID") or hit.get("pid")
            proc     = hit.get("Process") or hit.get("process_name")
            vad      = hit.get("Start VPN") or hit.get("vad_start")

            ttps: list[str] = []
            if "EXECUTE_READWRITE" in protect.upper():
                ttps.append("T1055 — Process Injection (RWX memory region)")
            if "4d5a" in hexdump.lower() or hexdump.startswith("MZ"):
                ttps.append("T1055.002 — PE Injection (MZ header in private memory)")
            if tag == "VadS":
                ttps.append("T1055.012 — Process Hollowing (VadS private executable memory)")

            enriched.append({
                "pid":        pid_hit,
                "process":    proc,
                "vad_start":  vad,
                "protection": protect,
                "tag":        tag,
                "hexdump":    hexdump[:32],
                "ttps":       ttps,
                "verdict":    "SUSPICIOUS" if ttps else "review manually",
            })

        suspicious_count = sum(1 for h in enriched if h["ttps"])
        output = {
            "malfind_hits":    enriched,
            "suspicious_count": suspicious_count,
            "total_hits":      len(result),
            "note": (
                "Each hit with TTPs warrants manual review. "
                "Use dump_process_memory() to extract the binary."
            ),
        }
        return json.dumps(output, indent=2)

    @tool
    def check_persistence() -> str:
        """
        Check all Windows persistence mechanisms in memory:
        Run/RunOnce registry keys, installed services, AppInit DLLs,
        Winlogon entries, and scheduled tasks.
        Maps each finding to the relevant ATT&CK persistence technique.
        """
        results: dict[str, Any] = {}

        # Registry Run keys
        run_keys = [
            "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
            "SYSTEM\\CurrentControlSet\\Services",
        ]
        registry_findings: list[dict] = []
        for key in run_keys:
            r = runner.run(
                "windows.registry.printkey",
                ["--key", key],
            )
            if isinstance(r, list) and r:
                for entry in r:
                    val_name = entry.get("Name") or entry.get("name", "")
                    val_data = entry.get("Data") or entry.get("data", "")
                    if val_name and val_name not in ("(Default)", ""):
                        registry_findings.append({
                            "key":    key,
                            "name":   val_name,
                            "data":   str(val_data)[:200],
                            "attck":  "T1547.001 — Registry Run Keys (Persistence)",
                        })

        results["registry_persistence"] = registry_findings

        # Scheduled tasks (Windows.ScheduledTasks if available)
        tasks = runner.run("windows.scheduled_tasks")
        if isinstance(tasks, list) and tasks and "error" not in str(tasks[0]):
            results["scheduled_tasks"] = tasks[:15]
            results["scheduled_tasks_note"] = "T1053.005 — Scheduled Task (Persistence)"
        else:
            results["scheduled_tasks"] = "Plugin not available or no tasks found"

        # Services (from registry hive)
        results["note"] = (
            "For full autorun coverage, also run: "
            "python3 vol.py -f dump windows.services"
        )

        output = {
            "persistence_findings": results,
            "registry_run_count":   len(registry_findings),
            "summary": (
                f"Found {len(registry_findings)} registry persistence entries. "
                "Review each entry's data field for suspicious executables."
            ),
        }
        return json.dumps(output, indent=2)

    @tool
    def dump_credentials() -> str:
        """
        Extract NTLM password hashes from the SAM database in memory
        using the hashdump plugin. These hashes can be used for
        pass-the-hash attacks without cracking (T1003.002, T1550.002).
        Returns usernames and their NTLM hashes.
        """
        result = runner.run("windows.hashdump")
        if not isinstance(result, list):
            return str(result)

        enriched: list[dict] = []
        for entry in result:
            user   = entry.get("User") or entry.get("username") or "?"
            lm     = entry.get("lmhash") or entry.get("LM") or "aad3b..."
            nt     = entry.get("nthash") or entry.get("NT") or "?"
            enriched.append({
                "username": user,
                "lm_hash":  lm,
                "nt_hash":  nt,
                "attck":    [
                    "T1003.002 — SAM Credential Dumping",
                    "T1550.002 — Pass the Hash (lateral movement risk)",
                ],
                "action":   f"Reset password for '{user}' immediately. "
                            f"Check if NT hash {nt[:8]}... appears in breach databases.",
            })

        output = {
            "credentials": enriched,
            "count":       len(enriched),
            "warning":     (
                "These hashes are live credential material. "
                "Do not store or transmit unencrypted. "
                "Rotate ALL passwords for accounts listed here."
            ),
        }
        return json.dumps(output, indent=2)

    @tool
    def dump_process_memory(pid: int) -> str:
        """
        Dump the memory of a specific process to disk for deeper analysis.
        Use this after finding a suspicious PID with list_processes() or
        find_injected_code(). The dump can be submitted to VirusTotal
        or analyzed with YARA rules.
        Requires pid: the process ID to dump.
        """
        if not pid:
            return json.dumps({"error": "pid is required"})

        output_dir = Path("./vol_dumps")
        output_dir.mkdir(exist_ok=True)

        # Dump process executable
        exe_result = runner.run(
            "windows.dumpfiles",
            ["--pid", str(pid)],
            use_cache=False,
        )
        # Dump process memory regions (VADs)
        vad_result = runner.run(
            "windows.memmap",
            ["--pid", str(pid), "--dump"],
            use_cache=False,
        )

        output = {
            "pid":         pid,
            "output_dir":  str(output_dir.absolute()),
            "exe_dump":    exe_result[:3] if isinstance(exe_result, list) else str(exe_result)[:300],
            "vad_dump":    vad_result[:3] if isinstance(vad_result, list) else str(vad_result)[:300],
            "next_steps": [
                f"Submit dumped .exe to VirusTotal: sha256sum vol_dumps/pid.{pid}.*.exe",
                f"Run YARA: yara malware_rules.yar vol_dumps/pid.{pid}.*",
                f"Run strings: strings -n 8 vol_dumps/pid.{pid}.*.dmp | grep -E 'http|cmd|powershell'",
            ],
        }
        return json.dumps(output, indent=2)

    @tool
    def check_dlls(pid: int) -> str:
        """
        List all DLLs loaded by a specific process.
        Detects DLL hijacking and side-loading by flagging DLLs
        loaded from non-standard paths (temp folders, AppData, Desktop).
        Requires pid: the process ID to inspect.
        """
        if not pid:
            return json.dumps({"error": "pid is required"})

        result = runner.run("windows.dlllist", ["--pid", str(pid)])
        if not isinstance(result, list):
            return str(result)

        standard_paths = [
            "\\windows\\system32\\",
            "\\windows\\syswow64\\",
            "\\program files\\",
            "\\program files (x86)\\",
        ]
        suspicious_dlls: list[dict] = []
        for dll in result:
            path = str(dll.get("Path") or dll.get("path") or "").lower()
            name = str(dll.get("Name") or dll.get("name") or "").lower()
            if path and not any(sp in path for sp in standard_paths):
                suspicious_dlls.append({
                    "name":   name,
                    "path":   path,
                    "attck":  "T1574.001 — DLL Search Order Hijacking, or T1574.002 — DLL Side-Loading",
                    "action": f"Verify '{name}' is legitimate. "
                              "Check file hash against VirusTotal.",
                })

        output = {
            "pid":            pid,
            "all_dlls":       result[:30],
            "suspicious_dlls": suspicious_dlls,
            "summary":        (
                f"{len(result)} DLLs loaded, "
                f"{len(suspicious_dlls)} from suspicious paths"
            ),
        }
        return json.dumps(output, indent=2)

    @tool
    def check_drivers() -> str:
        """
        Scan for kernel drivers and detect rootkit indicators.
        Flags drivers loaded from non-standard paths and checks
        for SSDT (System Service Descriptor Table) hooks,
        which are a classic rootkit technique (T1014).
        """
        drivers = runner.run("windows.driverscan")
        modules = runner.run("windows.modules")

        standard_paths = [
            "\\windows\\system32\\",
            "\\windows\\syswow64\\",
            "system32\\drivers\\",
        ]
        suspicious: list[dict] = []

        if isinstance(drivers, list):
            for drv in drivers:
                name = str(drv.get("DriverName") or drv.get("name") or "").lower()
                path = str(drv.get("DriverName") or "").lower()
                if name and not any(sp in path for sp in standard_paths):
                    suspicious.append({
                        "name":   name,
                        "offset": drv.get("Offset(P)") or drv.get("offset"),
                        "attck":  "T1014 — Rootkit (kernel driver from non-standard path)",
                        "action": "Extract with dumpfiles and submit to VirusTotal",
                    })

        # Try SSDT hooks
        ssdt = runner.run("windows.ssdt")
        ssdt_hooks: list[dict] = []
        if isinstance(ssdt, list):
            for entry in ssdt:
                module = str(entry.get("Module") or "").lower()
                if module and "ntoskrnl" not in module and "win32k" not in module:
                    ssdt_hooks.append({
                        "index":  entry.get("Index"),
                        "module": module,
                        "attck":  "T1014 — Rootkit (SSDT hook)",
                    })

        output = {
            "drivers_scanned":  len(drivers) if isinstance(drivers, list) else 0,
            "suspicious_drivers": suspicious,
            "ssdt_hooks":       ssdt_hooks,
            "summary": (
                f"{len(suspicious)} suspicious drivers, "
                f"{len(ssdt_hooks)} SSDT hooks detected"
            ),
        }
        return json.dumps(output, indent=2)

    @tool
    def run_attck_tagger() -> str:
        """
        Run the ATT&CK TTP tagger across all findings (processes, malfind,
        netstat, hashdump) and return a structured risk-scored report
        with MITRE technique mappings. This is the most comprehensive
        single-call analysis available.
        """
        try:
            # Try to import and run the tagger directly
            sys.path.insert(0, str(Path(__file__).parent))
            from volatility3.plugins.custom.attck_tagger import (
                tag_findings, build_report,
            )
            tagger_available = True
        except ImportError:
            tagger_available = False

        if tagger_available:
            # Collect raw findings
            raw: list[dict] = []
            for plugin_result in [
                runner.run("windows.pslist"),
                runner.run("windows.psscan"),
            ]:
                if isinstance(plugin_result, list):
                    for p in plugin_result:
                        raw.append({**p, "_type": "process"})
            tagged = tag_findings(
                [f for f in raw if f.get("_type") == "process"],
                "process"
            )
            report = build_report(tagged)
            return json.dumps(report, indent=2)
        else:
            # Fallback: synthesize a basic report from available data
            procs_raw   = runner.run("windows.pslist")
            psscan_raw  = runner.run("windows.psscan")
            netstat_raw = runner.run("windows.netstat")

            pslist_pids = {
                int(p.get("PID") or 0)
                for p in (procs_raw if isinstance(procs_raw, list) else [])
            }
            hidden_pids = [
                int(p.get("PID") or 0)
                for p in (psscan_raw if isinstance(psscan_raw, list) else [])
                if int(p.get("PID") or 0) not in pslist_pids
            ]

            return json.dumps({
                "note":         "attck_tagger.py not found — basic report only",
                "total_procs":  len(procs_raw) if isinstance(procs_raw, list) else 0,
                "hidden_procs": hidden_pids,
                "connections":  len(netstat_raw) if isinstance(netstat_raw, list) else 0,
            }, indent=2)

    @tool
    def generate_investigation_summary() -> str:
        """
        Generate a comprehensive investigation summary covering all
        available plugins: processes, network, injection, persistence,
        credentials, and drivers. Use this for a full picture of the
        incident before writing the report.
        """
        sections: dict[str, Any] = {}

        # Processes
        pslist = runner.run("windows.pslist")
        psscan = runner.run("windows.psscan")
        pslist_pids = {
            int(p.get("PID") or 0)
            for p in (pslist if isinstance(pslist, list) else [])
        }
        hidden = [
            p for p in (psscan if isinstance(psscan, list) else [])
            if int(p.get("PID") or 0) not in pslist_pids
        ]
        sections["processes"] = {
            "total":  len(pslist) if isinstance(pslist, list) else 0,
            "hidden": len(hidden),
            "hidden_details": hidden[:5],
        }

        # Network
        netstat = runner.run("windows.netstat")
        if isinstance(netstat, list):
            suspicious_conns = [
                c for c in netstat
                if int(c.get("ForeignPort") or 0) in _C2_PORTS
            ]
            sections["network"] = {
                "total_connections": len(netstat),
                "suspicious":        len(suspicious_conns),
                "suspicious_details": suspicious_conns[:5],
            }

        # Malfind
        malfind_hits = runner.run("windows.malfind")
        if isinstance(malfind_hits, list):
            sections["injection"] = {
                "malfind_hits": len(malfind_hits),
                "sample":       malfind_hits[:3],
            }

        # Hashdump
        hashes = runner.run("windows.hashdump")
        if isinstance(hashes, list) and hashes and "error" not in str(hashes[0]):
            sections["credentials"] = {
                "hashes_found": len(hashes),
                "users": [
                    h.get("User") or h.get("username") for h in hashes
                ],
            }

        # Build risk summary
        risk_indicators: list[str] = []
        if hidden:
            risk_indicators.append(
                f"CRITICAL: {len(hidden)} DKOM-hidden processes (T1014, T1055)"
            )
        if sections.get("network", {}).get("suspicious", 0) > 0:
            risk_indicators.append(
                f"HIGH: {sections['network']['suspicious']} suspicious C2 connections (T1071)"
            )
        if sections.get("injection", {}).get("malfind_hits", 0) > 0:
            risk_indicators.append(
                f"HIGH: {sections['injection']['malfind_hits']} code injection hits (T1055)"
            )
        if sections.get("credentials", {}).get("hashes_found", 0) > 0:
            risk_indicators.append(
                f"CRITICAL: {sections['credentials']['hashes_found']} credential hashes dumped (T1003)"
            )

        output = {
            "investigation_summary": sections,
            "risk_indicators":       risk_indicators,
            "overall_risk":          (
                "CRITICAL" if any("CRITICAL" in r for r in risk_indicators)
                else "HIGH" if any("HIGH" in r for r in risk_indicators)
                else "MEDIUM" if risk_indicators
                else "LOW"
            ),
            "recommended_next_steps": [
                "Run find_injected_code() on any suspicious PIDs",
                "Run dump_process_memory() on CRITICAL PIDs",
                "Run check_persistence() to find attacker footholds",
                "Submit dumped binaries to VirusTotal",
                "Rotate all credentials from dump_credentials() output",
            ],
        }
        return json.dumps(output, indent=2)

    @tool
    def search_registry(key_path: str) -> str:
        """
        Search a specific Windows registry key path in memory.
        Useful for finding persistence, attacker configuration,
        and malware settings stored in the registry.
        Example key_path: 'Software\\Microsoft\\Windows\\CurrentVersion\\Run'
        """
        result = runner.run(
            "windows.registry.printkey",
            ["--key", key_path],
        )
        if not isinstance(result, list):
            return str(result)
        return json.dumps({
            "key":     key_path,
            "entries": result[:20],
            "count":   len(result),
        }, indent=2)

    @tool
    def get_handles(pid: int) -> str:
        """
        List all open handles (files, registry keys, mutexes, events)
        for a specific process. Reveals what resources a process
        is accessing — files being exfiltrated, mutexes used by
        malware families for single-instance checks, etc.
        Requires pid: the process ID to inspect.
        """
        if not pid:
            return json.dumps({"error": "pid is required"})
        result = runner.run("windows.handles", ["--pid", str(pid)])
        if not isinstance(result, list):
            return str(result)

        # Filter to interesting handle types
        interesting_types = {"File", "Key", "Mutant", "Event", "Process", "Thread"}
        filtered = [
            h for h in result
            if (h.get("Type") or h.get("type") or "") in interesting_types
        ]
        return json.dumps({
            "pid":     pid,
            "handles": filtered[:30],
            "total":   len(result),
            "note":    "Mutant handles often contain malware family identifiers",
        }, indent=2)

    return [
        get_dump_info,
        list_processes,
        get_process_tree,
        get_cmdlines,
        check_network_connections,
        find_injected_code,
        check_persistence,
        dump_credentials,
        dump_process_memory,
        check_dlls,
        check_drivers,
        run_attck_tagger,
        generate_investigation_summary,
        search_registry,
        get_handles,
    ]


# ─────────────────────────────────────────────────────────────────────────────
# AGENT BUILDER
# ─────────────────────────────────────────────────────────────────────────────

AGENT_SYSTEM_PROMPT = """\
You are an expert digital forensics and incident response (DFIR) analyst \
with 15 years of experience. You are analyzing a Windows memory dump using \
Volatility 3 tools available to you as function calls.

Your behavior:
- Always call the appropriate tool before answering — never guess from memory
- When you find something suspicious, explain it clearly AND call the next \
  logical tool automatically (e.g. if list_processes() finds a hidden PID, \
  immediately call find_injected_code(pid=that_pid))
- Map every finding to its MITRE ATT&CK T-number
- Be specific: reference actual PIDs, process names, ports, hashes from the data
- Prioritize by risk: lead with CRITICAL, then HIGH, then MEDIUM
- End every response with: "→ Suggested next step: [specific action]"
- If asked for a report or summary, use generate_investigation_summary() first, \
  then write a structured response

Available tools:
  get_dump_info()                  — OS info, confirm dump loaded
  list_processes(show_hidden)      — pslist + psscan diff (finds DKOM hiding)
  get_process_tree()               — parent-child relationships
  get_cmdlines(pid)                — command line args, detect encoded PS
  check_network_connections()      — C2 connections, reverse shells
  find_injected_code(pid)          — malfind: shellcode, PE injection
  check_persistence()              — Run keys, services, scheduled tasks
  dump_credentials()               — NTLM hashes from SAM (hashdump)
  dump_process_memory(pid)         — extract process binary for analysis
  check_dlls(pid)                  — DLL hijacking detection
  check_drivers()                  — rootkit kernel drivers, SSDT hooks
  run_attck_tagger()               — full ATT&CK-tagged risk report
  generate_investigation_summary() — comprehensive all-plugin summary
  search_registry(key_path)        — search specific registry key
  get_handles(pid)                 — open files, mutexes, keys for a PID
"""


class AnthropicStreamingHandler(BaseCallbackHandler):
    """Stream text tokens to stdout, tolerant of Anthropic's content-block format.

    langchain-anthropic (LangChain 1.x) delivers each streamed token as either a
    plain string or a list of content-block dicts, e.g.
    ``[{"type": "text", "text": "..."}]``. The stock
    StreamingStdOutCallbackHandler assumes a string and raises
    ``write() argument must be str, not list`` on the list form. This handler
    pulls the text out of whichever shape arrives and ignores non-text blocks
    (tool-use input deltas, etc.).
    """

    @staticmethod
    def _extract_text(token: Any) -> str:
        if isinstance(token, str):
            return token
        if isinstance(token, list):
            parts = []
            for block in token:
                if isinstance(block, dict):
                    if block.get("type", "text") == "text" and "text" in block:
                        parts.append(block["text"])
                elif isinstance(block, str):
                    parts.append(block)
            return "".join(parts)
        return ""

    def on_llm_new_token(self, token: Any, **kwargs: Any) -> None:
        text = self._extract_text(token)
        if text:
            sys.stdout.write(text)
            sys.stdout.flush()


def build_agent(
    runner:     VolatilityRunner,
    model:      str  = DEFAULT_MODEL,
    streaming:  bool = True,
    memory_k:   int  = MEMORY_WINDOW,
) -> tuple[AgentExecutor, ConversationBufferWindowMemory]:
    """
    Build and return the LangChain agent and its memory object.
    Returns (executor, memory) so callers can inspect conversation history.
    """
    tools = build_tools(runner)

    callbacks = [AnthropicStreamingHandler()] if streaming else []

    llm = ChatAnthropic(
        model=model,
        temperature=0,        # deterministic for forensics
        streaming=streaming,
        callbacks=callbacks,
        anthropic_api_key=os.environ.get("ANTHROPIC_API_KEY"),
    )

    memory = ConversationBufferWindowMemory(
        k=memory_k,
        memory_key="chat_history",
        return_messages=True,
    )

    prompt = ChatPromptTemplate.from_messages([
        ("system", AGENT_SYSTEM_PROMPT),
        MessagesPlaceholder(variable_name="chat_history"),
        ("human", "{input}"),
        MessagesPlaceholder(variable_name="agent_scratchpad"),
    ])

    agent = create_tool_calling_agent(llm, tools, prompt)

    executor = AgentExecutor(
        agent=agent,
        tools=tools,
        memory=memory,
        verbose=True,
        handle_parsing_errors=True,
        max_iterations=8,          # prevent infinite tool loops
        early_stopping_method="generate",
    )

    return executor, memory


# ─────────────────────────────────────────────────────────────────────────────
# INTERACTIVE REPL
# ─────────────────────────────────────────────────────────────────────────────

REPL_HELP = """
Commands:
  exit / quit       — exit the REPL
  clear             — clear conversation history
  history           — show conversation history
  cache             — show cached plugin results
  clearcache        — clear the plugin cache (re-run plugins next query)
  tools             — list available tools
  help              — show this message

Example queries:
  show me all processes including hidden ones
  are there any C2 connections?
  analyze PID 2744 fully
  what persistence mechanisms exist?
  dump credentials
  give me a full incident summary
  write an executive summary
  what should I investigate next?
"""

def run_repl(executor: AgentExecutor, runner: VolatilityRunner, memory):
    """Run the interactive REPL loop."""
    print("\n" + "═" * 60)
    print("  Volatility AI Assistant")
    print(f"  Dump: {runner.dump_path}")
    print(f"  Model: {DEFAULT_MODEL}")
    print("  Type 'help' for commands, 'exit' to quit")
    print("═" * 60 + "\n")

    # Auto-run dump info on startup
    print("[init] Checking dump...", flush=True)
    try:
        info = runner.dump_info()
        os_info = info.get("Variable") or info.get("Value") or str(info)[:80]
        print(f"[init] Dump loaded: {runner.dump_path}")
    except Exception as e:
        print(f"[init] Warning: {e}")
    print()

    while True:
        try:
            query = input(">> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting.")
            break

        if not query:
            continue

        query_lower = query.lower()

        # Built-in commands
        if query_lower in ("exit", "quit"):
            print("Goodbye.")
            break

        if query_lower == "help":
            print(REPL_HELP)
            continue

        if query_lower == "clear":
            memory.clear()
            print("[cleared conversation history]")
            continue

        if query_lower == "history":
            msgs = memory.chat_memory.messages
            if not msgs:
                print("[no history yet]")
            for msg in msgs:
                role = "You" if isinstance(msg, HumanMessage) else "Agent"
                print(f"\n{role}: {str(msg.content)[:200]}")
            continue

        if query_lower == "cache":
            cached = list(runner._cache.keys())
            if cached:
                print(f"Cached plugins ({len(cached)}):")
                for k in cached:
                    print(f"  {k}")
            else:
                print("[cache empty]")
            continue

        if query_lower == "clearcache":
            runner.clear_cache()
            print("[plugin cache cleared]")
            continue

        if query_lower == "tools":
            tools = build_tools(runner)
            print(f"\nAvailable tools ({len(tools)}):")
            for t in tools:
                desc = t.description.split("\n")[0][:70]
                print(f"  {t.name:<30} {desc}")
            continue

        # Run the agent
        print()
        try:
            result = executor.invoke({"input": query})
            # Output is already streamed; just print a separator
            print("\n" + "─" * 60 + "\n")
        except KeyboardInterrupt:
            print("\n[interrupted]")
        except Exception as e:
            print(f"\n[error] {type(e).__name__}: {e}")
            if "API" in str(e) or "auth" in str(e).lower():
                print("Check your ANTHROPIC_API_KEY environment variable.")


# ─────────────────────────────────────────────────────────────────────────────
# BATCH MODE
# ─────────────────────────────────────────────────────────────────────────────

def run_batch(
    executor:    AgentExecutor,
    queries_file: str,
    output_file: str = "",
) -> list[dict]:
    """
    Run a list of queries from a file and collect results.
    queries_file: one query per line
    Returns list of {query, response} dicts.
    """
    with open(queries_file) as fh:
        queries = [
            line.strip()
            for line in fh
            if line.strip() and not line.startswith("#")
        ]

    print(f"[batch] Running {len(queries)} queries...")
    results: list[dict] = []

    for i, query in enumerate(queries, 1):
        print(f"\n[batch {i}/{len(queries)}] {query}")
        print("─" * 50)
        try:
            result = executor.invoke({"input": query})
            entry = {
                "query":     query,
                "response":  result.get("output", ""),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        except Exception as e:
            entry = {
                "query":     query,
                "response":  f"ERROR: {e}",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        results.append(entry)

    if output_file:
        with open(output_file, "w") as fh:
            json.dump(results, fh, indent=2)
        print(f"\n[batch] Results saved to: {output_file}")

    return results


# ─────────────────────────────────────────────────────────────────────────────
# CLI ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="LangChain natural language wrapper for Volatility 3",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              # Interactive REPL
              python3 vol_langchain.py --dump memory.dmp

              # Single query
              python3 vol_langchain.py --dump memory.dmp --query "show me hidden processes"

              # Batch mode
              python3 vol_langchain.py --dump memory.dmp --batch queries.txt --out report.json

              # Use environment variable for dump path
              export VOL_DUMP=/evidence/memory.dmp
              python3 vol_langchain.py
        """),
    )
    parser.add_argument(
        "--dump", "-f",
        default=DEFAULT_DUMP,
        help="Path to memory dump file (or set VOL_DUMP env var)",
    )
    parser.add_argument(
        "--query", "-q",
        default="",
        help="Run a single query and exit",
    )
    parser.add_argument(
        "--batch", "-b",
        default="",
        help="Path to file with one query per line (batch mode)",
    )
    parser.add_argument(
        "--out", "-o",
        default="",
        help="Output file for batch results (JSON)",
    )
    parser.add_argument(
        "--model",
        default=DEFAULT_MODEL,
        help=f"Claude model (default: {DEFAULT_MODEL})",
    )
    parser.add_argument(
        "--no-stream",
        action="store_true",
        help="Disable token streaming",
    )
    parser.add_argument(
        "--no-cache",
        action="store_true",
        help="Disable plugin result caching",
    )
    args = parser.parse_args()

    # Validate API key
    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("[ERROR] ANTHROPIC_API_KEY not set.")
        print("Get your key at https://console.anthropic.com/ and run:")
        print("  export ANTHROPIC_API_KEY=sk-ant-...")
        sys.exit(1)

    # Validate dump path
    if not args.dump:
        print("[ERROR] No memory dump specified.")
        print("Use --dump /path/to/memory.dmp or set VOL_DUMP env var.")
        sys.exit(1)

    if not Path(args.dump).exists():
        print(f"[ERROR] Dump file not found: {args.dump}")
        sys.exit(1)

    # Build runner and agent
    runner = VolatilityRunner(args.dump)
    executor, memory = build_agent(
        runner,
        model=args.model,
        streaming=not args.no_stream,
    )

    # Dispatch mode
    if args.query:
        # Single query mode
        print(f"\n[query] {args.query}\n")
        result = executor.invoke({"input": args.query})
        if not args.no_stream:
            # Already streamed above
            pass
        else:
            print(result.get("output", ""))

    elif args.batch:
        # Batch mode
        run_batch(executor, args.batch, output_file=args.out)

    else:
        # Interactive REPL
        run_repl(executor, runner, memory)


if __name__ == "__main__":
    main()