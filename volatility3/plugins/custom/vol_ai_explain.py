"""
vol_ai_explain.py — AI-powered explainer plugin for Volatility 3
=================================================================
Place this file at:  volatility3/plugins/custom/vol_ai_explain.py

Requires:
    pip install anthropic>=0.25.0

Environment variables:
    ANTHROPIC_API_KEY   Your Anthropic API key (required)
    VOL_AI_MODEL        Model to use (default: claude-opus-4-8)
    VOL_AI_MAX_TOKENS   Max tokens per LLM response (default: 2048)

Usage as Volatility plugin:
    python3 vol.py -f memory.dmp custom.VolAiExplain
    python3 vol.py -f memory.dmp custom.VolAiExplain --suspicious-only
    python3 vol.py -f memory.dmp custom.VolAiExplain --output json > report.json
    python3 vol.py -f memory.dmp custom.VolAiExplain --plugins pslist,malfind,netstat

Usage standalone (no Volatility, feed JSON from attck_tagger.py):
    python3 vol_ai_explain.py tagged_report.json
    python3 vol_ai_explain.py tagged_report.json --format markdown
    python3 vol_ai_explain.py tagged_report.json --format html

What it does:
    1. Runs ATT&CK tagger across pslist/psscan, malfind, netstat, hashdump
    2. Groups findings by severity (CRITICAL → HIGH → MEDIUM → LOW)
    3. Sends each severity group to Claude with forensic analyst system prompt
    4. Streams explanations back in real time
    5. Produces a structured JSON report with AI narratives per finding
    6. Optionally renders as Markdown or HTML for the blog / incident report
"""

from __future__ import annotations

import json
import os
import sys
import textwrap
from datetime import datetime, timezone
from typing import Any, Iterator, Optional

from dotenv import load_dotenv
load_dotenv()   # loads .env file automatically

def load_json_any_encoding(path: str) -> Any:
    """Load JSON regardless of byte-order mark / encoding.

    Files produced on Windows are commonly saved as UTF-8-BOM (e.g. some
    editors) or UTF-16 LE (PowerShell `>` redirection / Out-File). The stdlib
    ``json`` module chokes on a leading BOM, so detect it from the raw bytes
    and decode accordingly, falling back to plain UTF-8.
    """
    with open(path, "rb") as fh:
        raw = fh.read()

    if raw.startswith(b"\xef\xbb\xbf"):
        text = raw.decode("utf-8-sig")
    elif raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        text = raw.decode("utf-16")
    else:
        text = raw.decode("utf-8")

    # Tolerate trailing non-JSON text: attck_tagger.py prints a human-readable
    # summary after the JSON, which pollutes the file when output is redirected
    # with `>`. Parse only the leading JSON value and ignore the rest.
    obj, _end = json.JSONDecoder().raw_decode(text.lstrip())
    return obj


# ── Anthropic client ──────────────────────────────────────────────────────────
try:
    import anthropic
except ImportError:
    print("[ERROR] anthropic package not found. Run: pip install anthropic>=0.25.0")
    sys.exit(1)

# ── Volatility 3 imports (only needed when running as a plugin) ───────────────
try:
    from volatility3.framework import renderers, interfaces
    from volatility3.framework.configuration import requirements
    from volatility3.plugins.windows import pslist, psscan, malfind, netstat, hashdump
    _VOL3_AVAILABLE = True
except ImportError:
    _VOL3_AVAILABLE = False

# ── ATT&CK tagger (sibling module) ───────────────────────────────────────────
try:
    from volatility3.plugins.custom.attck_tagger import (
        TaggedFinding, tag_process, tag_malfind_hit,
        tag_netstat_row, tag_hashdump_row, tag_findings, build_report,
    )
    _TAGGER_AVAILABLE = True
except ImportError:
    _TAGGER_AVAILABLE = False
    # Standalone mode: user must pass pre-tagged JSON


# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────

DEFAULT_MODEL      = os.environ.get("VOL_AI_MODEL",      "claude-opus-4-8")
DEFAULT_MAX_TOKENS = int(os.environ.get("VOL_AI_MAX_TOKENS", "2048"))

# Risk levels in priority order
RISK_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

# ─────────────────────────────────────────────────────────────────────────────
# SYSTEM PROMPTS
# ─────────────────────────────────────────────────────────────────────────────

SYSTEM_PROMPT_ANALYST = """\
You are a senior digital forensics and incident response (DFIR) analyst with 15 years \
of experience. You are reviewing structured memory forensics data produced by Volatility 3 \
and enriched with MITRE ATT&CK TTP tags.

Your job is to explain each finding clearly so a junior analyst can understand:
  1. What the finding means technically
  2. Why it is suspicious (or not)
  3. What the attacker is likely trying to do (map to a real-world attack scenario)
  4. What the analyst should do next (concrete, actionable next step)
  5. Which MITRE ATT&CK technique it maps to and why

Formatting rules:
  - Start each finding with: CRITICAL / HIGH / MEDIUM / LOW (in caps)
  - Use plain English — no jargon without explanation
  - Be specific — reference the actual PID, process name, port, or hash from the data
  - Keep each finding explanation to 4–6 sentences max
  - End every finding with: "→ Next step: [specific action]"
  - If multiple findings are related (e.g. same PID appears in pslist AND malfind), \
    connect them explicitly
"""

SYSTEM_PROMPT_EXECUTIVE = """\
You are a cybersecurity expert writing for a non-technical executive audience. \
You are reviewing a memory forensics investigation report and must explain the \
key findings in plain business language.

Rules:
  - No technical jargon. If you must use a term, define it immediately.
  - Focus on business impact: what data was at risk, what systems were affected
  - Explain attacker intent in plain English ("the attacker was trying to steal passwords")
  - Keep the entire summary to 3 short paragraphs
  - End with 3 bullet points: immediate actions required
"""

SYSTEM_PROMPT_REPORT = """\
You are writing a section of a formal digital forensics incident report. \
You have been given structured memory forensics findings and must write the \
Technical Findings section in professional report language.

Format each finding as:
  Finding [N]: [Short title]
  Risk: [CRITICAL/HIGH/MEDIUM/LOW]
  Evidence: [What Volatility found, cited specifically]
  Analysis: [What it means, 2–3 sentences]
  ATT&CK Mapping: [T-number] — [Technique name] ([Tactic])
  Recommended Action: [Specific remediation step]

Use formal language. Cite evidence items. Be precise with timestamps and identifiers.
"""


# ─────────────────────────────────────────────────────────────────────────────
# AI CLIENT WRAPPER
# ─────────────────────────────────────────────────────────────────────────────

class AIExplainer:
    """
    Wraps the Anthropic client with retry logic, streaming support,
    and multiple output modes (analyst / executive / report).
    """

    def __init__(
        self,
        model:      str = DEFAULT_MODEL,
        max_tokens: int = DEFAULT_MAX_TOKENS,
        stream:     bool = True,
    ):
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            raise EnvironmentError(
                "ANTHROPIC_API_KEY environment variable not set.\n"
                "Get your key at https://console.anthropic.com/ and run:\n"
                "  export ANTHROPIC_API_KEY=sk-ant-..."
            )
        self.client     = anthropic.Anthropic(api_key=api_key)
        self.model      = model
        self.max_tokens = max_tokens
        self.stream     = stream

    def explain(
        self,
        findings_json: str,
        mode: str = "analyst",   # "analyst" | "executive" | "report"
        extra_context: str = "",
    ) -> str:
        """
        Send findings to Claude and return the explanation as a string.
        Streams tokens to stdout in real time if self.stream is True.
        """
        system_map = {
            "analyst":   SYSTEM_PROMPT_ANALYST,
            "executive": SYSTEM_PROMPT_EXECUTIVE,
            "report":    SYSTEM_PROMPT_REPORT,
        }
        system = system_map.get(mode, SYSTEM_PROMPT_ANALYST)

        user_content = f"Analyze these memory forensics findings:\n\n{findings_json}"
        if extra_context:
            user_content += f"\n\nAdditional context: {extra_context}"

        if self.stream:
            return self._stream_response(system, user_content)
        else:
            return self._blocking_response(system, user_content)

    def _stream_response(self, system: str, user_content: str) -> str:
        """Stream tokens to stdout, return full text when complete."""
        full_text = ""
        with self.client.messages.stream(
            model      = self.model,
            max_tokens = self.max_tokens,
            system     = system,
            messages   = [{"role": "user", "content": user_content}],
        ) as stream:
            for text in stream.text_stream:
                print(text, end="", flush=True)
                full_text += text
        print()  # newline after stream ends
        return full_text

    def _blocking_response(self, system: str, user_content: str) -> str:
        """Non-streaming call — returns full text at once."""
        response = self.client.messages.create(
            model      = self.model,
            max_tokens = self.max_tokens,
            system     = system,
            messages   = [{"role": "user", "content": user_content}],
        )
        return response.content[0].text

    def explain_single(self, finding: dict, mode: str = "analyst") -> str:
        """Explain a single tagged finding dict."""
        return self.explain(json.dumps(finding, indent=2), mode=mode)

    def explain_batch(
        self,
        findings: list[dict],
        mode:     str = "analyst",
        batch_size: int = 10,
    ) -> list[dict]:
        """
        Explain findings in batches to stay within context limits.
        Returns list of dicts with 'finding' and 'explanation' keys.
        """
        results = []
        for i in range(0, len(findings), batch_size):
            batch = findings[i : i + batch_size]
            batch_json = json.dumps(batch, indent=2)
            explanation = self.explain(batch_json, mode=mode)
            for finding in batch:
                results.append({
                    "finding":     finding,
                    "explanation": explanation,
                })
        return results

    def summarize_investigation(
        self,
        full_report: dict,
        mode: str = "executive",
    ) -> str:
        """
        Given the full build_report() output, produce a high-level summary.
        """
        summary_payload = {
            "stats":             full_report.get("summary", {}),
            "critical_findings": full_report.get("critical_findings", [])[:5],
            "high_findings":     full_report.get("high_findings", [])[:5],
        }
        return self.explain(
            json.dumps(summary_payload, indent=2),
            mode=mode,
            extra_context="Focus on the highest-risk findings. Be concise.",
        )


# ─────────────────────────────────────────────────────────────────────────────
# REPORT RENDERER
# ─────────────────────────────────────────────────────────────────────────────

class ReportRenderer:
    """
    Renders the enriched report (TaggedFindings + AI explanations)
    into different output formats.
    """

    RISK_EMOJI = {
        "CRITICAL": "🔴",
        "HIGH":     "🟠",
        "MEDIUM":   "🟡",
        "LOW":      "🟢",
    }

    def to_json(self, report: dict, explanations: dict) -> str:
        """Full JSON report with findings + AI explanations merged."""
        output = {
            "meta": {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "model":        DEFAULT_MODEL,
                "tool":         "vol_ai_explain.py",
            },
            "summary":          report.get("summary", {}),
            "ai_summary":       explanations.get("executive_summary", ""),
            "analyst_report":   explanations.get("analyst_report", ""),
            "findings_by_risk": {},
        }
        for level in RISK_ORDER:
            key = f"{level.lower()}_findings"
            findings = report.get(key, [])
            output["findings_by_risk"][level] = {
                "count":    len(findings),
                "findings": findings,
            }
        return json.dumps(output, indent=2)

    def to_markdown(self, report: dict, explanations: dict) -> str:
        """
        Render as Markdown — ready to paste into your blog or GitHub README.
        """
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        s   = report.get("summary", {})
        lines = [
            f"# Memory Forensics Investigation Report",
            f"",
            f"**Generated:** {now}  ",
            f"**Tool:** vol_ai_explain.py (Volatility 3 + Claude AI)  ",
            f"",
            f"---",
            f"",
            f"## Executive Summary",
            f"",
            explanations.get("executive_summary", "_No summary generated._"),
            f"",
            f"---",
            f"",
            f"## Statistics",
            f"",
            f"| Severity | Count |",
            f"|----------|-------|",
            f"| 🔴 Critical | {s.get('critical', 0)} |",
            f"| 🟠 High     | {s.get('high', 0)} |",
            f"| 🟡 Medium   | {s.get('medium', 0)} |",
            f"| 🟢 Low      | {s.get('low', 0)} |",
            f"| **Total**  | **{s.get('total_findings', 0)}** |",
            f"",
            f"**Unique ATT&CK TTPs detected:** "
            f"`{'`, `'.join(s.get('unique_ttps', []))}`",
            f"",
            f"---",
            f"",
            f"## Analyst Findings",
            f"",
            explanations.get("analyst_report", "_No analyst report generated._"),
            f"",
            f"---",
            f"",
            f"## Raw Findings",
            f"",
        ]

        for level in RISK_ORDER:
            key      = f"{level.lower()}_findings"
            findings = report.get(key, [])
            if not findings:
                continue
            emoji = self.RISK_EMOJI.get(level, "")
            lines.append(f"### {emoji} {level} ({len(findings)} findings)")
            lines.append("")
            for f in findings:
                ttp_ids = ", ".join(
                    t["id"] for t in f.get("ttps", [])
                ) or "—"
                lines += [
                    f"**{f.get('summary', 'Unknown finding')}**  ",
                    f"Plugin: `{f.get('source_plugin', '?')}` | "
                    f"Score: `{f.get('risk_score', 0)}` | "
                    f"TTPs: `{ttp_ids}`  ",
                    f"",
                ]

        lines += [
            f"---",
            f"",
            f"*Generated by [vol_ai_explain.py]"
            f"(https://github.com/YOUR_USERNAME/volatility3) — "
            f"a Volatility 3 fork with AI-powered analysis.*",
        ]
        return "\n".join(lines)

    def to_html(self, report: dict, explanations: dict) -> str:
        """
        Render as a self-contained HTML file — ready for your blog.
        """
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        s   = report.get("summary", {})

        risk_colors = {
            "CRITICAL": "#E24B4A",
            "HIGH":     "#EF9F27",
            "MEDIUM":   "#639922",
            "LOW":      "#1D9E75",
        }

        finding_rows = []
        for level in RISK_ORDER:
            key      = f"{level.lower()}_findings"
            findings = report.get(key, [])
            color    = risk_colors.get(level, "#888")
            for f in findings:
                ttp_ids = " | ".join(
                    t["id"] for t in f.get("ttps", [])
                ) or "—"
                row = f"""
                <tr>
                  <td><span style="color:{color};font-weight:600">{level}</span></td>
                  <td><code>{f.get('source_plugin','?')}</code></td>
                  <td>{f.get('summary','').replace('<','&lt;')}</td>
                  <td><code>{ttp_ids}</code></td>
                  <td style="text-align:center">{f.get('risk_score',0)}</td>
                </tr>"""
                finding_rows.append(row)

        exec_summary_html = (
            explanations.get("executive_summary", "")
            .replace("\n\n", "</p><p>")
            .replace("\n", "<br>")
        )
        analyst_html = (
            explanations.get("analyst_report", "")
            .replace("\n\n", "</p><p>")
            .replace("\n", "<br>")
            .replace("CRITICAL", '<span style="color:#E24B4A;font-weight:600">CRITICAL</span>')
            .replace("HIGH",     '<span style="color:#EF9F27;font-weight:600">HIGH</span>')
            .replace("MEDIUM",   '<span style="color:#639922;font-weight:600">MEDIUM</span>')
            .replace("LOW",      '<span style="color:#1D9E75;font-weight:600">LOW</span>')
            .replace("→ Next step:", '<br><strong>→ Next step:</strong>')
        )

        unique_ttps = s.get("unique_ttps", [])
        ttp_badges  = " ".join(
            f'<span style="background:#E6F1FB;color:#0C447C;'
            f'padding:2px 6px;border-radius:4px;font-size:12px;'
            f'font-family:monospace">{t}</span>'
            for t in unique_ttps
        )

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Memory Forensics Report — {now}</title>
<style>
  body {{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
         max-width:960px;margin:40px auto;padding:0 20px;color:#1a1a2e;
         line-height:1.6}}
  h1   {{font-size:24px;border-bottom:2px solid #E94560;padding-bottom:8px}}
  h2   {{font-size:18px;margin-top:32px;color:#1a1a2e}}
  .meta {{color:#888;font-size:13px;margin-bottom:24px}}
  .stat-grid {{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:16px 0}}
  .stat-card {{background:#f5f5f5;border-radius:8px;padding:12px 16px;text-align:center}}
  .stat-card .num {{font-size:28px;font-weight:600}}
  .stat-card .label {{font-size:12px;color:#888;margin-top:2px}}
  .critical .num {{color:#E24B4A}} .high .num {{color:#EF9F27}}
  .medium .num   {{color:#639922}} .low .num  {{color:#1D9E75}}
  .summary-box {{background:#f9f9f9;border-left:4px solid #E94560;
                 padding:16px 20px;border-radius:0 8px 8px 0;margin:16px 0}}
  table  {{width:100%;border-collapse:collapse;font-size:13px;margin:16px 0}}
  th     {{background:#1a1a2e;color:#fff;padding:10px 12px;text-align:left}}
  td     {{padding:8px 12px;border-bottom:1px solid #eee}}
  tr:hover td {{background:#f5f5f5}}
  code   {{background:#eee;padding:1px 4px;border-radius:3px;font-size:12px}}
  .ttp-grid {{display:flex;flex-wrap:wrap;gap:6px;margin:8px 0}}
  footer {{margin-top:48px;padding-top:16px;border-top:1px solid #eee;
           color:#aaa;font-size:12px;text-align:center}}
</style>
</head>
<body>
<h1>Memory Forensics Investigation Report</h1>
<div class="meta">Generated: {now} &nbsp;|&nbsp; Tool: vol_ai_explain.py
  &nbsp;|&nbsp; Model: {DEFAULT_MODEL}</div>

<h2>Executive Summary</h2>
<div class="summary-box"><p>{exec_summary_html}</p></div>

<h2>Risk Overview</h2>
<div class="stat-grid">
  <div class="stat-card critical">
    <div class="num">{s.get('critical',0)}</div>
    <div class="label">CRITICAL</div>
  </div>
  <div class="stat-card high">
    <div class="num">{s.get('high',0)}</div>
    <div class="label">HIGH</div>
  </div>
  <div class="stat-card medium">
    <div class="num">{s.get('medium',0)}</div>
    <div class="label">MEDIUM</div>
  </div>
  <div class="stat-card low">
    <div class="num">{s.get('low',0)}</div>
    <div class="label">LOW</div>
  </div>
</div>

<h2>ATT&amp;CK Techniques Detected</h2>
<div class="ttp-grid">{ttp_badges if ttp_badges else "<em>None detected</em>"}</div>

<h2>Analyst Report</h2>
<div class="summary-box"><p>{analyst_html}</p></div>

<h2>All Findings</h2>
<table>
  <thead>
    <tr>
      <th>Risk</th><th>Plugin</th><th>Summary</th>
      <th>TTP IDs</th><th>Score</th>
    </tr>
  </thead>
  <tbody>
    {''.join(finding_rows) if finding_rows else
     '<tr><td colspan="5" style="text-align:center;color:#888">No findings</td></tr>'}
  </tbody>
</table>

<footer>
  Generated by vol_ai_explain.py —
  <a href="https://github.com/YOUR_USERNAME/volatility3">
    Volatility 3 fork with AI analysis
  </a>
</footer>
</body>
</html>"""


# ─────────────────────────────────────────────────────────────────────────────
# MAIN ORCHESTRATOR
# ─────────────────────────────────────────────────────────────────────────────

class VolAiExplainOrchestrator:
    """
    Ties everything together:
      1. Collect raw Volatility data
      2. Tag with ATT&CK (via attck_tagger)
      3. Build structured report
      4. Send to AI for explanation
      5. Render output
    """

    def __init__(
        self,
        model:          str  = DEFAULT_MODEL,
        max_tokens:     int  = DEFAULT_MAX_TOKENS,
        stream:         bool = True,
        suspicious_only: bool = False,
    ):
        self.ai               = AIExplainer(model, max_tokens, stream)
        self.renderer         = ReportRenderer()
        self.suspicious_only  = suspicious_only

    # ── Data collection helpers (called when running as Volatility plugin) ──

    def collect_from_volatility(
        self,
        context,
        primary_layer: str,
        nt_symbols:    str,
        plugins:       list[str] = None,
    ) -> list[dict]:
        """
        Run Volatility plugins and return list of raw finding dicts.
        plugins: list of plugin names to run. Defaults to all.
        """
        if not _VOL3_AVAILABLE:
            raise RuntimeError("Volatility 3 not installed.")

        enabled = set(plugins or ["pslist", "psscan", "malfind", "netstat", "hashdump"])
        raw_findings: list[dict] = []

        # ── pslist + psscan (process analysis) ───────────────────────────────
        if "pslist" in enabled or "psscan" in enabled:
            pslist_pids: set[int] = set()
            proc_dicts:  list[dict] = []

            if "pslist" in enabled:
                for proc in pslist.PsList.list_processes(
                    context, primary_layer, nt_symbols
                ):
                    pid = int(proc.UniqueProcessId)
                    pslist_pids.add(pid)
                    proc_dicts.append({
                        "pid":    pid,
                        "name":   proc.ImageFileName.cast(
                                    "string", max_length=15, errors="replace"),
                        "ppid":   int(proc.InheritedFromUniqueProcessId),
                        "cmdline": "",
                        "path":   "",
                        "hidden": False,
                        "has_network": False,
                        "_type": "process",
                    })

            if "psscan" in enabled:
                for proc in psscan.PsScan.scan_processes(
                    context, primary_layer, nt_symbols
                ):
                    pid = int(proc.UniqueProcessId)
                    if pid not in pslist_pids:
                        proc_dicts.append({
                            "pid":    pid,
                            "name":   proc.ImageFileName.cast(
                                        "string", max_length=15, errors="replace"),
                            "ppid":   int(proc.InheritedFromUniqueProcessId),
                            "cmdline": "",
                            "path":   "",
                            "hidden": True,   # DKOM-hidden
                            "has_network": False,
                            "_type": "process",
                        })

            raw_findings.extend(proc_dicts)

        # ── windows.cmdline (enrich process cmdlines) ─────────────────────────
        # (would require separate plugin call — left as extension point)

        # ── malfind ───────────────────────────────────────────────────────────
        if "malfind" in enabled:
            for hit in malfind.Malfind.scan_vads(
                context, primary_layer, nt_symbols
            ):
                raw_findings.append({
                    "pid":          int(hit.get("PID", 0)),
                    "process_name": str(hit.get("Process", "")),
                    "vad_start":    hex(int(hit.get("Start VPN", 0))),
                    "vad_end":      hex(int(hit.get("End VPN", 0))),
                    "protection":   str(hit.get("Protection", "")),
                    "tag":          str(hit.get("Tag", "")),
                    "hexdump":      str(hit.get("Hexdump", ""))[:64],
                    "_type":        "malfind",
                })

        # ── netstat ───────────────────────────────────────────────────────────
        if "netstat" in enabled:
            for conn in netstat.NetStat.list_sockets(
                context, primary_layer, nt_symbols
            ):
                raw_findings.append({
                    "pid":          int(conn.get("PID", 0)),
                    "owner":        str(conn.get("Owner", "")),
                    "proto":        str(conn.get("Proto", "")),
                    "local_addr":   str(conn.get("LocalAddr", "")),
                    "local_port":   int(conn.get("LocalPort", 0)),
                    "foreign_addr": str(conn.get("ForeignAddr", "")),
                    "foreign_port": int(conn.get("ForeignPort", 0)),
                    "state":        str(conn.get("State", "")),
                    "_type":        "netstat",
                })

        # ── hashdump ──────────────────────────────────────────────────────────
        if "hashdump" in enabled:
            for entry in hashdump.Hashdump.get_hashes(
                context, primary_layer, nt_symbols
            ):
                raw_findings.append({
                    "username": str(entry.get("User", "")),
                    "rid":      int(entry.get("rid", 0)),
                    "lmhash":   str(entry.get("lmhash", "")),
                    "nthash":   str(entry.get("nthash", "")),
                    "_type":    "hashdump",
                })

        return raw_findings

    def tag_all(self, raw_findings: list[dict]) -> list:
        """Route each raw finding to the correct tagger and return TaggedFindings."""
        if not _TAGGER_AVAILABLE:
            raise RuntimeError(
                "attck_tagger.py not found. "
                "Place it at volatility3/plugins/custom/attck_tagger.py"
            )
        tagged = []
        for f in raw_findings:
            ftype = f.get("_type", "process")
            if ftype == "process":
                tagged.append(tag_process(f))
            elif ftype == "malfind":
                tagged.append(tag_malfind_hit(f))
            elif ftype == "netstat":
                tagged.append(tag_netstat_row(f))
            elif ftype == "hashdump":
                tagged.append(tag_hashdump_row(f))
        return tagged

    def run_full_analysis(
        self,
        tagged_findings: list,
        output_format:   str = "json",   # "json" | "markdown" | "html"
        context_note:    str = "",
    ) -> str:
        """
        Main entry point: takes tagged findings, runs AI analysis,
        returns formatted report string.
        """
        # Build structured report from ATT&CK tagger output
        report = build_report(tagged_findings)
        stats  = report["summary"]

        # Filter to suspicious only if requested
        if self.suspicious_only:
            all_tagged = (
                report["critical_findings"] +
                report["high_findings"] +
                report["medium_findings"]
            )
        else:
            all_tagged = (
                report["critical_findings"] +
                report["high_findings"] +
                report["medium_findings"] +
                report["low_findings"]
            )

        explanations: dict[str, str] = {}

        # ── 1. Executive summary ─────────────────────────────────────────────
        print("\n[vol_ai_explain] Generating executive summary...", flush=True)
        explanations["executive_summary"] = self.ai.summarize_investigation(
            report, mode="executive"
        )

        # ── 2. Analyst report (batch critical+high together, rest separate) ──
        print("\n[vol_ai_explain] Generating analyst findings report...", flush=True)
        priority_findings = (
            report["critical_findings"][:8] +
            report["high_findings"][:8]
        )

        if priority_findings:
            explanations["analyst_report"] = self.ai.explain(
                json.dumps(priority_findings, indent=2),
                mode="analyst",
                extra_context=context_note or (
                    f"Investigation stats: {stats['total_findings']} total findings, "
                    f"{stats['critical']} critical, {stats['high']} high. "
                    f"Unique TTPs: {', '.join(stats.get('unique_ttps', []))}"
                ),
            )
        else:
            explanations["analyst_report"] = (
                "No critical or high-severity findings detected in this memory dump."
            )

        # ── 3. Formal report section (for incident report writing) ────────────
        print("\n[vol_ai_explain] Generating formal report section...", flush=True)
        if priority_findings:
            explanations["formal_report_section"] = self.ai.explain(
                json.dumps(priority_findings[:5], indent=2),
                mode="report",
            )

        # ── 4. Render output ──────────────────────────────────────────────────
        if output_format == "markdown":
            return self.renderer.to_markdown(report, explanations)
        elif output_format == "html":
            return self.renderer.to_html(report, explanations)
        else:
            return self.renderer.to_json(report, explanations)


# ─────────────────────────────────────────────────────────────────────────────
# VOLATILITY 3 PLUGIN CLASS
# ─────────────────────────────────────────────────────────────────────────────

if _VOL3_AVAILABLE:

    class VolAiExplain(interfaces.plugins.PluginInterface):
        """
        Volatility 3 plugin: AI-powered memory forensics analyst.

        Runs pslist/psscan/malfind/netstat/hashdump, tags findings with
        MITRE ATT&CK TTPs, and sends results to Claude for plain-English
        explanation. Outputs a risk-sorted table with AI analysis.

        Examples:
            python3 vol.py -f memory.dmp custom.VolAiExplain
            python3 vol.py -f memory.dmp custom.VolAiExplain --suspicious-only
            python3 vol.py -f memory.dmp custom.VolAiExplain --output json > report.json
            python3 vol.py -f memory.dmp custom.VolAiExplain --format markdown > report.md
            python3 vol.py -f memory.dmp custom.VolAiExplain --format html > report.html
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
                    name="suspicious-only",
                    description="Only analyze CRITICAL and HIGH findings (faster)",
                    default=False,
                    optional=True,
                ),
                requirements.StringRequirement(
                    name="plugins",
                    description="Comma-separated plugins to run "
                                "(default: pslist,psscan,malfind,netstat,hashdump)",
                    default="pslist,psscan,malfind,netstat,hashdump",
                    optional=True,
                ),
                requirements.StringRequirement(
                    name="format",
                    description="Output format: json | markdown | html",
                    default="json",
                    optional=True,
                ),
                requirements.StringRequirement(
                    name="outfile",
                    description="Write report to this file path (optional)",
                    default="",
                    optional=True,
                ),
            ]

        def run(self):
            orchestrator = VolAiExplainOrchestrator(
                stream=True,
                suspicious_only=self.config.get("suspicious-only", False),
            )

            plugins_str = self.config.get(
                "plugins", "pslist,psscan,malfind,netstat,hashdump"
            )
            enabled_plugins = [p.strip() for p in plugins_str.split(",")]

            # Collect raw data from Volatility
            print(
                f"[vol_ai_explain] Running plugins: {', '.join(enabled_plugins)}",
                flush=True,
            )
            raw = orchestrator.collect_from_volatility(
                self.context,
                self.config["primary"],
                self.config["nt_symbols"],
                plugins=enabled_plugins,
            )
            print(
                f"[vol_ai_explain] Collected {len(raw)} raw findings. Tagging...",
                flush=True,
            )

            # Tag with ATT&CK
            tagged = orchestrator.tag_all(raw)
            print(
                f"[vol_ai_explain] Tagged {len(tagged)} findings. "
                f"Sending to AI...",
                flush=True,
            )

            # Run full analysis
            fmt    = self.config.get("format", "json")
            report = orchestrator.run_full_analysis(tagged, output_format=fmt)

            # Write to file if requested
            outfile = self.config.get("outfile", "")
            if outfile:
                with open(outfile, "w") as fh:
                    fh.write(report)
                print(f"\n[vol_ai_explain] Report saved to: {outfile}", flush=True)

            # Return findings table to Volatility renderer
            report_dict = json.loads(report) if fmt == "json" else {}
            return renderers.TreeGrid(
                [
                    ("Risk",    str),
                    ("Score",   int),
                    ("Plugin",  str),
                    ("TTPs",    str),
                    ("Summary", str),
                ],
                self._generator(tagged),
            )

        def _generator(self, tagged_findings):
            order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
            sorted_findings = sorted(
                tagged_findings,
                key=lambda f: (order.get(f.risk_level, 9), -f.risk_score),
            )
            for f in sorted_findings:
                ttp_ids = " | ".join(t.id for t in f.ttps) if f.ttps else "—"
                yield (0, (
                    f.risk_level,
                    f.risk_score,
                    f.source_plugin,
                    ttp_ids,
                    f.summary,
                ))


# ─────────────────────────────────────────────────────────────────────────────
# STANDALONE CLI
# ─────────────────────────────────────────────────────────────────────────────
#
# Run without Volatility — feed a pre-tagged JSON from attck_tagger.py:
#
#   python3 attck_tagger.py procs.json > tagged.json
#   python3 vol_ai_explain.py tagged.json
#   python3 vol_ai_explain.py tagged.json --format markdown > report.md
#   python3 vol_ai_explain.py tagged.json --format html > report.html

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="AI-powered Volatility findings explainer (standalone mode)"
    )
    parser.add_argument(
        "input_json",
        help="Path to tagged findings JSON (output of attck_tagger.py)",
    )
    parser.add_argument(
        "--format",
        choices=["json", "markdown", "html"],
        default="json",
        help="Output format (default: json)",
    )
    parser.add_argument(
        "--out",
        default="",
        help="Write output to this file (default: stdout)",
    )
    parser.add_argument(
        "--suspicious-only",
        action="store_true",
        help="Only explain CRITICAL and HIGH findings",
    )
    parser.add_argument(
        "--no-stream",
        action="store_true",
        help="Disable streaming (wait for full response before printing)",
    )
    parser.add_argument(
        "--model",
        default=DEFAULT_MODEL,
        help=f"Claude model to use (default: {DEFAULT_MODEL})",
    )
    args = parser.parse_args()

    # Load pre-tagged findings JSON (handles UTF-8, UTF-8-BOM, UTF-16)
    data = load_json_any_encoding(args.input_json)

    # Support both raw list-of-dicts and build_report() output
    if isinstance(data, dict) and "summary" in data:
        # Already a full report from build_report()
        print("[vol_ai_explain] Input is a full report dict.", flush=True)
        # Re-hydrate into a flat tagged list (simplified)
        all_findings_raw = (
            data.get("critical_findings", []) +
            data.get("high_findings", []) +
            data.get("medium_findings", []) +
            data.get("low_findings", [])
        )
    else:
        all_findings_raw = data if isinstance(data, list) else [data]

    # Create mock TaggedFinding objects from dicts for orchestrator
    from dataclasses import dataclass, field

    @dataclass
    class SimpleFinding:
        source_plugin: str
        raw: dict
        ttps: list
        risk_score: int
        risk_level: str
        summary: str

        def to_dict(self):
            return {
                "source_plugin": self.source_plugin,
                "raw": self.raw,
                "ttps": self.ttps,
                "risk_score": self.risk_score,
                "risk_level": self.risk_level,
                "summary": self.summary,
            }

    tagged = [
        SimpleFinding(
            source_plugin=f.get("source_plugin", "unknown"),
            raw=f.get("raw", f),
            ttps=f.get("ttps", []),
            risk_score=f.get("risk_score", 0),
            risk_level=f.get("risk_level", "LOW"),
            summary=f.get("summary", ""),
        )
        for f in all_findings_raw
    ]

    # Patch build_report to accept SimpleFinding objects
    def _simple_build_report(findings):
        """Minimal build_report for standalone mode."""
        critical = [f for f in findings if f.risk_level == "CRITICAL"]
        high     = [f for f in findings if f.risk_level == "HIGH"]
        medium   = [f for f in findings if f.risk_level == "MEDIUM"]
        low      = [f for f in findings if f.risk_level == "LOW"]
        all_ttp_ids = sorted({
            t["id"] for f in findings for t in f.ttps
        })
        tactic_cov: dict = {}
        for f in findings:
            for t in f.ttps:
                tactic_cov.setdefault(t["tactic"], [])
                if t["id"] not in tactic_cov[t["tactic"]]:
                    tactic_cov[t["tactic"]].append(t["id"])
        return {
            "summary": {
                "total_findings": len(findings),
                "critical": len(critical),
                "high": len(high),
                "medium": len(medium),
                "low": len(low),
                "unique_ttps": all_ttp_ids,
                "tactic_coverage": tactic_cov,
            },
            "critical_findings": [f.to_dict() for f in critical],
            "high_findings":     [f.to_dict() for f in high],
            "medium_findings":   [f.to_dict() for f in medium],
            "low_findings":      [f.to_dict() for f in low],
        }

    # Run orchestrator
    orchestrator = VolAiExplainOrchestrator(
        model=args.model,
        stream=not args.no_stream,
        suspicious_only=args.suspicious_only,
    )

    # Monkey-patch build_report for standalone mode.
    #
    # run_full_analysis() calls the bare name `build_report`, which it resolves
    # from the globals of the module where it was *defined* (this module) — not
    # from attck_tagger. The standalone path feeds in SimpleFinding objects whose
    # `ttps` are plain dicts, so we must swap in _simple_build_report in exactly
    # that namespace. Patching attck_tagger.build_report would have no effect.
    _target_globals = type(orchestrator).run_full_analysis.__globals__
    _orig_build_report = _target_globals.get("build_report")
    _target_globals["build_report"] = _simple_build_report

    try:
        # Direct call bypassing Volatility
        report_str = orchestrator.run_full_analysis(
            tagged,
            output_format=args.format,
        )
    finally:
        # Restore the original binding (or remove ours if there was none)
        if _orig_build_report is not None:
            _target_globals["build_report"] = _orig_build_report
        else:
            _target_globals.pop("build_report", None)

    # Output
    if args.out:
        with open(args.out, "w") as fh:
            fh.write(report_str)
        print(f"\n[vol_ai_explain] Report saved to: {args.out}", flush=True)
    else:
        print(report_str)