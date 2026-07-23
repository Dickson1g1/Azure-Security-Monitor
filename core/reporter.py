"""
core/reporter.py
================
Output formatters for processed Azure Security Center alerts.
Three formats: CLI (colorized), JSON (SIEM-ready), HTML (dashboard), CSV (Excel).
"""

import csv
import json
import os
from datetime import datetime, timezone

# ANSI
RESET = "\033[0m"; BOLD = "\033[1m"; DIM = "\033[2m"
RED   = "\033[91m"; YELLOW = "\033[93m"; GREEN = "\033[92m"
CYAN  = "\033[96m"; BLUE = "\033[94m"; GRAY = "\033[90m"
WHITE = "\033[97m"; MAGENTA = "\033[95m"

SEV_COLORS = {"High": RED + BOLD, "Medium": YELLOW, "Low": GREEN, "Informational": GRAY}


# ─────────────────────────────────────────────────────────────
# CLI Report
# ─────────────────────────────────────────────────────────────

def print_report(alerts: list, summary: dict) -> None:
    w = 68
    def line(c="─"): print(c * w)
    def hdr(t): print(f"\n{BOLD}{t}{RESET}"); line()

    print()
    print(f"{BOLD}╔{'═'*(w-2)}╗{RESET}")
    print(f"{BOLD}║{'  AZURE DEFENDER FOR CLOUD — ALERT MONITOR':^{w-2}}║{RESET}")
    print(f"{BOLD}╚{'═'*(w-2)}╝{RESET}")
    print()
    print(f"  {BOLD}Generated  :{RESET} {datetime.now().strftime('%Y-%m-%d %H:%M UTC')}")
    print(f"  {BOLD}Total alerts:{RESET} {summary['total']}")
    print(f"  {RED + BOLD}High       :{RESET} {summary['high']}")
    print(f"  {YELLOW}Medium     :{RESET} {summary['medium']}")
    print(f"  {GREEN}Low        :{RESET} {summary['low']}")
    print(f"  {RED}Critical path:{RESET} {summary['critical_path']} (immediate action required)")

    if not alerts:
        print(f"\n  {GREEN}No alerts found matching your filters.{RESET}\n")
        return

    hdr("ALERTS BY PRIORITY")

    for a in alerts:
        sc  = SEV_COLORS.get(a.severity, RESET)
        crit_tag = f" {RED}⚠ CRITICAL PATH{RESET}" if a.is_critical_path else ""
        age_str  = f"{a.age_hours}h ago"

        print(f"\n  [{a.priority_rank:>2}] {sc}{a.severity.upper():<8}{RESET}  {BOLD}{a.display_name}{RESET}{crit_tag}")
        print(f"       Entity   : {a.compromised_entity or 'N/A'}")
        print(f"       MITRE    : {CYAN}{a.mitre_technique}{RESET}  {a.mitre_name}  ({a.mitre_tactic})")
        print(f"       Age      : {age_str}  |  Resource group: {a.resource_group or 'N/A'}")

        if a.ioc_ips:
            print(f"       IPs      : {RED}{', '.join(a.ioc_ips[:3])}{RESET}")
        if a.ioc_accounts:
            print(f"       Accounts : {YELLOW}{', '.join(a.ioc_accounts[:3])}{RESET}")

        # Top 2 recommended actions
        for action in a.recommended_actions[:2]:
            print(f"       {GREEN}→{RESET} {action}")

        if a.alert_uri:
            print(f"       {BLUE}{a.alert_uri}{RESET}")

    hdr("AFFECTED ASSETS")
    if summary['affected_hosts']:
        print(f"  Hosts : {', '.join(summary['affected_hosts'])}")
    if summary['unique_ips']:
        print(f"  IPs   : {RED}{', '.join(summary['unique_ips'][:10])}{RESET}")
    if summary['tactics']:
        print(f"  Tactics covered: {', '.join(summary['tactics'])}")

    print()
    line("═")
    print()


# ─────────────────────────────────────────────────────────────
# JSON Report
# ─────────────────────────────────────────────────────────────

def build_json_report(alerts: list, summary: dict, subscription_id: str = "") -> dict:
    return {
        "report_type":     "azure_security_center_alerts",
        "generated_at":    datetime.now(timezone.utc).isoformat(),
        "subscription_id": subscription_id,
        "summary":         summary,
        "alerts": [
            {
                "priority_rank":      a.priority_rank,
                "id":                 a.id,
                "name":               a.name,
                "display_name":       a.display_name,
                "description":        a.description,
                "severity":           a.severity,
                "severity_score":     a.severity_score,
                "status":             a.status,
                "alert_type":         a.alert_type,
                "start_time":         a.start_time,
                "age_hours":          a.age_hours,
                "compromised_entity": a.compromised_entity,
                "resource_group":     a.resource_group,
                "is_critical_path":   a.is_critical_path,
                "mitre": {
                    "technique":  a.mitre_technique,
                    "name":       a.mitre_name,
                    "tactic":     a.mitre_tactic,
                    "url":        a.mitre_url,
                },
                "iocs": {
                    "ips":      a.ioc_ips,
                    "hosts":    a.ioc_hosts,
                    "accounts": a.ioc_accounts,
                },
                "recommended_actions": a.recommended_actions,
                "remediation_steps":   a.remediation_steps,
                "alert_uri":           a.alert_uri,
                "extended_properties": a.extended_properties,
            }
            for a in alerts
        ]
    }


def save_json(report: dict, output_dir: str) -> str:
    os.makedirs(output_dir, exist_ok=True)
    ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(output_dir, f"azure_alerts_{ts}.json")
    with open(path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    return path


# ─────────────────────────────────────────────────────────────
# CSV Report
# ─────────────────────────────────────────────────────────────

def save_csv(alerts: list, output_dir: str) -> str:
    os.makedirs(output_dir, exist_ok=True)
    ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(output_dir, f"azure_alerts_{ts}.csv")

    fieldnames = [
        "priority_rank", "severity", "display_name", "compromised_entity",
        "resource_group", "mitre_technique", "mitre_name", "mitre_tactic",
        "is_critical_path", "age_hours", "ioc_ips", "ioc_accounts",
        "status", "alert_type", "start_time", "alert_uri"
    ]

    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for a in alerts:
            writer.writerow({
                "priority_rank":      a.priority_rank,
                "severity":           a.severity,
                "display_name":       a.display_name,
                "compromised_entity": a.compromised_entity,
                "resource_group":     a.resource_group,
                "mitre_technique":    a.mitre_technique,
                "mitre_name":         a.mitre_name,
                "mitre_tactic":       a.mitre_tactic,
                "is_critical_path":   a.is_critical_path,
                "age_hours":          a.age_hours,
                "ioc_ips":            ", ".join(a.ioc_ips),
                "ioc_accounts":       ", ".join(a.ioc_accounts),
                "status":             a.status,
                "alert_type":         a.alert_type,
                "start_time":         a.start_time,
                "alert_uri":          a.alert_uri,
            })
    return path


# ─────────────────────────────────────────────────────────────
# HTML Report
# ─────────────────────────────────────────────────────────────

def build_html_report(alerts: list, summary: dict, subscription_id: str = "") -> str:
    ts = datetime.now().strftime("%Y-%m-%d %H:%M UTC")

    SEV_BADGE = {
        "High":          ("dc4e41", "fff"),
        "Medium":        ("f1813f", "fff"),
        "Low":           ("3fb950", "fff"),
        "Informational": ("8b949e", "fff"),
    }

    TACTIC_COLORS = {
        "Credential Access":    "#e67e22",
        "Lateral Movement":     "#e74c3c",
        "Impact":               "#922b21",
        "Execution":            "#f39c12",
        "Discovery":            "#1abc9c",
        "Defense Evasion":      "#3498db",
        "Persistence":          "#9b59b6",
        "Initial Access":       "#dc4e41",
        "Command and Control":  "#2980b9",
        "Exfiltration":         "#c0392b",
    }

    def sev_badge(sev):
        bg, fg = SEV_BADGE.get(sev, ("888", "fff"))
        return f'<span style="background:#{bg};color:#{fg};padding:2px 10px;border-radius:20px;font-size:.75rem;font-weight:600">{sev}</span>'

    def tactic_badge(tactic):
        color = TACTIC_COLORS.get(tactic, "#555")
        return f'<span style="background:{color}22;color:{color};border:1px solid {color}44;padding:2px 8px;border-radius:4px;font-size:.72rem">{tactic}</span>'

    alert_cards = ""
    for a in alerts:
        crit_banner = '<div style="background:#dc4e4122;border-left:3px solid #dc4e41;padding:6px 12px;margin-bottom:10px;font-size:.8rem;color:#dc4e41;font-weight:600">⚠ CRITICAL PATH — Immediate action required</div>' if a.is_critical_path else ""

        actions_html = "".join(f'<li style="margin-bottom:4px">{act}</li>' for act in a.recommended_actions[:4])
        steps_html   = "".join(f'<li style="margin-bottom:4px">{s}</li>' for s in a.remediation_steps[:4])
        ioc_html     = ""
        if a.ioc_ips:      ioc_html += f'<div><span style="color:#8b949e;font-size:.75rem">IPs:</span> <code style="color:#f85149">{", ".join(a.ioc_ips)}</code></div>'
        if a.ioc_hosts:    ioc_html += f'<div><span style="color:#8b949e;font-size:.75rem">Hosts:</span> <code style="color:#79c0ff">{", ".join(a.ioc_hosts)}</code></div>'
        if a.ioc_accounts: ioc_html += f'<div><span style="color:#8b949e;font-size:.75rem">Accounts:</span> <code style="color:#f0883e">{", ".join(a.ioc_accounts)}</code></div>'

        ext_rows = "".join(
            f'<tr><td style="color:#8b949e;padding:2px 8px 2px 0;font-size:.75rem">{k}</td><td style="font-size:.75rem;word-break:break-all">{v}</td></tr>'
            for k, v in list(a.extended_properties.items())[:6]
        )

        alert_cards += f"""
<div style="background:#161b22;border:1px solid {'#dc4e41' if a.is_critical_path else '#30363d'};border-radius:10px;padding:1.25rem;margin-bottom:1rem">
  {crit_banner}
  <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:1rem;margin-bottom:.75rem;flex-wrap:wrap">
    <div>
      <span style="color:#8b949e;font-size:.8rem">#{a.priority_rank}</span>
      <span style="font-weight:600;font-size:1rem;color:#e8eaf0;margin-left:.5rem">{a.display_name}</span>
    </div>
    <div style="display:flex;gap:.5rem;flex-wrap:wrap">
      {sev_badge(a.severity)}
      {tactic_badge(a.mitre_tactic)}
    </div>
  </div>
  <p style="font-size:.875rem;color:#8b949e;margin-bottom:.75rem">{a.description}</p>
  <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:.5rem;font-size:.8rem;margin-bottom:.75rem">
    <div><span style="color:#8b949e">Entity:</span> {a.compromised_entity or "N/A"}</div>
    <div><span style="color:#8b949e">Resource group:</span> {a.resource_group or "N/A"}</div>
    <div><span style="color:#8b949e">Age:</span> {a.age_hours}h ago</div>
    <div><span style="color:#8b949e">MITRE:</span> <a href="{a.mitre_url}" target="_blank" style="color:#58a6ff">{a.mitre_technique}</a> {a.mitre_name}</div>
  </div>
  {f'<div style="margin-bottom:.75rem">{ioc_html}</div>' if ioc_html else ""}
  <div style="display:grid;grid-template-columns:1fr 1fr;gap:1rem;background:#0d1117;border-radius:6px;padding:1rem;margin-bottom:.75rem">
    <div>
      <div style="font-size:.75rem;text-transform:uppercase;letter-spacing:.05em;color:#8b949e;margin-bottom:.4rem">Recommended Actions</div>
      <ul style="padding-left:1.2rem;font-size:.8rem;color:#cdd9e5;margin:0">{actions_html}</ul>
    </div>
    <div>
      <div style="font-size:.75rem;text-transform:uppercase;letter-spacing:.05em;color:#8b949e;margin-bottom:.4rem">Azure Remediation Steps</div>
      <ul style="padding-left:1.2rem;font-size:.8rem;color:#cdd9e5;margin:0">{steps_html}</ul>
    </div>
  </div>
  {f'<details><summary style="font-size:.75rem;color:#8b949e;cursor:pointer">Extended properties</summary><table style="margin-top:.5rem">{ext_rows}</table></details>' if ext_rows else ""}
  {f'<a href="{a.alert_uri}" target="_blank" style="font-size:.8rem;color:#58a6ff">View in Azure Portal →</a>' if a.alert_uri else ""}
</div>"""

    tactics_list = "".join(f'<span style="background:#21262d;padding:3px 10px;border-radius:20px;font-size:.75rem;margin:.2rem;display:inline-block">{t}</span>' for t in summary.get("tactics", []))
    hosts_list   = "".join(f'<code style="background:#21262d;padding:2px 8px;border-radius:4px;font-size:.75rem;margin:.2rem;display:inline-block;color:#79c0ff">{h}</code>' for h in summary.get("affected_hosts", []))
    ips_list     = "".join(f'<code style="background:#21262d;padding:2px 8px;border-radius:4px;font-size:.75rem;margin:.2rem;display:inline-block;color:#f85149">{ip}</code>' for ip in summary.get("unique_ips", []))

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Azure Security Center Alert Monitor</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0f1117;color:#e8eaf0;line-height:1.6;padding-bottom:3rem}}
  a{{color:#58a6ff}} code{{font-family:monospace}}
  details summary{{list-style:none}} details summary::-webkit-details-marker{{display:none}}
</style>
</head>
<body>

<div style="background:linear-gradient(135deg,#1a1f2e,#0d1117);border-bottom:1px solid #30363d;padding:1.5rem 2.5rem">
  <div style="display:flex;align-items:center;gap:1rem;margin-bottom:.5rem">
    <svg width="28" height="28" viewBox="0 0 18 18" fill="none"><path d="M9 1L1 5v8l8 4 8-4V5L9 1z" fill="#0078D4" opacity=".9"/></svg>
    <h1 style="font-size:1.3rem;font-weight:600">Azure Defender for Cloud — Alert Monitor</h1>
  </div>
  <div style="font-size:.85rem;color:#8b949e">
    Subscription: {subscription_id or "Demo"} &nbsp;·&nbsp; Generated: {ts} &nbsp;·&nbsp;
    Built by Dickson Boakye &nbsp;·&nbsp;
    <a href="https://portal.azure.com/#blade/Microsoft_Azure_Security" target="_blank">Open Defender for Cloud →</a>
  </div>
</div>

<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:1rem;padding:1.5rem 2.5rem;background:#0d1117;border-bottom:1px solid #21262d">
  <div style="background:#161b22;border:1px solid #30363d;border-radius:8px;padding:1rem;text-align:center">
    <div style="font-size:1.8rem;font-weight:600">{summary['total']}</div>
    <div style="font-size:.75rem;color:#8b949e;text-transform:uppercase;letter-spacing:.05em;margin-top:.2rem">Total Alerts</div>
  </div>
  <div style="background:#161b22;border:1px solid #30363d;border-radius:8px;padding:1rem;text-align:center">
    <div style="font-size:1.8rem;font-weight:600;color:#dc4e41">{summary['high']}</div>
    <div style="font-size:.75rem;color:#8b949e;text-transform:uppercase;letter-spacing:.05em;margin-top:.2rem">High Severity</div>
  </div>
  <div style="background:#161b22;border:1px solid #30363d;border-radius:8px;padding:1rem;text-align:center">
    <div style="font-size:1.8rem;font-weight:600;color:#f1813f">{summary['medium']}</div>
    <div style="font-size:.75rem;color:#8b949e;text-transform:uppercase;letter-spacing:.05em;margin-top:.2rem">Medium Severity</div>
  </div>
  <div style="background:#161b22;border:1px solid #30363d;border-radius:8px;padding:1rem;text-align:center">
    <div style="font-size:1.8rem;font-weight:600;color:#3fb950">{summary['low']}</div>
    <div style="font-size:.75rem;color:#8b949e;text-transform:uppercase;letter-spacing:.05em;margin-top:.2rem">Low Severity</div>
  </div>
  <div style="background:#161b22;border:1px solid #dc4e4144;border-radius:8px;padding:1rem;text-align:center">
    <div style="font-size:1.8rem;font-weight:600;color:#dc4e41">{summary['critical_path']}</div>
    <div style="font-size:.75rem;color:#8b949e;text-transform:uppercase;letter-spacing:.05em;margin-top:.2rem">Critical Path</div>
  </div>
</div>

<div style="padding:1.5rem 2.5rem">
  <div style="background:#161b22;border:1px solid #30363d;border-radius:8px;padding:1rem;margin-bottom:1.5rem">
    <div style="font-size:.75rem;text-transform:uppercase;letter-spacing:.05em;color:#8b949e;margin-bottom:.5rem">Tactics Covered</div>
    {tactics_list}
    {f'<div style="margin-top:.75rem"><div style="font-size:.75rem;text-transform:uppercase;letter-spacing:.05em;color:#8b949e;margin-bottom:.4rem">Affected Hosts</div>{hosts_list}</div>' if hosts_list else ""}
    {f'<div style="margin-top:.75rem"><div style="font-size:.75rem;text-transform:uppercase;letter-spacing:.05em;color:#8b949e;margin-bottom:.4rem">IOC IPs</div>{ips_list}</div>' if ips_list else ""}
  </div>

  <h2 style="font-size:1rem;font-weight:600;margin-bottom:1rem">Alerts — Prioritized</h2>
  {alert_cards}
</div>

<div style="text-align:center;font-size:.8rem;color:#8b949e;padding-top:2rem;border-top:1px solid #21262d;margin:0 2.5rem">
  Microsoft Azure Defender for Cloud &nbsp;·&nbsp; github.com/Dickson1g1/azure-security-monitor
</div>
</body>
</html>"""


def save_html(html: str, output_dir: str) -> str:
    os.makedirs(output_dir, exist_ok=True)
    ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(output_dir, f"azure_alerts_{ts}.html")
    with open(path, "w") as f:
        f.write(html)
    return path
