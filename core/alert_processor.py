"""
core/alert_processor.py
========================
Processes raw Azure Defender for Cloud alerts:
  - Severity scoring (numeric 0-100)
  - Priority flagging (critical path alerts that need immediate action)
  - MITRE ATT&CK technique mapping
  - IOC extraction (IPs, hostnames, accounts from entities)
  - Age calculation
  - Recommended action generation
"""

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


# ─────────────────────────────────────────────────────────────────
# MITRE ATT&CK mapping for common Azure Defender alert types
# ─────────────────────────────────────────────────────────────────

ALERT_TYPE_TO_MITRE = {
    # Credential access
    "CREDENTIAL_DUMPING_TOOLS":     {"technique": "T1003", "name": "OS Credential Dumping",    "tactic": "Credential Access"},
    "FAILED_BRUTE_FORCE":           {"technique": "T1110", "name": "Brute Force",               "tactic": "Credential Access"},
    "BRUTE_FORCE_SUCCESSFULL":      {"technique": "T1110", "name": "Brute Force",               "tactic": "Credential Access"},

    # Execution
    "SUSPICIOUS_POWERSHELL":        {"technique": "T1059.001", "name": "PowerShell",            "tactic": "Execution"},
    "MALICIOUS_SCRIPT_DETECTED":    {"technique": "T1059",     "name": "Command and Scripting", "tactic": "Execution"},
    "SHELLCODE_DETECTED":           {"technique": "T1055",     "name": "Process Injection",     "tactic": "Privilege Escalation"},

    # Lateral movement / discovery
    "SUSPICIOUS_RDP_ACTIVITY":      {"technique": "T1021.001", "name": "Remote Desktop Protocol","tactic": "Lateral Movement"},
    "NETWORK_SCAN":                  {"technique": "T1046",    "name": "Network Service Discovery","tactic": "Discovery"},
    "SMB_LATERAL_MOVEMENT":         {"technique": "T1021.002", "name": "SMB/Windows Admin Shares","tactic": "Lateral Movement"},

    # Impact
    "RANSOMWARE_BEHAVIOR":          {"technique": "T1486",     "name": "Data Encrypted for Impact","tactic": "Impact"},
    "SHADOW_COPY_DELETED":          {"technique": "T1490",     "name": "Inhibit System Recovery", "tactic": "Impact"},

    # Defense evasion
    "SECURITY_LOG_CLEARED":         {"technique": "T1562.002", "name": "Disable Windows Event Logging","tactic": "Defense Evasion"},
    "AV_DISABLED":                  {"technique": "T1562.001", "name": "Disable or Modify Tools","tactic": "Defense Evasion"},

    # Persistence
    "NEW_ADMIN_ACCOUNT":            {"technique": "T1136",     "name": "Create Account",        "tactic": "Persistence"},
    "REGISTRY_PERSISTENCE":         {"technique": "T1547.001", "name": "Registry Run Keys",     "tactic": "Persistence"},

    # Exfiltration / C2
    "C2_COMMUNICATION":             {"technique": "T1071",     "name": "Application Layer Protocol","tactic": "Command and Control"},
    "DATA_EXFILTRATION":            {"technique": "T1041",     "name": "Exfiltration Over C2",  "tactic": "Exfiltration"},

    # Azure-specific
    "UNUSUAL_AZURE_ACTIVITY":       {"technique": "T1078.004", "name": "Cloud Accounts",        "tactic": "Initial Access"},
    "SUSPICIOUS_CLOUD_ACTIVITY":    {"technique": "T1078.004", "name": "Cloud Accounts",        "tactic": "Defense Evasion"},
    "AZURE_RESOURCE_ABUSE":         {"technique": "T1078.004", "name": "Valid Accounts - Cloud", "tactic": "Initial Access"},
}

# Intent field to tactic mapping (fallback when alert_type unknown)
INTENT_TO_TACTIC = {
    "Initial Access":       "Initial Access",
    "Execution":            "Execution",
    "Persistence":          "Persistence",
    "Privilege Escalation": "Privilege Escalation",
    "Defense Evasion":      "Defense Evasion",
    "Credential Access":    "Credential Access",
    "Discovery":            "Discovery",
    "Lateral Movement":     "Lateral Movement",
    "Collection":           "Collection",
    "Command and Control":  "Command and Control",
    "Exfiltration":         "Exfiltration",
    "Impact":               "Impact",
}

# Severity to numeric score
SEVERITY_SCORES = {
    "High":          90,
    "Medium":        60,
    "Low":           30,
    "Informational": 10,
}

# Keywords that make an alert critical-path (immediate action required)
CRITICAL_KEYWORDS = [
    "ransomware", "mimikatz", "credential dump", "lsass", "shadow copy",
    "bcdedit", "lateral movement", "domain admin", "golden ticket",
    "data exfil", "log cleared", "security log", "c2", "command and control",
    "encrypted files", "ransom note", "vssadmin"
]

# IP regex
IP_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')


@dataclass
class ProcessedAlert:
    # Core fields
    id:                str
    name:              str
    display_name:      str
    description:       str
    severity:          str
    severity_score:    int          # 0–100
    status:            str
    alert_type:        str

    # Time
    start_time:        str
    age_hours:         float

    # Resource
    compromised_entity: str
    resource_group:    str
    subscription_id:   str

    # MITRE
    mitre_technique:   str          # e.g. "T1003"
    mitre_name:        str          # e.g. "OS Credential Dumping"
    mitre_tactic:      str          # e.g. "Credential Access"
    mitre_url:         str

    # Triage
    is_critical_path:  bool         # immediate action required
    priority_rank:     int          # 1 = highest priority
    recommended_actions: list
    remediation_steps:   list

    # IOCs
    ioc_ips:           list
    ioc_hosts:         list
    ioc_accounts:      list

    # Links
    alert_uri:         str
    extended_properties: dict


def process_alerts(raw_alerts: list) -> list:
    """
    Process a list of raw alert dicts into ProcessedAlert objects.
    Sorts by priority (critical path first, then severity score).
    """
    processed = []

    for i, alert in enumerate(raw_alerts):
        pa = _process_single(alert, rank=i + 1)
        processed.append(pa)

    # Sort: critical path first, then by severity score descending
    processed.sort(key=lambda a: (not a.is_critical_path, -a.severity_score))

    # Re-rank after sort
    for i, pa in enumerate(processed):
        pa.priority_rank = i + 1

    return processed


def _process_single(alert: dict, rank: int) -> ProcessedAlert:
    """Process a single raw alert dict into a ProcessedAlert."""

    alert_type = alert.get("alert_type", "").upper()
    description = alert.get("description", "")
    severity    = alert.get("severity", "Low")
    intent      = alert.get("intent", "")

    # ── MITRE mapping ──────────────────────────────────────────
    mitre = ALERT_TYPE_TO_MITRE.get(alert_type, {})
    if not mitre:
        # Fallback: map via intent field
        tactic = INTENT_TO_TACTIC.get(intent, "Unknown")
        mitre  = {"technique": "T????", "name": "See MITRE ATT&CK", "tactic": tactic}

    technique_id = mitre.get("technique", "")
    tid_url      = technique_id.replace(".", "/")
    mitre_url    = f"https://attack.mitre.org/techniques/{tid_url}/" if technique_id != "T????" else "https://attack.mitre.org/"

    # ── Age calculation ────────────────────────────────────────
    age_hours = 0.0
    start_str = alert.get("start_time_utc", "")
    if start_str:
        try:
            start_dt  = datetime.fromisoformat(start_str.replace("Z", "+00:00"))
            now       = datetime.now(timezone.utc)
            age_hours = round((now - start_dt).total_seconds() / 3600, 1)
        except Exception:
            pass

    # ── Critical path detection ────────────────────────────────
    combined_text = (description + " " + alert_type + " " +
                     str(alert.get("extended_properties", {}))).lower()
    is_critical = any(kw in combined_text for kw in CRITICAL_KEYWORDS)
    if severity == "High":
        is_critical = True

    # ── IOC extraction ─────────────────────────────────────────
    ioc_ips      = []
    ioc_hosts    = []
    ioc_accounts = []

    for entity in alert.get("entities", []):
        etype = str(entity.get("type", "")).lower()
        if "ip" in etype:
            addr = entity.get("address", entity.get("ip", ""))
            if addr:
                ioc_ips.append(addr)
        elif "host" in etype:
            host = entity.get("hostname", entity.get("display_name", ""))
            if host:
                ioc_hosts.append(host)
        elif "account" in etype:
            acct = entity.get("accountName", entity.get("account_name", entity.get("display_name", "")))
            if acct:
                ioc_accounts.append(acct)

    # Also pull IPs from extended_properties
    ext = alert.get("extended_properties", {})
    for val in ext.values():
        for ip in IP_RE.findall(str(val)):
            if ip not in ioc_ips:
                ioc_ips.append(ip)

    # ── Recommended actions ────────────────────────────────────
    recommended_actions = _generate_actions(alert, mitre["tactic"], is_critical)

    return ProcessedAlert(
        id                  = alert.get("id", ""),
        name                = alert.get("name", ""),
        display_name        = alert.get("display_name", "Unknown Alert"),
        description         = description,
        severity            = severity,
        severity_score      = SEVERITY_SCORES.get(severity, 10),
        status              = alert.get("status", "Active"),
        alert_type          = alert_type,
        start_time          = start_str,
        age_hours           = age_hours,
        compromised_entity  = alert.get("compromised_entity", ""),
        resource_group      = alert.get("resource_group", ""),
        subscription_id     = alert.get("subscription_id", ""),
        mitre_technique     = technique_id,
        mitre_name          = mitre.get("name", ""),
        mitre_tactic        = mitre.get("tactic", ""),
        mitre_url           = mitre_url,
        is_critical_path    = is_critical,
        priority_rank       = rank,
        recommended_actions = recommended_actions,
        remediation_steps   = alert.get("remediation_steps", []),
        ioc_ips             = list(set(ioc_ips)),
        ioc_hosts           = list(set(ioc_hosts)),
        ioc_accounts        = list(set(ioc_accounts)),
        alert_uri           = alert.get("alert_uri", ""),
        extended_properties = ext,
    )


def _generate_actions(alert: dict, tactic: str, is_critical: bool) -> list:
    """Generate triage action recommendations based on alert context."""
    actions = []
    severity = alert.get("severity", "Low")
    entity   = alert.get("compromised_entity", "the affected resource")
    ext      = alert.get("extended_properties", {})

    if is_critical:
        actions.append(f"⚠️  IMMEDIATE: Escalate to Tier 2 — critical-path indicator detected")

    tactic_actions = {
        "Credential Access":    [f"Rotate all credentials on {entity}", "Check for lateral movement using stolen credentials", "Review privileged account activity in Azure AD sign-in logs"],
        "Lateral Movement":     [f"Isolate {entity} from internal network", "Review east-west traffic in NSG flow logs", "Check for additional compromised hosts via similar alerts"],
        "Impact":               [f"IMMEDIATELY isolate {entity} from all networks", "Check Azure Backup for pre-infection restore points", "Notify CISO and Legal within 30 minutes"],
        "Execution":            ["Decode and analyse the executed payload", "Review parent process for initial infection vector", "Check recent email and downloads on the host"],
        "Discovery":            ["Verify if scanning is from an authorized tool", "Review NSG flow logs for follow-on exploitation attempts", "Apply NSG rules to restrict east-west traffic"],
        "Defense Evasion":      ["Check what was modified or disabled", "Review other alerts from the same host in last 24h", "Restore disabled security controls immediately"],
        "Persistence":          [f"Audit all accounts and autostart entries on {entity}", "Search for other persistence mechanisms on the same host"],
        "Initial Access":       ["Review Azure AD sign-in logs for this identity", "Check for MFA bypass or Conditional Access policy gaps", "Revoke active sessions for the compromised identity"],
        "Command and Control":  ["Block C2 IPs/domains at NSG and Azure Firewall", "Review outbound traffic logs for data exfiltration", "Isolate host to prevent further C2 communication"],
        "Exfiltration":         ["Assess what data was exfiltrated and notify DPO/Legal", "Block destination IPs/domains immediately", "Preserve egress logs as legal evidence"],
    }

    actions.extend(tactic_actions.get(tactic, ["Review alert details in Microsoft Defender for Cloud"]))

    # IP-specific action
    src_ip = ext.get("SourceIP", "")
    if src_ip:
        actions.append(f"Block source IP {src_ip} in Azure NSG and perimeter firewall")

    # Document
    actions.append("Document findings in ServiceNow/ticketing system with this report attached")

    return actions


def summarize(processed: list) -> dict:
    """Generate summary statistics from a list of ProcessedAlert objects."""
    return {
        "total":          len(processed),
        "high":           sum(1 for a in processed if a.severity == "High"),
        "medium":         sum(1 for a in processed if a.severity == "Medium"),
        "low":            sum(1 for a in processed if a.severity == "Low"),
        "critical_path":  sum(1 for a in processed if a.is_critical_path),
        "active":         sum(1 for a in processed if a.status == "Active"),
        "tactics":        list(set(a.mitre_tactic for a in processed if a.mitre_tactic)),
        "affected_hosts": list(set(h for a in processed for h in a.ioc_hosts)),
        "unique_ips":     list(set(ip for a in processed for ip in a.ioc_ips)),
    }
