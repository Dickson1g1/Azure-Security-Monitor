"""
core/azure_client.py
====================
Azure SDK wrapper handling authentication and alert retrieval
from Microsoft Defender for Cloud (formerly Azure Security Center).

Authentication priority (DefaultAzureCredential order):
  1. Environment variables (AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID)
  2. Azure CLI (az login)
  3. Managed Identity (when running inside Azure)
  4. Visual Studio Code credentials
  5. Interactive browser (fallback)

The script tries each in order automatically — no code changes needed
when moving from local dev (az login) to production (service principal).
"""

import os
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional
from dotenv import load_dotenv

load_dotenv()

log = logging.getLogger(__name__)

# Alert severity levels Azure uses
SEVERITY_LEVELS = ["High", "Medium", "Low", "Informational"]

# ─────────────────────────────────────────────────────────────────
# Mock alert generator (used in --demo mode when no Azure creds)
# ─────────────────────────────────────────────────────────────────

def _make_mock_alerts() -> list:
    """
    Generate realistic mock Azure Defender for Cloud alerts.
    These mirror the exact structure returned by the real SDK.
    Used in --demo mode — no Azure credentials needed.
    """
    now = datetime.now(timezone.utc)

    alerts = [
        {
            "id": "/subscriptions/sub-001/resourceGroups/rg-prod/providers/Microsoft.Security/locations/eastus/alerts/2024-alert-001",
            "name": "2024-alert-001",
            "alert_type": "CREDENTIAL_DUMPING_TOOLS",
            "display_name": "Credential Dumping Tool Detected",
            "description": "A tool associated with credential dumping activity (Mimikatz) was detected on the virtual machine PROD-VM-01. Attackers use these tools to harvest credentials from memory.",
            "severity": "High",
            "status": "Active",
            "start_time_utc": (now - timedelta(hours=2)).isoformat(),
            "end_time_utc": None,
            "compromised_entity": "PROD-VM-01",
            "resource_id": "/subscriptions/sub-001/resourceGroups/rg-prod/providers/Microsoft.Compute/virtualMachines/PROD-VM-01",
            "resource_group": "rg-prod",
            "subscription_id": "sub-001",
            "intent": "Collection",
            "alert_uri": "https://portal.azure.com/#blade/Microsoft_Azure_Security/AlertBlade/alertId/2024-alert-001",
            "remediation_steps": [
                "Isolate the virtual machine from the network immediately",
                "Collect volatile evidence before powering off",
                "Rotate all credentials that may have been exposed",
                "Review recent authentication events for lateral movement"
            ],
            "extended_properties": {
                "ProcessName": "powershell.exe",
                "CommandLine": "Invoke-Mimikatz -DumpCreds",
                "UserName": "PROD-VM-01\\Administrator",
                "ParentProcess": "cmd.exe"
            },
            "entities": [
                {"type": "host", "hostname": "PROD-VM-01"},
                {"type": "process", "processName": "powershell.exe"},
                {"type": "account", "accountName": "Administrator"}
            ]
        },
        {
            "id": "/subscriptions/sub-001/resourceGroups/rg-prod/providers/Microsoft.Security/locations/eastus/alerts/2024-alert-002",
            "name": "2024-alert-002",
            "alert_type": "SUSPICIOUS_RDP_ACTIVITY",
            "display_name": "Suspicious RDP Activity from External IP",
            "description": "Suspicious Remote Desktop Protocol (RDP) activity was detected from an external IP address 185.220.101.45 to virtual machine PROD-VM-02. This IP is associated with known threat actor infrastructure.",
            "severity": "High",
            "status": "Active",
            "start_time_utc": (now - timedelta(hours=1)).isoformat(),
            "end_time_utc": None,
            "compromised_entity": "PROD-VM-02",
            "resource_id": "/subscriptions/sub-001/resourceGroups/rg-prod/providers/Microsoft.Compute/virtualMachines/PROD-VM-02",
            "resource_group": "rg-prod",
            "subscription_id": "sub-001",
            "intent": "Lateral Movement",
            "alert_uri": "https://portal.azure.com/#blade/Microsoft_Azure_Security/AlertBlade/alertId/2024-alert-002",
            "remediation_steps": [
                "Block the source IP 185.220.101.45 at NSG and perimeter firewall",
                "Review RDP access logs for successful authentication",
                "Restrict RDP access to VPN only via Network Security Group",
                "Enable Just-in-Time VM access in Defender for Cloud"
            ],
            "extended_properties": {
                "SourceIP": "185.220.101.45",
                "DestinationPort": "3389",
                "ProtocolType": "TCP",
                "AttemptsCount": "47"
            },
            "entities": [
                {"type": "host", "hostname": "PROD-VM-02"},
                {"type": "ip", "address": "185.220.101.45"},
                {"type": "port", "portNumber": 3389}
            ]
        },
        {
            "id": "/subscriptions/sub-001/resourceGroups/rg-prod/providers/Microsoft.Security/locations/eastus/alerts/2024-alert-003",
            "name": "2024-alert-003",
            "alert_type": "RANSOMWARE_BEHAVIOR",
            "display_name": "Ransomware-Like Behavior Detected",
            "description": "Behavior consistent with ransomware was detected on PROD-VM-03. Multiple files were renamed with unknown extensions and shadow copies were deleted using vssadmin.",
            "severity": "High",
            "status": "Active",
            "start_time_utc": (now - timedelta(minutes=30)).isoformat(),
            "end_time_utc": None,
            "compromised_entity": "PROD-VM-03",
            "resource_id": "/subscriptions/sub-001/resourceGroups/rg-prod/providers/Microsoft.Compute/virtualMachines/PROD-VM-03",
            "resource_group": "rg-prod",
            "subscription_id": "sub-001",
            "intent": "Impact",
            "alert_uri": "https://portal.azure.com/#blade/Microsoft_Azure_Security/AlertBlade/alertId/2024-alert-003",
            "remediation_steps": [
                "IMMEDIATELY isolate PROD-VM-03 from all network connections",
                "Do NOT power off — preserve volatile evidence in RAM",
                "Check Azure Backup for pre-infection restore points",
                "Escalate to Tier 2 / DFIR team",
                "Notify CISO and Legal within 30 minutes"
            ],
            "extended_properties": {
                "FilesEncrypted": "2847",
                "NewExtension": ".locked",
                "ShadowCopyDeleted": "True",
                "RansomNoteFound": "DECRYPT_FILES.txt"
            },
            "entities": [
                {"type": "host", "hostname": "PROD-VM-03"},
                {"type": "file", "name": "DECRYPT_FILES.txt"}
            ]
        },
        {
            "id": "/subscriptions/sub-001/resourceGroups/rg-dev/providers/Microsoft.Security/locations/eastus/alerts/2024-alert-004",
            "name": "2024-alert-004",
            "alert_type": "SUSPICIOUS_POWERSHELL",
            "display_name": "Suspicious PowerShell Execution Detected",
            "description": "A PowerShell command with obfuscated, base64-encoded content was executed on DEV-VM-01. This technique is commonly used by attackers to evade detection.",
            "severity": "Medium",
            "status": "Active",
            "start_time_utc": (now - timedelta(hours=3)).isoformat(),
            "end_time_utc": None,
            "compromised_entity": "DEV-VM-01",
            "resource_id": "/subscriptions/sub-001/resourceGroups/rg-dev/providers/Microsoft.Compute/virtualMachines/DEV-VM-01",
            "resource_group": "rg-dev",
            "subscription_id": "sub-001",
            "intent": "Execution",
            "alert_uri": "https://portal.azure.com/#blade/Microsoft_Azure_Security/AlertBlade/alertId/2024-alert-004",
            "remediation_steps": [
                "Review the decoded base64 payload to assess intent",
                "Check parent process to determine initial infection vector",
                "Enable PowerShell Script Block Logging",
                "Review recent downloads and email attachments on this host"
            ],
            "extended_properties": {
                "CommandLine": "powershell.exe -EncodedCommand JABjAGwAaQBlAG4AdAAgAD0...",
                "DecodedCommand": "[ANALYST: decode and review]",
                "UserName": "DEV-VM-01\\jsmith",
                "ParentProcess": "WINWORD.EXE"
            },
            "entities": [
                {"type": "host", "hostname": "DEV-VM-01"},
                {"type": "process", "processName": "powershell.exe"},
                {"type": "account", "accountName": "jsmith"}
            ]
        },
        {
            "id": "/subscriptions/sub-001/resourceGroups/rg-dev/providers/Microsoft.Security/locations/eastus/alerts/2024-alert-005",
            "name": "2024-alert-005",
            "alert_type": "NETWORK_SCAN",
            "display_name": "Port Scan Activity Detected",
            "description": "Internal host DEV-VM-02 performed a port scan against 45 internal IP addresses, probing ports 22, 445, 3389, and 1433. This may indicate lateral movement reconnaissance.",
            "severity": "Medium",
            "status": "Active",
            "start_time_utc": (now - timedelta(hours=4)).isoformat(),
            "end_time_utc": None,
            "compromised_entity": "DEV-VM-02",
            "resource_id": "/subscriptions/sub-001/resourceGroups/rg-dev/providers/Microsoft.Compute/virtualMachines/DEV-VM-02",
            "resource_group": "rg-dev",
            "subscription_id": "sub-001",
            "intent": "Discovery",
            "alert_uri": "https://portal.azure.com/#blade/Microsoft_Azure_Security/AlertBlade/alertId/2024-alert-005",
            "remediation_steps": [
                "Investigate DEV-VM-02 for signs of compromise",
                "Check if this is authorized scanning (vulnerability scanner IP?)",
                "Review network flow logs for successful connections after scan",
                "Apply NSG rules to restrict lateral east-west traffic"
            ],
            "extended_properties": {
                "SourceIP": "10.0.1.42",
                "PortsScanned": "22,445,3389,1433",
                "TargetCount": "45",
                "ScanDuration": "120 seconds"
            },
            "entities": [
                {"type": "host", "hostname": "DEV-VM-02"},
                {"type": "ip", "address": "10.0.1.42"}
            ]
        },
        {
            "id": "/subscriptions/sub-001/resourceGroups/rg-prod/providers/Microsoft.Security/locations/eastus/alerts/2024-alert-006",
            "name": "2024-alert-006",
            "alert_type": "UNUSUAL_AZURE_ACTIVITY",
            "display_name": "Unusual Azure Management Activity",
            "description": "An unusual number of Azure management operations were performed from an unfamiliar location (IP: 194.165.16.72, Country: RU). Operations included listing storage account keys and modifying NSG rules.",
            "severity": "Medium",
            "status": "Active",
            "start_time_utc": (now - timedelta(hours=5)).isoformat(),
            "end_time_utc": None,
            "compromised_entity": "Azure Subscription sub-001",
            "resource_id": "/subscriptions/sub-001",
            "resource_group": "N/A",
            "subscription_id": "sub-001",
            "intent": "Collection",
            "alert_uri": "https://portal.azure.com/#blade/Microsoft_Azure_Security/AlertBlade/alertId/2024-alert-006",
            "remediation_steps": [
                "Review Azure Activity Log for all operations from this IP",
                "Rotate storage account access keys immediately",
                "Revoke any tokens issued during this session",
                "Enable Conditional Access policy requiring MFA from unfamiliar locations",
                "Review and revert any NSG changes made during this session"
            ],
            "extended_properties": {
                "SourceIP": "194.165.16.72",
                "Country": "RU",
                "OperationsPerformed": "ListStorageAccountKeys, UpdateNetworkSecurityGroup, ListRoleAssignments",
                "CallerIdentity": "admin@company.com"
            },
            "entities": [
                {"type": "ip", "address": "194.165.16.72"},
                {"type": "account", "accountName": "admin@company.com"}
            ]
        },
        {
            "id": "/subscriptions/sub-001/resourceGroups/rg-dev/providers/Microsoft.Security/locations/eastus/alerts/2024-alert-007",
            "name": "2024-alert-007",
            "alert_type": "FAILED_BRUTE_FORCE",
            "display_name": "Multiple Failed Login Attempts on Azure VM",
            "description": "47 failed SSH authentication attempts were detected against DEV-VM-03 from IP 45.33.32.156 within 10 minutes. Account admin was targeted.",
            "severity": "Low",
            "status": "Active",
            "start_time_utc": (now - timedelta(hours=6)).isoformat(),
            "end_time_utc": None,
            "compromised_entity": "DEV-VM-03",
            "resource_id": "/subscriptions/sub-001/resourceGroups/rg-dev/providers/Microsoft.Compute/virtualMachines/DEV-VM-03",
            "resource_group": "rg-dev",
            "subscription_id": "sub-001",
            "intent": "Credential Access",
            "alert_uri": "https://portal.azure.com/#blade/Microsoft_Azure_Security/AlertBlade/alertId/2024-alert-007",
            "remediation_steps": [
                "Block 45.33.32.156 at NSG inbound rules",
                "Disable password authentication for SSH — use key pairs only",
                "Enable Just-in-Time VM access to restrict SSH exposure",
                "Review auth.log for any successful logins from this IP"
            ],
            "extended_properties": {
                "SourceIP": "45.33.32.156",
                "TargetPort": "22",
                "FailedAttempts": "47",
                "TargetAccount": "admin"
            },
            "entities": [
                {"type": "host", "hostname": "DEV-VM-03"},
                {"type": "ip", "address": "45.33.32.156"}
            ]
        }
    ]
    return alerts


# ─────────────────────────────────────────────────────────────────
# Azure SDK client
# ─────────────────────────────────────────────────────────────────

class AzureSecurityClient:
    """
    Wraps azure-mgmt-security to pull alerts from
    Microsoft Defender for Cloud.

    Auth is handled by DefaultAzureCredential which tries:
      env vars → Azure CLI → Managed Identity → browser
    """

    def __init__(self):
        self.subscription_id  = os.getenv("AZURE_SUBSCRIPTION_ID", "")
        self.resource_group   = os.getenv("AZURE_RESOURCE_GROUP", "")
        self._client          = None
        self._credential      = None

    def connect(self) -> bool:
        """
        Authenticate to Azure. Returns True on success.
        Falls back gracefully with clear error messages.
        """
        try:
            from azure.identity import DefaultAzureCredential
            from azure.mgmt.security import SecurityCenter

            if not self.subscription_id:
                raise ValueError(
                    "AZURE_SUBSCRIPTION_ID not set.\n"
                    "Add it to your .env file or set the environment variable."
                )

            log.info("Authenticating to Azure via DefaultAzureCredential...")
            self._credential = DefaultAzureCredential()
            self._client     = SecurityCenter(
                credential       = self._credential,
                subscription_id  = self.subscription_id,
                asc_location     = "eastus"   # required param, doesn't filter by location
            )
            log.info(f"Connected to subscription: {self.subscription_id}")
            return True

        except ImportError:
            log.error(
                "azure-mgmt-security not installed.\n"
                "Run: pip install azure-mgmt-security azure-identity"
            )
            return False

        except Exception as e:
            log.error(f"Azure authentication failed: {e}")
            log.info("Tip: Run 'az login' for local dev, or check your .env credentials.")
            return False

    def get_alerts(self, severity_filter: list = None) -> list:
        """
        Pull all security alerts from Microsoft Defender for Cloud.

        Args:
            severity_filter : list of severities to include e.g. ["High","Medium"]
                              None = return all severities

        Returns:
            List of normalized alert dicts
        """
        if not self._client:
            raise RuntimeError("Not connected. Call connect() first.")

        try:
            log.info("Pulling alerts from Microsoft Defender for Cloud...")

            # Pull all alerts for the subscription
            raw_alerts = list(self._client.alerts.list())
            log.info(f"Retrieved {len(raw_alerts)} raw alerts")

            normalized = []
            for alert in raw_alerts:
                norm = self._normalize_alert(alert)
                if severity_filter and norm["severity"] not in severity_filter:
                    continue
                normalized.append(norm)

            log.info(f"After filtering: {len(normalized)} alerts")
            return normalized

        except Exception as e:
            log.error(f"Failed to retrieve alerts: {e}")
            raise

    def _normalize_alert(self, alert) -> dict:
        """
        Normalize a raw Azure SDK alert object into a clean dict.
        Handles missing fields gracefully.
        """
        props = alert.properties if hasattr(alert, 'properties') else {}

        def safe(attr, default=""):
            return getattr(props, attr, None) or default

        return {
            "id":                   alert.id or "",
            "name":                 alert.name or "",
            "alert_type":           safe("alert_type"),
            "display_name":         safe("alert_display_name"),
            "description":          safe("description"),
            "severity":             safe("severity", "Low"),
            "status":               safe("status", "Active"),
            "start_time_utc":       str(safe("start_time_utc", "")),
            "end_time_utc":         str(safe("end_time_utc", "")) if safe("end_time_utc") else None,
            "compromised_entity":   safe("compromised_entity"),
            "resource_id":          safe("resource_identifiers", [{}])[0].get("azureResourceId", "") if safe("resource_identifiers") else "",
            "resource_group":       self._extract_rg(alert.id or ""),
            "subscription_id":      self.subscription_id,
            "intent":               safe("intent"),
            "alert_uri":            safe("alert_uri"),
            "remediation_steps":    list(safe("remediation_steps") or []),
            "extended_properties":  dict(safe("extended_properties") or {}),
            "entities":             [self._norm_entity(e) for e in (safe("entities") or [])],
        }

    def _extract_rg(self, resource_id: str) -> str:
        """Extract resource group name from Azure resource ID."""
        parts = resource_id.lower().split("/")
        try:
            idx = parts.index("resourcegroups")
            return parts[idx + 1]
        except (ValueError, IndexError):
            return ""

    def _norm_entity(self, entity) -> dict:
        """Normalize an entity object to a simple dict."""
        if isinstance(entity, dict):
            return entity
        result = {"type": getattr(entity, "entity_type", "unknown")}
        for attr in ["display_name", "host_name", "address", "account_name",
                     "name", "process_name"]:
            val = getattr(entity, attr, None)
            if val:
                result[attr] = val
        return result
