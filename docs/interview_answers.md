# How to talk about this project in interviews

## "Walk me through a project you built."

> "I built an Azure Security Center alert monitoring script in Python. It
> connects to Microsoft Defender for Cloud using the Azure SDK and the
> DefaultAzureCredential authentication chain — which means it works the
> same way whether I'm running it locally with az login, in a CI/CD pipeline
> with a service principal, or inside Azure itself with Managed Identity.
>
> It pulls all active security alerts, normalizes them into a clean structure,
> scores them by severity, flags critical-path alerts that need immediate action
> — things like ransomware behavior or credential dumping — and maps each alert
> to a MITRE ATT&CK technique automatically based on the alert type. It then
> outputs three formats: a colorized CLI report for analysts, a structured JSON
> file ready to ingest into Splunk or ServiceNow, and an HTML dashboard that
> looks like a commercial SOC platform."

## "How does the Azure authentication work?"

> "I used DefaultAzureCredential from the azure-identity SDK, which implements
> a credential chain. It tries authentication methods in order: environment
> variables first — that's the service principal client ID, secret, and tenant
> ID — then Azure CLI if you're logged in locally, then Managed Identity if
> the script is running inside an Azure VM or Function App. This means the
> same code works in every environment without changes. For production I'd
> provision a service principal with just the Security Reader role — least
> privilege, no write access needed."

## "What's the MITRE ATT&CK mapping doing?"

> "Azure Defender assigns each alert an alert_type string — something like
> CREDENTIAL_DUMPING_TOOLS or SUSPICIOUS_RDP_ACTIVITY. I built a mapping
> table from those alert types to MITRE technique IDs and tactic names.
> So CREDENTIAL_DUMPING_TOOLS maps to T1003 OS Credential Dumping under
> Credential Access, and SUSPICIOUS_RDP_ACTIVITY maps to T1021.001 Remote
> Desktop Protocol under Lateral Movement. This lets SOC analysts see the
> adversary's goal and stage in the attack chain at a glance, not just a
> vendor-specific alert name."

## "How would you use this in a real SOC?"

> "Two ways. First, run it on a schedule — every 15 minutes is a good
> cadence for high-severity environments — and pipe the JSON output into
> Splunk via HEC or into a ServiceNow ITSM workflow to auto-create tickets.
> Second, use the HTML report as a shift handoff document — the on-call
> analyst gets a prioritized list of what needs attention, what the MITRE
> technique is, and the recommended actions already written out. It removes
> the context-switching of jumping between the Azure portal, the MITRE
> website, and the ticketing system."

## "What would you add next?"

> "Three things: Azure Sentinel integration to correlate alerts with SIEM
> incidents, email/Teams webhook notifications for critical-path alerts so
> on-call gets paged automatically, and a trend dashboard that tracks alert
> volume and tactic distribution over 30 days so you can spot if an attacker
> is escalating through the kill chain."
