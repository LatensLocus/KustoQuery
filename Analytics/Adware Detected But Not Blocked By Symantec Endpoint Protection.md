# Adware Detected But Not Blocked By Symantec Endpoint Protection
### Query Information
#### MITRE ATT&CK Technique(s)

| Technique ID  | Title                          |
| ------------- | ------------------------------ |
| T1204.002 | User Execution: Malicious File |
#### Description
This query lists all Adware events that Symantec Endpoint Protection detected but did not block and a summary count of unique alerts for a given time frame.
#### References
- https://learn.microsoft.com/en-us/azure/sentinel/data-connectors/symantec-endpoint-protection
- https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Symantec%20Endpoint%20Protection/Analytic%20Rules/MalwareDetected.yaml
### Microsoft Sentinel
```kusto
SymantecEndpointProtection
| where LogType == "Agent Security Logs" or LogType == "Agent Risk Logs"
| where EventDescription contains "Audit: Adware"
| where EventDescription contains "attack detected but not blocked"
| summarize Count=count() by UserName, LocalHostIpAddr, RemoteHostName, RemoteHostIpAddr, TrafficDirection, IntrusionUrl, EventDescription
```
