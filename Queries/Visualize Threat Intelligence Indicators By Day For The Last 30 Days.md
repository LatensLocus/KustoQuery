# Visualize Threat Intelligence Indicators By Day For The Last 30 Days
## Query Information
#### Description
This query visualizes the amount of IOCs that have triggered each day for the last 30 days in a time chart. This could indicate spikes in malicious activities by users or give insights in the value of Threat Intelligence feeds. 
## Microsoft Sentinel
```kusto
ThreatIntelligenceIndicator
| where TimeGenerated > ago(30d)
| extend IOC = iff(isnotempty(DomainName), DomainName, 
iff(isnotempty(NetworkIP), NetworkIP, iff(isnotempty(Url), Url, "No IOC defined")))
| summarize count() by bin(TimeGenerated, 1d), IOC
| render columnchart with (kind=stacked, title="Threat Intelligence Indicators triggered each day")
```
## Tags
- [[KQL]] [[Microsoft Sentinel]]