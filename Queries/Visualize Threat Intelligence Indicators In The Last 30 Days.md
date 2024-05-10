# Visualize Threat Intelligence Indicators In The Last 30 Days

## Query Information

#### Description
This query visualizes the IOCs that have triggered in the last 30 days. That can for example be Domains, IP addresses or URLs. The results are rendered in a pie chart. 
## Microsoft Sentinel
```kusto
ThreatIntelligenceIndicator
| where TimeGenerated > ago(30d)
| extend IOC = iff(isnotempty(DomainName), DomainName, iff(isnotempty(NetworkIP), NetworkIP, iff(isnotempty(Url),Url, "No IOC defined")))
| summarize count() by IOC
| render piechart with (title="Threat Intelligence Indicators by IOC last month")
```
## Tags
- [[KQL]] [[Microsoft Sentinel]]