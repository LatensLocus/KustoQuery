# List Analytics Rules Failures
### Query Information
#### Description
Check for failures in Analytics Rules.
#### References
- https://learn.microsoft.com/en-us/azure/sentinel/monitor-analytics-rule-integrity
### Microsoft Sentinel
```kusto
SentinelHealth
| where TimeGenerated > ago(30d)
| where Status == "Failure"
| where SentinelResourceType == "Analytics Rule"
| where ExtendedProperties !contains "TemporaryIssuesDelay"
| summarize Count=count() by SentinelResourceName, Issue=tostring(ExtendedProperties.Issues)
| project SentinelResourceName, Count, Issue
```
