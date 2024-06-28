# Data Connector Failures In The Last Three Days
### Query Information
#### Description
Detect latest failure events per Data connector in the last three days.
#### Risk
Failures in Data connectors mean that no data is being ingested thus no potential alerts will be triggered.
#### References
- https://learn.microsoft.com/en-us/azure/sentinel/monitor-data-connector-health
### Microsoft Sentinel
```kusto
SentinelHealth
| where TimeGenerated > ago(3d)
| where OperationName == 'Data fetch status change'
| where Status in ('Success', 'Failure')
| summarize TimeGenerated = arg_max(TimeGenerated,*) by SentinelResourceName, SentinelResourceId
| where Status == 'Failure'
```
