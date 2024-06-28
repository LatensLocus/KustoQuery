# List total number of incidents daily
### Query Information
#### Description
The results of this query provide the total number of incidents that have been triggered in your selected *timeframe*.
### Microsoft Sentinel
```kusto
SentinelHealth
| extend Rule_Health = tostring(parse_json(ExtendedProperties).RuleId)
| project TimeGenerated, SentinelResourceName, Rule_Health
| join kind=inner (SecurityIncident
| extend Rule_Incident = trim(@"[^\w]+",tostring(RelatedAnalyticRuleIds))
| project TimeGenerated, Title, Rule_Incident, IncidentNumber)
on $left.Rule_Health == $right.Rule_Incident
| summarize arg_min(TimeGenerated, *) by IncidentNumber
| project-rename Day = TimeGenerated1
| summarize Triggers = count(), AlertIds = make_set(IncidentNumber) by bin(Day, 1day)
```
