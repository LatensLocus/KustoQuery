# Visualize Successful PIM Activations
## Query Information
#### Description
This query visualizes the PIM activation performed by accounts. A user who has used many different PIM roles may be interesting to examine, it could be that a users always assigns their PIM access rights without needing them all the time. The same goes for PIM roles with high privileges. 
#### References
- https://learn.microsoft.com/en-us/azure/active-directory/privileged-identity-management/
## Microsoft Sentinel
```kusto
AuditLogs
| where OperationName == "Add member to role completed (PIM activation)"
| summarize TotalActivations = count() by Identity
| sort by TotalActivations
| render columnchart
```
## Tags
- [[KQL]] [[Microsoft Sentinel]]