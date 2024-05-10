# Conditional Access Policy Deleted

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title                         |
| ------------ | ----------------------------- |
| [[T1556]]    | Modify Authentication Process |
#### Description
This KQL query lists all conditional access policies that have been deleted. The modification of authentication processes can be used to create persistence on an cloud account.
#### Risk
Adversaries can delete CA policies to get persistence.
#### References
- https://learn.microsoft.com/en-us/azure/active-directory/architecture/security-operations-consumer-accounts
- https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/
## Microsoft Sentinel
```kusto
AuditLogs
| where OperationName == "Delete conditional access policy"
| extend DeletedPolicy = TargetResources.[0].displayName, Actor = InitiatedBy.user.userPrincipalName
| project TimeGenerated, Actor, DeletedPolicy, TargetResources
```
## Tags
- [[KQL]] [[MITRE ATT&CK]] [[Microsoft Sentinel]]