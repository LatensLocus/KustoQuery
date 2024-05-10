# Conditional Access Policy Changed
## Query Information
#### MITRE ATT&CK Technique(s)

| Technique ID | Title                         |
| ------------ | ----------------------------- |
| [[T1556]]    | Modify Authentication Process |
#### Description
This KQL query lists all conditional access policies that have been changed. The modification of authentication processes can be used to create persistence on an cloud account.
#### Risk
Adversaries can update CA policies to get persistence by removing the necessary strong authentication mechanisms for a account.
#### References
- https://learn.microsoft.com/en-us/azure/active-directory/architecture/security-operations-consumer-accounts
- https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/
## Microsoft Sentinel
```kusto
AuditLogs
| where OperationName == "Update conditional access policy"
| extend DeletedPolicy = TargetResources.[0].displayName, Actor = InitiatedBy.user.userPrincipalName
| project TimeGenerated, Actor, DeletedPolicy, TargetResources
```
## Tags
- [[KQL]] [[MITRE ATT&CK]] [[Microsoft Sentinel]]