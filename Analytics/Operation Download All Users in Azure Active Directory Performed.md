# Operation Download All Users in Azure Active Directory Performed
## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID  | Title                                     |
| ------------- | ----------------------------------------- |
| [[T1087.004]] | Account Discovery: Cloud Account          |
| [[T1069.003]] | Permission Groups Discovery: Cloud Groups |
#### Description
Detect when a user account downloads all Azure Active Directory users. This can be used to dump all Azure AD users. Both admin and non-admin users can download user lists.
#### Risk
A malicious actor downloads Azure Active Directory to gain valuable information of the users and groups in your domain. 
#### References
- https://learn.microsoft.com/en-us/azure/active-directory/enterprise-users/users-bulk-download
## Microsoft Sentinel
```kusto
AuditLogs
| where OperationName contains "Download users"
| extend InitiatedByInfo = parse_json(InitiatedBy).['user']
| extend InitiatedByUser = InitiatedByInfo.userPrincipalName
| project-reorder OperationName, ResultDescription, InitiatedByUser, TimeGenerated
```
## Tags
- [[KQL]] [[MITRE ATT&CK]] [[Microsoft Sentinel]]