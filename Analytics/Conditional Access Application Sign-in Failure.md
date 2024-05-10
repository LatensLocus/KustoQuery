# Conditional Access Application Sign-in Failure
## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID  | Title                          |
| ------------- | ------------------------------ |
| [[T1078.004]] | Valid Accounts: Cloud Accounts |
#### Description
This KQL query lists all applications that trigger failed sign-in requests due to conditional access failures. This can indicate that a certain policy is not well configured and need to be changed in order for accounts to be able to access the application. On the other hand it can also be that the failed sign-ins are valid credentials that adversaries have obtained and they are used to try and gain access to certain applications in your environment. The CA policy will only block if the previous authentication requirements have already been met (e.g. username + password (+mfa)).
#### Risk
Adversaries have access to cloud credentials and are stopped due to CA policies.
#### References
- https://learn.microsoft.com/en-us/azure/active-directory/architecture/security-operations-consumer-accounts
- https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/
## Microsoft Sentinel
```kusto
SigninLogs
| where ResultType != 0
| where ResultDescription has "Conditional Access"
| summarize Total = count(), ResultTypes = make_set(ResultType), ResultDescriptions = make_set(ResultDescription) by AppDisplayName
| sort by Total
```
## Tags
- [[KQL]] [[MITRE ATT&CK]] [[Microsoft Sentinel]]