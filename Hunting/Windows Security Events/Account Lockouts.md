# List All Global Admins In Your Tenant
### Description
This query lists all accounts that have in the Active Directory domain. 
### References
-
### Microsoft Sentinel
```kusto
SecurityEvent
| where EventID == 4740
| summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated), LockoutsCount = count() by Activity, Account, TargetSid, TargetDomainName, SourceComputerId, SourceDomainController = Computer
| extend timestamp = StartTime, AccountCustomEntity = Account, HostCustomEntity = TargetDomainName
```
