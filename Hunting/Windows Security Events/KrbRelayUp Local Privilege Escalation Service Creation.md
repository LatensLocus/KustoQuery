# KrbRelayUp Local Privilege Escalation Service Creation
### Description
This query detects the default service name created by KrbRelayUp. KrbRelayUp is Local Privilege Escalation tool that combine features of Rubeus and KrbRelay.
### References
-
### Microsoft Sentinel
```kusto
  let MaliciousService = dynamic (["KrbSCM"]);
  Event
  | where Source == "Service Control Manager" and EventID == 7045
  | parse EventData with * 'ServiceName">' ServiceName "<" * 'ImagePath">' ImagePath "<" *
  | where ServiceName has_any (MaliciousService) or ImagePath has_any (MaliciousService)
  | parse EventData with * 'AccountName">' AccountName "<" *
  | summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated) by EventID, Computer, ServiceName, ImagePath, AccountName
```
