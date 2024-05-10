# List Sign-ins By UserAgent

## Query Information

#### Description
This query can be used to detect rare UserAgents that are used to sign into your tenant. Those rare UserAgents can be used for malicious acces into your tenant.

The query can be extended by filtering on successful and failed sign ins. 
## Microsoft Defender For Endpoint
```kusto
AADSignInEventsBeta
| summarize count() by UserAgent
| sort by count_
```

## Microsoft Sentinel
```kusto
SigninLogs
| summarize count() by UserAgent
| sort by count_
```
## Tags
- [[KQL]] [[Microsoft Defender for Endpoint]] [[Microsoft Sentinel]]