# List New UserAgent Used Based On OfficeActivity
### Query Information
#### Description
This query can be used to detect new UserAgents that have been used to perform sign in activities (successful or failed). If you company only uses windows devices it will be interesting to investigate the other UserAgents that have been used. 

False positives can be new browser updates that trigger new UserAgents, this can be detected by a lot of entries for a specific agent. 
#### Risk
A malicious actor signs in to your tenant with a user agent that is not user in your environment. It can also be a script that uses (leaked) credentials on your tenant.
### Microsoft Sentinel
```kusto
let KnownUserAgents = OfficeActivity
  | where TimeGenerated > ago(90d) and TimeGenerated < ago(3d)
  | distinct UserAgent;
OfficeActivity
| where TimeGenerated > ago(3d)
| where UserAgent !in (KnownUserAgents)
| project TimeGenerated, UserAgent, UserId, ClientIP
```
