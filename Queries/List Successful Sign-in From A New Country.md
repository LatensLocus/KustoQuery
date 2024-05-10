# List Successful Sign-in From A New Country

## Query Information

#### Description
This query detects successful sign-ins from countries that have not been seen before. Depending on where you run this query the look-back period is different, Microsoft 365 Defender uses 30 days and Microsoft Sentinel uses 90 days. If you have longer retention periods it is recommended to use longer thresholds.
#### Risk
An adversary signs in from a new country to your azure AD tenant.
## Microsoft Defender For Endpoint
```kusto
let KnownCountries = AADSignInEventsBeta
    | where Timestamp > ago(30d) and Timestamp < ago(3d)
    // Only filter on successful logins
    | where ErrorCode == 0
    | where isnotempty(Country)
    | distinct Country;
AADSignInEventsBeta
| where Timestamp > ago(3d)
| where ErrorCode == 0
| where isnotempty(Country)
| where Country !in (KnownCountries)
| project Timestamp, Country, UserAgent, ErrorCode, AccountObjectId,AccountDisplayName, IPAddress
```
## Microsoft Sentinel
```kusto
let KnownCountries = SigninLogs
  | where TimeGenerated > ago(90d) and TimeGenerated < ago(3d)
    //Only filter on successful logins
    | where ResultType == 0
    | where isnotempty(Location)
    | distinct Location;
SigninLogs
| where TimeGenerated > ago(3d)
| where ResultType == 0
| where isnotempty(Location)
| where Location !in (KnownCountries)
| project TimeGenerated, Location, UserAgent, ResultType, Identity, UserPrincipalName, IPAddress
```
## Tags
- [[KQL]] [[Microsoft Defender for Endpoint]] [[Microsoft Sentinel]]