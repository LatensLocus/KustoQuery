# List Top 10 Users With The Most IP Addresses Used To Successfully Sign-in

## Query Information

#### Description
Collect the top 10 user with the most IP used to successfully sign in to a tenant. This query displays the 10 users that have used the most IP addresses so sign in.

False positives can be a VPN that changes IP addresses, which results in a high number of IP addresses used to sign in.
#### Risk
The risk is that an actor uses an rare IP address to sign into your tenant.
## Defender For Endpoint
```kusto
AADSignInEventsBeta
| summarize IPsUsed = make_set(IPAddress), locations = make_set(Country) by AccountObjectId
| extend CountIP = array_length(IPsUsed)
| project-reorder CountIP
| top 10 by CountIP
```
## Sentinel
```kusto
SigninLogs
| summarize IPsUsed = make_set(IPAddress), locations = make_set(LocationDetails) by Identity
| extend CountIP = array_length(IPsUsed)
| project-reorder CountIP
| top 10 by CountIP
```
## Tags
- [[KQL]] [[Microsoft Defender for Endpoint]] [[Microsoft Sentinel]]