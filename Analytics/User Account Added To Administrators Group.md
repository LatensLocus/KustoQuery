# User Account Added To Administrators Group
## Query Information
#### MITRE ATT&CK Technique(s)

| Technique ID  | Title                         |
| ------------- | ----------------------------- |
| [[T1136.001]] | Create Account: Local Account |
#### Description
Adversaries may create local accounts to maintain access to victim systems. This query lists all the local admins that have been added in the selected time frame per device. 
#### Risk
Local Admin accounts have high privileges on and can should be limited.
#### References
- https://learn.microsoft.com/en-us/windows/security/identity-protection/access-control/local-accounts#administrator
## Microsoft Defender For Endpoint
```kusto
DeviceEvents
| where ActionType == "UserAccountAddedToLocalGroup"
| extend Details = parse_json(AdditionalFields)
| extend
    GroupName = tostring(Details.GroupName),
    GroupDomainName = tostring(Details.GroupDomainName),
    GroupSid = tostring(Details.GroupSid)
// Filter Local Administrators
| where GroupSid == "S-1-5-32-544"
| summarize LocalAdmins = make_set(AccountSid) by DeviceName
| extend TotalLocalAdmins = array_length(LocalAdmins)
| sort by TotalLocalAdmins
```
## Microsoft Sentinel
```kusto
DeviceEvents
| where ActionType == "UserAccountAddedToLocalGroup"
| extend Details = parse_json(AdditionalFields)
| extend
    GroupName = tostring(Details.GroupName),
    GroupDomainName = tostring(Details.GroupDomainName),
    GroupSid = tostring(Details.GroupSid)
// Filter Local Administrators
| where GroupSid == "S-1-5-32-544"
| summarize LocalAdmins = make_set(AccountSid) by DeviceName
| extend TotalLocalAdmins = array_length(LocalAdmins)
| sort by TotalLocalAdmins
```
## Tags
- [[KQL]] [[MITRE ATT&CK]] [[Microsoft Defender for Endpoint]] [[Microsoft Sentinel]]