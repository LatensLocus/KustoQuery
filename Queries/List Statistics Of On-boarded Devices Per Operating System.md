# List Statistics Of On-boarded Devices Per Operating System
## Query Information
#### Description
This query lists how many devices have been on-boarded per operating system.
#### References
- https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/onboard-configure?view=o365-worldwide
## Defender For Endpoint
```kusto
DeviceInfo
| where OnboardingStatus == "Onboarded"
| summarize arg_max(Timestamp, *) by DeviceId
| summarize TotalDevices = count() by OSPlatform
```
## Sentinel
```kusto
DeviceInfo
| where OnboardingStatus == "Onboarded"
| summarize arg_max(Timestamp, *) by DeviceId
| summarize TotalDevices = count() by OSPlatform
```
## Tags
- [[KQL]] [[Microsoft Defender for Endpoint]] [[Microsoft Sentinel]]