# List Recently Found Devices That Can Be On-boarded
## Query Information
#### Description
This query lists devices that can be on-boarded to Defender For Endpoint and have recently been detected. You can determine what recently is by using the *RecentDetection* parameter.
#### Risk
Devices that are not on-boarded can be misused without detection. 
#### References
- https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/configure-machines-onboarding?view=o365-worldwide
## Microsoft Defender For Endpoint
```kusto
let RecentDetection = 10d;
DeviceInfo
| where Timestamp > ago(RecentDetection)
| summarize arg_max(Timestamp, *) by DeviceId
| where OnboardingStatus == "Can be onboarded"
| summarize TotalDevices = dcount(DeviceId), DeviceNames = make_set(DeviceName) by OSPlatform, DeviceType
```
## Microsoft Sentinel
```kusto
let RecentDetection = 10d;
DeviceInfo
| where TimeGenerated > ago(RecentDetection)
| summarize arg_max(TimeGenerated, *) by DeviceId
| where OnboardingStatus == "Can be onboarded"
| summarize TotalDevices = dcount(DeviceId), DeviceNames = make_set(DeviceName) by OSPlatform, DeviceType
```
## Tags
- [[KQL]] [[Microsoft Defender for Endpoint]] [[Microsoft Sentinel]]