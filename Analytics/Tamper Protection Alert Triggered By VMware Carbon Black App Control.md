# Tamper Protection Alert Triggered By VMware Carbon Black App Control
### Query Information
#### MITRE ATT&CK Technique(s)

| Technique ID | Title |
| ------------ | ----- |
|              |       |
#### Description
This rule trigger alerts where Tamper Protection is detected by VMware Carbon Black App Control.
#### Risk
#### References
- https://learn.microsoft.com/en-us/azure/sentinel/data-connectors/vmware-carbon-black-cloud
- https://docs.vmware.com/en/VMware-Carbon-Black-App-Control/8.10/cb-ac-events-guide.pdf
### Microsoft Sentinel
```kusto
CommonSecurityLog
| where DeviceVendor == "VMware Carbon Black"
| where DeviceProduct == "App Control"
| where Activity == "Tamper Protection"
| project TimeGenerated, DestinationHostName, DestinationIP, DestinationUserName, FilePath, FileName
```
