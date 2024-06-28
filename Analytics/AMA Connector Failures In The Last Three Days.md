# AMA Connector Failures In The Last Three Days
### Query Information
#### Description
Detect latest failure events per AMA connector in the last three days.
#### Risk
Failures in AMA connectors mean that no data is being ingested thus no potential alerts will be triggered.
### Microsoft Sentinel
```kusto
CommonSecurityLog
| where TimeGenerated > ago(3d)
| extend sent_by_ama = column_ifexists('CollectorHostName','')
| where isnotempty(sent_by_ama)
| where isnotempty(DeviceVendor)
| summarize LastLogReceived = max(TimeGenerated) by DeviceVendor, DeviceProduct
| project IsConnected = LastLogReceived > ago(3d), DeviceVendor, DeviceProduct
| where IsConnected == "false"
```
