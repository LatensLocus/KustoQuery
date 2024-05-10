# Visualize Antivirus Detection By Day
## Query Information
#### Description
This query visualizes the daily antivirus detection, which can give an indication in anomalous amount of activities that are performed in your environment. 
## Microsoft Defender For Endpoint
```kusto
DeviceEvents
| where Timestamp > ago(30d)
| where ActionType == 'AntivirusDetection'
| summarize count() by bin(Timestamp, 1d)
| render linechart with(title="Antivirus Detections by Day")
```
## Microsoft Sentinel
```kusto
DeviceEvents
| where TimeGenerated > ago(30d)
| where ActionType == 'AntivirusDetection'
| summarize count() by bin(TimeGenerated, 1d)
| render linechart with(title="Antivirus Detections by Day")
```
## Tags
- [[KQL]] [[Microsoft Defender for Endpoint]] [[Microsoft Sentinel]]