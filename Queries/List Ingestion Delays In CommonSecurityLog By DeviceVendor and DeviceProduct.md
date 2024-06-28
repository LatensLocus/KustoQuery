# List Ingestion Delays In CommonSecurityLog By DeviceVendor and DeviceProduct
### Query Information
#### Description
This query will check for ingestion delays in CommonSecurityLog by DeviceVendor and DeviceProduct.

Note: Azure Sentinel scheduled alert rules are delayed by 5 minutes. This allows data types with a smaller delay to be ingested on time for the scheduled run.
#### Risk
Explain what risk this detection tries to cover.
#### References
- [Handle ingestion delay in Microsoft Sentinel | Microsoft Learn](https://learn.microsoft.com/en-us/azure/sentinel/ingestion-delay)
- [Handling ingestion delay in Azure Sentinel scheduled alert rules - Microsoft Community Hub](https://techcommunity.microsoft.com/t5/microsoft-sentinel-blog/handling-ingestion-delay-in-azure-sentinel-scheduled-alert-rules/ba-p/2052851)
### Microsoft Sentinel
```kusto
CommonSecurityLog
| extend delay = ingestion_time() - TimeGenerated
| summarize percentiles(delay,50,100) by DeviceVendor, DeviceProduct
```
