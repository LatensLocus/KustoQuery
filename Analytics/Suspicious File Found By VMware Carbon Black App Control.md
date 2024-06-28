# Suspicious File Found By VMware Carbon Black App Control
### Query Information
#### MITRE ATT&CK Technique(s)

| Technique ID  | Title                          |
| ------------- | ------------------------------ |
| T1204.002 | User Execution: Malicious File |
#### Description
This rule identifies potential risky files that were detected by VMware Carbon Black App Control.
#### Risk
An adversary may rely upon a user opening a malicious file in order to gain execution. Users may be subjected to social engineering to get them to open a file that will lead to code execution. This user action will typically be observed as follow-on behavior from Spearphishing Attachment. Adversaries may use several types of files that require a user to execute them, including .doc, .pdf, .xls, .rtf, .scr, .exe, .lnk, .pif, and .cpl.
#### References
- https://learn.microsoft.com/en-us/azure/sentinel/data-connectors/vmware-carbon-black-cloud
- https://docs.vmware.com/en/VMware-Carbon-Black-App-Control/8.10/cb-ac-events-guide.pdf
### Microsoft Sentinel
```kusto
CommonSecurityLog
| where DeviceVendor == "VMware Carbon Black"
| where DeviceProduct == "App Control"
| where Activity == "Suspicious file found"
| summarize Count=count() by DestinationHostName, Activity, ProcessName, FilePath
```
