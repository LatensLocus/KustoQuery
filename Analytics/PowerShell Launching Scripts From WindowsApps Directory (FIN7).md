# PowerShell Launching Scripts From WindowsApps Directory (FIN7)
## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID  | Title                                         |
| ------------- | --------------------------------------------- |
| [[T1059.001]] | Command and Scripting Interpreter: PowerShell |
#### Description
Detection opportunity: Launching PowerShell scripts from **windowsapps** directory

This pseudo-detector looks for the execution of PowerShell scripts from the windowsapps directory. There are instances where benign PowerShell scripts run from this directory, but analysts can sort out malicious or suspicious activity by investigating follow-on actions and network connections. However, in this case we see the adversary calling `StartingScriptWrapper.ps1` from the windowsapps directory to execute their malicious payload script.
#### Risk
FIN7 have been observed performing this behavior in recent intrusions. FIN7 activity has frequently preceded ransomware deployment. We’ve detected activity within this cluster attempting to install malicious instances of NetSupport Manager RAT. In the detections we’ve observed within this cluster, the adversary leverages the MSIX-PackageSupportFramework tool to create their malicious MSIX files. When the victim opens the MSIX, the StartingScriptWrapper.ps1 component of the MSIX package support framework launches an embedded PowerShell script from the windowsapps directory.
#### References
- [https://kqlquery.com/](https://redcanary.com/blog/msix-installers/)
## Microsoft Defender For Endpoint
```kusto
DeviceProcessEvents
| where InitiatingProcessFolderPath contains "windowsapps" and FileName =~ "powershell.exe" and ProcessCommandLine has_all ("windowsapps","-file",".ps1")
```
## Microsoft Sentinel
```kusto
DeviceProcessEvents
| where InitiatingProcessFolderPath contains "windowsapps" and FileName =~ "powershell.exe" and ProcessCommandLine has_all ("windowsapps","-file",".ps1")
```
## Tags
- [[KQL]] [[MITRE ATT&CK]] [[Microsoft Defender for Endpoint]] [[Microsoft Sentinel]]