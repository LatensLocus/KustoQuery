# Powercat Download
### Description
Powercat is a PowerShell implementation of netcat. Whilst it can be used as a legitimate administrative tool it can be abused by attackers to exfiltrate data. This query looks for command line activity downloading PowerCat.
### References
-
### Microsoft Sentinel
```kusto
  SecurityEvent
  | where EventID == 4688
  | where Process has_any ("cmd.exe", "powershell.exe", "PowerShell_ISE.exe")
  | where CommandLine hassuffix "powercat.ps1"
  | extend timestamp = TimeGenerated, AccountCustomEntity = Account, HostCustomEntity = Computer
```
