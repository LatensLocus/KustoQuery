# Suspected LSASS Dump
### Description
Look for evidence of the LSASS process being dumped either using Procdump or comsvcs.dll. Often used by attackers to access credentials stored on a system.
### References
- https://risksense.com/blog/hidden-gems-in-windows-the-hunt-is-on
- https://docs.microsoft.com/sysinternals/downloads/procdump
### Microsoft Sentinel
```kusto
  SecurityEvent 
  | where EventID == 4688
  | where CommandLine has_all ("procdump", "lsass") or CommandLine has_all ("rundll32", "comsvcs", "MiniDump")
  | extend timestamp = TimeGenerated, AccountCustomEntity = Account, HostCustomEntity = Computer
```
