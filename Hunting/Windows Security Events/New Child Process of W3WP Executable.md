# New Child Process of W3WP Executable
### Description
Hunting Query detects unusual child processes of w3wp.exe not seen in 14 days, signaling potential web server compromise and web shell installation.
### References
-
### Microsoft Sentinel
```kusto
  let starttime = todatetime('{{StartTimeISO}}');
  let endtime = todatetime('{{EndTimeISO}}');
  let lookback = starttime - 14d;
  let known_procs = (
  SecurityEvent
  | where TimeGenerated between(lookback..starttime)
  | where EventID == 4688
  | where ParentProcessName hassuffix "w3wp.exe"
  | extend ProcessHost = strcat(Process, "-", Computer)
  | summarize by ProcessHost);
  SecurityEvent
  | where TimeGenerated between(starttime..endtime)
  | where EventID == 4688
  | where ParentProcessName hassuffix "w3wp.exe"
  | extend ProcessHost = strcat(Process, "-", Computer)
  | where ProcessHost !in (known_procs)
  | project-reorder TimeGenerated, Computer, NewProcessName, ParentProcessName, Account, NewProcessId
  | extend timestamp = TimeGenerated, HostCustomEntity = Computer, AccountCustomEntity = Account
```
