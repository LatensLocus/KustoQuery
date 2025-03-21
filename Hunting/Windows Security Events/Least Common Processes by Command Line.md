# Least Common Processes by Command Line
### Description
Looks across your environment for least common Process Command Lines, may be noisy and require allowlisting.
### References
-
### Microsoft Sentinel
```kusto
  let starttime = todatetime('{{StartTimeISO}}');
  let endtime = todatetime('{{EndTimeISO}}');
  let lookback = starttime - 7d;  
  let Allowlist = dynamic (['foo.exe', 'baz.exe']);
  let Sensitivity = 5;  
  SecurityEvent
  | where TimeGenerated between(lookback..endtime)
  | where EventID == 4688 and NewProcessName !endswith 'conhost.exe'
  | extend ProcArray = split(NewProcessName, '\\')
  // ProcArrayLength is Folder Depth
  | extend ProcArrayLength = array_length(ProcArray)
  | extend LastIndex = ProcArrayLength - 1
  | extend Proc = ProcArray[LastIndex]
  | where Proc !in (Allowlist)
  | summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), TimesSeen = count(), HostCount = dcount(Computer), Hosts = make_set(Computer,maxSize=500), UserCount = dcount(SubjectUserName), Users = make_set(SubjectUserName,maxSize=500) by CommandLine
  | where TimesSeen < Sensitivity
  | extend timestamp = StartTimeUtc
```
