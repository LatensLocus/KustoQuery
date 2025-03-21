# Least Common Processes Including Folder Depth
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
  let Sensitivity = 15;
  SecurityEvent
  | where TimeGenerated between(lookback..endtime)
  | where EventID == 4688
  | extend ProcArray = split(NewProcessName, '\\')
  // ProcArrayLength is Folder Depth
  | extend ProcArrayLength = array_length(ProcArray)
  | extend LastIndex = ProcArrayLength - 1
  | extend Proc = ProcArray[LastIndex]
  | where Proc !in (Allowlist)
  // ProcArray[0] is the proc's Drive
  | extend DriveDepthProc = strcat(ProcArray[0], '-', ProcArrayLength, '-', Proc)
  | summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), TimesSeen = count(), HostCount = dcount(Computer), Hosts = make_set(Computer,maxSize=2000), UserCount = dcount(SubjectUserName), Users = make_set(SubjectUserName,maxSize=2000) by DriveDepthProc
  | where TimesSeen < Sensitivity
  | extend timestamp = StartTimeUtc
```
