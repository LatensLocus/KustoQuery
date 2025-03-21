# Remote Task Creation Using Schtasks Process
### Description
This query detects a scheduled task, created/updated remotely, using the Schtasks process.
### References
-
### Microsoft Sentinel
```kusto
   SecurityEvent
   | where EventID == 4688 and NewProcessName == "C:\\Windows\\System32\\schtasks.exe" and CommandLine has " /s "
   | summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated) by EventID, Computer, SubjectUserName, CommandLine
```
