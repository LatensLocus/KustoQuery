# Domain Controller Installation Media Creation
### Description
This hunting query helps to detect attempts to create installation media from domain controllers, either remotely or locally using a commandline tool called ntdsutil. These media are intended to be used in the installation of new domain controllers.
### References
-
### Microsoft Sentinel
```kusto
(union isfuzzy=true 
(SecurityEvent
| where EventID == 4688
| where CommandLine has_all ("ntdsutil", "ac i ntds", "create full")
| project TimeGenerated, Computer, Account, Process, ProcessId, NewProcessName, NewProcessId, CommandLine, ParentProcessName, _ResourceId, SourceComputerId, SubjectLogonId, SubjectUserSid
),
(WindowsEvent
| where EventID == 4688 
| extend CommandLine = tostring(EventData.CommandLine)
| where CommandLine has_all ("ntdsutil", "ac i ntds", "create full")
| extend NewProcessName = tostring(EventData.NewProcessName), NewProcessId = tostring(EventData.NewProcessId)
| extend Process=tostring(split(NewProcessName, '\\')[-1]),  ProcessId = tostring(EventData.ProcessId)
| extend Account =  strcat(EventData.SubjectDomainName,"\\", EventData.SubjectUserName)
| extend ParentProcessName = tostring(EventData.ParentProcessName) 
| extend SubjectUserName = tostring(EventData.SubjectUserName), SubjectDomainName = tostring(EventData.SubjectDomainName), SubjectLogonId = tostring(EventData.SubjectLogonId)
| project TimeGenerated, Computer, Account, Process, ProcessId, NewProcessName, NewProcessId, CommandLine, ParentProcessName, _ResourceId, SubjectUserName, SubjectDomainName, SubjectLogonId
) 
)
```
