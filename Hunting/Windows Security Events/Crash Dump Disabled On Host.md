# Crash Dump Disabled On Host
### Description
This detection looks the prevention of crash dumps being created. This can be used to limit reporting by malware, look for suspicious processes setting this registry key.
### References
-
### Microsoft Sentinel
```kusto
SecurityEvent
| where EventID == 4657
| parse ObjectName with "\\REGISTRY\\" KeyPrefix "\\" RegistryKey
| project-reorder RegistryKey
| where RegistryKey has "SYSTEM\\CurrentControlSet\\Control\\CrashControl"
| where ObjectValueName =~ "CrashDumpEnabled"
| extend  RegistryValueData = iff (OperationType == "%%1906", OldValue, NewValue)
| where RegistryValueData == 0
| extend NTDomain = tostring(split(Account,'\\',0)[0]), Name = tostring(split(Account,'\\',1)[0])
| extend HostName = tostring(split(Computer, '.', 0)[0]), DnsDomain = tostring(strcat_array(array_slice(split(Computer, '.'), 1, -1), '.'))
| extend Account_0_Name = Name
| extend Account_0_NTDomain = NTDomain
| extend Host_0_HostName = HostName
| extend Host_0_DnsDomain = DnsDomain
```
