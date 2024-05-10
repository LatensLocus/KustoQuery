# User Account Created Using Command-line
## Query Information
#### MITRE ATT&CK Technique(s)

| Technique ID  | Title                          |
| ------------- | ------------------------------ |
| [[T1136.001]] | Create Account: Local Account  |
| [[T1136.002]] | Create Account: Domain Account |
#### Description
This query is aimed to detect users that are added via the command-line. Adding users via the command-line is a common technique used by adversaries to gain persistence on systems. Some examples of command-lines used by adversaries are shown below.

```cmd
net user username \password \domain
net user /add /domain
```
#### Risk
An attacker got access to a system and created an account for persistence.
#### References
- https://www.huntress.com/blog/slashandgrab-screen-connect-post-exploitation-in-the-wild-cve-2024-1709-cve-2024-1708
## Microsoft Defender For Endpoint
```kusto
DeviceProcessEvents
| where FileName in ("net.exe", "net1.exe")
| where ProcessCommandLine has_all ("add", "user") 
| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessCommandLine
```
## Microsoft Sentinel
```kusto
DeviceProcessEvents
| where FileName in ("net.exe", "net1.exe")
| where ProcessCommandLine has_all ("add", "user") 
| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessCommandLine
```
## Tags
- [[KQL]] [[MITRE ATT&CK]] [[Microsoft Defender for Endpoint]] [[Microsoft Sentinel]]