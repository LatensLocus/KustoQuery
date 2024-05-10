# User Account Added To Sudoers Group
## Query Information
#### MITRE ATT&CK Technique(s)

| Technique ID  | Title                                                    |
| ------------- | -------------------------------------------------------- |
| [[T1548.003]] | Abuse Elevation Control Mechanism: Sudo and Sudo Caching |
#### Description
This query allows you to hunt for users that have been added to the sudo group. The current list does not contain all additions, but it covers most common additions. More can be added in the commandslist. Users that have been added to the sudoers group have root privileges.
#### Risk
A adversary adds itself to the sudoers group and can perform actions with root privileges. 
## Microsoft Defender For Endpoint

```kusto
let Commands = dynamic([@"usermod -aG sudo", @"usermod -a -G sudo"]);
DeviceProcessEvents
| extend RegexGroupAddition = extract("adduser(.*) sudo", 0, ProcessCommandLine)
| where ProcessCommandLine has_any (Commands) or isnotempty(RegexGroupAddition)
```
## Microsoft Sentinel
```kusto
let Commands = dynamic([@"usermod -aG sudo", @"usermod -a -G sudo"]);
DeviceProcessEvents
| extend RegexGroupAddition = extract("adduser(.*) sudo", 0, ProcessCommandLine)
| where ProcessCommandLine has_any (Commands) or isnotempty(RegexGroupAddition)
```
## Tags
- [[KQL]] [[MITRE ATT&CK]] [[Microsoft Defender for Endpoint]] [[Microsoft Sentinel]]