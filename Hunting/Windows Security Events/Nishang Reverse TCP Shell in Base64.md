# Nishang Reverse TCP Shell in Base64
### Description
This query searches for Base64-encoded commands associated with the Nishang reverse TCP shell.
### References
- https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1
### Microsoft Sentinel
```kusto
  SecurityEvent
  | where EventID == 4688
  | where Process in("powershell.exe","powershell_ise.exe") and CommandLine has "-e" 
  | mv-expand SS = split(CommandLine, " ") 
  | where SS matches regex "[A-Za-z0-9+/]{50,}[=]{0,2}" 
  | extend DecodeString = base64_decode_tostring(tostring(SS)) 
  | extend FinalString = replace("\\0", "", DecodeString) 
  | where FinalString has "tcpclient" and FinalString contains "$" and (FinalString contains "invoke" or FinalString contains "iex") 
  | extend timestamp = TimeGenerated, HostName = split(Computer, '.', 0)[0], DnsDomain = strcat_array(array_slice(split(Computer, '.'), 1, -1), '.')
  | extend Account_0_Name = SubjectUserName
  | extend Account_0_NTDomain = SubjectDomainName
  | extend Host_0_HostName = HostName
  | extend Host_0_DnsDomain = DnsDomain 
```
