# Invoke-PowerShellTcpOneLine Usage
### Description
Invoke-PowerShellTcpOneLine is a PowerShell script to create a simple and small reverse shell. It can be abused by attackers to exfiltrate data. This query looks for command line activity similar to Invoke-PowerShellTcpOneLine.
### References
-
### Microsoft Sentinel
```kusto
  SecurityEvent
  | where EventID == 4688
  | where Process has_any ("powershell.exe", "PowerShell_ISE.exe", "cmd.exe")
  | where CommandLine has "$client = New-Object System.Net.Sockets.TCPClient"
  | extend NTDomain = tostring(split(Account,'\\',0)[0]), Name = tostring(split(Account,'\\',1)[0])
  | extend timestamp = TimeGenerated, AccountCustomEntity = Account, HostCustomEntity = Computer, IPCustomEntity = IpAddress
  | extend HostName = tostring(split(Computer, '.', 0)[0]), DnsDomain = tostring(strcat_array(array_slice(split(Computer, '.'), 1, -1), '.'))
  | extend Account_0_Name = Name
  | extend Account_0_NTDomain = NTDomain
  | extend Host_0_HostName = HostName
  | extend Host_0_DnsDomain = DnsDomain
  | extend IP_0_Address = IpAddress
```
