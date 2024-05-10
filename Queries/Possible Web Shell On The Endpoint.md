# Possible Web Shell On The Endpoint
## Query Information
#### MITRE ATT&CK Technique(s)

| Technique ID  | Title                                |
| ------------- | ------------------------------------ |
| [[T1505.003]] | Server Software Component: Web Shell |
#### Description 
Attackers install web shells on servers by taking advantage of security gaps, typically vulnerabilities in web applications, in internet-facing servers. These attackers scan the internet, often using public scanning interfaces like shodan.io, to locate servers to target. They may use previously fixed vulnerabilities that unfortunately remain unpatched in many servers, but they are also known to quickly take advantage of newly disclosed vulnerabilities.
#### Risk
Attackers can run arbitrary code on a server by exploiting a vulnerable web application
#### References
- https://www.microsoft.com/en-us/security/blog/2021/02/11/web-shell-attacks-continue-to-rise/
#### Scenario 1
Look for suspicious process that IIS worker process (w3wp.exe), nginx, Apache HTTP server processes (httpd.exe, visualsvnserver.exe), etc. do not typically initiate (e.g., cmd.exe, powershell.exe and /bin/bash)
#### Scenario 2 
Look for suspicious web shell execution, this can identify processes that are associated with remote execution and reconnaissance activity (example: “arp”, “certutil”, “cmd”, “echo”, “ipconfig”, “gpresult”, “hostname”, “net”, “netstat”, “nltest”, “nslookup”, “ping”, “powershell”, “psexec”, “qwinsta”, “route”, “systeminfo”, “tasklist”, “wget”, “whoami”, “wmic”, etc.)
## Microsoft Defender For Endpoint
```kusto
let webservers = dynamic(["beasvc.exe", "coldfusion.exe", "httpd.exe", "owstimer.exe", "visualsvnserver.exe", "w3wp.exe", "tomcat", "apache2", "nginx"]);
let linuxShells = dynamic(["/bin/bash", "/bin/sh", "python", "python3"]);
let windowsShells = dynamic(["powershell.exe", "powershell_ise.exe", "cmd.exe"]);
let exclusions = dynamic(["csc.exe", "php-cgi.exe", "vbc.exe", "conhost.exe"]);
DeviceProcessEvents
| where (InitiatingProcessParentFileName in~(webservers) or InitiatingProcessCommandLine in~(webservers))
| where (InitiatingProcessFileName in~(windowsShells) or InitiatingProcessCommandLine has_any(linuxShells))
| where FileName !in~ (exclusions)
| extend Reason = iff(InitiatingProcessParentFileName in~ (webservers), "Suspicious web shell execution", "Suspicious webserver process")
| summarize by FileName, DeviceName, Reason, InitiatingProcessParentFileName, InitiatingProcessCommandLine
```
## Microsoft Sentinel
```kusto
let webservers = dynamic(["beasvc.exe", "coldfusion.exe", "httpd.exe", "owstimer.exe", "visualsvnserver.exe", "w3wp.exe", "tomcat", "apache2", "nginx"]);
let linuxShells = dynamic(["/bin/bash", "/bin/sh", "python", "python3"]);
let windowsShells = dynamic(["powershell.exe", "powershell_ise.exe", "cmd.exe"]);
let exclusions = dynamic(["csc.exe", "php-cgi.exe", "vbc.exe", "conhost.exe"]);
DeviceProcessEvents
| where (InitiatingProcessParentFileName in~(webservers) or InitiatingProcessCommandLine in~(webservers))
| where (InitiatingProcessFileName in~(windowsShells) or InitiatingProcessCommandLine has_any(linuxShells))
| where FileName !in~ (exclusions)
| extend Reason = iff(InitiatingProcessParentFileName in~ (webservers), "Suspicious web shell execution", "Suspicious webserver process")
| summarize by FileName, DeviceName, Reason, InitiatingProcessParentFileName, InitiatingProcessCommandLine
```
## Tags
- [[KQL]] [[MITRE ATT&CK]] [[Microsoft Defender for Endpoint]] [[Microsoft Sentinel]]