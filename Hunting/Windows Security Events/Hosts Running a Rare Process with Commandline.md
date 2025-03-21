# Hosts Running a Rare Process with Commandline
### Description
This query searches for hosts running a rare process. A rare process has execution requency of less than 1% of the average for 30 days and less than a count of 100 on a given host or less than a 14 count on a given host from the last 7 days.
### References
-
### Microsoft Sentinel
```kusto
  let starttime = todatetime('{{StartTimeISO}}');
  let endtime = todatetime('{{EndTimeISO}}');
  let lookback = starttime - 14d;
  let basic=materialize(
    SecurityEvent
      | where TimeGenerated >= lookback
      | where EventID == 4688
      | where isnotempty(CommandLine) and NewProcessName !endswith ":\\windows\\system32\\conhost.exe" and CommandLine !~ NewProcessName and CommandLine !~ strcat('\"',NewProcessName,'\"'," ")
      | extend CommandLine=tolower(CommandLine)
      | summarize FullCount = count()
                  , Count= countif(TimeGenerated between (starttime .. endtime))
                  , min_TimeGenerated=min(TimeGenerated)
                  , max_TimeGenerated=max(TimeGenerated)
                        by Computer, NewProcessName, CommandLine
      | where Count > 0 and Count < 100);
  let basic_avg = basic
      | summarize Avg = avg(FullCount) by  NewProcessName, CommandLine;
  basic | project-away FullCount
    | join kind=inner
  basic_avg
    on NewProcessName, CommandLine | project-away NewProcessName1, CommandLine1
    | where Count < 7 or (Count <= Avg*0.01 and Count < 100)
    | extend HostName = split(Computer, '.', 0)[0], DnsDomain = strcat_array(array_slice(split(Computer, '.'), 1, -1), '.')
    | extend Host_0_HostName = HostName
    | extend Host_0_DnsDomain = DnsDomain 
```
