# Visualize Sign-In Failures Due To Conditional Access Policy

## Query Information

#### Description
This visualization will return the failure types that occur in your tenant that are related to any conditional access failure. This can be used to determine which failures are related to a policy and if strange activity is being performed or if a policy needs to be tuned in a specific manner.
#### References
- https://learn.microsoft.com/en-us/azure/active-directory/develop/reference-error-codes
## Microsoft Sentinel
```kusto
SigninLogs
| where ResultDescription has "Conditional Access"
| summarize Total = count() by ResultType, ResultDescription
| render barchart with(title="Conditional Access Failures")
```
## Tags
- [[KQL]] [[Microsoft Sentinel]]