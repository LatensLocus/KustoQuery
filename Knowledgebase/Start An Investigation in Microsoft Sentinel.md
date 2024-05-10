```kusto
search "interest"
| distinct $table
```

```kusto
search in (TableOfInterest) "interest"
```
