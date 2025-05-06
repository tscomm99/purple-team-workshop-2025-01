Going back to the basics, a simple keyword can be added to a lookup, for searching or handling exceptions
```
| makeresults 
| eval searchterm="mimikatz" 
| eval insert_datetime=strftime(_time,"%Y-%m-%dT%H:%M:%S") 
| eval operator = "blueteam1" 
| fields - _time
| outputlookup append=true hackingtools.csv
```
```
| makeresults 
| eval searchterm="goodguyhacker" 
| eval insert_datetime=strftime(_time,"%Y-%m-%dT%H:%M:%S") 
| eval operator = "blueteam1" 
| fields - _time
| outputlookup append=true allowlisted_hacking_events.csv
```

Use one or more lookups to feed your query against relevant data sources while silencing others
```
index=win [|inputlookup hackingtools.csv | fields searchterm | rename searchterm AS query] 
| search NOT [|inputlookup allowlisted_hacking_events.csv | fields searchterm | rename searchterm AS query]
```

Events from multiple data sources or tools may need to be normalized for simpler correlation (e.g. user, usr, User, src_usr) without relying on Splunk "schema on the fly" (REF CIM Splunk).
Finally, you can use the collect command to send data to a different index for safekeeping and correlation
```
index IN (win,sysmon,edr1,edr2) [|inputlookup hackingtools.csv | fields searchterm | rename searchterm AS query] | 
| <normalize> 
| collect index=notables_endpoint_hackingtool
```


The CIM helps you to normalize your data to match a common standard, using the same field names and event tags for equivalent events from different sources or vendors. 
The CIM acts as a search-time schema ("schema-on-the-fly") to allow you to define relationships in the event data while leaving the raw machine data intact.
