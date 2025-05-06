As we've seen, sometimes detections go missing. Looking into Splunk, running a simple search `index=win mimikatz` reveals many events missed. 

Going back to the basics, a simple keyword can be added to a lookup, for future searches
```
| makeresults 
| eval searchterm="mimikatz" 
| eval insert_datetime=strftime(_time,"%Y-%m-%dT%H:%M:%S") 
| eval operator = "blueteam1" 
| fields - _time
| outputlookup append=true hackingtools.csv
```
Or when handling exceptions such as true positive benigns, or false positives.
```
| makeresults 
| eval searchterm="knowngoodhacker" 
| eval insert_datetime=strftime(_time,"%Y-%m-%dT%H:%M:%S") 
| eval operator = "blueteam1" 
| fields - _time
| outputlookup append=true allowlisted_hacking_events.csv
```

Splunk lets you use one or more lookups to feed your query against relevant data sources while silencing others, expanding in "OR" statements
```
index=win [|inputlookup hackingtools.csv | fields searchterm | rename searchterm AS query] 
| search NOT [|inputlookup allowlisted_hacking_events.csv | fields searchterm | rename searchterm AS query]
```

Events from multiple data sources or tools may need to be normalized for simpler correlation (e.g. user, usr, User, src_usr) without relying on Splunk "schema on the fly" (REF CIM Splunk).
When relying on correlation, you can create select summary indexes: Navigate to Settings, Data, Indexes, and find the `New index` button. Enter the name "notables_endpoint_hackingtool" if you would like to follow along.

Finally, you can leverage the collect command to send data to a your summary index for safekeeping and/or correlation
```
index IN (win,sysmon,edr1,edr2) [|inputlookup hackingtools.csv | fields searchterm | rename searchterm AS query] 
| search NOT [|inputlookup allowlisted_hacking_events.csv | fields searchterm | rename searchterm AS query] 
| eval score=10
| eval EventCategory="EndpointHackingKeyword"
| rename _raw AS raw
| table _time, raw, score, EventCategory, host
| collect index=notables_endpoint_hackingtool
```
Once in place, a simple correlation search becomes "easy"
```
index="notables_endpoint_hackingtool" 
| stats count AS CountNotable, sum(score) AS Score, dc(EventCategory) AS CountCategories by orig_host
| where count > 2 OR Score > 20 OR CountCategories > 2
```

The CIM helps you to normalize your data to match a common standard, using the same field names and event tags for equivalent events from different sources or vendors. 
The CIM acts as a search-time schema ("schema-on-the-fly") to allow you to define relationships in the event data while leaving the raw machine data intact.
