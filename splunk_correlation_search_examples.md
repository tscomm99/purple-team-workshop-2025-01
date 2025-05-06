Below is a simple approach to correlating events found in one's environment, which could be adapted to other technologies.
- Create a summary index
- Identify low fidelity searches and normalize their output
- Assign a score and a priority to low fidelity but valuable detection use cases
- Leverage the "collect" command to send events to a summary index
- Search the summary index based on summarized events, per system, user, or behavior, with thresholds.

As an example, we'll proceed to detecting mimikatz, a simple string. 

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

Once the events are aggregated, a simple correlation search becomes "easy" and can be adapted to longer time periods
- for the last 1h? (taking into account the delays due to ingestion and other pipelines)
- for the last 24h?
- for the last 7d?
- # of entities per search?
- # of different searches per entity?
- # of events per entity?

```
index="notables_endpoint_hackingtool" 
| stats count AS CountNotable, sum(score) AS Score, dc(EventCategory) AS CountCategories by orig_host
| where count > 2 OR Score > 20 OR CountCategories > 2
```

The CIM helps you to normalize your data to match a common standard, using the same field names and event tags for equivalent events from different sources or vendors. 
The CIM acts as a search-time schema ("schema-on-the-fly") to allow you to define relationships in the event data while leaving the raw machine data intact.

Below is a real life example of this concept in action.

#### Example search in Splunk to export a notable event (Yes, a look up would be better to support silenced behavior)
```
index=teams download "event.name"=download 
| search NOT "that one user@company.com" ```2023-01-28 analystname silencing the activity of this generic user``` 
| search NOT "that one automated thing@company.com" ```2023-01-28 analystname silencing the activity of this generic user with explicit purpose```
| rex field=_raw "{\"name\": \"owner\", \"value\": \"(?<owner>[^\"]+)\"" 
| search doc_title!="*.log"
| rename "actor.email" AS Username
| stats dc(doc_title) as CountFiles, values(doc_title) as FileNames, values(owner) AS FileOwners, min(_time) AS EarliestTime, max(_time) AS LatestTime by Username, ipAddress, owner_is_team_drive, owner_is_shared_drive, doc_type
| eval EventCategory="Downloads" ```Used to identify source of the data in the summary index```
| iplocation ipAddress
| table EventCategory, Username, ipAddress, EarliestTime, LatestTime, Country, Region, City, lat, lon, owner_is_team_drive, owner_is_shared_drive, doc_type, CountFiles, FileOwners, FileNames
| ldapfilter search="(&(objectclass=user)(mail=$Username$))" attrs="cn, displayName, employeeType, companyIsPrimaryUserID"
| rename cn AS ADUsername
| rename Username AS email
| eval score=5
| collect index=dlp
```
