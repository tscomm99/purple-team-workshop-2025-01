# We've shown you optimal conditions without much attacker interference
In our workshop the systems are set up with Sysmon, events are generated, logs are flowing, and everything is smooth. In real life, IT operations are far from ideal and each organization is equipped differently. Raising the bar for attackers and ultimately making your life easier implies selecting efforts and picking what makes sense to detect, reliably or opportunistically, and knowing how to respond to alerts. 

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

## Think of capabilities and embrace True Positive Benign and False positives
Have a look at the behavior of certutil and abstract it. Exploit developers think in terms of "primitives" e.g. write what where. In many environments, the use of certutil.exe is supposed to be rare. It is a so-called LOLBIN - Living Off the Land Binary, part of the bigger LOLBAS (Applications and Scripts) family <REF to LOLBAS project>. Certutil is used by many threat actors as downloader, encoder, as it is signed by Microsoft and already installed. This is one less "feature" or "capability" that the authors need to develop and embed in their toolkit to achieve their objectives. Detection opportunities for this kind of behaviors are multiple, and can yield some false positives, or strong signals. This differenciation is the hard work you need to perform, luckily only as you establish the detection (see #baselining). It is often required to run multiple queries in parallel - think of it as a playbook - when reviewing events with low fidelity, effectively treating them as triggers rather than a final product. 

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

For complicated scenarios, you will need to turn to canaries and other early warning systems. 

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
