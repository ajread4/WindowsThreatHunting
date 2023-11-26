
# Examine PDFs [T1024.002](https://attack.mitre.org/techniques/T1204/002/)
1. Use ```pdfid.py``` to summarize risky aspects of the file. 
2. Use ```pdf-parser.py``` to search for objects within PDFs. 
3. Use ```peepdf.py``` to summarize aspects of file and search for objects. 
4. Use ```swf_mastah.py``` to extract Flash from PDF files. 
5. Use [origami-pdf](https://github.com/cogent/origami-pdf) to analyze PDFs. 
6. 
# De-obfuscate Code [T1027.010](https://attack.mitre.org/techniques/T1027/010/)
1. Beautify the script using Notepad++ and JSTool plugins such as JSMin and JSFormat. 
2. Use [SpiderMonkey](https://spidermonkey.dev/) to analyze JavaScript and VBScript. 
3. Use [CScript](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cscript) to analyze JavaScript and VBScript. 
4. Use [box-js](https://github.com/CapacitorSet/box-js) within the command line to analyze JavaScript. 
5. Use ```base64dump.py``` to decode Base64 strings. 
# View Embedded Strings [T1024](https://attack.mitre.org/techniques/T1204/)
1. Run ```pestr``` on a linux operating system to view strings on an executable. 
2. Run ```strings -a``` on a linux OS to view strings on an executable. 
3. Run ```strings --encoding=l``` on a lnux OS to view strings of an executable. 
4. Place the file in [PeStudio](https://www.winitor.com/download). 
# Identify WMI Activity [T1047](https://attack.mitre.org/techniques/T1047/)
1. Focus on ShimCache, AmCache.hve, and Prefetch with ```wmic.exe``` on source machine. 
2. Focus on ShimCache, AmCache.hve, and Prefetch with ```wmic.exe```, ```scrons.exe```, ```mofcomp.exe```, or ```wmiprvse.exe``` on target machine. 
3. Use ```eventvwr.msc``` with Microsoft-Windows-WMI-Activity%4Operational for event ID 5857, 5860, and 5861 for ```wmiprvse``` execution. 

# Examine RDP Connections [T1563.002](https://attack.mitre.org/techniques/T1563/002/) [T1210](https://attack.mitre.org/techniques/T1210/)
1. Use ```eventvwr.msc``` with Windows Security Event logs event ID 4648. 
2. Use ```eventvwr.msc``` with Microsoft-Windows-TerminalServices-RDPClient%4Operational for eventid 1024 and 1102 with destination hostname or IP address. 
3. View registry ```NTUSER\Software\Microsoft\Terminal Server Client\Servers ``` to find RDP connections per user. 
4. Focus on ShimCache and AmCache.hve with ```mstsc.exe``` for RDP source machine. 
5. Focus on prefetch with ```mstsc.exe```,```rdpclip.exe``` or ```tstheme.exe```within the name of the file. 
6. View jumplists at ```C:\Users\[username]\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\``` for RDP destinations and times. 
7. Use ```eventvwr.msc``` with Windows Security Event logs event ID 4624 for logon type 10. 
8. Use ```eventvwr.msc``` with Windows Security Event logs event ID 4778/4779 for logon source and username. 
9. Use ```eventvwr.msc``` with Microsoft-Windows-RemoteDesktopServices-RdpCoreTS%4Operational for eventid 131 and 98 for connection attempt IPs and successful connections. 
10. Use ```eventvwr.msc``` with Microsoft-Windows-TerminalServices-RDPClient%4Operational for eventid 1149 with source IP and Logon username. 
14. Use ```eventvwr.msc``` with Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational for eventid 21, 22, 25, and 41 for source IP or logon username. 
15. Focus on ShimCache and AmCache.hve with ```rdpclip.exe``` or ```tstheme.exe``` for RDP destination machine. 

# View Change to Logging [T1070.001](https://attack.mitre.org/techniques/T1070/001/)
1. Use ```eventvwr.msc``` with Windows System Event logs 4719. 

# View Account Changes [T1098](https://attack.mitre.org/techniques/T1098/)
1. Use ```eventvwr.msc``` with Windows Security Event logs event id 4724 to view password reset. 
2. Use ```eventvwr.msc``` with Windows Security Event logs event id 4735 to view local group changes. 
3. Use ```eventvwr.msc``` with Windows Security Event logs event id 4738 to view local password change. 
4. Use ```wevutil.exe``` and search for appropriate Windows Security Eveents logs. 
	- Command to use is ```wevutil.exe qe Security /q:"*[System[EventID=4725 or EventID=4722 or EventID=4723 or EventID=4724 or EventID=4726 or EventID=4767)]]```

# Examine Macros in Word Documents [T1137.001](https://attack.mitre.org/techniques/T1137/001/) [T1564.007](https://attack.mitre.org/techniques/T1564/007/) [T1024.002](https://attack.mitre.org/techniques/T1204/002/)
1. Use [wmd.pl](https://gist.github.com/kost/eb95e623f1b286aee890) to extract metadata. 
2. Use ```olevba.py``` to examine metadata. 
3. Unzip the docx to deflate media and other sections of the document. 
4. Use ```oledump.py``` to view the macros within a document. 
5. View macros within p-code called [pcodedmp.py](https://github.com/bontchev/pcodedmp). 

# Examine RTF Documents [T1024.002](https://attack.mitre.org/techniques/T1204/002/)
1. Use ```rtfdump.py``` to examine the file. 

#  Determine Persistence at Startup in Registry [T1547.001](https://attack.mitre.org/techniques/T1547/001/)
1. View registry at ```HKLM\Software\Microsoft\Windows\CurrentVersion\Runonce```. 
2. View registry at ```HKLM\Software\Microsoft\Windows\CurrentVersion\policies\Explorer\Run```.
3. View registry at ```HKLM\Software\Microsoft\Windows\CurrentVersion\Run```. 
4. View registry at ```HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows\Run```. 
5. View registry at ```HKCU\Software\Microsoft\Windows\CurrentVersion\Run```. 
6. View registry at ```HKCU\Software\Microsoft\Windows\CurrentVersion\Runonce```. 

# Detect External Devices [T1025](https://attack.mitre.org/techniques/T1025/)
1. Track USBs in machine at ```SYSTEM\CurrentControlSet\Enum\USBSTOR``` or ```SYSTEM\CurrentControlSet\Enum\USB```. 
2. Create timeline for USB connections with ```C:\Windows\inf\setupapi.dev.log``` or ```SYSTEM\CurrentControlSet\Enum\USBSTOR\Ven_Prod_Version\USB```. 
3. Find the user with the USB device at ```SYSTEM\MountedDevices``` with a GUID or ```NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2```. 
4. Find the USB volume serial number at ```SOFTWARE\Microsoft\WindowsNT\CurrentVersion\ENDMgmt```. 
5. Find the drive letter for the USB device ```SOFTWARE\Microsoft\Windows Portable Devices\Devices``` or ```SYSTEM\MountedDevices```. 
6. Device mounting creates a link file at ```C:\%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Recent``` or ```C:\%USERPROFILE%\AppData\Roaming\Microsoft\Office\Recent```. 
7. Use ```eventvwr.msc``` with Windows Security Event logs 20001. 
8. View USB connection time at ```HKLM\Software\Microsoft\Windows NT\CurrentVersion\EMDMgmt```. 

# Identify TimeZone [No TTP]
1. Look at ```SYSTEM\CurrentControlSet\Control\TimeZoneInformation``` within the System Hive. 

# Explore File Deletion [T1485](https://attack.mitre.org/techniques/T1485/) [T1070.004](https://attack.mitre.org/techniques/T1070/004/) [T1070.009](https://attack.mitre.org/techniques/T1070/009/)
1. Focus on WordWheelQuery from the START menu located at ```NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery```. 
2. View the Last Visited MRU at ```NTUSER.dat\Software\Microsoft\Windows\CurrentVersion\Explorer\Comdlg32\LastVisited[PID]MRU```. 
3. Focus on the thumbnails/thumbscache that are not deleted after file deletion at ```C:\%USERPROFILE%\AppData\Local\Microsoft\Windows\Explorer```. 
4. Examine the recycle bin at ```C:\$Recycle.bin```. 
5. View files access from IE at ```%USERPROFILE%\AppData\Local\Microsoft\Windows\WebCache\WebCacheV*.dat```. 
6. Use [Rifiuti2](https://github.com/abelcheung/rifiuti2) to exmaine the Recycle Bin. 

# Examine Executables [T1547.004](https://attack.mitre.org/techniques/T1547/004/) [T1059.006](https://attack.mitre.org/techniques/T1059/006/) [T15559.001]([T1070.004](https://attack.mitre.org/techniques/T1559/001/)) [T1027.004]([T1070.004](https://attack.mitre.org/techniques/T1027/004/)) [T1027.004]([T1070.009](https://attack.mitre.org/techniques/T1027/009/)) [T1055.002](https://attack.mitre.org/techniques/T1055/002)
1. View the registry at ```NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count``` where the GUID is specific for the OS. 
2. View the Windows Background Activity Monitor at ```SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}``` or ```SYSTEM\CurrentControlSet\Services\dam\UserSettings\{SID}```
3. View the Last Visited MRU at ```NTUSER.dat\Software\Microsoft\Windows\CurrentVersion\Explorer\Comdlg32\LastVisited[PID]MRU```. 
4. View the RunMRU at ```NTUser.dat\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU``` for Start-> Run execution. 
5. View the RecentApps key for program execution at ```NTUser.dat\Software\Microsoft\Windows\Current Version\Search\RecentApps``` where each GUID is a specific application. 
6. View the AppCompatCache to determine time of execution and name of executable at ```SYSTEM\CurrentControlSet\Control\SessionManager\AppCompatCache```. 
7. Utilize jump lists at ```C:\%UserProfile%\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations``` to view user access of executables. 
8. Use ```PECmd.exe``` (from Eric Zimmerman [here](https://ericzimmerman.github.io/#!index.md) with Command line. 
	- Command to use ```PECmd.exe -f [prefetch_file]```
9. View prefetch files at ```C:\Windows\Prefetch``` for program execution. 
10. View the Amcache or recentfile cache for data storage during process creation at ```C:\Windows\AppCompat\Programs\Amcache.hve```.
11. Run ```pestr``` on a linux operating system to view strings on an executable. 
12. Run ```strings -a``` on a linux OS to view strings on an executable. 
13. Run ```strings --encoding=l``` on a lnux OS to view strings of an executable. 
14. Place the file in [PeStudio](https://www.winitor.com/download). 
15. Run ```peframe``` on a linux machine to view imports and other file properties. 
16. Place the file in [DetectItEasy](https://github.com/horsicq/Detect-It-Easy). 
17. Place the file in [ExeInfoPE](http://www.exeinfo.byethost18.com/?i=1). 
18. Analyze the file with [signsrch](https://aluigi.altervista.org/mytoolz.htm). 
19. Analyze the file with [pescan](https://tzworks.com/prototype_page.php?proto_id=15). 
20. Analyze the file with [MASTIFF](https://git.korelogic.com/mastiff.git/). 
21. Analyze the file with [Exiftool](https://exiftool.org/). 
22. Analyze the file with [TrID](https://mark0.net/soft-trid-e.html). 
23. Analyze the file with [Viper](https://github.com/viper-framework/viper). 
24. Analyze the file with [PortEx](https://github.com/struppigel/PortEx).
25. Examine the execution within [ProcDot](https://www.procdot.com/downloadprocdotbinaries.htm). 

# Examine the Shimcache/Amcache
1. View the AppCompatCache to determine time of execution and name of executable at ```SYSTEM\CurrentControlSet\Control\SessionManager\AppCompatCache```. 
2. View the Amcache or recentfile cache for data storage during process creation at ```C:\Windows\AppCompat\Programs\Amcache.hve```. 
3. Focus on ShimCache and AmCache.hve with ```mstsc.exe``` for RDP source connections. 
4. Focus on ShimCache and AmCache.hve with ```rdpclip.exe``` or ```tstheme.exe``` for RDP destination machine. 

# Examine Application Crashes [T1499.004](https://attack.mitre.org/techniques/T1499/004)
1. Use ```eventvwr.msc``` with Windows Security Event logs 1001. 

# Examine SMB Shares/Sessions [T1021](https://attack.mitre.org/techniques/T1021/002/)
1. Use ```Get-WmiObject``` within Powershell. 
	- Command to use is ```Get-WmiObject -Class win32_share```
2. Use ```Get-SMBSession``` within Powershell. 
	- Command to use is ```Get-SmbSession | Select-Object ClientComputerName,Dialect,SecondsExist,SecondsIdle```
3. Use ```Get-SMBMapping``` within Powershell. 
4. Examine remotely mapped shares at ```NTUSER\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2``` on source machine. 
5. Look for ShimCache, Amcache, BAM, DAM, or Prefetch with ```net.exe``` or ```net1.exe``` on source machine. 
6. Use ```eventvwr.msc``` with Windows Security Event logs event ID 4648 on source machine. 
7. Use ```eventvwr.msc``` with Windows Security Event logs event ID 4624, 4672, 4776, 4768, 4769, 5140, and 5145 on destination machine. 

# Examine Services [T1569](https://attack.mitre.org/techniques/T1569/) [T1569.002](https://attack.mitre.org/techniques/T1569/002)
1. Use ```Get-Service``` within Powershell.
2. Use ```Get-CimInstance -ClassName Win32_Service | Format-List Name, Caption, Description,PathName``` within Powershell. 
3. Use ```Get-WinEvent``` within Powershell looking for Event ID 7045 in the Security Log. 
	- Command to use is ```Get-WinEvent -LogName System | Where-Object -Property ID -EQ 7045 | Format-List -Property TimeCreated,Message```. 
4. Use [volatility](https://www.volatilityfoundation.org/releases-vol3) with a forensic image. 
	- Version 3 uses windows.svcscan.SvcScan
5. Use ```DeepBlueCLI``` (from [here](https://github.com/sans-blue-team/DeepBlueCLI)) and Powershell. 
6. Use ```eventvwr.msc``` with Windows Security Event logs 4697. 
7. Use ```eventvwr.msc``` with Windows System Event logs 7034, 7035, 7036, 7040 in that order. 
8. Use ```eventvwr.msc``` with Windows System Event logs 6045 for service installation on a server. 
9. Use ```sc.exe``` to query services. 
	- Command to use ```sc.exe query state= all```
10. Use ```wevutil.exe``` and search for appropriate Windows Security Events logs. 
	- Command to use is ```wevutil.exe qe Security /q:"*[System[(EventID=7045)]]```
11. Use ```eventvwr.msc``` with Windows System Event logs 7045. 
12. View registry for new service creations at ```SYSTEM\CurrentControlSet\Services\[servicename]```. 

# Analyze OneNote Files [T1137](https://attack.mitre.org/techniques/T1137)
1. Use ```OneNoteAnalyzer``` found [here](https://github.com/knight0x07/OneNoteAnalyzer)

# Unsigned Files in C:\Windows\System32 [T1587.002](https://attack.mitre.org/techniques/T1587/002)
1. Use ```sigcheck``` within Sysinternals.
	- ```sigcheck -u -e C:\Windows\System32 -accepteula```

# Alternate Data Streams [T1564.004](https://attack.mitre.org/techniques/T1564/004)
1. Use ```streams``` within Sysinternals
	- ```streams C:\Users\Administrator\Desktop\maliciousfile.txt -accepteula```
2. Use ```more``` to view the ADS files on the command line.
	- ```more < C:\Users\Administrator\Desktop\maliciousfile.txt:ads.txt```
3. Use ```Get-WinEvent``` with Sysmon Event Logs. 
	- Command to use is ```Get-WinEvent -Path <Path to Log> -FilterXPath '*/System/EventID=8'```
4. Use ```eventvwr.msc``` with Sysmon Event logs and Event ID 8. 

# Autoruns [T1547](https://attack.mitre.org/techniques/T1547)
1. Use ```autoruns``` within Sysinternals 
	- ```autoruns```
1. Use ```osquery``` on the Windows Command line. 
	- Command to use in interactive mode is ```select path from autoexec;```. 

# Dump Processes on Host [T1059](https://attack.mitre.org/techniques/T1059)
1. Use ```procdump``` within Sysinternals 
	- ```procdump -accepteula```

# Explore Processes [T1059](https://attack.mitre.org/techniques/T1059)
1. Use ```procexp``` within Sysinternals
	- ```procexp -accepteula```
2. Use [Process Hacker](https://processhacker.sourceforge.io/)
	- Download as Desktop application 
3. Use ```procmon``` within SysInternals
	- ```procmon -accepteula```
4. Use ```Get-WinEvent``` with Sysmon Event Logs. 
	- Command to use is ```Get-WinEvent -Path <Path to Log> -FilterXPath '*/System/EventID=1'```
	- Command to use is ```Get-WinEvent -Path <Path to Log> -FilterXPath '*/System/EventID=8'```
5. Use ```eventvwr.msc``` with Sysmon Event logs and Event ID 1. 
6. Use ```eventvwr.msc``` with Sysmon Event logs and Event ID 8. 
7. Use ```osquery``` on the Windows Command line. 
	- Command to use in interactive mode is ```select sid,path from userassist```. 
8. Use ```DeepBlueCLI``` (from [here](https://github.com/sans-blue-team/DeepBlueCLI)) and Powershell. 
9. Use ```eventvwr.msc``` with Windows Security Event logs 4688. 
10. Use ```Get-Process``` within Powershell.
11. Use ```Get-CimInstance -Class Win32_Process | Select-Object ProcessId, ProcessName,CommandLine``` within Powershell.
12. Use [volatility](https://www.volatilityfoundation.org/releases-vol3) with a forensic image. 
	- Version 3 uses windows.pslist.Pslist, windows.pstree.PsTree, windows.netscan.NetScan, windows.cmdline.Cmdline, windows.dlllist.DllList
13. Use [SRUM Dump](https://github.com/MarkBaggett/srum-dump) to examine system usages related to processes. 
14. View the registry at ```NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count``` where the GUID is specific for the OS. 
15. View the Windows Background Activity Monitor at ```SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}``` or ```SYSTEM\CurrentControlSet\Services\dam\UserSettings\{SID}```
16. View the Last Visited MRU at ```NTUSER.dat\Software\Microsoft\Windows\CurrentVersion\Explorer\Comdlg32\LastVisited[PID]MRU```. 
17. View the RunMRU at ```NTUser.dat\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU``` for Start-> Run execution. 
18. Examine the execution within [ProcDot](https://www.procdot.com/downloadprocdotbinaries.htm). 


# Explore Registry Activity [T1564.001](https://attack.mitre.org/techniques/T1564/001) [T1574](https://attack.mitre.org/techniques/T1574)[T1112](https://attack.mitre.org/techniques/T1112)[T1070.007](https://attack.mitre.org/techniques/T1070/007) [T1070.009](https://attack.mitre.org/techniques/T1070/009)[T1003.002](https://attack.mitre.org/techniques/T1003/002)[T1027.011](https://attack.mitre.org/techniques/T1027/011)[T1137](https://attack.mitre.org/techniques/T1137)[T1012](https://attack.mitre.org/techniques/T1012) [T1033](https://attack.mitre.org/techniques/T1033) [T1569.002](https://attack.mitre.org/techniques/T1569/002) [T1552.002](https://attack.mitre.org/techniques/T1552/002)
1. Use ```procmon``` within SysInternals
	- ```procmon -accepteula```
2. Use ```Get-WinEvent``` with Sysmon Event Logs. 
	- Command to use is ```Get-WinEvent -Path <Path to Log> -FilterXPath '*/System/EventID=13'```
	- Command to use is ```Get-WinEvent -Path <Path to Log> -FilterXPath '*/System/EventID=12'```
3. Use ```eventvwr.msc``` with Sysmon Event logs and Event ID 12. 
4. Use ```eventvwr.msc``` with Sysmon Event logs and Event ID 13. 
5. Use ```eventvwr.msc``` with Windows Security Event logs 4657. 
6. Use ```Get-ChildItem``` with the specific registry key in Powershell.
7. Use ```Get-ItemProperty``` with the specific registry key in Powershell.
8. Use [Regshot](https://github.com/Seabreg/Regshot) to compare initial registry with final registry post execution. 
9. Use [RegRipper](https://github.com/keydet89/RegRipper3.0). 

# Explore Scheduled Tasks [T1036.004](https://attack.mitre.org/techniques/T136/004) [T1053.005](https://attack.mitre.org/techniques/T1053/005)
1. Use ```Get-WinEvent``` with Sysmon Event Logs. 
	- Command to use is ```Get-WinEvent -Path <Path to Log> -FilterXPath '*/System/EventID=1'```
2. Use ```eventvwr.msc``` with Sysmon Event logs and Event ID 1. 
3. Use ```Get-ScheduledTask``` within Powershell. https://learn.microsoft.com/en-us/sysinternals/downloads/procmon
	- Command to use is ```Get-ScheduledTask -TaskName [TaskName]```
4. Use ```Export-ScheduledTask``` within Powershell. 
	- Command to use is ```Get-ScheduledTask -TaskName [Name]```. 
5. Use ```eventvwr.msc``` with Windows Security Event logs 4698. 
6. Use ```eventvwr.msc``` with Windows Security Event logs 4702. 
7. Use ```eventvwr.msc``` with Windows Security Event logs 4699. 
8. Use ```eventvwr.msc``` with Windows Security Event logs 4701. 
9. Identify processes of ```at.exe``` or ```schtasks.exe``` on the source machine. 
10. View registry at ```Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks``` or ```Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree``` on target machine to find scheduled tasks. 

#  Explore Process Thread Activity [T1134.003](https://attack.mitre.org/techniques/T1134/003) [T1574.005](https://attack.mitre.org/techniques/T574/005) [T1574.010](https://attack.mitre.org/techniques/T1574/010) [T1055.003](https://attack.mitre.org/techniques/T1055/003) [T1055.005](https://attack.mitre.org/techniques/T1055/005) [T1620](https://attack.mitre.org/techniques/T1620)
1. Use ```procmon``` within SysInternals
	- ```procmon -accepteula```
2. Use ```Get-WinEvent``` with Sysmon Event Logs and look at the call trace. 
	- Command to use is ```Get-WinEvent -Path <Path to Log> -FilterXPath '*/System/EventID=10'``` 
3. Use ```eventvwr.msc``` with Sysmon Event logs and look at call trace in Event ID 10. 
4. Use ```osquery``` on the Windows Command line. 
	- Command to use in interactive mode is ```select sid,path from userassist;```. 
5. Use ```DeepBlueCLI``` (from [here](https://github.com/sans-blue-team/DeepBlueCLI)) and Powershell. 
6. Examine the execution within [ProcDot](https://www.procdot.com/downloadprocdotbinaries.htm). 

# Explore File Read Activity [No TTP]
1. Use ```procmon``` within SysInternals
	- ```procmon -accepteula```
2. Use ```LECmd.exe``` (from Eric Zimmerman [here](https://ericzimmerman.github.io/#!index.md) with Command line. 
	- Command to use ```LECmd.exe -f [shortcut_file]```
	- Shortcut files: ```C:\Users\<username>\AppData\Roaming\Microsoft\Windows\Recent\``` or ```C:\Users\<username>\AppData\Roaming\Microsoft\Office\Recent\```
3. View the OpenSaveMRU to detect file opening at ```NTUSER.dat\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSave[PID]MRU```. 
4. View the Last Visited MRU at ```NTUSER.dat\Software\Microsoft\Windows\CurrentVersion\Explorer\Comdlg32\LastVisited[PID]MRU```. 
5. Examine the RecentFiles at ```NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs```. 
6. Examine Office RecentFiles at ```NTUSER.DAT\Sofware\Microsoft\Office\VERSION```. 
7. Focus on Shellbags for find file access at ```NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU``` or ```NTUSER.DAT\Software\Microsoft\Windows\Shell\Bags```. 
8. Each open of file creates a link file at ```C:\%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Recent``` or ```C:\%USERPROFILE%\AppData\Roaming\Microsoft\Office\Recent```. 
9. Utilize jump lists at ```C:\%UserProfile%\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations``` to view user access of files. 
10. Use ```PECmd.exe``` (from Eric Zimmerman [here](https://ericzimmerman.github.io/#!index.md) with Command line. 
	- Command to use ```PECmd.exe -f [prefetch_file]```
11. View prefetch files at ```C:\Windows\Prefetch``` for program execution. 
12. View files access from IE at ```%USERPROFILE%\AppData\Local\Microsoft\Windows\WebCache\WebCacheV*.dat```. 


# Explore File Download [T1546.016](https://attack.mitre.org/techniques/T1546/016) [T1027.006](https://attack.mitre.org/techniques/T1027/006) [T1566.002](https://attack.mitre.org/techniques/T1566/002) [T1218.001](https://attack.mitre.org/techniques/T1218/001) [T1189](https://attack.mitre.org/techniques/T1189) [T1203](https://attack.mitre.org/techniques/T1203)[T1608.004](https://attack.mitre.org/techniques/T1608/004) [T1218.005](https://attack.mitre.org/techniques/T1218/005) [T1204.001](https://attack.mitre.org/techniques/T1204/001) [T1176](https://attack.mitre.org/techniques/T1176) [T1185](https://attack.mitre.org/techniques/T1185)
1. View the MRU at ```NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSave[PID]MRU```. 
2. View email attachments at ```%USERPROFILE%\AppData\Local\Microsoft\Outlook```. 
3. View skype history at ```C\%USERPROFILE%\AppData\Roaming\Skype\[skypename]```.
4. View IE user account and download history at ```%USERPROFILE%\AppData\Local\Microsoft\Windows\WebCache\WebCacheV*.dat```. 
5. View Firefox user account at ```%USERPROFILE%\AppData\Roaming\Mozilla\Firefox\Profiles\[randomtext].default\places.sqlite```.
6. View chrome user account at ```%USERPROFILE%\AppData\Local\Google\Chrome\UserData\Default\History```. 
7. View firefox download history at ```%USERPROFILE%\AppData\Roaming\Mozilla\Firefox\Profiles\[randomtext].default\downloads.sqlite```.

# View Email Attachments [T1566.001](https://attack.mitre.org/techniques/T1566/001)[T1566.002](https://attack.mitre.org/techniques/T1566/002)
1. View email attachments at ```%USERPROFILE%\AppData\Local\Microsoft\Outlook```. 

# View Skype History [No TTP]
1. View skype history at ```C\%USERPROFILE%\AppData\Roaming\Skype\[skypename]```.

# View Firefox History [T1189](https://attack.mitre.org/techniques/T1189) [T1203](https://attack.mitre.org/techniques/T1203)[T1608.004](https://attack.mitre.org/techniques/T1608/004) [T1218.001](https://attack.mitre.org/techniques/T1218/001) [T1218.005](https://attack.mitre.org/techniques/T1218/005) [T1204.001](https://attack.mitre.org/techniques/T1204/001) [T1176](https://attack.mitre.org/techniques/T1176) [T1185](https://attack.mitre.org/techniques/T1185)
1. View Firefox user account and history at ```%USERPROFILE%\AppData\Roaming\Mozilla\Firefox\Profiles\[randomtext].default\places.sqlite```. 
2. View firefox download history at ```%USERPROFILE%\AppData\Roaming\Mozilla\Firefox\Profiles\[randomtext].default\downloads.sqlite```.
3. Focus on cookiest at ```%\USERPROFILE%\AppData\Roaming\Mozilla\Firefox\Profiles\[random].default\cookies.sqlite```. 
4. Look at user cache at ```\%USERPROFILE%\AppData\Local\Mozilla\Firefox\Profiles\[random].default\Cache```. 
5. View the session restore within ```%\USERPROFILE%\AppData\Roaming\Mozilla\Firefox\Profiles\[random].default\sessionstore.js```. 
6. View flash cookies at ```%APPDATA%\Roaming\Macromedia\FlashPlayer\#SharedObjects\[random]```. 

# View Chrome History [T1189](https://attack.mitre.org/techniques/T1189) [T1203](https://attack.mitre.org/techniques/T1203)[T1608.004](https://attack.mitre.org/techniques/T1608/004) [T1218.001](https://attack.mitre.org/techniques/T1218/001) [T1218.005](https://attack.mitre.org/techniques/T1218/005) [T1204.001](https://attack.mitre.org/techniques/T1204/001) [T1176](https://attack.mitre.org/techniques/T1176) [T1185](https://attack.mitre.org/techniques/T1185)
1. View chrome user account and history at ```%USERPROFILE%\AppData\Local\Google\Chrome\User Data\Default\History```. 
2. Focus on cookies at ```%\USERPROFILE%\AppData\Local\Google\Chrome\UserData\Default\Local Storage```. 
3. Look at user cache at ```%USERPROFILE%\AppData\Local\Google\Chrome\User Data\Default\Cache```. 
4. Look at session restore data at ```%USERPROFILE%\AppData\Local\Google\Chrome\User Data\Default```. 
5. View flash cookies at ```%APPDATA%\Roaming\Macromedia\FlashPlayer\#SharedObjects\[random]```. 

# Explore Internet Explorer or Edge Browsing History [T1189](https://attack.mitre.org/techniques/T1189) [T1203](https://attack.mitre.org/techniques/T1203)[T1608.004](https://attack.mitre.org/techniques/T1608/004) [T1218.001](https://attack.mitre.org/techniques/T1218/001) [T1218.005](https://attack.mitre.org/techniques/T1218/005) [T1204.001](https://attack.mitre.org/techniques/T1204/001) [T1176](https://attack.mitre.org/techniques/T1176) [T1185](https://attack.mitre.org/techniques/T1185)
1. Use ```Autopsy``` as a secondary tool. 
	- View information located at: ```C:\Users\<username>\AppData\Local\Microsoft\Windows\WebCache\WebCacheV*.dat```
2. Focus on cookies at ```%\USERPROFILE%\AppData\Roaming\Microsoft\Windows\Cookies``` or ```%\USERPROFILE%\AppData\Local\Microsoft\Windows\INetCookies```. 
3. Look at user cache or Edge at  ```\%USERPROFILE%\AppData\Local\Packages\microsoft.microsoftedge_[APPID]\AC\MicrosoftEdge\Cache``` or for IE at ```%\USERPROFILE%\AppData\Local\Microsoft\Windows\INetCache\IE```. 
4. Look at session restore data in IE at ```%USERPROFILE%\AppData\Local\Microsoft\Internet Explorer\Recovery```. 
5. View flash cookies at ```%APPDATA%\Roaming\Macromedia\FlashPlayer\#SharedObjects\[random]```. 
6. Use [Pasco](https://github.com/bauman/python-pasco) to inspect ```index.dat``` file. 

# View Cookies [T1606.001](https://attack.mitre.org/techniques/T1606/001) [T1539](https://attack.mitre.org/techniques/T1539) [T1550.004](https://attack.mitre.org/techniques/T1550/004)
1. Focus on cookies at ```%\USERPROFILE%\AppData\Roaming\Microsoft\Windows\Cookies``` or ```%\USERPROFILE%\AppData\Local\Microsoft\Windows\INetCookies```. 
2. Focus on cookies at ```%\USERPROFILE%\AppData\Local\Google\Chrome\UserData\Default\Local Storage```. 
3. Focus on cookiest at ```%\USERPROFILE%\AppData\Roaming\Mozilla\Firefox\Profiles\[random].default\cookies.sqlite```.
4. View flash cookies at ```%APPDATA%\Roaming\Macromedia\FlashPlayer\#SharedObjects\[random]```. 

# Explore Deleted Files [T1070.004](https://attack.mitre.org/techniques/T1070/004) [T1485](https://attack.mitre.org/techniques/T1485)
1. Use ```Autopsy``` as a secondary tool.  
2. Use ```LECmd.exe``` (from Eric Zimmerman [here](https://ericzimmerman.github.io/#!index.md) with Command line. 
	- Command to use ```LECmd.exe -f [shortcut_file]```
	- Shortcut files: ```C:\Users\<username>\AppData\Roaming\Microsoft\Windows\Recent\``` or ```C:\Users\<username>\AppData\Roaming\Microsoft\Office\Recent\```

# Explore Shortcut Files [T1080](https://attack.mitre.org/techniques/T1080) [T1547.009](https://attack.mitre.org/techniques/T1547/009) [T1222](https://attack.mitre.org/techniques/T1222) [T1204.002])(https://attack.mitre.org/techniques/T1204/002)
1. Use ```LECmd.exe``` (from Eric Zimmerman [here](https://ericzimmerman.github.io/#!index.md) with Command line. 
	- Command to use ```LECmd.exe -f [shortcut_file]```
	- Shortcut files: ```C:\Users\<username>\AppData\Roaming\Microsoft\Windows\Recent\``` or ```C:\Users\<username>\AppData\Roaming\Microsoft\Office\Recent\```
2. Each open of file creates a link file at ```C:\%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Recent``` or ```C:\%USERPROFILE%\AppData\Roaming\Microsoft\Office\Recent```. 

# Explore File Write Activity [No TTP]
1. Use ```procmon``` within SysInternals
	- ```procmon -accepteula```
2. Use ```LECmd.exe``` (from Eric Zimmerman [here](https://ericzimmerman.github.io/#!index.md) with Command line. 
	- Command to use ```LECmd.exe -f [shortcut_file]```
	- Shortcut files: ```C:\Users\<username>\AppData\Roaming\Microsoft\Windows\Recent\``` or ```C:\Users\<username>\AppData\Roaming\Microsoft\Office\Recent\```

# Explore Prefetch Files [T1204](https://attack.mitre.org/techniques/T1204)
1. Use ```PECmd.exe``` (from Eric Zimmerman [here](https://ericzimmerman.github.io/#!index.md) with Command line. 
	- Command to use ```PECmd.exe -f [prefetch_file]```
2. View prefetch files at ```C:\Windows\Prefetch``` for program execution. 
# Parse Windows 10 Timeline [No TTP]
1. Use ```WxTCmd.exe``` (from Eric Zimmerman [here](https://ericzimmerman.github.io/#!index.md) on Windows Command line. 
	- Command to use ```WxTCmd.exe -f [timeline_file]```
	- Timeline file: ```C:\Users\<username>\AppData\Local\ConnectedDevicesPlatform\{randomfolder}\ActivitiesCache.db```

# Parse Windows Jump Lists [No TTP]
1. Use ```JLECmd.exe``` (from Eric Zimmerman [here](https://ericzimmerman.github.io/#!index.md) on Windows Command line. 
	- Command to use ```JLECmd.exe -f [jumplist_file]```
	- Jump List file: ```C:\Users\<username>\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations```

# Explore File Creation Activity
1. Use ```Get-WinEvent``` with Sysmon Event Logs. 
	- Command to use is ```Get-WinEvent -Path <Path to Log> -FilterXPath '*/System/EventID=11'```
2. Use ```eventvwr.msc``` with Sysmon Event logs and Event ID 11. 
3. Use ```LECmd.exe``` (from Eric Zimmerman [here](https://ericzimmerman.github.io/#!index.md) with Command line. 
	- Command to use ```LECmd.exe -f [shortcut_file]```
	- Shortcut files: ```C:\Users\<username>\AppData\Roaming\Microsoft\Windows\Recent\``` or ```C:\Users\<username>\AppData\Roaming\Microsoft\Office\Recent\```

# Explore Powershell Activity [T1059.001](https://attack.mitre.org/techniques/T1059/001) [T1546.013](https://attack.mitre.org/techniques/T1546/013)
1. Use ```eventvwr.msc``` on a Windows system and navigate to Applications and Services Logs -> Microsoft -> Windows -> PowerShell -> Operational. 
2. Use ```DeepBlueCLI``` (from [here](https://github.com/sans-blue-team/DeepBlueCLI)) and Powershell. 
3. Use ```wevutil.exe``` to find Powershell execution. 
	- Command to use is ```wevutil.exe qe “Windows PowerShell” /q:"*[System[(EventID=501 or EventID=500)]]"```
4. Use ```wevutil.exe``` to find Powershell execution to find Get calls. 
	- Command to use is ```wevutil.exe qe "Microsoft-Windows-PowerShell/Operational" /q:"*[System[(EventID=4104)]]" /c:1000 /rd:true /f:text | findstr /i "Get-"```
5. Use ```wevutil.exe``` to find Powershell execution to find invoke execution calls. 
	- Command to use is ```wevutil.exe qe "Microsoft-Windows-PowerShell/Operational" /q:"*[System[(EventID=4104)]]" /c:1000 /rd:true /f:text | findstr /i "iex"```
6. Focus on ShimCache, AmCache.hve, Prefetch, DAM, and BAM with ```powershell.exe``` on source machine.
7. Use ```eventvwr.msc``` to view  Microsoft-Windows-WinRM%4Operational logs for event id 6, 8, 15, 16, or 33 on source machine for remote connection. 
8. Use ```eventvwr.msc``` to view  Microsoft-Windows-PowerShell%4Operational for event id 40961, 40962, 8193, 8194, and 8197 on source machine for remote connection. 
9. Use ```eventvwr.msc``` to view  Microsoft-Windows-PowerShell%4Operational for event id 4103, 4104, 53504 on target machine for remote connection. 
10. Use ```eventvwr.msc``` to view  Microsoft-Windows-WinRM%4Operational logs for event id 91 or 168 on target machine for remote connection. 

# View PowerShell Command Execution [T1059.001](https://attack.mitre.org/techniques/T1059/001) [T1546.013](https://attack.mitre.org/techniques/T1546/013)
1. Use ```eventvwr.msc``` on a Windows system and navigate to Applications and Services Logs -> Microsoft -> Windows -> PowerShell -> Operational and look for EventID 4104.  
2. Use ```eventvwr.msc``` on a Windows system and navigate to Applications and Services Logs -> Microsoft -> Windows -> PowerShell -> Operational and look for EventID 800. 
3. Use ```eventvwr.msc``` on a Windows system and look for event ID 4104 within the Powershell (Microsoft-Windows-Powershell) log. 
4. Use ```DeepBlueCLI``` (from [here](https://github.com/sans-blue-team/DeepBlueCLI)) and Powershell. 
5. Focus on ShimCache, AmCache.hve, Prefetch, DAM, and BAM with ```powershell.exe``` on source machine.

# Determine the Number Of Log Names [No TTP]
1. Use ```wevutil.exe``` with Powershell 
	- Command is ```wevutil.exe el```
2. Use ```Get-WinEvent``` with Powershell
	- Command is ```Get-WinEvent -ListLog *```

# Determine User Account Creation [T1078.002](https://attack.mitre.org/techniques/T1078/002) [T1136.002](https://attack.mitre.org/techniques/T1136/002) [T1098](https://attack.mitre.org/techniques/T1098)
1. Use ```Get-WinEvent``` with XPath queries using PowerShell. 
	- Command would be ```Get-WinEvent -LogName Security -FilterXPath '*/System/EventID=4720 and */EventData/Data[@Name="TargetUserName"]="[UserName]"'```
2. Use ```DeepBlueCLI``` (from [here](https://github.com/sans-blue-team/DeepBlueCLI)) and Powershell. 

# Determine PowerShell Down Grade Attack [T1059.001](https://attack.mitre.org/techniques/T1059/001) [T1546.013](https://attack.mitre.org/techniques/T1546/013)
1. Use ```Get-WinEvent``` using PowerShell. 
	- Command would be ```Get-WinEvent -LogName "Windows PowerShell" | Where-Object Id -eq 400 | Foreach-Object {$version = [Version] (
            $_.Message -replace '(?s).*EngineVersion=([\d\.]+)*.*','$1')
        if($version -lt ([Version] "5.0")) { $_ }}```
2. User ```eventvwr.msc``` on a Windows system and filter for event ID 400 within the PowerShell logs. 
	- ```EngineVersion``` will have a different number than other PowerShell logs 

# Determine Log Clearing [T1070.001](https://attack.mitre.org/techniques/T1070/004) [T1485](https://attack.mitre.org/techniques/T1485)
1. Use ```eventvwr.msc``` on a Windows system and filter for event ID 104 within the Microsoft-Windows-Eventlog source. 
2. Use ```eventvwr.msc``` with Windows Security Event logs 517. 
3. Use ```eventvwr.msc``` with Windows Security Event logs 1102 to view Audit log clearing. 

# Explore Group Enumeration [T1069](https://attack.mitre.org/techniques/T1069)
1. Use ```eventvwr.msc``` on a Windows system and filter for event ID 4799 within Security event logs. 

# Determine Number of Network Connections [T1021](https://attack.mitre.org/techniques/T1021)
1. Use ```Get-WinEvent``` with Sysmon Event Logs. 
	- Command to use is ```Get-WinEvent -Path <Path to Log> -FilterXPath '*/System/EventID=3 | Measure-Object```

# Find Common Meterpreter Connections [T1572](https://attack.mitre.org/techniques/T1572) [T1090](https://attack.mitre.org/techniques/T1090) [T1001](https://attack.mitre.org/techniques/T1001) [T1041](https://attack.mitre.org/techniques/T1041)
1. Use ```Get-WinEvent``` with Sysmon Event Logs. 
	- Command to use is ```Get-WinEvent -Path <Path to Log> -FilterXPath '*/System/EventID=3 and */EventData/Data[@Name="DestinationPort"] and */EventData/Data=4444'```
	- Command to use is ```Get-WinEvent -Path <Path to Log> -FilterXPath '*/System/EventID=3 and */EventData/Data[@Name="DestinationPort"] and */EventData/Data=5555```

# Find Mimikatz Execution [T1003.005](https://attack.mitre.org/techniques/T1003/005) [T1003.004](https://attack.mitre.org/techniques/T1003/006) [T1003.001](https://attack.mitre.org/techniques/T1003/001) [T1649](https://attack.mitre.org/techniques/T1649) [T1558.001](https://attack.mitre.org/techniques/T1558/001) [T1558.002](https://attack.mitre.org/techniques/T1558.002) [T1552.004](https://attack.mitre.org/techniques/T1552/004) [T1550.002](https://attack.mitre.org/techniques/T1550/002) [T1550.003](https://attack.mitre.org/techniques/T1550/003) [T1555](https://attack.mitre.org/techniques/T1555)
1. Use ```Get-WinEvent``` with Sysmon Event Logs. 
	- Command to use is ```Get-WinEvent -Path <Path to Log> -FilterXPath '*/System/EventID=10 and */EventData/Data[@Name="TargetImage"] and */EventData/Data="C:\Windows\system32\lsass.exe"'```
2. Use ```DeepBlueCLI``` (from [here](https://github.com/sans-blue-team/DeepBlueCLI)) and Powershell. 
3. View the Last Visited MRU at ```NTUSER.dat\Software\Microsoft\Windows\CurrentVersion\Explorer\Comdlg32\LastVisited[PID]MRU```. 
4. Examine the execution within [ProcDot](https://www.procdot.com/downloadprocdotbinaries.htm). 

# Find Common RAT Connections. [T1021](https://attack.mitre.org/techniques/T1021)
1. Use ```Get-WinEvent``` with Sysmon Event Logs. 
	- Command to use is ```Get-WinEvent -Path <Path to Log> -FilterXPath '*/System/EventID=3 and */EventData/Data[@Name="DestinationPort"] and */EventData/Data=8080'```
2. Use ```DeepBlueCLI``` (from [here](https://github.com/sans-blue-team/DeepBlueCLI)) and Powershell.

# View Installed Programs [T1543](https://attack.mitre.org/techniques/T1543) [T1036.005](https://attack.mitre.org/techniques/T1036/005)[T1569](https://attack.mitre.org/techniques/T1569)
1. Use ```osquery``` on the Windows Command line. 
	- Command to use ```select * from programs;```

# View All Users [T1078.002](https://attack.mitre.org/techniques/T1078/002)[T1136.002]((https://attack.mitre.org/techniques/T1136/002))[T1098](https://attack.mitre.org/techniques/T1098) [T1070.009](https://attack.mitre.org/techniques/T1070/009) [T1531](https://attack.mitre.org/techniques/T1531)
1. Use ```osquery``` on the Windows Command line. 
	- Command to use ```select * from users;```
2. Use ```Get-LocalUser``` within Powershell.
	- Command to use ```Get-LocalUser | Where-Object 'Enabled' -eq $True```
3. Use ```Get-LocalGroup``` within Powershell.
4. Use ```Get-LocalGroupMember``` within Powershell with a specific group in mind.

# Determine Browser Extension [T1176](https://attack.mitre.org/techniques/T1176)
1. Use ```osquery``` on the Windows Command line. 
	- Command to use ```select * from ie_extensions;```

# View UserAssist Activity [No TTP]
1. Use ```osquery``` on the Windows Command line. 
	- Command to use in interactive mode is ```select sid,path from userassist;```. 
2. View the registry at ```NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count``` where the GUID is specific for the OS. 

# Parse $MFT for Windows NTFS [T1564](https://attack.mitre.org/techniques/T1564)
1. Use ```MFTECmd.exe``` on the Windows command line. 
	- Command to use ```MCTECmd.exe -f [file] --csv [path_to_csv_output]```
2. Use ```Autopsy``` as a secondary tool. 

# Parse $Boot for Windows NTFS [T1564](https://attack.mitre.org/techniques/T1564)
1. Use ```MFTECmd.exe``` on the Windows command line. 
	- Command to use ```MCTECmd.exe -f [file] --csv [path_to_csv_output]```
2. Use ```Autopsy``` as a secondary tool. 

# Parse $J for Windows NTFS [T1564](https://attack.mitre.org/techniques/T1564)
1. Use ```MFTECmd.exe``` (from Eric Zimmerman [here](https://ericzimmerman.github.io/#!index.md) on the Windows command line. 
	- Command to use ```MCTECmd.exe -f [file] --csv [path_to_csv_output]```	
2. Use ```Autopsy``` as a secondary tool. 

# Parse $SDS for Windows NTFS [T1564](https://attack.mitre.org/techniques/T1564)
1. Use ```MFTECmd.exe``` (from Eric Zimmerman [here](https://ericzimmerman.github.io/#!index.md) on the Windows command line. 
	- Command to use ```MCTECmd.exe -f [file] --csv [path_to_csv_output]```
2. Use ```Autopsy``` as a secondary tool. 

# Parse Volume Shadow Copies for Windows NTFS [T1564](https://attack.mitre.org/techniques/T1564)
1. Use ```MFTECmd.exe``` (from Eric Zimmerman [here](https://ericzimmerman.github.io/#!index.md) on the Windows command line. 
	- Command to use ```MCTECmd.exe -f [file] --csv [path_to_csv_output]```
2. Use ```Autopsy``` as a secondary tool. 

# Parse $LogFile for Windows NTFS [T1564](https://attack.mitre.org/techniques/T1564)
1. Use ```MFTECmd.exe``` (from Eric Zimmerman [here](https://ericzimmerman.github.io/#!index.md) on the Windows command line. 
	- Command to use ```MCTECmd.exe -f [file] --csv [path_to_csv_output]```
2. Use ```Autopsy``` as a secondary tool. 

# Find Service Creation [T1569.002](https://attack.mitre.org/techniques/T1569/002) [T1543.003](https://attack.mitre.org/techniques/T1543/003)
1. Use ```DeepBlueCLI``` (from [here](https://github.com/sans-blue-team/DeepBlueCLI)) and Powershell. 
2. Use ```eventvwr.msc``` with Windows System Event logs 7045. 
3. Use ```eventvwr.msc``` with Windows Security Event logs 4697. 

# View User Authentications [T1078](https://attack.mitre.org/techniques/T1078/)
1. Use [LogonTracer](https://github.com/JPCERTCC/LogonTracer) to map out logons by users. 
2. Use ```eventvwr.msc``` with Windows Security Event logs 4624. 
3. View the SAM at ```C:\Windows\system32\config\SAM``` or ```SAM\Domains\Account\Users```. 
4. Use ```eventvwr.msc``` with Windows Security Event logs 4625 for failed logons. 
5. Use ```eventvwr.msc``` with Windows Security Event logs 4634 for logoff. 
6. Use ```eventvwr.msc``` with Windows Security Event logs 4647 for logoff. 
7. Use ```eventvwr.msc``` with Windows Security Event logs 4648 for run as login. 
8. Use ```eventvwr.msc``` with Windows Security Event logs 4672 for admin login. 
9. Use ```eventvwr.msc``` with Windows Security Event logs 4778 for RDP login. 
10. Use ```eventvwr.msc``` with Windows Security Event logs 4779 for RDP logoff. 
11. Use ```eventvwr.msc``` with Windows Security Event logs 4776 for NTLM authentication. 
12. Use ```eventvwr.msc``` with Windows Security Event logs 4768 for TGT successful logon. 
13. Use ```eventvwr.msc``` with Windows Security Event logs 4769 for TGS access to service. 
14. Use ```eventvwr.msc``` with Windows Security Event logs 4771 failed ticket logon. 
15. Use ```wevutil.exe``` and search for appropriate Windows Security Eveents logs. 
	- Command to use is ```wevutil.exe qe Security /q:"*[System[(EventID=4624 or EventID=4625)]]```
