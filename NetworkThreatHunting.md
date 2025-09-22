# Find SQL Injection [T1190](https://attack.mitre.org/techniques/T1190/)
1. Look for ```'```, ```---```, ```#```, ```UNION```, ```WAITFOR DELAY```, and ```SLEEP()``` statements in web traffic. 

# Find Cross Site Scripting [T1189](https://attack.mitre.org/techniques/T1189/)
1. Look for ```<script>```, ```onmouseover```, ```onclick```, and ```onerror``` statements in traffic. 

# Find Path Traversal
1. Look for traffic with ```/etc/shadow``` and ```/etc/passwd``` in the traffic. 
2. Look for traffic with ```%2E%2E%2F%2E%2E%2F``` url encoded data. 

# Detect Self Signed Certificates [T1587.003](https://attack.mitre.org/techniques/T1587/003/)
1. Identify Server or Client traffic in Wireshark with "Certificate, Server Key Exchange, Server Hello Done" and identify the issuer and subject. If same, then self signed. 

# Detect Zone Transfer [T1590.002](https://attack.mitre.org/techniques/T1590/002/)
1. Use WireShark to find DNS zone transfers with ```dns.qry.type == 252```. 

# Detect Port Scanning [T1595.001](https://attack.mitre.org/techniques/T1595/001/)
1. Filter traffic in WireShark for source and destination IP with SYN ACK (```tcp.flags == 0x0012```) to show ports that responded to SYN from the adversary. 
2. Filter traffic in WireShark for source and destination IP with reset flag set by the target using ```tcp.flags.reset == 1```. 

# Identify Web Scanning [T1595.003](https://attack.mitre.org/techniques/T1595/003/)
1. Filter traffic in WireShark to display the various URIs and GET requests from HTTP traffic. A large number means adversary is web scanning. 
2. Look for all subdomains during web scanning in WireShark with ````_ws.col.info == "HTTP/1.1 200 OK  (text/html)"````.

# Identify LLMNR Poisoning [T1557.001](https://attack.mitre.org/techniques/T1557/001/)
1. Filter for "LLMNR" traffic within wireshark pcap and identify numerous resquests and response failures from a machine. There will be NTLMSSP_NEGOTIATE, NTLMSSP_CHALLENGE, and NTLMSSP_AUTH messages. 

# Identify Credential Stuffing [T1110.004](https://attack.mitre.org/techniques/T1110/004/)
1. Use ```wireshark``` with http traffic to identify username and password combinations to the same destination IP address, repeatedly using POST REQUESTS, and in quick succession. The HTTP status of 404 is a common response from the target. 
2. Use ```tshark``` to filter and identify repeated POST requests with username and password combinations. 
	- Command line: ```$ tshark -Y "http.request.method==POST and ip.src ==156.146.62.213 and http.request.uri contains loginservice" -r meerkat.pcap -T fields -e text | cut -d " " -f 7,11 | sort | uniq```

# View Network Connections to Workstation [No TTP]
1. Use ```tcpview``` within Sysinternals 
	- ```tcpview -accepteula```
2. Use the native to windows,```resmon``` via command line
	- ```resmon```
3. Use ```procmon``` within SysInternals
	- ```procmon -accepteula```
4. Use ```zeek``` with conn.log from a pcap
	- ```zeek-cut``` can be beneficial on the command line to pick specific fields
5. Use ```Get-NetTCPConnection -State Listen | Select-Objecct -Property LocalAddress,LocalPort,OwingProcess``` within Powershell
6. Use ```tcpdump``` on the command line. 
	- Command to use is ```tcpdump -r file -n ```
7. Use [volatility](https://www.volatilityfoundation.org/releases-vol3) with a forensic image. 
	- Version 3 uses windows.netscan.NetScan
8. Use [Rita](https://github.com/activecm/rita) to find beaconing activity. 
9. Use [SRUM Dump](https://github.com/MarkBaggett/srum-dump) to examine system usages related to processes. 
10. View old network connections at ```SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged``` or ```SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed``` or ```SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Nla\Cache```. 
11. Use ```eventvwr.msc``` with Windows Security Event logs 5156 for Windows Filtering Platform permitted connections. 

# View Network Flow to/from Workstations [No TTP]
1. Use ```zeek``` with conn.log from a pcap
	- ```zeek-cut``` can be beneficial on the command line to pick specific fields
2. Use [Rita](https://github.com/activecm/rita) to find beaconing activity. 

# View DHCP Leases [No TTP]
1. Use ```zeek``` with dhcp.log from pcap
	- ```zeek-cut``` can be beneficial on the command line to pick specific fields
2. Use Wireshark and filter on DHCP traffic. 

# View DNS Activity [No TTP]
1. Use ```zeek``` with dns.log from pcap
	- ```zeek-cut``` can be beneficial on the command line to pick specific fields
2. Use Wireshark and filter on DNS traffic. 
3. Use [Rita](https://github.com/activecm/rita) to find beaconing activity. 
4. Use WireShark to find DNS zone transfers with ```dns.qry.type == 252```. 

# View SNMP Activity [No TTP]
1. Use ```zeek``` with snmp.log from pcap
	- ```zeek-cut``` can be beneficial on the command line to pick specific fields
2. Use Wireshark and filter on SNMP traffic. 

# View Syslog Activity [No TTP]
1. Use ```zeek``` with syslog.log from pcap
	- ```zeek-cut``` can be beneficial on the command line to pick specific fields

# View File Hashes In Transit [T1020](https://attack.mitre.org/techniques/T1020)
1. Use ```zeek``` with the ```/opt/zeek/share/zeek/policy/frameworks/files/hash-all-files.zeek``` framework 
	- ```zeek-cut``` can be beneficial on the command line to pick specific fields
	- examine the ```files.log``` file 

# Extract Files in Transit [T1020](https://attack.mitre.org/techniques/T1020) [T1048](https://attack.mitre.org/techniques/T1048)
1. Use ```zeek``` with the ```/opt/zeek/share/zeek/policy/frameworks/files/extract-all-files.zeek``` framework
	- ```zeek-cut``` can be beneficial on the command line to pick specific fields
	- examine the ```extract-files``` folder
2. Use Wireshark and extract objects. 

# View Cleartext Information in HTTP Traffic [T1020](https://attack.mitre.org/techniques/T1020) [T1048.003](https://attack.mitre.org/techniques/T1048/003) [T1567](https://attack.mitre.org/techniques/T1567)
1. Use ```zeek``` with the ```zeek-sniffpass``` package
	- ```zeek-cut``` can be beneficial on the command line to pick specific fields
2. Use Wireshark and examine packets. 

# View GEO IP Information in Traffic [No TTP]
1. Use ```zeek``` with the ```geoip-conn``` package. 
	- ```zeek-cut``` can be beneficial on the command line to pick specific fields

# Detect Log4J Exploitation [T1059.007](https://attack.mitre.org/techniques/T1059/007)
1. Use ```zeek``` with the ```/opt/zeek/share/zeek/site/cve-2021-44228``` script/package
	- ```zeek-cut``` can be beneficial on the command line to pick specific fields
	- examine the ```log4j.log``` file 

# Determine Number of Network Connections [No TTP]
1. Use ```Get-WinEvent``` with Sysmon Event Logs. 
	- Command to use is ```Get-WinEvent -Path <Path to Log> -FilterXPath '*/System/EventID=3 | Measure-Object```
2. Use Wireshark statistics. 

# Find Beaconing within ICMP Packets [T1020](https://attack.mitre.org/techniques/T1020) [T1048.003](https://attack.mitre.org/techniques/T1048/003)
1. Use ```tshark``` within the command line. 
	- Command to use is ```"C:\Program Files\Wireshark\tshark.exe" -r pcap_file.pcap -Y "icmp" -T fields -e data```
2. Use [Rita](https://github.com/activecm/rita) to find beaconing activity. 

# Find Beaconing Activity [T1048](https://attack.mitre.org/techniques/T1048/003) [T1573](http://attack.mitre.org/techniques/T1573/)
1. Use [Rita](https://github.com/activecm/rita) to find beaconing activity. 

# Find VPN Connections [T1333](https://attack.mitre.org/techniques/T1133/)
1. Use Event ID 6272 within windows security logs for external IP of user. 

# View RDP Connections [T1210](https://attack.mitre.org/techniques/T1210/) [T1563.002](https://attack.mitre.org/techniques/T1563/002/)
1. Look for port 3389 connections within network traffic 

# View WMI Traffic [T1047](https://attack.mitre.org/techniques/T1047/)
1. Identify traffic on port 135 or 137 with ```dce_rpc``` service. 

# View Non Standard Port Traffic [T1509](https://attack.mitre.org/techniques/T1509/).
1. Use PSReadline to view scriptblock activity. 

# Identify Web Shells [T1505.003](https://attack.mitre.org/techniques/T1505/003/)
1. Look for out of date browser agents with HTTP traffic on port 80. 
2. Look for connections to webpages like ```.php, .aspx, .jsp, or .asp```. 

# Identify Ping Sweeps
1. Use tcpdump with ```-n``` to resolve.
	- Command to use: ```tcpdump -r pcap 'host 92.242.140.21' -n```

# Identify Sharphound/Bloodhound Activity [T1087](https://attack.mitre.org/techniques/T1087/) [T1482](https://attack.mitre.org/techniques/T1482/)[T1615](https://attack.mitre.org/techniques/T1615/)[T1069](https://attack.mitre.org/techniques/T1069/)[T1018](https://attack.mitre.org/techniques/T1018/) [T1033](https://attack.mitre.org/techniques/T1033/)
1. Look for increase in traffic with destination port 445 and destination process ```ntoskrnl.exe``` to each workstation within a domain. 