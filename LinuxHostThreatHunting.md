# Explore Process Thread Activity [T1134.003](https://attack.mitre.org/techniques/T1134/003) [T1574.005](https://attack.mitre.org/techniques/T574/005) [T1574.010](https://attack.mitre.org/techniques/T1574/010) [T1055.003](https://attack.mitre.org/techniques/T1055/003) [T1055.005](https://attack.mitre.org/techniques/T1055/005) [T1620](https://attack.mitre.org/techniques/T1620)
1. On the command line, use ```lsof``` to examine process calls and possible network connections. 
2. On the command line, use ```osqueryi``` to examine processes with ```SELECT pid, fd, socket, local_address, remote_address FROM process_open_sockets WHERE pid = [PID];```. 
3. View process execution with [pspy](https://github.com/DominicBreuker/pspy). 

# Examine Executables [T1547.004](https://attack.mitre.org/techniques/T1547/004/) [T1059.006](https://attack.mitre.org/techniques/T1059/006/) [T1559.001]([T1070.004](https://attack.mitre.org/techniques/T1559/001/)) [T1027.004]([T1070.004](https://attack.mitre.org/techniques/T1027/004/)) [T1027.004]([T1070.009](https://attack.mitre.org/techniques/T1027/009/)) [T1055.002](https://attack.mitre.org/techniques/T1055/002)
1. On the command line, use ```lsof``` to examine process calls and possible network connections. 
2. On the command line, use ```osqueryi``` to examine processes with ```SELECT pid, fd, socket, local_address, remote_address FROM process_open_sockets WHERE pid = [PID];```. 

# Explore Processes [T1059](https://attack.mitre.org/techniques/T1059) [T1055](https://attack.mitre.org/techniques/T1055/)
1. On the command line, use ```lsof``` to examine process calls and possible network connections. 
2. On the command line, use ```osqueryi``` to examine processes with ```SELECT pid, fd, socket, local_address, remote_address FROM process_open_sockets WHERE pid = [PID];```. 
3. View process execution with [pspy](https://github.com/DominicBreuker/pspy). 

# User Creation [T1136](https://attack.mitre.org/techniques/T1136/)
1. Look within auth.log for ```useradd``` events. 
2. Look within ```/etc/passwd``` for another user creation. 

# Explore Scheduled Tasks/CronJobs [T1036.004](https://attack.mitre.org/techniques/T136/004) [T1053.005](https://attack.mitre.org/techniques/T1053/005)
1. Look within ```/var/spool/crontab``` to find each cronjob associated with each user. 
2. Look at the system level crontabs with ```/etc/crontab```.
3. A helpful resource can be found [here](https://crontab.guru/).
4. Use the ```crontab``` command to view the user crontabs. 
5. Loop through each of the users and find the crontabs with ```sudo bash -c 'for user in $(cut -f1 -d: /etc/passwd); do entries=$(crontab -u $user -l 2>/dev/null | grep -v "^#"); if [ -n "$entries" ]; then echo "$user: Crontab entry found!"; echo "$entries"; echo; fi; done'```. 
6. Look for cron execution within ```/var/log/syslog```. 
7. View process execution and focus on cronjobs using [pspy](https://github.com/DominicBreuker/pspy). 
8. Find the system level crobjobs within ```/etc/``` within ```

# Find Service Creation [T1569.002](https://attack.mitre.org/techniques/T1569/002) [T1543.003](https://attack.mitre.org/techniques/T1543/003)
1. Look within ```/etc/systemd/service``` to find anomalous services. 
2. Look within the logs at ```/var/log/syslog```. 
3. Find using ```journalctl``` on the command line. 
4. Run the command ```systemctl list-units --type=service --state=running``` to find all running services. 
5. Find information about the service within ```/etc/systemd/system```. 

# Find Installed Packages [T1072](https://attack.mitre.org/techniques/T1072/)
1. Use the command ```dpkg -l``` on the system.  
2. Search for package installs within ```/var/log/dpkg.log```. 

# View User Authentications [T1078](https://attack.mitre.org/techniques/T1078/)
1. Look at ```/var/log/auth.log``` file. 

# Find Autostarts [T1547](https://attack.mitre.org/techniques/T1547/)
1. Look for files within ```/etc/init.d```, ```/etc/rc.d```, and ```/etc/systemd/system```. 
2. User specific autostrart scripts can be found in ```~/.config/autostart``` and ```~/.config```. 

# Find Vim Use [T1059.004](https://attack.mitre.org/techniques/T1059/004/)
1. Look within the user ```.viminfo``` file saved in their home directory. 

# Find Browser Artifacts [T1606.001](https://attack.mitre.org/techniques/T1606/001) [T1539](https://attack.mitre.org/techniques/T1539) [T1550.004](https://attack.mitre.org/techniques/T1550/004) [T1189](https://attack.mitre.org/techniques/T1189) [T1203](https://attack.mitre.org/techniques/T1203)[T1608.004](https://attack.mitre.org/techniques/T1608/004) [T1218.001](https://attack.mitre.org/techniques/T1218/001) [T1218.005](https://attack.mitre.org/techniques/T1218/005) [T1204.001](https://attack.mitre.org/techniques/T1204/001) [T1176](https://attack.mitre.org/techniques/T1176) [T1185](https://attack.mitre.org/techniques/T1185)
1. Look within user home directory for ```.mozilla/firefox``` or ```.config/googlechrome``` files. 
2. Use [dumpzilla](https://github.com/Busindre/dumpzilla).
