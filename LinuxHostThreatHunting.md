# Find Command Line Execution [T1059.004](https://attack.mitre.org/techniques/T1059/004/)
1. Look within the user home directories for ```.bash_history```. 
2. Look for aliasing within ```.bashrc``` in the user home directory. 

# Find USB Devices [T1025](https://attack.mitre.org/techniques/T1025/)
1. Look at ```usb``` strings within ```/var/log/syslog```. 
2. Look at ```dmesg``` strings within ```/var/log/syslog```. 

# Find Hidden Files [T1564.001](https://attack.mitre.org/techniques/T1564/001/)
1. Use ```osqueryi``` with ```SELECT filename, path, directory, size, type FROM file WHERE path LIKE '/.%';```. 

# Explore Process Thread Activity [T1134.003](https://attack.mitre.org/techniques/T1134/003) [T1574.005](https://attack.mitre.org/techniques/T574/005) [T1574.010](https://attack.mitre.org/techniques/T1574/010) [T1055.003](https://attack.mitre.org/techniques/T1055/003) [T1055.005](https://attack.mitre.org/techniques/T1055/005) [T1620](https://attack.mitre.org/techniques/T1620)
1. On the command line, use ```lsof``` to examine process calls and possible network connections. 
2. On the command line, use ```osqueryi``` to examine processes with ```SELECT pid, fd, socket, local_address, remote_address FROM process_open_sockets WHERE pid = [PID];```. 
3. View process execution with [pspy](https://github.com/DominicBreuker/pspy). 
4. Look for aliasing within ```.bashrc``` in the user home directory. 

# Examine Executables [T1547.004](https://attack.mitre.org/techniques/T1547/004/) [T1059.006](https://attack.mitre.org/techniques/T1059/006/) [T1559.001]([T1070.004](https://attack.mitre.org/techniques/T1559/001/)) [T1027.004]([T1070.004](https://attack.mitre.org/techniques/T1027/004/)) [T1027.004]([T1070.009](https://attack.mitre.org/techniques/T1027/009/)) [T1055.002](https://attack.mitre.org/techniques/T1055/002)
1. On the command line, use ```lsof``` to examine process calls and possible network connections. 
2. On the command line, use ```osqueryi``` to examine processes with ```SELECT pid, fd, socket, local_address, remote_address FROM process_open_sockets WHERE pid = [PID];```. 
3. Look for aliasing within ```.bashrc``` in the user home directory. 

# Explore Processes [T1059](https://attack.mitre.org/techniques/T1059) [T1055](https://attack.mitre.org/techniques/T1055/)
1. On the command line, use ```lsof``` to examine process calls and possible network connections. 
2. On the command line, use ```osqueryi``` to examine processes with ```SELECT pid, fd, socket, local_address, remote_address FROM process_open_sockets WHERE pid = [PID];```. 
3. View process execution with [pspy](https://github.com/DominicBreuker/pspy). 
4. Find all running processes using ```osqueryi``` wiht ```SELECT pid, name, path, state FROM processes;```. 
5. Find the open files associated with a running process using ```osueryi``` with the ```process_open_files_``` table. 
6. Look for aliasing within ```.bashrc``` in the user home directory. 

# User Creation [T1136](https://attack.mitre.org/techniques/T1136/)
1. Look within auth.log for ```useradd``` events. 
2. Look within ```/etc/passwd``` for another user creation. 
3. If service based, look within ```journalctl``` output for the specific service. 
4. Use osqueryi with ```Select username, uid, description from users;``` to find all users. 

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
3. Use the command ```apt list --installed```. 

# View User Authentications [T1078](https://attack.mitre.org/techniques/T1078/)
1. Look at ```/var/log/auth.log``` file and focus on authentications with ```Accepted Password``` or ```Sessions opened```. 
2. View login and logout activity with ```/var/log/btmp``` and ```/var/log/wtmp```. 
3. Look for ```gdm-password``` within ```auth.log```. 

# Find Autostarts [T1547](https://attack.mitre.org/techniques/T1547/)
1. Look for files within ```/etc/init.d```, ```/etc/rc.d```, and ```/etc/systemd/system```. 
2. User specific autostrart scripts can be found in ```~/.config/autostart``` and ```~/.config```. 

# Find Vim Use [T1059.004](https://attack.mitre.org/techniques/T1059/004/)
1. Look within the user ```.viminfo``` file saved in their home directory. 

# Find Browser Artifacts [T1606.001](https://attack.mitre.org/techniques/T1606/001) [T1539](https://attack.mitre.org/techniques/T1539) [T1550.004](https://attack.mitre.org/techniques/T1550/004) [T1189](https://attack.mitre.org/techniques/T1189) [T1203](https://attack.mitre.org/techniques/T1203)[T1608.004](https://attack.mitre.org/techniques/T1608/004) [T1218.001](https://attack.mitre.org/techniques/T1218/001) [T1218.005](https://attack.mitre.org/techniques/T1218/005) [T1204.001](https://attack.mitre.org/techniques/T1204/001) [T1176](https://attack.mitre.org/techniques/T1176) [T1185](https://attack.mitre.org/techniques/T1185)
1. Look within user home directory for ```.mozilla/firefox``` or ```.config/googlechrome``` files. 
2. Use [dumpzilla](https://github.com/Busindre/dumpzilla).

# Look for Kernel Exploits [T1014](https://attack.mitre.org/techniques/T1014/)
1. View log entries within ```/var/log/kern.log``` and ```/var/log/desmg```. 
2. Use the ```dmesg``` command to find recent kernel events. 
3. Look for log files with kernel in ```/var/log/syslog```. 
