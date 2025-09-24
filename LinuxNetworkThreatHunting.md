# Web Shell Execution [T1505.003](https://attack.mitre.org/techniques/T1505/003/)
1. Look within the ```/var/log/[browser]/access.log``` log file for GET or POST requests.  

# Active Network Connections
1. Use ```osquery``` with ```SELECT pid, family, remote_address, remote_port, local_address, local_port, state FROM process_open_sockets LIMIT 20;```. 
