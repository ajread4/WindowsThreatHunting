# AWS 

## Host

### Detect Potential Financial Theft [T1657](https://attack.mitre.org/techniques/T1657/)
1. Query Amazon Macie for alerts the GUI. 

### Detect Potential PII [No TTP]
1. Query Amazon Macie for alerts within the GUI. 
2. View CloudWatch Logs Alerts for PII within data. 
### Detect Cloud Compute Infra Modification [T1578](https://attack.mitre.org/techniques/T1578/)
1. Query AWS Config with the specific security group. 
	- Commands to run: 
		- ```INSTANCE_ID=$(aws ec2 describe-instances --filters Name=tag:Name,Values=[Role] --query Reservations[].Instances[].InstanceId --output text)```
		- ```aws configservice get-resource-config-history --resource-type AWS::EC2::Instance --resource-id $INSTANCE_ID]```
2. Use the Resource Timeline within AWS Config GUI. 
### Detect Non Standard Port Listening [T1571](https://attack.mitre.org/techniques/T1571/)
1. Query the security group of the asset and find the ports available. 
	- Commands to run: 
		- ```SG_ID=$(aws ec2 describe-instances --filters Name=tag:Name,Values="SherlocksBlog" --query Reservations[].Instances[].SecurityGroups[0].GroupId --output text)```
		- ```aws ec2 describe-security-groups --group-ids $SG_ID | jq '.SecurityGroups[].IpPermissions[] | {FromPort, ToPort, IpProtocol}'```
2. Review AWS Inspector Network Reachability results for the specific instance. 
### Detect Crypto Miner [T1496](https://attack.mitre.org/techniques/T1496/)
1. View the Kubernetes Cluster CPU level within the CloudWatch GUI Alarms. 
2. Query the CloudWatch Logs Inisights for alarms related to crypto miners.
	- Command to run: ```aws cloudwatch describe-alarms | jq -r '.MetricAlarms[] | select(.StateValue == "ALARM") | .AlarmName'```
3. Query CloudWatch via the CLI with the appropriate log group of Kubernetes application logs to see interesting pod name. 
	- Commands to run: 
		- ```QUERY_ID=$(aws logs start-query --start-time $(date -d "30 mins ago" +"%s") --end-time $(date +"%s") --log-group-name [ApplicationLogGroupName] --query-string 'fields @message | filter kubernetes.container_name == "[ContainerName]"' --output text)```
		- ```aws logs get-query-results --query-id $QUERY_ID | jq -r '.results[][] | select(.field == "@message") | select(.value | contains ("appdeploymentfromfile"))'```
### View ListBuckets Activity [T1526](https://attack.mitre.org/techniques/T1526/)
1. Query CloudTrail for ListBuckets within AWS CLI. 
	- Command to use: ```aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=ListBuckets --query 'Events[].{EventId:EventId,EventName:EventName,EventTime:EventTime,Username:Username}' --output table```
2. Query CloudTrail for ListBuckets with AWS CLI and jq with a focus on specific Username. 
	- Command to use: ```aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=ListBuckets | jq -r '[.Events[]|select((.Username | startswith("i-"))) | {EventId,Username, CloudTrailEvent: (.CloudTrailEvent|fromjson)}]'```
3. Query CloudTrail for ListBuckets within AWS CLI using [JMESPath](https://jmespath.org/specification.html) query.
	- Command to use: ```aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=ListBuckets --query 'Events[].{EventId:EventId,EventName:EventName,EventTime:EventTime,Username:Username}' --output table```
4. Query CloudTrail for ListBuckets but filter based on a certain Username within query. 
	1. Command to use: ```aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=ListBuckets --query 'Events[?starts_with(Username, `i-`)==`true`].{EventId:EventId,EventName:EventName,EventTime:EventTime,Username:Username}' --output table```
5. Query CloudTrail for ListBuckets but only those where AccessDenied. 
	- Command to use: ```aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=ListBuckets | jq '.Events[]|select((.Username | startswith("i-")) and (.CloudTrailEvent|fromjson|select(.errorCode=="AccessDenied"))) '```
6. Query CloudTrail for ListBuckets as the Event name within the GUI. 
7. Query CloudWatch LogInsights within the GUI.
	- Query to use: ```fields eventID, eventName, eventTime, userIdentity.sessionContext.sessionIssuer.userName as userName | sort @timestamp desc | filter eventName = "ListBuckets"```
8. Query CloudWatch LogInsights via CLI. 
	- Command to use: 
		- ```aws logs start-query --log-group-name [LogGroupName] --start-time [EpochTime] --end-time [EpochTime] --query-string "fields eventID, eventName, eventTime, userIdentity.sessionContext.sessionIssuer.userName as userName | sort @timestamp desc | filter eventName=\"ListBuckets\""```
		- ```aws logs get-query-results --query-id [query-id]```
### View CreateBucket Activity [T1526](https://attack.mitre.org/techniques/T1526/)
1. Query CloudTrail for CreateBucket but filter based on certain username. 
	- Command to use: ```aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=CreateBucket --max-results 10 --query 'Events[?starts_with(Username, `i-`)==`true`].{EventId:EventId,EventName:EventName,EventTime:EventTime,Username:Username}' --output table```
2. Query CloudTrail for CreateBucket as the Event name within the GUI. 
3. Query CloudWatch LogInsights within the GUI.
	- Query to use: ```fields eventID, eventName, eventTime, userIdentity.sessionContext.sessionIssuer.userName as userName | sort @timestamp desc | filter eventName = "CreateBucket"```
4. Query CloudWatch LogInsights via CLI. 
	- Command to use: 
		- ```aws logs start-query --log-group-name [LogGroupName] --start-time [EpochTime] --end-time [EpochTime] --query-string "fields eventID, eventName, eventTime, userIdentity.sessionContext.sessionIssuer.userName as userName | sort @timestamp desc | filter eventName=\"CreateBucket\""```
		- ```aws logs get-query-results --query-id [query-id]```

### View DescribeInstances Activity [T1526]().
1. Query CloudTrail for DescribeInstances events with AWS CLI. 
	- Command to use: ```aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=DescribeInstances --query 'Events[].{EventId:EventId,EventName:EventName,EventTime:EventTime,Username:Username}' --output table```
2. Query CloudTrail for DescribeInstances as the Event name within the GUI. 
3. Query CloudWatch LogInsights within the GUI.
	- Query to use: ```fields eventID, eventName, eventTime, userIdentity.sessionContext.sessionIssuer.userName as userName | sort @timestamp desc | filter eventName = "DescribeInstances"```
4. Query CloudWatch LogInsights via CLI. 
	- Command to use: 
		- ```aws logs start-query --log-group-name [LogGroupName] --start-time [EpochTime] --end-time [EpochTime] --query-string "fields eventID, eventName, eventTime, userIdentity.sessionContext.sessionIssuer.userName as userName | sort @timestamp desc | filter eventName=\"DescribeInstances\""```
		- ```aws logs get-query-results --query-id [query-id]```
### View StopLogging Activity [T1562.008](https://attack.mitre.org/techniques/T1562/008/)
1. Query CloudTrail for StopLogging events. 
	- Command to use: ```aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=StopLogging --query 'Events[].{EventId:EventId,EventName:EventName,EventTime:EventTime,Username:Username}' --output table```
2. Query CloudTrail for StopLogging as the Event name within the GUI. 
3. Query CloudWatch LogInsights within the GUI.
	- Query to use: ```fields eventID, eventName, eventTime, userIdentity.sessionContext.sessionIssuer.userName as userName | sort @timestamp desc | filter eventName = "StopLogging"```
4. Query CloudWatch LogInsights via CLI. 
	- Command to use: 
		- ```aws logs start-query --log-group-name [LogGroupName] --start-time [EpochTime] --end-time [EpochTime] --query-string "fields eventID, eventName, eventTime, userIdentity.sessionContext.sessionIssuer.userName as userName | sort @timestamp desc | filter eventName=\"StopLogging\""```
		- ```aws logs get-query-results --query-id [query-id]```
### View DeleteTrail Activity [T1562.008](https://attack.mitre.org/techniques/T1562/008/)
1. Query CloudTrail for DeleteTrail events. 
	- Command to use: ```aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=DeleteTrail --query 'Events[].{EventId:EventId,EventName:EventName,EventTime:EventTime,Username:Username}' --output table```
2. Query CloudTrail for DeleteTrail as the Event name within the GUI. 
3. Query CloudWatch LogInsights within the GUI.
	- Query to use: ```fields eventID, eventName, eventTime, userIdentity.sessionContext.sessionIssuer.userName as userName | sort @timestamp desc | filter eventName = "DeleteTrail"```
4. Query CloudWatch LogInsights via CLI. 
	- Command to use: 
		- ```aws logs start-query --log-group-name [LogGroupName] --start-time [EpochTime] --end-time [EpochTime] --query-string "fields eventID, eventName, eventTime, userIdentity.sessionContext.sessionIssuer.userName as userName | sort @timestamp desc | filter eventName=\"DeleteTrail\""```
		- ```aws logs get-query-results --query-id [query-id]```
### View UpdateTrail Activity [T1562.008](https://attack.mitre.org/techniques/T1562/008/)
1. Query CloudTrail for UpdateTrail events. 
	- Command to use: ```aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=UpdateTrail --query 'Events[].{EventId:EventId,EventName:EventName,EventTime:EventTime,Username:Username}' --output table```
2. Query CloudTrail for UpdateTrail as the Event name within the GUI. 
3. Query CloudWatch LogInsights within the GUI.
	- Query to use: ```fields eventID, eventName, eventTime, userIdentity.sessionContext.sessionIssuer.userName as userName | sort @timestamp desc | filter eventName = "UpdateTrail"```
4. Query CloudWatch LogInsights via CLI. 
	- Command to use: 
		- ```aws logs start-query --log-group-name [LogGroupName] --start-time [EpochTime] --end-time [EpochTime] --query-string "fields eventID, eventName, eventTime, userIdentity.sessionContext.sessionIssuer.userName as userName | sort @timestamp desc | filter eventName=\"UpdateTrail\""```
		- ```aws logs get-query-results --query-id [query-id]```
### View All Activity based on KeyID [No TTP]
1. Query AWS CloudTrail related to specific attacker KeyID. 
	- Command to use: ```aws cloudtrail lookup-events --max-results 200 --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=$KEY_ID | jq '[.Events[].EventName]| unique[]'```
2. Query AWS CloudTrail with the KeyID as the AWS access key within the GUI. 
### View Deployed Containers [T1610](https://attack.mitre.org/techniques/T1610/)
1. Query with [kai](https://github.com/anchore/k8s-inventory) to inventory containers within the environment. 
2. Query AWS Config GUI within the Resources section. 
## Network

### Detect Web Fuzzing [T1190](https://attack.mitre.org/techniques/T1190/)
1. Query CloudWatch Log Insights for file or directory access. 
	- Command to run: ```QUERY_ID=$(aws logs start-query --start-time $(date -d '-3 hours' "+%s") --end-time $(date "+%s") --query-string 'fields integrationErrorMessage | filter integrationErrorMessage ~= "No such file or directory" and sourceIp == "'[SuspectIPs]'"' --log-group-name [LogGroupName] --query 'queryId' --output text)```
	- ```aws logs get-query-results --query-id $QUERY_ID```

### Detect Container API Unsecured Credentials Access [T1552.007](https://attack.mitre.org/techniques/T1552/007/)
1. Query CloudWatch Log Insights for access to a specific log stream and focus on the URI. 
	- Commands to run: 
		- ```aws logs start-query --start-time $(date -d "30 mins ago" +"%s") --end-time $(date +"%s") --log-group-name $LOG_GROUP --query-string 'fields @message | filter @logStream ~= "kubernetes-dashboard"' --output text)```
		- ```aws logs get-query-results --query-id $QUERY_ID | jq -r '.results[][] | select(.value | contains("aws-secrets"))'```
2. Query CloudWatch Log Insights via the GUI and a specific log group. 
	- Query to run: ```fields integrationErrorMessage | filter integrationErrorMessage ~= "No such file or directory"```
### View User Agents
1. Use ```s3logparse.py``` found [here](https://www.google.com/search?q=s3logparse+py&oq=s3logparse+py&aqs=chrome..69i57j33i299.2618j0j7&sourceid=chrome&ie=UTF-8). 
	- Command to use is ```s3logparse.py useragent [useragent]```.

### Detect SSH Brute Force [T1110](https://attack.mitre.org/techniques/T1110/)
1. Query CloudWatch Log Insights via the GUI looking at VPC Flow Logs. 
	- Query to use: ```filter dstPort=22 | stats  count(*) as total by srcAddr as source | sort total desc | limit 10```
2. Query CloudWatch Log Insights via CLI ;ooking at VPC Flow Logs.
	- Commands to run: 
		- ```aws logs start-query --log-group-name [LogGroupName] --start-time [EpochTime] --end-time [EpochTime] --query-string "filter dstPort=22 | stats  count(*) as total by srcAddr as source | sort total desc | limit 10"```
		- ```aws logs get-query-results --query-id [query-id]```
3. Query Athena within the GUI looking at VPC Flow Logs.
	- Query to use: ```SELECT sourceaddress, count(*) as total FROM vpc_flow_logs WHERE (destinationport = 22) group by distinct sourceaddress ORDER by total desc```
4. Query Athena within the CLI looking at VPC Flow Logs.
	- Commands to use: 
		- ```QUERY_ID=$(aws athena start-query-execution --query-string "SELECT sourceaddress, count(*) as total FROM vpc_flow_logs WHERE (destinationport = 22) group by distinct sourceaddress ORDER by total desc" --query-execution-context Database=[DatabaseLogs] --work-group [WorkGroup] --query QueryExecutionId --output text)```
		- ```aws athena get-query-results --query-execution-id $QUERY_ID --query ResultSet```
5. Use AWS GuardDuty in the GUI and look for ``` UnauthorizedAccess:EC2/SSHBruteForce``` findings. 
6. Use AWS GuardDuty via the CLI with the appropriate detector ID.
	- Commands to run: 
		- ```DETECTOR_ID=$(aws guardduty list-detectors --query DetectorIds[0] --output text)```
		- ```aws guardduty list-findings --detector-id $DETECTOR_ID --finding-criteria '{"Criterion": {"type": {"Eq":["UnauthorizedAccess:EC2/SSHBruteForce"]}}}'```
		- ```aws guardduty get-findings --detector-id $DETECTOR_ID --finding-ids $FINDING_IDS --query Findings[0]```
### Detect Non Standard Port Interactions [T1571](https://attack.mitre.org/techniques/T1571/)
1. Query Athena within the GUI looking at VPC Flow Logs.
	- Query to use: ```SELECT destinationport, count(*) as total FROM vpc_flow_logs WHERE destinationport < 1024 AND action='ACCEPT' group by distinct destinationport ORDER by total ASC LIMIT 50```
2. Query Athena within the CLI looking at VPC Flow Logs.
	- Commands to use: 
		- ```QUERY_ID=$(aws athena start-query-execution --query-string "SELECT destinationport, count(*) as total FROM vpc_flow_logs WHERE destinationport < 1024 AND action='ACCEPT' group by distinct destinationport ORDER by total ASC LIMIT 50" --query-execution-context Database=[DatabaseLogs] --work-group [WorkGroup] --query QueryExecutionId --output text)```
		- ```aws athena get-query-results --query-execution-id $QUERY_ID --query ResultSet```
3. Query CloudWatch Log Insights via the GUI looking at VPC Flow Logs.
	- Query to use: ```filter dstPort < 1024 and action='ACCEPT' | stats  count(*) as total by dstPort | sort total desc | limit 50```
4. Query CloudWatch Log Insights via the CLI looking at VPC Flow Logs.
	- Commands to use: 
		- ```aws logs start-query --log-group-name [LogGroupName] --start-time [EpochTime] --end-time [EpochTime] --query-string "filter dstPort < 1024 and action='ACCEPT' | stats  count(*) as total by dstPort | sort total desc | limit 50"```
		- ```aws logs get-query-results --query-id [query-id]```
5. Query the security group of the asset and find the ports available. 
	- Commands to run: 
		- ```SG_ID=$(aws ec2 describe-instances --filters Name=tag:Name,Values="SherlocksBlog" --query Reservations[].Instances[].SecurityGroups[0].GroupId --output text)```
		- ```aws ec2 describe-security-groups --group-ids $SG_ID | jq '.SecurityGroups[].IpPermissions[] | {FromPort, ToPort, IpProtocol}'```
6. Review AWS Inspector Network Reachability results for the specific instance. 

### Detect Scanning/Recon [T1595](https://attack.mitre.org/techniques/T1595/) [T1590](https://attack.mitre.org/techniques/T1590/)
1. Query Athena within the GUI looking at VPC Flow Logs.
	- Query to use: ```SELECT sourceaddress, destinationaddress,  count(*) count, action FROM vpc_flow_logs WHERE action = 'REJECT' GROUP BY sourceaddress, destinationaddress, action ORDER BY count desc LIMIT 25```
2. Query Athena within the CLI looking at VPC Flow Logs.
	- Commands to use: 
		- ```QUERY_ID=$(aws athena start-query-execution --query-string "SELECT sourceaddress, destinationaddress,  count(*) count, action FROM vpc_flow_logs WHERE action = 'REJECT' GROUP BY sourceaddress, destinationaddress, action ORDER BY count desc LIMIT 25" --query-execution-context Database=[DatabaseLogs] --work-group [WorkGroup] --query QueryExecutionId --output text)```
		- ```aws athena get-query-results --query-execution-id $QUERY_ID --query ResultSet```
3. Query CloudWatch Log Insights within the GUI looking at VPC Flow Logs.
	- Query to use: ```filter action='REJECT' | stats count(*) by srcAddr, dstAddr | display srcAddr, dstAddr | limit 25```
4. Query CloudWatch Insights within the CLI looking at VPC Flow Logs.
	- Commands to use: 
		- ```aws logs start-query --log-group-name [LogGroupName] --start-time [EpochTime] --end-time [EpochTime] --query-string "filter action='REJECT' | stats count(*) by srcAddr, dstAddr | display srcAddr, dstAddr | limit 25"```
		- ```aws logs get-query-results --query-id [query-id]```
5. Query CloudWatch log stream directly for events from log. 
	- Command to use: ```aws logs get-log-events --log-group-name [LogGroup] --log-stream [LogStream]```
6. Query CloudWatch Log Insights for web scanning activity within logs. 
	- Commands to use: 
		- ```aws logs start-query --start-time $(expr $(date +"%s") - 86400) --end-time $(date +"%s") --log-group-name [LogGroupName] \ --query-string 'display @message' \ --output text)```
		- ```aws logs get-query-results --query-id $QUERY_ID | jq -r \ '.results[][] | select(.field == "@message") | .value'```
### Detect Egress Traffic Rejection [No TTP]
1. Query Athena within the GUI looking at VPC Flow Logs.
	- Query to use: ```SELECT sourceaddress, destinationaddress,  count(*) count, action FROM vpc_flow_logs WHERE action = 'REJECT' AND sourceaddress LIKE '10.0.%' GROUP BY sourceaddress, destinationaddress, action ORDER BY count desc LIMIT 25```
2. Query Athena within the CLI looking at VPC Flow Logs.
	- Commands to use: 
		- ```QUERY_ID=$(aws athena start-query-execution --query-string "SELECT sourceaddress, destinationaddress,  count(*) count, action FROM vpc_flow_logs WHERE action = 'REJECT' AND sourceaddress LIKE '10.0.%' GROUP BY sourceaddress, destinationaddress, action ORDER BY count desc LIMIT 25" --query-execution-context Database=[DatabaseLogs] --work-group [WorkGroup] --query QueryExecutionId --output text)```
		- ```aws athena get-query-results --query-execution-id $QUERY_ID --query ResultSet```
3. Query CloudWatch Log Insights within the GUI looking at VPC Flow Logs.
	- Query to use: ```filter action='REJECT' and strcontains(srcAddr, "10.0.") | stats  count(*) by srcAddr, dstAddr, action | display srcAddr, dstAddr, action | limit 25```
4. Query CloudWatch Insights within the CLI looking at VPC Flow Logs.
	- Commands to use: 
		- ```aws logs start-query --log-group-name [LogGroupName] --start-time [EpochTime] --end-time [EpochTime] --query-string "filter action='REJECT' and strcontains(srcAddr, "10.0.") | stats  count(*) by srcAddr, dstAddr, action | display srcAddr, dstAddr, action| limit 25"```
		- ```aws logs get-query-results --query-id [query-id]```
### Identify Top Internal Talkers [No TTP]
1. Query Athena within the GUI looking at VPC Flow Logs.
	- Query to use: ```SELECT ip, sum(bytes) as total_bytes FROM (SELECT destinationaddress as ip,sum(numbytes) as bytes FROM vpc_flow_logs GROUP BY 1 UNION ALL SELECT sourceaddress as ip,sum(numbytes) as bytes FROM vpc_flow_logs GROUP BY 1) GROUP BY ip ORDER BY total_bytes DESC LIMIT 10```
2. Query Athena within the CLI looking at VPC Flow Logs.
	- Commands to use: 
		- ```QUERY_ID=$(aws athena start-query-execution --query-string "SELECT ip, sum(bytes) as total_bytes FROM (SELECT destinationaddress as ip,sum(numbytes) as bytes FROM vpc_flow_logs GROUP BY 1 UNION ALL SELECT sourceaddress as ip,sum(numbytes) as bytes FROM vpc_flow_logs GROUP BY 1) GROUP BY ip ORDER BY total_bytes DESC LIMIT 10" --query-execution-context Database=[DatabaseLogs] --work-group [WorkGroup] --query QueryExecutionId --output text)```
		- ```aws athena get-query-results --query-execution-id $QUERY_ID --query ResultSet```

### View Deployed Containers [T1610](https://attack.mitre.org/techniques/T1610/)
1. Query CloudWatch Log Insights with the container log stream/group of application logs. 
	- Commands to run: 
		- ```aws logs start-query --log-group-name [LogGroupContainer] --start-time $(date -d '1 hour ago' +"%s") --end-time $(date +"%s") --query-string 'fields log | filter kubernetes.container_name == "[ContainerName]" and log ~= "Incoming HTTP" and log ~= "appdeploymentfromfile"' --output text)```
		- ```aws logs get-query-results --query-id $QUERY_ID```
2. Query CloudWatch Log Insights within the GUI with the correct log group of application logs. 
	- Query to use: ```fields log | filter kubernetes.container_name == "kubernetes-dashboard" and log ~= "Incoming HTTP" and log ~= "appdeploymentfromfile"```

### Detect Access EC2 Metadata Service Vulnerability [T1552.005](https://attack.mitre.org/techniques/T1552/005/)
1. Use AWS Inspector results to view IMDSv2, not Version 1 interactions. 
# Azure 

## Host

### Identify Suspicious Cloud Accounts [T1078.004](https://attack.mitre.org/techniques/T1078/004/)
1. Query the Azure Log Analytics Workspace via the GUI with the BehaviorAnalytics table. 
	- Query to run: ```BehaviorAnalytics | where ActivityInsights.CountryUncommonlyConnectedFromAmongPeers == True | project TimeGenerated, ActivityType, UserName, SourceIPAddress, ActivityInsights```
2. Query the Azure Log Analytics Workspace via the CLI with the BehaviorAnalytics table. 
	- Commands to run: 
		- ```WORKSPACE_GUID=$(az monitor log-analytics workspace show --resource-group [RsourceGroup] --workspace-name [WorkspaceName] --query 'customerId' --output tsv)```
		- ```az monitor log-analytics query --workspace $WORKSPACE_GUID --analytics-query 'BehaviorAnalytics | where ActivityInsights.CountryUncommonlyConnectedFromAmongPeers == True | project TimeGenerated, ActivityType, UserName, SourceIPAddress, ActivityInsights'```
### Inventory Roles [No TTP]
1. Query the Azure CLI. 
	- Command to run: ```az role assignment list --all --query '[].{UPN:principalName,RoleDef:roleDefinitionName,Scope:scope}' --output table```

### Identify User Groups [T1078.002](https://attack.mitre.org/techniques/T1078/002/)
1. View information within Azure AD Users within the Portal GUI. 
2. View changes of AD within AuditLogs of the Azure Log Analytics Workspace. 

### Identify Spam Messages [T1566](https://attack.mitre.org/techniques/T1566/)
1. View spam filtering within the Microsoft 365 Admin Center. 

### Vulnerability Assessment of VMs [No TTP]
1. Query Microsoft Defender for Cloud with Qualys for vulnerability's. 
2. Query Azure Log Analytics Workspace within the ```SecurityBaseline``` table. 
3. Use the Microsoft Defender CLI with ```az security alert list```. 

### Vulnerability Assessment of Containers [No TTP]
1. Query Microsoft Defender for Cloud with Qualys with Container Image Scanning capability. 
2. Use the Microsoft Defender CLI with ```az security alert list```. 

### View File Retrieval [No TTP]
1. Query the Azure Log Analytics Workspace via the GUI. 
	- Query to run: ```StorageBlobLogs | where OperationName =="GetBlob" | project TimeGenerated,AccountName,CallerIpAddress, Uri```
2. Query the Azure Log Analytics Workspace via the CLI. 
	- Commands to run: 
		- ```WORKSPACE_GUID=$(az monitor log-analytics workspace show --resource-group [RsourceGroup] --workspace-name [WorkspaceName] --query 'customerId' --output tsv)```
		- ```az monitor log-analytics query --workspace $WORKSPACE_GUID --analytics-query 'StorageBlobLogs | where OperationName =="GetBlob" | project TimeGenerated,AccountName,CallerIpAddress, Uri'```
3. Query for other log sources within Azure Log Analytics Workspace to include: ```StorageFileLogs```, ```StorageTableLogs```, and ```StorageQueueLogs```. 

### View File Creation Events [No TTP]
1. Query the Azure Log Analytics Workspace via the GUI. 
	- Query to run: ```StorageFileLogs | where OperationName =="CreateFile" | project TimeGenerated,CallerIpAddress, Uri```
2. Query the Azure Log Analytics Workspace via the CLI. 
	- Commands to run: 
		- ```WORKSPACE_GUID=$(az monitor log-analytics workspace show --resource-group [RsourceGroup] --workspace-name [WorkspaceName] --query 'customerId' --output tsv)```
		- ```az monitor log-analytics query --workspace $WORKSPACE_GUID --analytics-query 'StorageFileLogs | where OperationName =="CreateFile" | project TimeGenerated,CallerIpAddress, Uri'```

### View Deployed Containers [T1610](https://attack.mitre.org/techniques/T1610/)
1. Query the Azure Log Analytics Workspace with the specific table. 
	- Query to run: ```ContainerInstanceLog_CL | project TimeGenerated, ContainerGroup_s, Message```
2. Query the Azure Log Analytics Workspace for the following tables: ```ContainerInventory```, ```ContainerNodeInventory```, ```InsightsMetricss```, ```KubeEvents```, ```KubeMonAgentEvents```, ```KubeNodeInventory```, ```KubeServices```, or ```ContainerLog```. 

### Identify Cloud Instance Creation [T1578.002](https://attack.mitre.org/techniques/T1578/002/)
1. Review alerts within Azure Activity Log GUI for "Microsoft.Compute/virtualMachines/create" operations.
2. Query the Azure Log Analytics GUI for VM creation. 

### Identify Cloud Instance Deletion [T1578.003](https://attack.mitre.org/techniques/T1578/003/)
1. Review alerts within Azure Activity Log GUI for "Microsoft.Compute/virtualMachines/delete" operations. 
2. Query Azure Activity Log for delete operations. 
	- Command to run: ```az monitor activity-log list --offset 1h --query "[?authorization.action=='Microsoft.Compute/virtualMachines/delete’].{Time:eventTimestamp,Caller:caller,SourceIP:claims.ipaddr}" --output table```
3. Query Azure Log Analytics GUI for VM deletion. 
	- Query to run: ```AzureActivity | extend Action= extractjson("$.action", Authorization) | where Action == "Microsoft.Compute/virtualMachines/delete" | project TimeGenerated, Action, Caller, CallerIpAddress | sort by TimeGenerated desc```
4. Query Azure Log Analytics via the CLI for VM deletion. 
	- Commands  to run: 
		- ```WORKSPACE_GUID=$(az monitor log-analytics workspace show --resource-group [RsourceGroup] --workspace-name [WorkspaceName] --query 'customerId' --output tsv)```
		- ```az monitor log-analytics query --workspace $WORKSPACE_GUID --analytics-query 'AzureActivity | extend Action= extractjson("$.action", Authorization) | where Action == "Microsoft.Compute/virtualMachines/delete" | project TimeGenerated, Action, Caller, CallerIpAddress | sort by TimeGenerated desc'```

### Identify Cloud Instance Updates [T1578](https://attack.mitre.org/techniques/T1578)
1. Review alerts within Azure Activity Log GUI for instance updates.
2. Query the Azure Log Analytics GUI for VM updates. 
### Identify Reverse Shell Activity [T1059](https://attack.mitre.org/techniques/T1059/)
1. Query the Log Analytics Workspace for SecurityAlert. 
	- Query to run: ```SecurityAlert | where TimeGenerated between(datetime("8/9/2023 00:00:00")..datetime("8/10/2023 00:00:00")) | where DisplayName == "Possible reverse shell" | take 1 | extend FilePath = extract_json("$.File Path", ExtendedProperties) | extend FileName = extract_json("$.File Name", ExtendedProperties) | extend FileHash = extract_json("$.File Sha256", ExtendedProperties) | extend UserName = extract_json("$.User Name", ExtendedProperties) | extend MachineName = extract_json("$.Machine Name", ExtendedProperties) | project TimeGenerated, FilePath, FileName, FileHash, UserName, MachineName```
2. Query the Log Analytics Workspace via the CLI. 
	- Commands to run: 
		- ```WORKSPACE_GUID=$(az monitor log-analytics workspace show --resource-group [RsourceGroup] --workspace-name [WorkspaceName] --query 'customerId' --output tsv)```
		- ```az monitor log-analytics query --workspace $WORKSPACE_GUID --analytics-query 'SecurityAlert | where TimeGenerated between(datetime("8/9/2023 00:00:00")..datetime("8/10/2023 00:00:00")) | where DisplayName == "Possible reverse shell" | take 1 | extend FilePath = extract_json("$.File Path", ExtendedProperties) | extend FileName = extract_json("$.File Name", ExtendedProperties) | extend FileHash = extract_json("$.File Sha256", ExtendedProperties) | extend UserName = extract_json("$.User Name", ExtendedProperties) | extend MachineName = extract_json("$.Machine Name", ExtendedProperties) | project TimeGenerated, FilePath, FileName, FileHash, UserName, MachineName'```
3. Review alerts in Microsoft Defender for Cloud in the GUI. 
4. Use the Microsoft Defender CLI with ```az security alert list```. 

### Identify Data Exfiltration [T1530](https://attack.mitre.org/techniques/T1530/)
1. Query the Log Analytics Workspace in the GUI for StorageBlobLogs. 
	- Query to run: ```StorageBlobLogs | where TimeGenerated between(datetime("8/9/2023 00:00:00")..datetime("8/10/2023 00:00:00"))```
2. Query the Log Analytics Workspace through the CLI. 
	- Commands to run: 
		- ```WORKSPACE_GUID=$(az monitor log-analytics workspace show --resource-group [RsourceGroup] --workspace-name [WorkspaceName] --query 'customerId' --output tsv)```
		- ```az monitor log-analytics query --workspace $WORKSPACE_GUID --analytics-query 'StorageBlobLogs | where TimeGenerated between(datetime("8/9/2023 00:00:00")..datetime("8/10/2023 00:00:00"))'```
3. Query the Log Analytics Workspace in the GUI for StorageBlobLogs. 
	- Query to run: ```StorageBlobLogs | where TimeGenerated between(datetime("8/9/2023 00:00:00")..datetime("8/10/2023 00:00:00")) | extend SourceIP = splitCallerIpAddress,":")[0] | summarize dataOut = sum(ResponseBodySize) by tostring(SourceIP), OperationName | sort by dataOut```
4. Query the Log Analytics Workspace through the CLI. 
	- Commands to run: 
		- ```WORKSPACE_GUID=$(az monitor log-analytics workspace show --resource-group [RsourceGroup] --workspace-name [WorkspaceName] --query 'customerId' --output tsv)```
		- ```az monitor log-analytics query --workspace $WORKSPACE_GUID --analytics-query 'StorageBlobLogs | where TimeGenerated between(datetime("8/9/2023 00:00:00")..datetime("8/10/2023 00:00:00")) | extend SourceIP = split(CallerIpAddress,":")[0] | summarize dataOut = sum(ResponseBodySize) by tostring(SourceIP), OperationName | sort by dataOut'```
### Identify Data Staging [T1074.002](https://attack.mitre.org/techniques/T1074/002/)
1. Query the Log Analytics Workspace in the GUI for StorageBlobLogs. 
	- Query to run: ```StorageBlobLogs | where TimeGenerated between(datetime("8/9/2023 00:00:00")..datetime("8/10/2023 00:00:00")) | extend SourceIP = split(CallerIpAddress,":")[0] | summarize dataOut = sum(ResponseBodySize) by tostring(SourceIP), OperationName | sort by dataOut```
2. Query the Log Analytics Workspace through the CLI. 
	- Commands to run: 
		- ```WORKSPACE_GUID=$(az monitor log-analytics workspace show --resource-group [RsourceGroup] --workspace-name [WorkspaceName] --query 'customerId' --output tsv)```
		- ```az monitor log-analytics query --workspace $WORKSPACE_GUID --analytics-query 'StorageBlobLogs | where TimeGenerated between(datetime("8/9/2023 00:00:00")..datetime("8/10/2023 00:00:00")) | extend SourceIP = split(CallerIpAddress,":")[0] | summarize dataIn = sum(ResponseBodySize) by tostring(SourceIP), OperationName | sort by dataIn'```
### Detect Command Execution [T1059](https://attack.mitre.org/techniques/T1059/)
1. Query the Log Analytics Workspace in the GUI for AzureActivity. 
	- Query to run: ```AzureActivity | where TimeGenerated between(datetime("8/9/2023 00:00:00")..datetime("8/10/2023 00:00:00")) | project TimeGenerated,  OperationNameValue, Level, Caller```
2. Query the Log Analytics Workspace through the CLI. 
	- Commands to run: 
		- ```WORKSPACE_GUID=$(az monitor log-analytics workspace show --resource-group [RsourceGroup] --workspace-name [WorkspaceName] --query 'customerId' --output tsv)```
		- ```az monitor log-analytics query --workspace $WORKSPACE_GUID --analytics-query 'AzureActivity | where TimeGenerated between(datetime("8/9/2023 00:00:00")..datetime("8/10/2023 00:00:00")) | project TimeGenerated,  OperationNameValue, Level, Caller'```

### Detect Managed Identity Usage [T1552.005](https://attack.mitre.org/techniques/T1552/005/)
1. Query the Log Analytics Workspace through the CLI and the AADManagedIdentitySignInLogs table and match ServicePrincipalId with the user identities. 
	- Commands to run: 
		- ```WORKSPACE_GUID=$(az monitor log-analytics workspace show --resource-group [RsourceGroup] --workspace-name [WorkspaceName] --query 'customerId' --output tsv)```
		- ```az monitor log-analytics query --workspace $WORKSPACE_GUID --analytics-query 'AADManagedIdentitySignInLogs | where TimeGenerated between(datetime("8/9/2023 00:00:00")..datetime("8/10/2023 00:00:00"))'```
		- ```az monitor log-analytics query --workspace $WORKSPACE_GUID --analytics-query 'AzureActivity | where TimeGenerated between(datetime("8/9/2023 00:00:00")..datetime("8/10/2023 00:00:00")) and Caller == [UserID]'```
2. Query the Log Analytics Workspace within the GUI. 
	- Queries to run: 
		- ```AADManagedIdentitySignInLogs | where TimeGenerated between(datetime("8/9/2023 00:00:00")..datetime("8/10/2023 00:00:00"))```
		- ```AzureActivity | where TimeGenerated between(datetime("8/9/2023 00:00:00")..datetime("8/10/2023 00:00:00")) and Caller == [UserID]```
## Network 

### Detect SSH Brute Force [T1110](https://attack.mitre.org/techniques/T1110/)
1. Review alerts for "Failed SSH brute force attack" within Microsoft Defender for Cloud alerts. 
2. Review alerts for "SSH - Potential Brute Force" in Microsoft Sentinel. 
3. Use Azure Network Watcher Packet Capture capability. 
4. Query Azure Log Analytics Workspace with the configured authentication log from ```/var/log/secure``` sent via the agent. 
	- Query to run: ```LinuxAuth_CL | where RawData contains "Failed password" or RawData contains "Invalid user" | project TimeGenerated, RawData```
5. View Sign-in logs from Azure Active Directory within the web GUI. 
6. Use the Microsoft Defender CLI with ```az security alert list```. 
7. Query Log Analytics Workspace in the GUI with the SecurityAlert table. 
	- Query to run: ```SecurityAlert | where Tactics == "CredentialAccess" | extend MaliciousIP = split(split(tostring(Entities),"Address")[1],'"')[2] | project TimeGenerated, DisplayName, MaliciousIP | sort by TimeGenerated asc```
8. Query Log Analytics Workspace within the CLI with the SecurityAlert table. 
	- Commands to run: 
		- ```WORKSPACE_GUID=$(az monitor log-analytics workspace show --resource-group [RsourceGroup] --workspace-name [WorkspaceName] --query 'customerId' --output tsv)```
		- ```az monitor log-analytics query --workspace $WORKSPACE_GUID --analytics-query 'SecurityAlert | where Tactics == "CredentialAccess" | extend MaliciousIP = split(split(tostring(Entities),"Address")[1],'"')[2] | project TimeGenerated, DisplayName, MaliciousIP | sort by TimeGenerated asc'```

### Detect Sign in Activity [T1078.004](https://attack.mitre.org/techniques/T1078/004/) [T1110.001](https://attack.mitre.org/techniques/T1110/001/)
1. Query the Log Analytics Workspace in the GUI for all successful logins. 
	- Command to run: ```SigninLogs | extend AuthenticationMethod = extractjson("$.[0].authenticationMethod", AuthenticationDetails) | extend Succeeded = extractjson("$.[0].succeeded", AuthenticationDetails) | project TimeGenerated, AuthenticationMethod, Succeeded, IPAddress, UserAgent```
2.  Query the Log Analytics Workspace through the CLI. 
	- Commands to run: 
		- ```WORKSPACE_GUID=$(az monitor log-analytics workspace show --resource-group [RsourceGroup] --workspace-name [WorkspaceName] --query 'customerId' --output tsv)```
		- ```az monitor log-analytics query --workspace $WORKSPACE_GUID --analytics-query 'SigninLogs | extend AuthenticationMethod = extractjson("$.[0].authenticationMethod", AuthenticationDetails) | extend Succeeded = extractjson("$.[0].succeeded", AuthenticationDetails) | project TimeGenerated, AuthenticationMethod, Succeeded, IPAddress, UserAgent'```
3. Use Azure Network Watcher Packet Capture capability. 
4. Query Azure Log Analytics Workspace with the configured authentication log from ```/var/log/secure``` sent via the agent. 
	- Query to run: ```LinuxAuth_CL | project TimeGenerated, RawData```
5. View Risky sign-ins from Azure Active Directory. 
6. View Sign-in logs from Azure Active Directory within the web GUI. 

### Detect Failed Password Attempts [T1110.001](https://attack.mitre.org/techniques/T1110/001/)
1. Query the Log Analytics Workspace in the GUI for failed login attempts with a password. 
	- Query to run: ```SigninLogs | extend AuthenticationMethod = extractjson("$.[0].authenticationMethod", AuthenticationDetails) | extend Succeeded = extractjson("$.[0].succeeded", AuthenticationDetails) | where Succeeded == "false" and AuthenticationMethod == "Password" | project TimeGenerated, AuthenticationMethod, Succeeded, IPAddress, UserAgent```
2. Query the Log Analytics Workspace in the GUI for multiple failed logon attempts. 
	- Query to run: ```SigninLogs | where TimeGenerated between(datetime("8/9/2023 00:00:00")..datetime("8/10/2023 00:00:00")) | extend AuthenticationMethod = extractjson("$.[0].authenticationMethod", AuthenticationDetails) | extend Succeeded = extractjson("$.[0].succeeded", AuthenticationDetails) | where Succeeded == "false" and AuthenticationMethod == "Password" | summarize count() by IPAddress```
3.  Query the Log Analytics Workspace through the CLI. 
	- Commands to run: 
		- ```WORKSPACE_GUID=$(az monitor log-analytics workspace show --resource-group [RsourceGroup] --workspace-name [WorkspaceName] --query 'customerId' --output tsv)```
		- ```az monitor log-analytics query --workspace $WORKSPACE_GUID --analytics-query 'SigninLogs | where TimeGenerated between(datetime("8/9/2023 00:00:00")..datetime("8/10/2023 00:00:00")) | extend AuthenticationMethod = extractjson("$.[0].authenticationMethod", AuthenticationDetails) | extend Succeeded = extractjson("$.[0].succeeded", AuthenticationDetails) | where Succeeded == "false" and AuthenticationMethod == "Password" | summarize count() by IPAddress'```
4. Review alerts within Microsoft Sentinel for "Password spray attack against Azure AD application."
5. Use Azure Network Watcher Packet Capture capability. 
6. Query Azure Log Analytics Workspace with the configured authentication log from ```/var/log/secure``` sent via the agent. 
	- Query to run: ```LinuxAuth_CL | where RawData contains "Failed password" or RawData contains "Invalid user" | project TimeGenerated, RawData```
7. View Sign-in logs from Azure Active Directory within the web GUI. 
8. Query Log Analytics Workspace in the GUI with the SecurityAlert table. 
	- Query to run: ```SecurityAlert | where Tactics == "CredentialAccess" | extend MaliciousIP = split(split(tostring(Entities),"Address")[1],'"')[2] | project TimeGenerated, DisplayName, MaliciousIP | sort by TimeGenerated asc```
9. Query Log Analytics Workspace within the CLI with the SecurityAlert table. 
	- Commands to run: 
		- ```WORKSPACE_GUID=$(az monitor log-analytics workspace show --resource-group [RsourceGroup] --workspace-name [WorkspaceName] --query 'customerId' --output tsv)```
		- ```az monitor log-analytics query --workspace $WORKSPACE_GUID --analytics-query 'SecurityAlert | where Tactics == "CredentialAccess" | extend MaliciousIP = split(split(tostring(Entities),"Address")[1],'"')[2] | project TimeGenerated, DisplayName, MaliciousIP | sort by TimeGenerated asc'```
### Identify Network Scanning [T1046]()
1. Query Log Analytics Workspace in the GUI with the AzureNetworkAnalytics_CL. 
	- Query to run: ```AzureNetworkAnalytics_CL | where FlowStartTime_t between(datetime("8/9/2023 00:00:00")..datetime("8/10/2023 00:00:00")) | summarize Count = count() by PublicIPs_s```
2. Query Log Analytics Workspace within the CLI. 
	- Commands to run: 
		- ```WORKSPACE_GUID=$(az monitor log-analytics workspace show --resource-group [RsourceGroup] --workspace-name [WorkspaceName] --query 'customerId' --output tsv)```
		- ```az monitor log-analytics query --workspace $WORKSPACE_GUID --analytics-query 'AzureNetworkAnalytics_CL | where FlowStartTime_t between(datetime("8/9/2023 00:00:00")..datetime("8/10/2023 00:00:00")) | summarize Count = count() by PublicIPs_s'```
3. Use Azure Network Watcher Packet Capture capability. 
### Identify Network Flows [No TTP]
1. Query Log Analytics Workspace in the GUI with the AzureNetworkAnalytics_CL focusing on ingress traffic from specific IP. 
	- Query to run: ```AzureNetworkAnalytics_CL | where TimeGenerated between(datetime("8/9/2023 00:00:00")..datetime("8/10/2023 00:00:00")) and PublicIPs_s contains "40.70.212.199" and FlowDirection_s == "I" and FlowStatus_s == "A" | distinct L7Protocol_s, L4Protocol_s, DestPort_d```
2. Query Log Analytics Workspace within the CLI with the AzureNetworkAnalytics_CL focusing on ingress traffic from specific IP. 
	- Commands to run: 
		- ```WORKSPACE_GUID=$(az monitor log-analytics workspace show --resource-group [RsourceGroup] --workspace-name [WorkspaceName] --query 'customerId' --output tsv)```
		- ```az monitor log-analytics query --workspace $WORKSPACE_GUID --analytics-query 'AzureNetworkAnalytics_CL | where TimeGenerated between(datetime("8/9/2023 00:00:00")..datetime("8/10/2023 00:00:00")) and PublicIPs_s contains "40.70.212.199" and FlowDirection_s == "I" and FlowStatus_s == "A" | distinct L7Protocol_s, L4Protocol_s, DestPort_d'```
3. Query Log Analytics Workspace in the GUI with the AzureNetworkAnalytics_CL focusing on egress traffic. 
	- Query to run: ```AzureNetworkAnalytics_CL | where TimeGenerated between(datetime("8/9/2023 00:00:00")..datetime("8/10/2023 00:00:00")) and PublicIPs_s contains "40.70.212.199" and FlowDirection_s == "O" and FlowStatus_s == "A" | distinct L7Protocol_s, L4Protocol_s, DestPort_d```
4. Query Log Analytics Workspace within the CLI with the AzureNetworkAnalytics_CL focusing on egress traffic. 
	- Commands to run: 
		- ```WORKSPACE_GUID=$(az monitor log-analytics workspace show --resource-group [RsourceGroup] --workspace-name [WorkspaceName] --query 'customerId' --output tsv)```
		- ```az monitor log-analytics query --workspace $WORKSPACE_GUID --analytics-query 'AzureNetworkAnalytics_CL | where TimeGenerated between(datetime("8/9/2023 00:00:00")..datetime("8/10/2023 00:00:00")) and PublicIPs_s contains "40.70.212.199" and FlowDirection_s == "O" and FlowStatus_s == "A" | distinct L7Protocol_s, L4Protocol_s, DestPort_d'```
5. Use Azure Network Watcher Packet Capture capability. 

### Identify Suspicious Email Traffic [T1566](https://attack.mitre.org/techniques/T1566/)
1. View Mail Flow within the Microsoft 365 Exchange Admin Center. 

### Identify Database Scanning [T1190](https://attack.mitre.org/techniques/T1190/)
1. Query Log Analytics Workspace in the GUI with the AzureDiagnostics table. 
	- Query to run: ```AzureDiagnostics | where TimeGenerated between(datetime("10/29/2021 2:45 PM").. datetime("10/29/2021 3:00 PM")) and Category == "SQLSecurityAuditEvents" and action_id_s == "BCM " | extend statementLength = strlen(statement_s) | sort by statementLength | project client_ip_s, statementLength, statement_s```
2. Query Log Analytics Workspace within the CLI with the AzureDiagnostics table. 
	- Commands to run: 
		- ```WORKSPACE_GUID=$(az monitor log-analytics workspace show --resource-group [RsourceGroup] --workspace-name [WorkspaceName] --query 'customerId' --output tsv)```
		- ```az monitor log-analytics query --workspace $WORKSPACE_GUID --analytics-query 'AzureDiagnostics | where TimeGenerated between(datetime("10/29/2021 2:45 PM").. datetime("10/29/2021 3:00 PM")) and Category == "SQLSecurityAuditEvents" and action_id_s == "BCM " | extend statementLength = strlen(statement_s) | sort by statementLength | project client_ip_s, statementLength, statement_s'```

### Identify C2 Traffic [T1571](https://attack.mitre.org/techniques/T1571/)
1. Query Log Analytics Workspace in the GUI with the AzureNetworkAnalytics_CL table. 
	- Query to run: ```AzureNetworkAnalytics_CL | where TimeGenerated between(datetime("9/27/2021 00:00:00") ..datetime("9/27/2021 23:59:59")) and PublicIPs_s contains "3.95.15.41" and FlowDirection_s == "O" and DestPort_d == 443 and L4Protocol_s == "T" | summarize Count = count() by bin(FlowStartTime_t, 1m) | project Count, FlowStartTime_t | render columnchart```
2. Query Log Analytics Workspace within the CLI with the AzureNetworkAnalytics_CL table. 
	- Commands to run: 
		- ```WORKSPACE_GUID=$(az monitor log-analytics workspace show --resource-group [RsourceGroup] --workspace-name [WorkspaceName] --query 'customerId' --output tsv)```
		- ```az monitor log-analytics query --workspace $WORKSPACE_GUID --analytics-query 'AzureNetworkAnalytics_CL | where TimeGenerated between(datetime("9/27/2021 00:00:00") ..datetime("9/27/2021 23:59:59")) and PublicIPs_s contains "3.95.15.41" and FlowDirection_s == "O" and DestPort_d == 443 and L4Protocol_s == "T" | summarize Count = count() by bin(FlowStartTime_t, 1m) | project Count, FlowStartTime_t | render columnchart'```