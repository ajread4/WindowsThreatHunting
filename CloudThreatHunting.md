# AWS 

## Host
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
## Network

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
# Azure 

## Host
## Network 

