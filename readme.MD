


# DefensePro – Best Practice configuration analyzer:


# ChangeLog

v1.3 
- Added running dpconfig data parsing with cache data
	--use-cache-data
	
v1.4
- dpconfig_parser.py
	- Change log to csv instead of dictionary
	- Code revise

v1.5 
- dpconfig_parser.py
	- If no profiles, no need to log missing specific profiles
	- Fixed ERT Active Attacker Feed profile logging
	- Added BDOS profile is in "Report-Only" mode

v1.6
- dpconfig_parser.py
	- Fixed bug with policies priorities in ver 7.x while policy name/policy priority is 'null'

V1.9
-	Code optimization

V1.13
-	Code optimization, added folders Requests, Raw Data, Reports

V2.0
-	Split config analyzer as a dedicated app

V2.1
-	Check BDOS profile Footprint Strictness and alert if not set to Medium
-	Added printing and logging of script progress
-	Check BDOS profile and alert if learning suppression is set to less than 50%
-	Disabled sending email by default when running the script.
-	Added creation of empty folders if does not exist “log”, “Raw Data”, “Reports”

V2.2
-	Added downloading DP config file, normalization and parsing
-	Added checking SSH timeout
-	Added Configuration audit check is enabled
-	Added Configuration audit type extended check
-	Added checking if management access through HTTP is disabled
-	Added checking if management access through Telnet is disabled
-	Added checking if web-services is disabled
- 	Added network class parsing 
	1. Network class is a subnet of another network class
	2. Network class is unused(orphaned)
	3. Same network class is shared with antoher policy
	4. Network class has a duplicate network with another network class
-	Added BDOS config check - UDP Packet sensitivity recommendation of "Low" or "Ignore or Disabled"
-	Added BDOS config check - Flood settings - check that every protocol is enabled (SYN, SYN+ACK, UDP, etc.)
-	Added BDOS "Burst-Attack Protection" detection if enabled
-	Added BDOS check if Inbound/Outbound traffic is not set lower than desired value (Default 100Mbps)
-	Changed BDOS learning suppression to be configurable through config.cfg
-	Updated config.cfg example

V2.3
-	Signature sample rate
-	SMTP_AUTH variable
-	Enhanced error logging while collecting the data

V2.4
-	5/30/22 Enhanced logging errors

V2.5
-	7/2/22 Removed printing "Signature dos-shield sampling rate is set to default 5001"

V2.6
- 	11/25/22 Added new feature
		- Collecting the data for SYN Flood profiles
		- Detection if SYN Flood profile is in Report mode
		- Detection if SYN Flood profile is not applied on any policy (orphaned)

3.0
-	12/2/22 Added new functionality- DefensePro Configuration mapping .\Reports\dpconfig_map.csv
		- This is includes DefensePro, Policy and BDOS profile mapping only

3.1
	12/9/22 Listed all common protection profiles (BDOS and DNS maps common settings as well).

3.2

	- 2/28/23 Added mapping SYN Flood protection settings/thresholds

3.3

	- 3/9/23 Added mapping Connecion limit protection settings/thresholds
	- 3/10/23 Bugfixes (value null, non-existing connlim keys in older versions), added configurable variable "ANALYZE_CONFIG" to config.py 

3.4

	- 3/15/23 Added mapping OOS main settings/thresholds

3.5
	- 3/16/23 Added Policy state Enabled/Disabled, OOS bugfix

3.6
	- 3/23/23 Added mapping source and destination networks

4.0
	- Added choosing DefensePro Scope
		!!! New mandatory variable "DP_IP_SCOPE_LIST" added into config.py, add below line into "config.py"
			DP_IP_SCOPE_LIST = [] # List of DefensePro IP addresses to analyze, comma separated, example ['1.1.1.2','1.1.1.3']. if empty []- analyze all DefensePro in Vision

	- Added cleaning up existing DP config before collecting new ones
	- Added writing device list to the raw json file
	- Added run.sh (necessary if run from the container)

4.1
	3/28/23 
	- Added cleanup of Raw_Data folder before script runs
	- Bug fixes in config.py DP_IP_SCOPE_LIST
	- Added new functionality - defining DP scope using customers.json file
		!!! New mandatory variables added into config.py
		add below line into "config.py"

		CUSTOMERS_JSON = False # True - scope for the data collection will be defined from "customers.json" file, False - scope will be defined using config.py variable "DP_IP_SCOPE_LIST"

		CUSTOMERS_JSON_CUST_ID_LIST = [] # List of customer IDs to collect data for, comma separated, example ['Customer A','Customer B']. If empty [] - collect data for all customers defined in customers.json file

	- Optimized netClassDuplication() function to execute only if isDPAvailable() function is True

# Functionality to be added:

- Add full configuration mapping with thresholds to a separate file
- Add check if network class is in use by any of the ACL's- currently it checks only if it is applied on the policies
- Add connection limit profiles are orphaned
- Add traffic filters (report/block), orphaned
- Add recommendation priority High/Med/Low to the final report

# Overview 

The script purpose is to provide DefensePro Best Practice Configuration Recommendations report (dpconfig_report.csv)

The script interacts with Radware APSolute Vision DefensePro and collects all the necessary data through REST API calls.

## IMPORTANT

● Read the entire file before attempting to configure/executing.


# Script Output

The script output generates one report in csv format. Report name is “dpconfig_report.csv”

DefensePro Best Practice Configuration Recommendations report (dpconfig_report.csv)

DefensePro Best Practice Configuration Recommendations report includes the following configuration checks:
1.	DefensePro has no catchall policy
2.	Policy has no security profiles applied
3.	Policy is configured two-way
4.	Policy is in report mode
5.	Policy is disabled
6.	Packet reporting is disabled
7.	Policy has no BDOS profile applied
8.	Policy has no Signature profile applied
9.	Signature profile applied on the policy does not include all DoS-All rules
10.	DNS Signature profile applied on the DNS policy does not include all DoS-All rules and DNS Services Signatures
11.	Policy has no Out of state profile applied
12.	Policy has no Connection Limit applied
13.	Policy has no SYN Flood profile applied
14.	Policy has no ERT Active Attacker Feed profile applied
15.	DefensePro has no Heartbeat policy for the Silicom Bypass Switch (if exists)
16.	Catchall policy has not the lowest priority
17.	Policies distribution across instances is not equal for DefensePro version 7.x 
18.	BDOS profile is in report mode
19.	BDOS profile is not applied on any policy(orphaned)
20.	BDOS profile has Footprint Strictness is not set to Medium 
21.	BDOS profile learning suppression is less than 50%
22.	SSH Timeout
23.	Configuration audit is enabled
24.	Configuration audit type extended is enabled
25.	Management access through HTTP is disabled
26.	Management access through Telnet is disabled
27.	Web-services is disabled if unnecessary.
28.	Network class parsing 
    a. Network class is a subnet of another network class
    b. Network class is unused(orphaned)
    c. Same network class is shared with antoher policy
    d. Network class has a duplicate network with another network class
29.	SYN Flood profile is in report mode
30.	SYN Flood profile is not applied on any policy(orphaned)


# Setup

## Requirements

The solution requires python 3.6 and higher

### Packages required but should be part of the standard 3.6 library- no need to install

json
csv
socket
logging
smtplib
email
datetime
os
sys

### Packages required but may requires installation

urllib3
ipaddress

Use the following command in order to install urllib3

pip install -r requirements.txt


## Instructions and recommendations

1. Place the script folder into the appropriate location on the server
2. Install dependencies and necessary libraries/packages
3. Rename file `config.py example` to ‘config.py’ and set the necessary values.
4. Set up the script to run periodically (optional) though cron (linux) or windows scheduler on windows:

    Linux cron example

    0 4 * * * /path/to/app/python3 main.py #example setting the script to run every day at 4 am.

5. Navigate to the folder containing the script and run 
python3 main.py
-	Runs the script, produces all 4 reports and sends them by email
Script can be run with the following arguments (multiple arguments may be combined together)
python3 main.py --use-cache-data
-	Script parses previously collected data only (stage 2 only, no data collection)
python3 main.py --email
-	Script runs and sends email at the end
python3 main.py --test-email"
-	Script runs test email function to test email server connectivity.

# Components for the script operation

## “config.py”

“config.py” includes all the configurable variables in order to run the script. Below is the list of the configurable variables

VISION_IP = "1.1.1.1" # APSolute Vision IP
VISION_USER = "user" # APSolute Vision username
VISION_PASS = "password" # APSolute Vision password

/# Script logging set up parameters 
LOG_FILE_PATH = "./log/" # folder to save the script logging events
LOG_ROTATION_SIZE = 20000000 # Maximum rotation log file size in Bytes after which it will be split to another file
LOG_ROTATION_HISTORY = 10 # Maximum amount of log files to keep
SYSLOG_SERVER = "1.1.1.2" # Syslog server destination IP for sending events through syslog
SYSLOG_PORT = 514 # Syslog server destination UDP port

/# Email set up parameters for sending email with reports
SMTP_SERVER = "smtp.gmail.com" # SMTP server name
SMTP_SERVER_PORT = 587 # SMTP server port
SMTP_SENDER = 'sender@gmail.com' # Email sender address setting
SMTP_PASSWORD = radware # Email password (optional)
SMTP_LIST = ['recepient@radware.com'] # Email address/address list recepient/s(comma separated)
SMTP_SUBJECT_PREFIX = "ALARM:DP - " # Email Subject
SMTP_MSG_BODY = "This email was automated by the DefensePro monitoring script" # Email message body


## “main.py”

-	main.py is a main file which actually runs the script 
-	By default, the script will generate the report and send it by email.
-	The script logs errors through syslog for remote monitor and write to a local log.
-	At the end, the script sends an email with generated report attached.

## “vision.py”
	
This file includes all the instructions how to connect to the APSolute Vision and construct proper API calls to fetch the data

## logging_helper.py

	This file includes all the settings and functions for setting up the logging  and email  functionality

## dpconfig_parser.py

“dpconfig_parser.py” parses the collected data and writes deviations from the best practice into “dp_config.csv” final report. The checks are listed under the “Script output” section


# Script operation stages

## Stage 1- Data collection

At stage 1, the data is collected for all registered DefensePro/policies and is written to intermediate files.

Files necessary for the Best practice configuration review

### full_bdosprofconf_dic.json

This file is being generated once the data collection is complete and it includes all the bdos profiles configuration data.

### full_net_dic.json

This file is being generated once the data collection is complete and it includes all the network classes profiles configuration data.

### full_sig_dic.json

This file is being generated once the data collection is complete and it includes all the signature profiles configuration data.

### full_pol_dic.json

“full_pol_dic.json” is generated once the data collection is complete, it stores all the information for all the policies for all the registered DefensePro’s in the APSolute Vision and is used for the further data parsing.

# Stage 2- Data parsing

## dpconfig_parser.py

“dpconfig_parser.py” parses the collected data and writes deviations from the best practice into “dp_config.csv” final report. The checks are listed under the “Script output” section

## Stage 3 – email alert
By default, once the script finishes its operation, “dp_config.csv” report will be sent to the email address/es listed in ”config.py”.


