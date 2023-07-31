


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

5.0 
	4/5/2023
	- Merged traffic stats collector script (https://github.com/Radware/DP_stats_collector) with this script (https://github.com/Radware/DP_config_analyzer)
	- Added cleaning existing raw data, reports, dp configs before collecting the new data
	- Optimized data collection code
	- Directories paths optimization
	- Added new config.py variables
	
		TRAFFIC_STATS
			True- collect traffic stats collection and report generation configurable setting
			False - do not collect traffic stats collection and report generation configurable setting
	
		ANALYZE_CONFIG
			True - parse the data and generate "dpconfig_report.csv"
			False - do not parse the data and generate "dpconfig_report.csv"


		MAP_CONFIG
			True - parse the data and generate "dpconfig_map.csv"
			False - do not parse the data and generate "dpconfig_map.csv"

5.1
	4/6/2023 
	-	get_data_from_vision function code optimization, 
	-	added measuring time it takes for the script to complete
	4/17/2023
	-	Added keeping old reports (configurable )

5.2
	4/27/2023
	-	added writing configured bdos bandwidth to traffic_stats report

5.3
	6/15/2023
	-	added checking for the outdated signatures
		!! config.py update is required - added new variable below:
			SIG_DB_DELTA = 2 # Signature DB Delta from the latest release to the current release in weeks

5.4
	6/23/2023
	-	Added sending requests through Proxy option
				!! config.py update is required (see config.py example) - added new proxy variables below:

				################# Proxy settings #################

				PROXY = False # True - use proxy server, False - don't use proxy server

				PROXY_HTTP = "proxy-radware.com"
				PROXY_HTTP_PORT = 80

				PROXY_HTTPS = "proxy-radware.com"
				PROXY_HTTPS_PORT = 443

				PROXY_USER = "radware"
				PROXY_PASS = "radware"
	- 	Added UA header to InternetConnectivity function
	
5.4.1
	6/28/2023
	-	Changed the way to get the latest signatures from vision instead of Radware

5.4.2
	6/30/2023
	-	Added condition when checking for the latest signatures from vision, if Vision has no connectivity to www.radware.com , latest signature database can be set manually with a new variable as in below example SIG_LATEST_VER = "0009.0739.00"

	!! config.py update is required (see config.py example) - added new proxy variable below:
	
	SIG_LATEST_VER
	
5.5
	7/4/2023
	-	Added new feature to control which checks to be done when providing recommendations.

	!! config.py update is required (see config.py example) - added new proxy variable below:

					################# Best practice checklist parameters switch On/Off #################
				# This section defines what parameters to check from the Best Practice Checklist

				ANALYZE_CONFIG = True # True - Analyze DefensePro configuration to /Reports/dpconfig_report.csv, False - don't analyze configuration 

				ALL_CHECKS = False # True - Run all checks and override all checks defined below, False - Run only checks defined below

				POLICY_NO_PROFILES =			True # True - Report if DefensePro policy does not have any profiles applied. False - do not report if DefensePro policy does not have any profiles applied
				POLICY_TWO_WAY = 				True # True - Report if DefensePro policy is configued in two-way mode. False - do not report if DefensePro policy is configued in two-way mode
				POLICY_REPORT_MODE = 			True # True - Report if DefensePro policy is configued in report mode. False - do not report if DefensePro policy is configued in report mode
				POLICY_DISABLED = 				True # True - Report if DefensePro policy is configued in disabled mode. False - do not report if DefensePro policy is configued in disabled mode
				POLICY_PACKET_REPORTING = 		True # True - Report if DefensePro packet reporting is disabled on the policy. False - do not report if DefensePro packet reporting is disabpled on the policy
				POLICY_BDOS_PROF = 				True # True - Report if BDOS profile is not applied on the DefensePro policy. False - do not report if BDOS profile is not applied on the DefensePro policy
				POLICY_SIG_PROF = 				True # True - Report if Signature profile is not applied on the DefensePro policy. False - do not report if Signature profile is not applied on the DefensePro policy
				POLICY_SIG_DOSALL = 			True # True - Report if Signature profile does not have all Dos-All rules. False - do not report if Signature profile does not have all Dos-All rules
				POLICY_OOS_PROF = 				True # True - Report if Out of State profile is not applied on the DefensePro policy. False - do not report if Out of State profile is not applied on the DefensePro policy
				POLICY_CONNLIM_PROF =			True # True - Report if Connection Limit profile is not applied on the DefensePro policy. False - do not report if Connection Limit profile is not applied on the DefensePro policy
				POLICY_SYNP_PROF = 				True # True - Report if SYN Protection profile is not applied on the DefensePro policy. False - do not report if SYN Protection profile is not applied on the DefensePro policy
				POLICY_EAAF_PROF = 				True # True - Report if EAAF profile is not applied on the DefensePro policy. False - do not report if EAAF profile is not applied on the DefensePro policy
				POLICY_DNS_PROF = 				True # True - Report if DNS profile on the DNS policy does not have the DNS Services Signature + DOS-All rules. False - do not report if DNS profile on the DNS policy does not have the DNS Services Signature + DOS-All rules.
				POLICY_CATCHALL_LAST = 			True # True - Report if Catch-All rule is not the last rule in the DefensePro policy. False - do not report if Catch-All rule is not the last rule in the DefensePro policy
				BDOS_PROF_CHECKS = 				True # True - Run BDOS profile checks, False - do not run BDOS profile checks. BDOS profile checks are: 
														# BDOS profiles is in Report-Only mode
														# Footprint Strictness is not Medium
														# Learning suppression is set not to the configured value(defined as "BDOS_LST" in config.py)
														# UDP Packet Rate Detection Sensitivity is not set to Low/Ignore
														# Check if all BDOS supported prootocols are enabled for BDOS inspection
														# Inbound or outbound BDOS bandwidth is configured below the configured threshold (defined as "BDOS_BW_IN" and "BDOS_BW_OUT" in config.py)
														# Burst-Attack Protection" is disabled
														# BDOS Profile is not applied on any policy (orphaned)
				SYNP_PROF_CHECKS = 				True # True - Run SYN Protection profile checks, False - do not run SYN Protection profile checks. SYN Protection profile checks are:
														# SYN FLood Profile is in Report-Only mode
														# SYN Flood Profile is not applied on any policy (orphaned)
				BYPASS_SWITCH = 				False # True - DefensePro is deployed with Silicom bypass switch, report if DefensePro does not have a heartbeat policy for the Silicom bypass switch, False - DefensePro is deployed without bypass switch
				NO_CATCHALL_POL = 				True # True - Report if DefensePro does not have a Catch-All policy, False - do not report if DefensePro does not have a Catch-All policy
				DP_V7_EVEN_INSTANCE = 			True # True - Report if DefensePro version 7.x instances are not evenly distributed across the policies. False - do not report if DefensePro version 7.x instances are not evenly distributed across the policies.
				WEB_SERVICES_ACCESS_ENABLED = 	True # True - Report if Web Services Access is enabled on the DefensePro, False - do not report if Web Services Access is enabled on the DefensePro
				HTTP_ACCESS_ENABLED =			True # True - Report if HTTP Access is enabled on the DefensePro, False - do not report if HTTP Access is enabled on the DefensePro
				SSH_TIMEOUT_DEFAULT = 			True # True - Report if SSH timeout is set to default value (v8.x 10 min, v6.x 5 min), False - do not report if SSH timeout is set to default value (v8.x 10 min, v6.x 5 min)
				SERVICE_AUDITING = 				True # True - Report if Service Auditing is disabled and not in extended mode on the DefensePro, False - do not report if Service Auditing is disabled on the DefensePro
				TELNET_ACCESS_ENABLED = 		True # True - Report if Telnet Access is enabled on the DefensePro, False - do not report if Telnet Access is enabled on the DefensePro
				SIG_SMPL_RATE_DEFAULT = 		True # True - Report if Signature Sample Rate is set to default value (5001) instead of the recommended or configured value (defined as SIG_SMPL_RATE in config.py). False - do not report if Signature Sample Rate is set to default value (5001) instead of the recommended or configured value (defined as SIG_SMPL_RATE in config.py)
				SSH_TIMEOUT_CHECK =				True # True - Report if SSH timeout is not set to the configured value (defined as "SSH_TIMEOUT" in config.py), False - do not report if SSH timeout is not set to the configured value (defined as "SSH_TIMEOUT" in config.py)
				SIG_SMPL_RATE_CHECK = 			True # True - Report if Signature Sample Rate is not set to the configured value (defined as SIG_SMPL_RATE in config.py), False - do not report if Signature Sample Rate is not set to the configured value (defined as SIG_SMPL_RATE in config.py)
				SIG_LATEST_VER_CHECK = 			True # True - Report if DefensePro signature database is outdated, False - do not report if DefensePro signature database is outdated
				NETCLASS_CHECKS = 				True # True - Run Network Class checks, False - do not run Network Class checks. Network Class checks are:
														# Network class "{net}" is not applied on any policy
														# Network classss "{net}" is shared across multiple policies
														# Network class has a network subnet which is subnet of another larger subnet in another network class
														# Duplicate network in different network classes

5.6 (7/25/2023)

	-	Added collecting and reporting on max average BDOS PPS and PPS Baseline under traffic_stats report

6.0 (7/31/2023)
	-	Added checking low BDOS baselines (combined from the DP_BDOS_Monitor V3.2.1)
	-	Added BDOS PPS reporting if BDOS PPS rate exceeds the BDOS PPS baseline for every protocol
	-	Added new variables under config.py (! Must update config.py file)
			ANALYZE_BDOS_BASELINES = True # True - Generate low baselines report to /Reports/low_bdos_baselines.csv, False - don't generate low baselines report
			HIGH_BDOS_BASELINE_REPORT = False
			DET_MARGIN_RATIO = 1 #sets the virtual baseline ratio. For example 1 = Virtual baseline is the same as the actual baseline (100% of the actual Normal bassline), 0.3 = 30% etc.
			DET_ALARM_THRESHOLD = 10 #sets threshold for the number of occurances where the actual traffic went above the Virtual baseline. In case there were more occurrences than the defined threshold, these policies and protocols will be listed in the “low_bdos_baselines.csv”
			UDP_NBASELINE = 100000 # sets UDP Normal Baseline threhold, below which all policies will be listed
	-	Changed "timenow" behavior is taken from main.py and passed to other files
	-	Cosmetic logging improvements
	-	Added cust_id while collecting BDOS stats
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

VISION_VER = 4.85 # APSolute Vision version

TRAFFIC_STATS = True # True - Collect Traffic and BDOS statistics from DefensePro, False - don't collect Traffic/BDOS statistics and do not generate the traffic_stats.csv report

DURATION = 1 # sets the time frame in days for the traffic stats, BDOS, DNS data collection period

###########################################
REPORTS_TO_KEEP = 3 # Number of reports to keep in the Reports folder
###########################################


#################  Scope  #################

Scope can be defined in one of two ways:

#######- EITHER -#######

1. Using the same format of the customers.json file from Monthly Report script- just place the file into the same directory.

CUSTOMERS_JSON = True
	True - scope for the data collection will be defined from "customers.json" file, 
	False - scope will be defined using config.py variable "DP_IP_SCOPE_LIST"


CUSTOMERS_JSON_CUST_ID_LIST = ['ICN-DMZ'] 

	List of customer IDs to collect data for, comma separated, example ['Customer A','Customer B']. If empty [] - collect data for all customers defined in customers.json file

######   --OR--  #######

2. Manully defining the scope of DefensePro using "DP_IP_SCOPE_LIST" variable

DP_IP_SCOPE_LIST = [] 
	Example DP_IP_SCOPE_LIST = ['10.105.192.30','10.105.192.34'] 
	This is list of DefensePro IP addresses to analyze, comma separated, example ['1.1.1.2','1.1.1.3']. if empty []- analyze all DefensePro in Vision
	
###########################################

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

## dpconfig_mapper.py

“dpconfig_mapper.py” parses the collected data and maps the most common policy settings, profiles into dpconfig_map.csv report

## traffic_stats_parser.py

"traffic_stats_parser.py" parses the collected traffic statistics data and statistics for traffic utilization max (CPS, PPS, BPS, CEC, BDOS baselines) into dp\.csv report


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


################################################## DefensePro – traffic stats collector ################################################################################



# Overview 

The below functionality is now part of the config analyzer script

The script purpose is to provide a report which includes DefensePro highest peak average traffic statistics for every policy CPS/PPS/BPS/CEC/BDOS/DNS (.\Reports\traffic_stats.csv folder).

The script interacts with Radware APSolute Vision DefensePro and collects all the necessary data through REST API calls.

## IMPORTANT
● Read the entire file before attempting to configure/executing.


# Script Output

The script output includes  report in csv format:

DefensePro Traffic statistics report (traffic_stats.csv)

“traffic_stats.csv” report includes highest traffic utilization average for the configurable historical timeframe in days (default is 6 days) for every policy including the following stats
CPS = Connections Per Second per policy per DefensePro
PPS = Packets Per Second per policy per DefensePro
BPS = Traffic utilization in Mbps per policy per DefensePro
BDOS protected protocols and Normal baseline BPS per policy per DefensePro
DNS protected record types and Normal baseline QPS per policy per DefensePro
CEC = Concurrent established Connections per DefensePro All policies combined


# Script operation stages

## Stage 1- Data collection

At stage 1, the data is collected for all registered DefensePro/policies and is written to intermediate files.

Following files are mandatory in order to collect the BDOS/DNS baselines and traffic stats for low/high baselines detection.
.\Requests\BDOStrafficRequest.json

Defines the JSON payload for constructing BDOS data (traffic utilization and BDOS baselines) collection API calls.
.\Raw Data\BDOS_traffic_report.json

This file is being generated after the successful collection of all BDOS baselines and traffic stats for all registered DefensePro and policies. It includes all the traffic raw data and is used for the data parsing at the later stage. The data collection may take long time (~3 hours) and can generate large file of data ~300MB or more, depending on how large is the scale of the environment, how many DefensePro are registered to Vision and historical data collection setting ( DURATION in days under the config.py file).

.\Requests\DNStrafficRequest.json

Defines the JSON payload for constructing DNS data (DNS traffic and baselines) collection API calls.
.\Raw Data\DNS_traffic_report.json

This file is being generated after the successful collection of all DNS baselines and traffic stats for all registered DefensePro and policies. It includes all the traffic raw data and is used for the data parsing at the later stage. The data collection may take long time (~3 hours) and can generate large file of data ~300MB or more, depending on how large is the scale of the environment, how many DefensePro are registered to Vision and historical data collection setting ( DURATION in days under the config.py file).

.\Raw Data\full_net_dic.json

This file is being generated once the data collection is complete and it includes all the network classes profiles configuration data.

## full_pol_dic.json

“full_pol_dic.json” is generated once the data collection is complete, it stores all the information for all the policies for all the registered DefensePro’s in the APSolute Vision and is used for the further data parsing.


Following files are required in order to construct the API calls to Vision to collect all the CPS/PPS/BPS/CEC traffic statistics

## TrafficRequest.json

This file is required in order to construct an API call to Vision to collect BPS (Bits Per Second) and PPS(Packets Per Second) data.

## TrafficRequestCEC.json

This file is required in order to construct an API call to Vision to collect CEC(Concurrent Established Connections) data.

## TrafficRequestCPS.json

This file is required in order to construct an API call to Vision to collect CPS(Connections Per Second) data.


The files below are being generated once the traffic statistics data collection is complete. They include raw json data.
Traffic_report_CEC.json
Traffic_report_CPS.json
Traffic_report_PPS.json
Traffic_report_BPS.json


# Stage 2- Data parsing

## traffic_stats_parser.py

traffic_stats_parser.py parses the collected traffic raw reports(Traffic_report_CEC.json,  Traffic_report_CPS.json, Traffic_report_PPS.json, Traffic_report_BPS.json, BDOS_traffic_report.json), calculates and presents the highest average traffic utilization statistics for all DefensePro and all policies in csv format (traffic_stats.csv) as an output
