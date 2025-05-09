# DefensePro – Best Practice configuration analyzer:

# Overview 

The script generates multiple csv reports which can help Resident Engineers/TAM’s/PS with DefensePro config audits, traffic stats review and threshold tuning decisions, mapping the settings.


The script interacts with Radware APSolute Vision DefensePro and collects all the necessary data through REST API calls.

5 reports can be generated

		1.  Traffic statistics report.
			Traffic Statistics will create a report in csv format which includes highest traffic utilization average for the configurable historical timeframe in days (default is 1 day) for every policy including the following stats
			#	CPS = Connections Per Second per policy per DefensePro
			#	PPS = Packets Per Second per policy per DefensePro
			#	BPS = Traffic utilization in Mbps per policy per DefensePro
			#	BDOS protected protocols and Normal baseline BPS per policy per DefensePro
			#	DNS protected record types and Normal baseline QPS per policy per DefensePro
			#	CEC = Concurrent established Connections per DefensePro All policies combined
			
			# This report helps understanding volume of the traffic and make threshold based tuning decisions (BDOS, connection limit, traffic filter)
			# Report will be created under /Reports directory. Example /Reports/traffic_stats_20231227-1415.csv
			
		2. Low bdos baselines
			# Low bdos baselines report will create a csv report which includes policies that traffic is above normal baselines and tuning is required
		
		3. High bdos baselines
			# High bdos baselines report will create a csv report which includes policies that the baseline is X times higher than the maximum average traffic (X is configurable - default is 10).
		
		4. DefensePro configuration mapping
			# This report includes DefensePro Configuration mapping in csv format
			
		5. Best practice configuration report
			# This report will check DP configuration and create report when configuration does not comply with best practice. Below checks are included
			
			
			#	- 1.  DefensePro has no catchall policy
			#	- 2.  Policy has no security profiles applied
			#	- 3.  Policy is configured two-way
			#	- 4.  Policy is in report mode
			#	- 5.  Policy is disabled
			#	- 6.  Packet reporting is disabled
			#	- 7.  Policy has no BDOS profile applied
			#	- 8.  Policy has no Signature profile applied
			#	- 9.  Signature profile applied on the policy does not include all DoS-All rules
			#	- 10. DNS Signature profile applied on the DNS policy does not include all DoS-All rules and DNS Services Signatures
			#	- 11. Policy has no Out of state profile applied
			#	- 12. Policy has no Connection Limit applied
			#	- 13. Policy has no SYN Flood profile applied
			#	- 14. Policy has no ERT Active Attacker Feed profile applied
			#	- 15. DefensePro has no Heartbeat policy for the Silicom Bypass Switch (if exists)
			#	- 16. Catchall policy has not the lowest priority
			#	- 17. Policies distribution across instances is not equal for DefensePro version 7.x 
			#	- 18. BDOS profile is in report mode
			#	- 19. BDOS profile is not applied on any policy(orphaned)
			#	- 20. BDOS profile has Footprint Strictness is not set to Medium 
			#	- 21. BDOS profile learning suppression is less than 50%
			#	- 22. SSH Timeout
			#	- 23. Configuration audit is enabled
			#	- 24. Configuration audit type extended is enabled
			#	- 25. Management access through HTTP is disabled
			#	- 26. Management access through Telnet is disabled
			#	- 27. Web-services is disabled if unnecessary.
			#	- 28. Network class parsing 
			#	-     a. Network class is a subnet of another network class
			#	-     b. Network class is unused(orphaned)
			#	-     c. Same network class is shared with antoher policy
			#	-     d. Network class has a duplicate network with another network class
			#	- 29. Detection if SYN Flood profile is in Report mode
			#	- 30. Detection if SYN Flood profile is not applied on any policy (orphaned)
			#	- 31. Check if signature database is outdated

## IMPORTANT

● Read the entire file before attempting to configure/executing.


# Setup

## Requirements

1. The solution requires python 3.6 and higher and installing required libraries

2. Create a virtual environment (optional but recommended):**
 
   ```bash
    # macOS/Linux
    # You may need to run `sudo apt-get install python3-venv` first on Debian-based OSs
    python3 -m venv .venv

    # Windows
    # You can also use `py -3 -m venv .venv`
    python -m venv .venv

    #Activeate

    # On Windows: 
    
    .venv\Scripts\activate

    #Linux
    source .venv/bin/activate   


   ```

3. Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```
## How to run

1. Create config.py file from `config.py example`
2. Open "config.py" and set the mandatory and optional variables (read config.py comments with explanations).
3. Navigate to the directory containing the script and run the script from that directory.

python3 main.py

Notes:

Script can be run with the following arguments (multiple arguments may be combined together)

python3 main.py --use-cache-data
-	Script parses previously collected data only (stage 2 only, no data collection)

python3 main.py --email
-	Script runs and sends email at the end (requires SMTP configuration block to be set)

python3 main.py --test-email"
-	Script runs test email function to test email server connectivity.


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

V6.1 (8/10/23)
	-	New feature - added collecting Traffic Filter Profiles configuration data and added mapping the below fields:
			1. Traffic filter Action(Block/Report)
			2. List of all the TF rules including Rule Name, Rule ID, Threshold type(PPS/Kbps) and threhold value

V6.1.1 (9/7/23)
	-	Fixed bug when traffic filter has profile but no rules (found by Ali Rios Tovar - bug name Barrie)

V6.2
	-	TF mapping, added mapping Tracking type

V6.2.1 (9/11/23)
	-	Finished mappping all TF settings

V6.2.2 (10/16/23)
	-	Bugfixes 
			- sending email for traffic_stats 
			- sending email for dpconfig_map
			- setting signature version file to "N/A" if Vision does not have the internet to fetch it.

V6.2.3
	- Added mapping UDP-Frag

V6.2.4
	- config.py and traffic_stats_parser.py
	 configurable variable AVG_POINTS

V6.2.4.1
	- config.py example
		Reorganized

V6.2.4.2
	- config.py example
		Reorganized
	- bdos_parser.py
		bugfix for empty traffic stats for BDOS and dns stats
	- requirements.txt
		updated to include only requests

V6.3 (10/11/24)
	- Added policy priority mapping

V6.4 (5/9/2025)
	- Added reauthentication logic if JSESSIONID has expired
	
# Functionality planned to be added:

- HTTPS flood protection mapping
1 - get multiple API calls and responses
2 - review, map each key/value and decide what needs to be mapped and how (how many columns, how exactly)
3 - get the data through API call
4 - parse the output and map to csv

V6.3.1 (3/31/25)

	- Fixed a bug to send low baselines report over email

-------------------------------

Functionality to be added

- ACL mapping
- Add check if network class is in use by any of the ACL's- currently it checks only if it is applied on the policies

- Add full configuration mapping with thresholds to a separate file
- Add connection limit profiles are orphaned (low)
- Connection limit orphaned rules (low)
- Add traffic filters (report/block), orphaned
- Add recommendation priority High/Med/Low to the final report (Medium)
-