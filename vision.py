from requests import Session
import requests
import json
from logging_helper import logging
import config as cfg
import os
import time
import random

raw_data_path = "./Raw Data/"
config_path = "./Config/"
requests_path = "./Requests/"

class Vision:

	def __init__(self, ip, username, password):
		self.ip = ip
		self.login_data = {"username": username, "password": password}
		self.base_url = "https://" + ip
		self.sess = Session()
		
		self.sess.headers.update({"Content-Type": "application/json"})
		self.login()
		logging.info('Connecting to Vision')
		print('Connecting to Vision')
		self.vision_ver = cfg.VISION_VER
		self.report_duration = self.epochTimeGenerator(cfg.DURATION)
		self.time_now = int(time.time())*1000
		#self.internet_connectivity = self.InternetConnectivity()
		
		self.all_subscriptions = self.getAllSubscriptionsVision()

		try:
			self.latest_sig_db = self.all_subscriptions[0]["lastrelease"]
		except:
			self.latest_sig_db = "N/A"
			
		logging.info('Collecting DefensePro device list')
		print('Collecting DefensePro device list')		
		self.device_list = self.getDeviceList()


		with open(requests_path + 'BDOStrafficRequest.json') as outfile:
			self.BDOSformatRequest = json.load(outfile)
		with open(requests_path + 'BDOStrafficRequest_PPS.json') as BDOStrafficRequest_PPS_file:
			self.BDOSformatRequest_PPS = json.load(BDOStrafficRequest_PPS_file)
		with open(requests_path + 'DNStrafficRequest.json') as dnstrafficrequest:
			self.DNSformatRequest = json.load(dnstrafficrequest)
		with open(requests_path + 'TrafficRequest.json') as trafficrequest:
			self.trafficformatrequest = json.load(trafficrequest)
		with open(requests_path + 'TrafficRequestCPS.json') as trafficrequestCPS:
			self.trafficformatrequestCPS = json.load(trafficrequestCPS)
		with open(requests_path + 'TrafficRequestCEC.json') as trafficrequestcec:
			self.trafficformatrequestcec = json.load(trafficrequestcec)

	def login(self):

		login_url = self.base_url + '/mgmt/system/user/login'
		try:
			r = self.sess.post(url=login_url, json=self.login_data, verify=False)
			r.raise_for_status()
			response = r.json()
		except (requests.exceptions.HTTPError, requests.exceptions.ConnectionError,requests.exceptions.SSLError,requests.exceptions.Timeout,requests.exceptions.ConnectTimeout,requests.exceptions.ReadTimeout) as err:
			logging.info(str(err))
			raise SystemExit(err)

		if response['status'] == 'ok':
			self.sess.headers.update({"JSESSIONID": response['jsessionid']})
			# print("Auth Cookie is:  " + response['jsessionid'])
		else:
			logging.info('Vision Login error: ' + response['message'])
			exit(1)

	def _post(self, url, json = ""):

		max_retries = 3  # Number of retries for 403 errors

		for attempt in range(max_retries):
			try:
				response = self.sess.post(url=url, verify=False, json=json)

				# Check if session expired (403 Forbidden)
				if response.status_code == 403:
					print(f"Attempt {attempt + 1}: Received 403 Forbidden. Refreshing session...")
					self.login()  # Refresh session
					
					# Retry after logging in
					response = self.sess.post(url=url, verify=False, json=json)

				# Raise an exception if the response is an error (except 403 which we handled or 200 OK)
				response.raise_for_status()

				return response  # Return the successful response

			except (requests.exceptions.HTTPError, requests.exceptions.ConnectionError, requests.exceptions.SSLError,
				requests.exceptions.Timeout, requests.exceptions.ConnectTimeout,
				requests.exceptions.ReadTimeout) as err:
				print(f"Request failed: {err}")
				time.sleep(2 ** attempt)  # Exponential backoff before retry

		print("Max retries reached. Request failed.")
		return None  # Return None if all retries fail
	
	def _get(self, url, params=None, headers=None, proxy=None):
		max_retries = 3  # Number of retries for 403 errors

		for attempt in range(max_retries):
			try:
				response = self.sess.get(url=url, verify=False, params=params, headers=headers, proxies=proxy)

				# Check if session expired (403 Forbidden)
				if response.status_code == 403:
					print(f"Attempt {attempt + 1}: Received 403 Forbidden. Refreshing session...")
					self.login()  # Refresh session
					
					# Retry after logging in
					response = self.sess.get(url=url, verify=False, params=params, headers=headers, proxies=proxy)

				# Raise an exception if the response is an error
				response.raise_for_status()

				return response  # Return the successful response

			except (requests.exceptions.HTTPError, requests.exceptions.ConnectionError, requests.exceptions.SSLError,
					requests.exceptions.Timeout, requests.exceptions.ConnectTimeout,
					requests.exceptions.ReadTimeout) as err:
				print(f"Request failed: {err}")
				time.sleep(2 ** attempt)  # Exponential backoff

		print("Max retries reached. Request failed.")
		return None  # Return None if all retries fail

	def InternetConnectivity(self):
		# Check if there is internet access

		url = 'https://www.radware.com'
		# this is to avoid getting blocked by radware appsec
		headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.' + str(random.randint(1, 1000)) + '.0.0 Safari/537.36'}

		try:

			if cfg.PROXY:
				proxy = {
				'http': cfg.PROXY_HTTP + ':' + str(cfg.PROXY_HTTP_PORT),
				}
				# response = requests.request(method='GET', url=url, headers=headers, proxies=proxy, verify=False)
				response = self._get(url=url, headers=headers, proxy=proxy)
			else:
				# response = requests.request(method='GET', url=url, verify=False)
				response = self._get(url=url, headers=headers)

				
			if response.status_code == 200:
				print('Internet connection is available.')
				return True
			
			else:
				print('Healtcheck response is not 200 OK')
				return False
			
		except:
			print("No internet connection")
			return False
		
	def getDeviceList(self):
		# Returns list of DP with mgmt IP, type, Name
		devices_url = self.base_url + '/mgmt/system/config/itemlist/alldevices'
		r = self._get(url=devices_url)
		json_txt = r.json()

		dev_list = {item['managementIp']: {'Type': item['type'], 'Name': item['name'],
			'Version': item['deviceVersion'], 'ormId': item['ormId']} for item in json_txt if item['type'] == "DefensePro"}
		
		with open(raw_data_path + 'full_dev_list.json', 'w') as full_dev_list_file:
			json.dump(dev_list,full_dev_list_file)

		return dev_list

	def epochTimeGenerator(self,days):
		current_time = time.time()
		daysInSeconds = 86400 * days
		return (int(current_time) - daysInSeconds) * 1000
	
	def getSignatureProfileListByDevice(self, dp_ip):
		# Returns Signature profile list with rules
		policy_url = self.base_url + "/mgmt/device/byip/" + \
			dp_ip + "/config/rsIDSSignaturesProfilesTable?props=rsIDSSignaturesProfileName,rsIDSSignaturesProfileRuleName,rsIDSSignaturesProfileRuleAttributeType,rsIDSSignaturesProfileRuleAttributeName"
		r = self._get(url=policy_url)
		sig_list = r.json()
		
		if sig_list.get("status") == "error":
			logging.info("Signature Profile list get error. DefensePro IP: " + dp_ip + ". Error message: " + sig_list['message'])
			return []
		return sig_list

	def getBDOSProfileConfigByDevice(self, dp_ip):
		# Returns BDOS profile config
		policy_url = self.base_url + "/mgmt/device/byip/" + \
			dp_ip + "/config/rsNetFloodProfileTable"
		r = self._get(url=policy_url)
		bdos_config = r.json()
		
		if bdos_config.get("status") == "error":
			logging.info("BDOS Profile list get error. DefensePro IP: " + dp_ip + ". Error message: " + bdos_config['message'])

			return []
		return bdos_config

	def getDNSProfileConfigByDevice(self, dp_ip):
		# Returns DNS profile config
		policy_url = self.base_url + "/mgmt/device/byip/" + \
			dp_ip + "/config/rsDnsProtProfileTable"
		r = self._get(url=policy_url)
		dns_config = r.json()
		
		if dns_config.get("status") == "error":
			logging.info("DNS Profile list get error. DefensePro IP: " + dp_ip + ". Error message: " + dns_config['message'])

			return []
		return dns_config

	def getSYNPProfileListByDevice(self, dp_ip):
		# Returns BDOS profile config
		policy_url = self.base_url + "/mgmt/device/byip/" + \
			dp_ip + "/config/rsIDSSynProfilesTable?props=rsIDSSynProfilesName,rsIDSSynProfileServiceName"
		r = self._get(url=policy_url)
		synp_prof_list = r.json()
		
		if synp_prof_list.get("status") == "error":
			logging.info("SYNP Profile list get error. DefensePro IP: " + dp_ip + ". Error message: " + synp_prof_list['message'])
			# print("SYNP Profile list get error. DefensePro IP: " + dp_ip + ". Error message: " + synp_prof_list['message'])
			return []
		return synp_prof_list

	def getSYNPProfileParamsByDevice(self, dp_ip):
		# Returns BDOS profile config
		url = self.base_url + "/mgmt/device/byip/" + \
			dp_ip + "/config/rsIDSSynProfilesParamsTable"
		r = self._get(url=url)
		synp_prof_params_list = r.json()
		
		if synp_prof_params_list.get("status") == "error":
			logging.info("SYN Flood Profiles parameters get error. DefensePro IP: " + dp_ip + ". Error message: " + synp_prof_params_list['message'])

			return []
		return synp_prof_params_list

	def getSYNPProtectionsTableByDevice(self, dp_ip):
		# Returns SYNP profile config
		url = self.base_url + "/mgmt/device/byip/" + \
			dp_ip + "/config/rsIDSSYNAttackTable"
		r = self._get(url=url)
		synp_protections_table = r.json()
		
		if synp_protections_table.get("status") == "error":
			logging.info("SYN Flood Protections get error. DefensePro IP: " + dp_ip + ". Error message: " + synp_protections_table['message'])

			return []
		return synp_protections_table

	def getConnlimProfileListByDevice(self, dp_ip):
		# Returns Connectlion limit profile config
		policy_url = self.base_url + "/mgmt/device/byip/" + \
			dp_ip + "/config/rsIDSConnectionLimitProfileTable"
		r = self._get(url=policy_url)
		connlim_prof_list = r.json()
		
		if connlim_prof_list.get("status") == "error":
			logging.info("Connection Limit Profile list get error. DefensePro IP: " + dp_ip + ". Error message: " + connlim_prof_list['message'])
			# print("Connection Limit Profile list get error. DefensePro IP: " + dp_ip + ". Error message: " + connlim_prof_list['message'])
			return []
		return connlim_prof_list
	

	def getConnlimProfileAttackTableByDevice(self, dp_ip):
		# Returns Connlim profile config
		url = self.base_url + "/mgmt/device/byip/" + \
			dp_ip + "/config/rsIDSConnectionLimitAttackTable"
		r = self._get(url=url)
		connlim_prof_attacktable_list = r.json()
		
		if connlim_prof_attacktable_list.get("status") == "error":
			logging.info("Connection Limit Profiles parameters get error. DefensePro IP: " + dp_ip + ". Error message: " + connlim_prof_attacktable_list['message'])

			return []
		return connlim_prof_attacktable_list

	def getOOSProfileListByDevice(self, dp_ip):
		# Returns Out of State profile config
		policy_url = self.base_url + "/mgmt/device/byip/" + \
			dp_ip + "/config/rsStatefulProfileTable"
		r = self._get(url=policy_url)
		oos_prof_list = r.json()
		
		if oos_prof_list.get("status") == "error":
			logging.info("Out of State Profile list get error. DefensePro IP: " + dp_ip + ". Error message: " + oos_prof_list['message'])
			# print("Connection Limit Profile list get error. DefensePro IP: " + dp_ip + ". Error message: " + oos_prof_list['message'])
			return []
		
		return oos_prof_list


	def getTFProfileListByDevice(self, dp_ip):
		# Returns TF profiles
		policy_url = self.base_url + "/mgmt/device/byip/" + \
			dp_ip + "/config/rsNewTrafficProfileTable"
		r = self._get(url=policy_url)
		tf_prof_list = r.json()
		
		if tf_prof_list.get("status") == "error":
			logging.info("Traffic Filter Profile list get error. DefensePro IP: " + dp_ip + ". Error message: " + tf_prof_list['message'])
			# print("Traffic Filter Profile list get error. DefensePro IP: " + dp_ip + ". Error message: " + tf_prof_list['message'])
			return []
		return tf_prof_list


	def getTFRulesByDevice(self, dp_ip):
		# Returns TF rules 
		url = self.base_url + "/mgmt/device/byip/" + \
			dp_ip + "/config/rsNewTrafficFilterTable/"
		r = self._get(url=url)
		tf_prof_rules_list = r.json()
		
		if tf_prof_rules_list.get("status") == "error":
			logging.info("Traffic Filter Profiles parameters get error. DefensePro IP: " + dp_ip + ". Error message: " + tf_prof_rules_list['message'])

			return []
		return tf_prof_rules_list





	def getNetClassListByDevice(self, dp_ip):
		#Returns Network Class list with networks

		policy_url = self.base_url + "/mgmt/device/byip/" + \
			dp_ip + "/config/rsBWMNetworkTable/"
		r = self._get(url=policy_url)
		net_list = r.json()
		
		if net_list.get("status") == "error":
			logging.info("Network class get error. DefensePro IP: " + dp_ip + ". Error message: " + net_list['message'])
			return []
		return net_list

	def getPolicyListByDevice(self, dp_ip):
		# Returns policies list with all its attributes
		policy_url = self.base_url + "/mgmt/device/byip/" + \
			dp_ip + "/config/rsIDSNewRulesTable"
		# URL params ?count=1000&props=rsIDSNewRulesName
		r = self._get(url=policy_url)
		policy_list = r.json()

		if policy_list.get("status") == "error":
			logging.info("Policies list get error. DefensePro IP: " + dp_ip + ". Error message: " + policy_list['message'])

			return []

		return policy_list

	def getDPConfigByDevice(self, dp_ip):
		# Downloads DefensePro configuration file
		policy_url = self.base_url + "/mgmt/device/byip/" + \
			dp_ip + "/config/getcfg?saveToDb=false&includePrivateKeys=false&passphrase="
		# URL params ?count=1000&props=rsIDSNewRulesName
		r = self._get(url=policy_url)

		with open(config_path + f'{dp_ip}_config.txt', 'wb') as f:
			f.write(r.content) #Write to file

		return
	

	def getMonitorInfo(self,dp_ip):

		# Downloads DefensePro monitor info
		policy_url = self.base_url + "/mgmt/device/byip/" + \
			dp_ip + "/monitor?prop=rsPlatformIdentifier,rsWSDSysUpTime,rsWSDSysBaseMACAddress,rsIDSAttackDBVersion,rndManagedTime,rndManagedDate,rndBrgVersion,rdwrDPBuildID,rsWSDVersionStatus,rdwrDeviceThroughput,rsWSDDRAMSize,rsCoresNumber,rsCPUFrequency"

		try:
			r = self._get(url=policy_url)
			r.raise_for_status()
			monitor_info = r.json()
			return monitor_info

		except:
			logging.info("Monitor info get error. DefensePro IP: " + dp_ip + ". Error message: " + r.text)
			monitor_info = {'rsWSDSysBaseMACAddress': '00:00:00:00:00:00','rsIDSAttackDBVersion': '0000.0000.00'}
			return monitor_info
		
	

		
	def getLatestSigDBRadwre(self,dp_base_mac):

		# Downloads DefensePro monitor info
		url = "https://www.radware.com/modules/radware/packages/mis/autoattackupdate/FIRST.asp?protocol=2&pass=" + dp_base_mac
		# add header User-Agent and Accept-Encoding to avoid 403 error
		headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.' + str(random.randint(1, 1000)) + '.0.0 Safari/537.36'}
		try:
			r = self._get(url,headers=headers)
			r.raise_for_status()

			latest_sig_db = r.content

		except (requests.exceptions.HTTPError, requests.exceptions.ConnectionError,requests.exceptions.SSLError,requests.exceptions.Timeout,requests.exceptions.ConnectTimeout,requests.exceptions.ReadTimeout) as err:	
			logging.info(str(err))
			print(str(err))
			latest_sig_db = "No Connectivity"
			# raise SystemExit(err)
			

		return latest_sig_db
	
	def getAllSubscriptionsVision(self):
		# Downloads DefensePro monitor info
		url = self.base_url + "/mgmt/monitor/scc/AllSubscriptions"

		try:
			r = self._get(url)
			r.raise_for_status()

			all_subscriptions = r.content
			all_subscriptions = json.loads(all_subscriptions) #change all_subscriptions from bytes to json

			with open(raw_data_path + 'dev_subscriptions.json', 'w') as dev_subscriptions_file:
				json.dump(all_subscriptions,dev_subscriptions_file)

			return all_subscriptions

		except (requests.exceptions.HTTPError, requests.exceptions.ConnectionError,requests.exceptions.SSLError,requests.exceptions.Timeout,requests.exceptions.ConnectTimeout,requests.exceptions.ReadTimeout) as err:	
			logging.info(str(err))
			print(str(err))
			all_subscriptions = "No Connectivity"

		return all_subscriptions

	def getBDOSTrafficReport(self,pol_dp_ip,pol_attr,net_list):

		pol_name = pol_attr["rsIDSNewRulesName"]
		pol_src_net = pol_attr["rsIDSNewRulesSource"]
		pol_dst_net = pol_attr["rsIDSNewRulesDestination"]

		if self.vision_ver < 4.83:
			url = f'https://{self.ip}/mgmt/monitor/reporter/reports-ext/BDOS_BASELINE_RATE_REPORTS' #pre 4.83 Vision
		else:
			url = f'https://{self.ip}/mgmt/monitor/reporter/reports-ext/BDOS_BASELINE_RATE_HOURLY_REPORTS' #4.83 Vision

		BDOS_portocols = ['udp','tcp-syn','tcp-syn-ack','tcp-rst','tcp-ack-fin','tcp-frag','udp-frag','icmp','igmp']

		self.BDOSformatRequest['criteria'][5]['upper'] = self.time_now
		self.BDOSformatRequest['criteria'][5]['lower'] = self.report_duration
		self.BDOSformatRequest['criteria'][6]["filters"][0]['filters'][0]['value'] = pol_dp_ip
		self.BDOSformatRequest['criteria'][6]["filters"][0]['filters'][1]["filters"][0]["value"] = pol_name 
		self.BDOSformatRequest['criteria'][0]['value'] = 'true' # default IPv4 true
		
		
		ipv6 = False
		ipv4 = False
		
		bdosReportList = []
		
		for net_dp_ip, dp_attr in net_list.items():
			if dp_attr == ([]):
				#if unreachable do not perform other tests
				continue
			
			if net_dp_ip == pol_dp_ip:

				for netcl in dp_attr['rsBWMNetworkTable']: #for each netclass element
					net_name = netcl['rsBWMNetworkName']
					net_addr = netcl['rsBWMNetworkAddress']
					
					if net_name == pol_src_net and net_name != "any":
						if ":" in net_addr:
							ipv6 = True
							#logging.info(f'dp ip is {net_dp_ip},policy {pol_name}, network {net_name} - src net is IPv6')  
							# self.BDOSformatRequest['criteria'][0]['value'] = 'false'
							
						if "." in net_addr:
							ipv4 = True
							#logging.info(f'dp ip is {net_dp_ip},policy {pol_name}, network {net_name} - src net is IPv4')  
							# self.BDOSformatRequest['criteria'][0]['value'] = 'true'			

					if net_name == pol_dst_net and net_name != "any":
						if ":" in net_addr:
							ipv6 = True
							#logging.info(f'dp ip is {net_dp_ip},policy {pol_name}, network {net_name} - dst net is IPv6')
							# self.BDOSformatRequest['criteria'][0]['value'] = 'false'
							
						if "." in net_addr:
							ipv4 = True
							#logging.info(f'dp ip is {net_dp_ip},policy {pol_name}, network {net_name} - dst net is IPv4')  
							# self.BDOSformatRequest['criteria'][0]['value'] = 'true'								
						

				
		for protocol in BDOS_portocols:
			self.BDOSformatRequest['criteria'][1]["value"] = protocol
			
			if ipv6:
			
				self.BDOSformatRequest['criteria'][0]['value'] = 'false'
				r = self._post(url = url, json = self.BDOSformatRequest )
				jsonData = json.loads(r.text)
				
				if jsonData['data'] == ([]): #Empty response
					# print(f'{pol_dp_ip},{pol_name},{protocol},{jsonData}')
					empty_resp = [{'row': {'response': 'empty', 'protection': protocol}}]
					# print(f'Printing empty resp ipv6 - {empty_resp}')
					bdosReportList.append(empty_resp)

					# print(f'{pol_dp_ip}, policy {pol_name} - executing IPv6 query')
				else:
					bdosReportList.append(jsonData['data'])

			if ipv4:
			
				self.BDOSformatRequest['criteria'][0]['value'] = 'true'
				r = self._post(url = url, json = self.BDOSformatRequest)
				print(f'BDOS - {pol_dp_ip},{pol_name},{protocol}')
				jsonData = json.loads(r.text)
				
				

				if jsonData['data'] == ([]): #Empty response
					# print(f'{pol_dp_ip},{pol_name},{protocol},{jsonData}')
					empty_resp = [{'row': {'response': 'empty', 'protection': protocol}}]
					# print(f'Printing empty resp ipv6 - {empty_resp}')
					bdosReportList.append(empty_resp)

				# print(f'{pol_dp_ip},{pol_name},{protocol},{jsonData}')
					# print(f'{pol_dp_ip}, policy {pol_name} - executing IPv4 query')
				else:
					bdosReportList.append(jsonData['data'])

		bdosTrafficReport = {pol_name:bdosReportList}
		
		return bdosTrafficReport



	def getBDOSTrafficReport_PPS(self,pol_dp_ip,pol_attr,net_list):
		pol_name = pol_attr["rsIDSNewRulesName"]
		pol_src_net = pol_attr["rsIDSNewRulesSource"]
		pol_dst_net = pol_attr["rsIDSNewRulesDestination"]

		if self.vision_ver < 4.83:
			url = f'https://{self.ip}/mgmt/monitor/reporter/reports-ext/BDOS_BASELINE_RATE_REPORTS' #pre 4.83 Vision
		else:
			url = f'https://{self.ip}/mgmt/monitor/reporter/reports-ext/BDOS_BASELINE_RATE_HOURLY_REPORTS' #4.83 Vision
		BDOS_portocols = ['udp','tcp-syn','tcp-syn-ack','tcp-rst','tcp-ack-fin','tcp-frag','udp-frag','icmp','igmp']
		
		self.BDOSformatRequest_PPS['criteria'][5]['upper'] = self.time_now
		self.BDOSformatRequest_PPS['criteria'][5]['lower'] = self.report_duration
		self.BDOSformatRequest_PPS['criteria'][6]["filters"][0]['filters'][0]['value'] = pol_dp_ip
		self.BDOSformatRequest_PPS['criteria'][6]["filters"][0]['filters'][1]["filters"][0]["value"] = pol_name 
		self.BDOSformatRequest_PPS['criteria'][0]['value'] = 'true' # default IPv4 true

		
		
		ipv6 = False
		ipv4 = False
		
		bdosReportList = []
		
		for net_dp_ip, dp_attr in net_list.items():

			if dp_attr == ([]):
				#if unreachable do not perform other tests
				continue
			
			if net_dp_ip == pol_dp_ip:
				

				for netcl in dp_attr['rsBWMNetworkTable']: #for each netclass element
					net_name = netcl['rsBWMNetworkName']
					net_addr = netcl['rsBWMNetworkAddress']
					#print(f'dp ip is {net_dp_ip},policy {pol_name}, network {net_name}')  
					if net_name == pol_src_net and net_name != "any":
						if ":" in net_addr:
							ipv6 = True
							# logging.info(f'dp ip is {net_dp_ip},policy {pol_name}, network {net_name} - src net is IPv6')  
							# self.BDOSformatRequest['criteria'][0]['value'] = 'false'
							
						if "." in net_addr:
							ipv4 = True
							# logging.info(f'dp ip is {net_dp_ip},policy {pol_name}, network {net_name} - src net is IPv4')  
							# self.BDOSformatRequest['criteria'][0]['value'] = 'true'			

					if net_name == pol_dst_net and net_name != "any":
						if ":" in net_addr:
							ipv6 = True
							#logging.info(f'dp ip is {net_dp_ip},policy {pol_name}, network {net_name} - dst net is IPv6')
							# self.BDOSformatRequest['criteria'][0]['value'] = 'false'
							
						if "." in net_addr:
							ipv4 = True
							#logging.info(f'dp ip is {net_dp_ip},policy {pol_name}, network {net_name} - dst net is IPv4')  
							# self.BDOSformatRequest['criteria'][0]['value'] = 'true'								
						
	
		for protocol in BDOS_portocols:

			self.BDOSformatRequest_PPS['criteria'][1]["value"] = protocol

			if ipv6:
				#print(f'dp ip is {net_dp_ip},policy {pol_name}, network {net_name} - IPv6')  

				self.BDOSformatRequest_PPS['criteria'][0]['value'] = 'false'
				r = self._post(url = url, json = self.BDOSformatRequest)

				jsonData = json.loads(r.text)

				if jsonData['data'] == ([]): #Empty response
					#print(f'{pol_dp_ip} empty response')
					empty_resp = [{'row': {'response': 'empty', 'protection': protocol, 'ipv': 'IPv6'}}]
					# print(f'Printing empty resp ipv6 - {empty_resp}')
					bdosReportList.append(empty_resp)

					# print(f'{pol_dp_ip}, policy {pol_name} - executing IPv6 query')
				else:
					bdosReportList.append(jsonData['data'])

			if ipv4:
			
				self.BDOSformatRequest_PPS['criteria'][0]['value'] = 'true'
				r = self._post(url = url, json = self.BDOSformatRequest_PPS)
				print(f'BDOS PPS - {pol_dp_ip},{pol_name},{protocol}')

				jsonData = json.loads(r.text)
				
				if jsonData['data'] == ([]): #Empty response

					# print(f'{pol_dp_ip} empty response')
					empty_resp = [{'row': {'response': 'empty', 'protection': protocol, 'ipv': 'IPv4'}}]	
					# print(f'Printing empty resp ipv6 - {empty_resp}')
					bdosReportList.append(empty_resp)

				# print(f'{pol_dp_ip},{pol_name},{protocol},{jsonData}')
					# print(f'{pol_dp_ip}, policy {pol_name} - executing IPv4 query')
				else:
					bdosReportList.append(jsonData['data'])

		bdosTrafficReport_PPS = {pol_name:bdosReportList}
		
		return bdosTrafficReport_PPS
	


	################DNS Query############################
	def getDNStrafficReport(self,pol_dp_ip,pol_attr,net_list):

		pol_name = pol_attr["rsIDSNewRulesName"]
		pol_src_net = pol_attr["rsIDSNewRulesSource"]
		pol_dst_net = pol_attr["rsIDSNewRulesDestination"]

		url = f'https://{self.ip}/mgmt/monitor/reporter/reports-ext/DNS_BASELINE_RATE_REPORTS'
		
		DNS_protocols = ['dns-a','dns-aaaa',"dns-mx","dns-text","dns-soa","dns-srv","dns-ptr","dns-naptr","dns-other"]

		self.DNSformatRequest['criteria'][5]['upper'] = self.time_now
		self.DNSformatRequest['criteria'][5]['lower'] = self.report_duration
		self.DNSformatRequest['criteria'][6]["filters"][0]['filters'][0]['value'] = pol_dp_ip
		self.DNSformatRequest['criteria'][6]["filters"][0]['filters'][1]["filters"][0]["value"] = pol_name 
		
		ipv6 = False
		ipv4 = False
		
		dnsReportList = []

		for net_dp_ip, dp_attr in net_list.items():
			if dp_attr == ([]):
				#if unreachable do not perform other tests
				continue

			if net_dp_ip == pol_dp_ip:

				for netcl in dp_attr['rsBWMNetworkTable']: #for each netclass element
					net_name = netcl['rsBWMNetworkName']
					net_addr = netcl['rsBWMNetworkAddress']
					
					if net_name == pol_src_net and net_name != "any":
						if ":" in net_addr:
							ipv6 = True
		
						if "." in net_addr:
							ipv4 = True		

					if net_name == pol_dst_net and net_name != "any":
						if ":" in net_addr:
							ipv6 = True
							
						if "." in net_addr:
							ipv4 = True							
						
		for protocol in DNS_protocols:

			self.DNSformatRequest['criteria'][1]["value"] = protocol

			if ipv6:
						
				self.DNSformatRequest['criteria'][0]['value'] = 'false'
				r = self._post(url = url, json = self.DNSformatRequest)
				jsonData = json.loads(r.text)
				

				if jsonData['data'] == ([]): #Empty response
					# print(f'{pol_dp_ip},{pol_name},{protocol},{jsonData}')
					empty_resp = [{'row': {'response': 'empty', 'protection': protocol}}]
					# print(f'Printing empty resp ipv6 - {empty_resp}')
					dnsReportList.append(empty_resp)

					# print(f'{pol_dp_ip}, policy {pol_name} - executing IPv6 query')
				else:
					dnsReportList.append(jsonData['data'])



			if ipv4:

				self.DNSformatRequest['criteria'][0]['value'] = 'true'
				
				r = self._post(url = url, json = self.DNSformatRequest)
				print(f'DNS - {pol_dp_ip},{pol_name},{protocol}')

				jsonData = json.loads(r.text)
				
				# print(f'{pol_dp_ip}, policy {pol_name} - executing DNS IPv4 query')
				
				if jsonData['data'] == ([]): #Empty response
					# print(f'{pol_dp_ip},{pol_name},{protocol},{jsonData}')
					empty_resp = [{'row': {'response': 'empty', 'protection': protocol}}]
					# print(f'Printing empty resp ipv6 - {empty_resp}')
					dnsReportList.append(empty_resp)

				# print(f'{pol_dp_ip},{pol_name},{protocol},{jsonData}')
					# print(f'{pol_dp_ip}, policy {pol_name} - executing IPv4 query')
				else:
					dnsReportList.append(jsonData['data'])

		dnsTrafficReport = {pol_name:dnsReportList}
		
		return dnsTrafficReport

################Traffic stats Bps######################

	def getTrafficStatsBPS(self, dp_ip, policy):

		# url = f'https://{self.ip}/mgmt/monitor/reporter/reports-ext/DP_TRAFFIC_UTILIZATION_AGG_REPORTS'
		url = f'https://{self.ip}/mgmt/monitor/reporter/reports-ext/DP_TRAFFIC_UTILIZATION_RAW_REPORTS'
		
		self.trafficformatrequest['aggregation']['criteria'][1]['value'] = 'bps'
		self.trafficformatrequest['aggregation']['criteria'][3]['lower'] = self.report_duration
		self.trafficformatrequest['aggregation']['criteria'][4]['filters'][0]['filters'][0]['value'] = dp_ip
		self.trafficformatrequest['aggregation']['criteria'][4]['filters'][0]['filters'][1]['filters'][0]['value'] = policy

		r = self._post(url = url, json = self.trafficformatrequest)
		print(f'Traffic BPS - {dp_ip}, {policy}')

		jsonData = json.loads(r.text)
	
		TrafficReportListBPS = {policy:jsonData['data']}
		return TrafficReportListBPS

############################################

################Traffic stats PPS######################

	def getTrafficStatsPPS(self, dp_ip, policy):
		# url = f'https://{self.ip}/mgmt/monitor/reporter/reports-ext/DP_TRAFFIC_UTILIZATION_AGG_REPORTS'
		url = f'https://{self.ip}/mgmt/monitor/reporter/reports-ext/DP_TRAFFIC_UTILIZATION_RAW_REPORTS'

		self.trafficformatrequest['aggregation']['criteria'][1]['value'] = 'pps'
		self.trafficformatrequest['aggregation']['criteria'][3]['lower'] = self.report_duration
		self.trafficformatrequest['aggregation']['criteria'][4]['filters'][0]['filters'][0]['value'] = dp_ip
		self.trafficformatrequest['aggregation']['criteria'][4]['filters'][0]['filters'][1]['filters'][0]['value'] = policy

		r = self._post(url = url, json = self.trafficformatrequest)
		print(f'Traffic PPS - {dp_ip}, {policy}')
		jsonData = json.loads(r.text)
	
		TrafficReportListPPS = {policy:jsonData['data']}
		return TrafficReportListPPS

############################################

################Traffic stats CPS######################

	def getTrafficStatsCPS(self, dp_ip, policy):
		url = f'https://{self.ip}/mgmt/monitor/reporter/reports-ext/DP_CONNECTION_HOURLY_STATISTICS'
		
		self.trafficformatrequestCPS['aggregation']['criteria'][2]['lower'] = self.report_duration
		self.trafficformatrequestCPS['aggregation']['criteria'][3]['filters'][0]['filters'][0]['value'] = dp_ip
		self.trafficformatrequestCPS['aggregation']['criteria'][3]['filters'][0]['filters'][1]['filters'][0]['value'] = policy

		r = self._post(url = url, json = self.trafficformatrequestCPS)
		print(f'Traffic CPS - {dp_ip}, {policy}')
		jsonData = json.loads(r.text)
	
		trafficreportlistcps = {policy:jsonData['data']}

		return trafficreportlistcps

############################################

################Traffic stats CEC - Concurrent Established Connections######################

	def getTrafficStatsCEC(self, dp_ip):
		url = f'https://{self.ip}/mgmt/monitor/reporter/reports-ext/DP_CONCURRENT_CONNECTIONS_HOURLY_REPORTS'
		
		self.trafficformatrequestcec['aggregation']['criteria'][0]['lower'] = self.report_duration
		self.trafficformatrequestcec['aggregation']['criteria'][1]['filters'][0]['filters'][0]['value'] = dp_ip

		r = self._post(url = url, json = self.trafficformatrequestcec)
		print(f'Traffic CEC - {dp_ip}')
		jsonData = json.loads(r.text)
	
		trafficreportlistcec = jsonData['data']

		return trafficreportlistcec




	def getFullPolicyDictionary(self,key,val,full_pol_dic):
		# Create Full Policies list with attributes dictionary per DefensePro

		full_pol_dic[key] = {}
		full_pol_dic[key]['Name'] = val['Name']
		full_pol_dic[key]['Version'] = val['Version']
		full_pol_dic[key]['Policies'] = self.getPolicyListByDevice(key)



		return full_pol_dic

	def getFullSignatureProfileDictionary(self,key,val,full_sig_dic):
		# Create Full Signature profile list with rules dictionary per DefensePro

		full_sig_dic[key] = self.getSignatureProfileListByDevice(key)



			
		return full_sig_dic

	def getFullNetClassDictionary(self,key,val,full_net_dic):
		# Create Full Network class profile list with networks dictionary per DefensePro
		full_net_dic[key] = {}
		

		if self.getNetClassListByDevice(key) == ([]): #If DefensePro is unreachable
			full_net_dic[key]['rsBWMNetworkTable'] = []
			full_net_dic[key]['Name'] = val['Name']

		else:

			full_net_dic[key] = self.getNetClassListByDevice(key)
			full_net_dic[key]['Name'] = val['Name']
			
		
		return full_net_dic

	def getFullBDOSProfConfigDictionary(self,key,val,full_bdosprofconf_dic):
		# Create Full BDOS Profile config list with all BDOS attributes dictionary per DefensePro

		full_bdosprofconf_dic[key] = {}
		full_bdosprofconf_dic[key]['Name'] = val['Name']
		full_bdosprofconf_dic[key]['Version'] = val['Version']
		full_bdosprofconf_dic[key]['Policies'] = self.getBDOSProfileConfigByDevice(key)




		return full_bdosprofconf_dic

	def getFullDNSProfConfigDictionary(self,key,val,full_dnsprofconf_dic):
		# Create Full DNS Profile config list with all BDOS attributes dictionary per DefensePro

		full_dnsprofconf_dic[key] = {}
		full_dnsprofconf_dic[key]['Name'] = val['Name']
		full_dnsprofconf_dic[key]['Version'] = val['Version']
		full_dnsprofconf_dic[key]['Policies'] = self.getDNSProfileConfigByDevice(key)



		return full_dnsprofconf_dic



	def getFullSYNPConfigDictionary(self,dp_ip,val,full_synprofconf_dic):
		# Create Full SYNP Profile config list with all BDOS attributes dictionary per DefensePro

		full_synprofconf_dic[dp_ip] = {}
		full_synprofconf_dic[dp_ip]['Name'] = val['Name']
		full_synprofconf_dic[dp_ip]['Version'] = val['Version']

		synp_prof_list = self.getSYNPProfileListByDevice(dp_ip)
		synp_prof_params_table = self.getSYNPProfileParamsByDevice(dp_ip)
		synp_protections_table = self.getSYNPProtectionsTableByDevice(dp_ip)

		full_synprofconf_dic[dp_ip]['Profiles'] = {}
		
		if synp_prof_params_table: #If table is not empty
			for synp_prof_param_set in synp_prof_params_table['rsIDSSynProfilesParamsTable']:
				full_synprofconf_dic[dp_ip]['Profiles'][synp_prof_param_set['rsIDSSynProfilesParamsName']] = {}
				full_synprofconf_dic[dp_ip]['Profiles'][synp_prof_param_set['rsIDSSynProfilesParamsName']]['Parameters'] = synp_prof_param_set


				full_synprofconf_dic[dp_ip]['Profiles'][synp_prof_param_set['rsIDSSynProfilesParamsName']]['Protections'] = []

				for synp_prof in synp_prof_list['rsIDSSynProfilesTable']:
					if synp_prof['rsIDSSynProfilesName'] == synp_prof_param_set['rsIDSSynProfilesParamsName']:
					
						for syn_protection in synp_protections_table['rsIDSSYNAttackTable']:
							if syn_protection['rsIDSSYNAttackName'] == synp_prof['rsIDSSynProfileServiceName']:
								full_synprofconf_dic[dp_ip]['Profiles'][synp_prof_param_set['rsIDSSynProfilesParamsName']]['Protections'].append(syn_protection)
					



		return full_synprofconf_dic


	def getFullConnlimConfigDictionary(self,dp_ip,val,full_connlimprofconf_dic):
		# Create Full Connection Limit Profile config list with all BDOS attributes dictionary per DefensePronnectionLimitProfileName

		full_connlimprofconf_dic[dp_ip] = {}
		full_connlimprofconf_dic[dp_ip]['Name'] = val['Name']
		full_connlimprofconf_dic[dp_ip]['Version'] = val['Version']

		connlim_prof_list = self.getConnlimProfileListByDevice(dp_ip)
		connlim_prof_attack_table = self.getConnlimProfileAttackTableByDevice(dp_ip)


		full_connlimprofconf_dic[dp_ip]['Profiles'] = {}
		
		if connlim_prof_list: #If table is not empty

			for connlim_prof in connlim_prof_list['rsIDSConnectionLimitProfileTable']:

				if full_connlimprofconf_dic[dp_ip]['Profiles'].get(connlim_prof['rsIDSConnectionLimitProfileName']) is None:
					full_connlimprofconf_dic[dp_ip]['Profiles'][connlim_prof['rsIDSConnectionLimitProfileName']] = {}

				if full_connlimprofconf_dic[dp_ip]['Profiles'][connlim_prof['rsIDSConnectionLimitProfileName']].get('Protections') is None:
					full_connlimprofconf_dic[dp_ip]['Profiles'][connlim_prof['rsIDSConnectionLimitProfileName']]['Protections'] = []

				for connlim_protectionid in connlim_prof_attack_table['rsIDSConnectionLimitAttackTable']:

					if connlim_protectionid['rsIDSConnectionLimitAttackId'] == connlim_prof['rsIDSConnectionLimitProfileAttackId']:
						full_connlimprofconf_dic[dp_ip]['Profiles'][connlim_prof['rsIDSConnectionLimitProfileName']]['Protections'].append(connlim_protectionid)




		return full_connlimprofconf_dic
	
	def getFullOOSConfigDictionary(self,dp_ip,val,full_oosprofconf_dic):
		# Create Full Out of State Profile config list with all BDOS attributes dictionary per DefensePro

		full_oosprofconf_dic[dp_ip] = {}
		full_oosprofconf_dic[dp_ip]['Name'] = val['Name']
		full_oosprofconf_dic[dp_ip]['Version'] = val['Version']

		oos_prof_list = self.getOOSProfileListByDevice(dp_ip)


		full_oosprofconf_dic[dp_ip]['Profiles'] = []
		
		if oos_prof_list: #If table is not empty

			for oos_prof in oos_prof_list['rsStatefulProfileTable']:
				
				full_oosprofconf_dic[dp_ip]['Profiles'].append(oos_prof)	




		return full_oosprofconf_dic
	

	def getFullSigDB(self,dp_ip,val,full_sig_db_dic):
		# Create Full Out of State Profile config list with all BDOS attributes dictionary per DefensePro
		full_sig_db_dic[dp_ip] = {}
		full_sig_db_dic[dp_ip]['Name'] = val['Name']
		full_sig_db_dic[dp_ip]['Version'] = val['Version']

		dp_monitor_json = self.getMonitorInfo(dp_ip)
		dp_base_mac = dp_monitor_json['rsWSDSysBaseMACAddress']

		full_sig_db_dic[dp_ip]['BaseMACAddress'] = dp_base_mac
		full_sig_db_dic[dp_ip]['CurrentSignatureFileVersion'] = dp_monitor_json['rsIDSAttackDBVersion']

		full_sig_db_dic[dp_ip]['LatestSignatureFileVersion'] = self.latest_sig_db
		
		return full_sig_db_dic
	

	def getFullTFConfigDictionary(self,dp_ip,val,full_tfprofconf_dic):
		# Create Full TF Profile config list with all rules dictionary

		full_tfprofconf_dic[dp_ip] = {}
		full_tfprofconf_dic[dp_ip]['Name'] = val['Name']
		full_tfprofconf_dic[dp_ip]['Version'] = val['Version']

		tf_prof_list = self.getTFProfileListByDevice(dp_ip)
		tf_rules_list = self.getTFRulesByDevice(dp_ip)


		full_tfprofconf_dic[dp_ip]['Profiles'] = {}
		
		if tf_prof_list: #If table is not empty

			for tf_prof in tf_prof_list['rsNewTrafficProfileTable']:

				if full_tfprofconf_dic[dp_ip]['Profiles'].get(tf_prof['rsNewTrafficProfileName']) is None: # If profile name var key does not exist in dictionary, create one with value of empty dictionary
					full_tfprofconf_dic[dp_ip]['Profiles'][tf_prof['rsNewTrafficProfileName']] = {}

				# if full_tfprofconf_dic[dp_ip]['Profiles'][tf_prof['rsNewTrafficProfileName']].get('Action') is None: # If "Action" key does not exist in full TF dictionary, create one with value of empty dictionary
				full_tfprofconf_dic[dp_ip]['Profiles'][tf_prof['rsNewTrafficProfileName']]['Action'] = tf_prof['rsNewTrafficProfileAction']

				if full_tfprofconf_dic[dp_ip]['Profiles'][tf_prof['rsNewTrafficProfileName']].get('Rules') is None: # If "Rules" key does not exist in full TF dictionary, create one with value of empty dictionary
					full_tfprofconf_dic[dp_ip]['Profiles'][tf_prof['rsNewTrafficProfileName']]['Rules'] = []

				if tf_rules_list:
					for tf_rule in tf_rules_list['rsNewTrafficFilterTable']:

						if tf_rule['rsNewTrafficFilterProfileName'] == tf_prof['rsNewTrafficProfileName']:
							full_tfprofconf_dic[dp_ip]['Profiles'][tf_prof['rsNewTrafficProfileName']]['Rules'].append(tf_rule)




		return full_tfprofconf_dic



	def getBDOSReportFromVision(self,dev_list_dp_ip,dev_list_dp_ip_attr,full_pol_dic,full_net_dic,bdos_stats_dict,cust_id):

		bdos_stats_dict[dev_list_dp_ip] = {
			'Name': dev_list_dp_ip_attr['Name'],
			'Customer ID': cust_id,
			'BDOS Report': []
		}

		device_policies = full_pol_dic.get(dev_list_dp_ip, {}).get('Policies', {})
		rules_table = device_policies.get('rsIDSNewRulesTable', [])

		for pol_attr in rules_table:
			if (
				pol_attr.get("rsIDSNewRulesProfileNetflood") not in ("", "null") and
				pol_attr.get("rsIDSNewRulesName") != "null" and
				pol_attr.get("rsIDSNewRulesState") != "2"
			):
				bdos_report = self.getBDOSTrafficReport(dev_list_dp_ip, pol_attr, full_net_dic)
				bdos_stats_dict[dev_list_dp_ip]['BDOS Report'].append(bdos_report)

		return bdos_stats_dict


	def getBDOSReportFromVision_PPS(self,dev_list_dp_ip,dev_list_dp_ip_attr,full_pol_dic,full_net_dic,bdos_stats_dict_pps,cust_id):

		bdos_stats_dict_pps[dev_list_dp_ip] = {
			'Name': dev_list_dp_ip_attr['Name'],
			'Customer ID': cust_id,
			'BDOS Report': []
		}

		device_policies = full_pol_dic.get(dev_list_dp_ip, {}).get('Policies', {})
		rules_table = device_policies.get('rsIDSNewRulesTable', [])

		for pol_attr in rules_table:
			if (
				pol_attr.get("rsIDSNewRulesProfileNetflood") not in ("", "null") and
				pol_attr.get("rsIDSNewRulesName") != "null" and
				pol_attr.get("rsIDSNewRulesState") != "2"
			):
				bdos_report_pps = self.getBDOSTrafficReport_PPS(dev_list_dp_ip, pol_attr, full_net_dic)
				bdos_stats_dict_pps[dev_list_dp_ip]['BDOS Report'].append(bdos_report_pps)

		return bdos_stats_dict_pps


	def getDNSReportFromVision(self,dev_list_dp_ip,dev_list_dp_ip_attr,full_pol_dic,full_net_dic,dns_stats_dict,cust_id):

		dns_stats_dict[dev_list_dp_ip] = {
			'Name': dev_list_dp_ip_attr['Name'],
			'Customer ID': cust_id,
			'DNS Report': []
		}

		device_policies = full_pol_dic.get(dev_list_dp_ip, {}).get('Policies', {})
		rules_table = device_policies.get('rsIDSNewRulesTable', [])

		for pol_attr in rules_table:
			if (
				pol_attr.get("rsIDSNewRulesProfileDNS") not in ("", "null") and
				pol_attr.get("rsIDSNewRulesName") != "null" and
				pol_attr.get("rsIDSNewRulesState") != "2"
			):
				dns_report = self.getDNStrafficReport(dev_list_dp_ip, pol_attr, full_net_dic)
				dns_stats_dict[dev_list_dp_ip]['DNS Report'].append(dns_report)

		return dns_stats_dict


	def getTrafficUtilizationBPS(self,dev_list_dp_ip,dev_list_dp_ip_attr,full_pol_dic,traffic_stats_dict_bps):

		traffic_stats_dict_bps[dev_list_dp_ip] = {
			'Name': dev_list_dp_ip_attr['Name'],
			'Traffic Report BPS': []
		}

		device_policies = full_pol_dic.get(dev_list_dp_ip, {}).get('Policies', {})
		rules_table = device_policies.get('rsIDSNewRulesTable', [])

		for pol_attr in rules_table:
			pol_name = pol_attr.get("rsIDSNewRulesName")
			if pol_name:  # Optional check if name exists
				# traffic_report_bps = self.getTrafficStatsBPS(dev_list_dp_ip,pol_name) # THis is for older Vision versions
				traffic_report_bps = self.ams_stats_dashboards(dev_list_dp_ip, pol_name, units="bps")
				traffic_stats_dict_bps[dev_list_dp_ip]['Traffic Report BPS'].append(traffic_report_bps)

		return traffic_stats_dict_bps
	
	def getTrafficUtilizationPPS(self,dev_list_dp_ip,dev_list_dp_ip_attr,full_pol_dic,traffic_stats_dict_pps):
		# Get Traffic Utilization PPS - Packets per second per DefensePro
		traffic_stats_dict_pps[dev_list_dp_ip] = {
			'Name': dev_list_dp_ip_attr['Name'],
			'Traffic Report PPS': []
		}

		device_policies_list = full_pol_dic.get(dev_list_dp_ip, {}).get('Policies', {})
		
		for pol_attr in device_policies_list['rsIDSNewRulesTable']:
			pol_name = pol_attr.get("rsIDSNewRulesName")
			if pol_name:
				# traffic_report_pps = self.getTrafficStatsPPS(dev_list_dp_ip, pol_name) # THis is for older Vision versions
				traffic_report_pps = self.ams_stats_dashboards(dev_list_dp_ip, pol_name, units="pps")
				traffic_stats_dict_pps[dev_list_dp_ip]['Traffic Report PPS'].append(traffic_report_pps)

		return traffic_stats_dict_pps

	def getTrafficUtilizationCPS(self,dev_list_dp_ip,dev_list_dp_ip_attr,full_pol_dic,traffic_stats_dict_cps):
		# Get Traffic Utilization CPS - Connections per second per DefensePro
		traffic_stats_dict_cps[dev_list_dp_ip] = {
			'Name': dev_list_dp_ip_attr['Name'],
			'Traffic Report CPS': []
		}

		device_policies = full_pol_dic.get(dev_list_dp_ip, {}).get('Policies', {})
		rules_table = device_policies.get('rsIDSNewRulesTable', [])

		for pol_attr in rules_table:
			pol_name = pol_attr.get("rsIDSNewRulesName")
			if pol_name:
				traffic_report_cps = self.getTrafficStatsCPS(dev_list_dp_ip, pol_name)
				traffic_stats_dict_cps[dev_list_dp_ip]['Traffic Report CPS'].append(traffic_report_cps)

		return traffic_stats_dict_cps


	def getCEC(self, dev_list_dp_ip,dev_list_dp_ip_attr, full_pol_dic,traffic_stats_dict_cec):
		# Get CEC - Concurrent Established Connections per DefensePro

		traffic_stats_dict_cec[dev_list_dp_ip] = {
			'Name': dev_list_dp_ip_attr['Name'],
			'Traffic Report CEC': []
		}

		device_policies = full_pol_dic.get(dev_list_dp_ip, {}).get('Policies', {})
		if not device_policies:
			return traffic_stats_dict_cec

		traffic_report_cec = self.getTrafficStatsCEC(dev_list_dp_ip)
		traffic_stats_dict_cec[dev_list_dp_ip]['Traffic Report CEC'].append(traffic_report_cec)

		return traffic_stats_dict_cec




	def ams_stats_dashboards(self, dp_ip, policy, units, uri = "/mgmt/vrm/monitoring/traffic/periodic/report"):

		api_url = f'https://{self.ip}' + uri

		query = {
			"direction": "Inbound",
			"timeInterval": {
				"from": self.report_duration,
				"to": None
			},

		}

		if units == "bps" or units=="pps":
			query.update({"unit": units})



		query.update({"selectedDevices":  [
			{
				"deviceId": dp_ip,
				"networkPolicies": [policy],
				"ports": []
			}
			]
		})

		r = self._post(api_url, json=query)

		print(f'{dp_ip}, {policy}')

		jsonData = json.loads(r.text)
	
		TrafficReportListBPS = {policy:jsonData['data']}
		return TrafficReportListBPS