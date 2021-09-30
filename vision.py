import config as cfg
from requests import Session
import requests
import json
import time
from logging_helper import logging




class Vision:

	def __init__(self, ip, username, password):
		self.ip = ip
		self.login_data = {"username": username, "password": password}
		self.base_url = "https://" + ip
		self.sess = Session()
		self.sess.headers.update({"Content-Type": "application/json"})
		self.login()
		self.device_list = self.getDeviceList()
		# self.last_24_hours = self.epochTimeGenerator(1)
		# self.last_week = self.epochTimeGenerator(7)

		self.report_duration = self.epochTimeGenerator(cfg.DURATION)

		with open('BDOStrafficRequest.json') as outfile:
			self.BDOSformatRequest = json.load(outfile)
		with open('DNStrafficRequest.json') as dnstrafficrequest:
			self.DNSformatRequest = json.load(dnstrafficrequest)
		with open('TrafficRequest.json') as trafficrequest:
			self.trafficformatrequest = json.load(trafficrequest)
		with open('TrafficRequestCPS.json') as trafficrequestCPS:
			self.trafficformatrequestCPS = json.load(trafficrequestCPS)
		with open('TrafficRequestCEC.json') as trafficrequestcec:
			self.trafficformatrequestcec = json.load(trafficrequestcec)
	def login(self):
		logging.info('Start connecting to Vision')
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
			logging.info('Login error: ' + response['message'])
			exit(1)

	def getDeviceList(self):
		# Returns list of DP with mgmt IP, type, Name
		devices_url = self.base_url + '/mgmt/system/config/itemlist/alldevices'
		r = self.sess.get(url=devices_url, verify=False)
		json_txt = r.json()

		dev_list = {item['managementIp']: {'Type': item['type'], 'Name': item['name'],
			'Version': item['deviceVersion'], 'ormId': item['ormId']} for item in json_txt if item['type'] == "DefensePro"}
		return dev_list
		
	def epochTimeGenerator(self,days):
		current_time = time.time()
		daysInSeconds = 86400 * days
		return (int(current_time) - daysInSeconds) * 1000

	
	def getSignatureProfileListByDevice(self, dp_ip):
		# Returns Signature profile list with rules
		policy_url = self.base_url + "/mgmt/device/byip/" + \
			dp_ip + "/config/rsIDSSignaturesProfilesTable?props=rsIDSSignaturesProfileName,rsIDSSignaturesProfileRuleName,rsIDSSignaturesProfileRuleAttributeType,rsIDSSignaturesProfileRuleAttributeName"
		r = self.sess.get(url=policy_url, verify=False)
		sig_list = r.json()
		
		if sig_list.get("status") == "error":
			logging.info("Error: " + sig_list['message'])
			return []
		return sig_list

	def getBDOSProfileConfigByDevice(self, dp_ip):
		# Returns BDOS profile config
		policy_url = self.base_url + "/mgmt/device/byip/" + \
			dp_ip + "/config/rsNetFloodProfileTable"
		r = self.sess.get(url=policy_url, verify=False)
		bdos_config = r.json()
		
		if bdos_config.get("status") == "error":
			logging.info("Error: " + bdos_config['message'])
			return []
		return bdos_config

	def getNetClassListByDevice(self, dp_ip):
		#Returns Network Class list with networks

		policy_url = self.base_url + "/mgmt/device/byip/" + \
			dp_ip + "/config/rsBWMNetworkTable/"
		r = self.sess.get(url=policy_url, verify=False)
		net_list = r.json()
		
		if net_list.get("status") == "error":
			logging.info("Error: " + net_list['message'])
			return []
		return net_list

	def getPolicyListByDevice(self, dp_ip):
		# Returns policies list with all its attributes
		policy_url = self.base_url + "/mgmt/device/byip/" + \
			dp_ip + "/config/rsIDSNewRulesTable"
		# URL params ?count=1000&props=rsIDSNewRulesName
		r = self.sess.get(url=policy_url, verify=False)
		policy_list = r.json()

		if policy_list.get("status") == "error":
			logging.info("Error: " + policy_list['message'])
			return []

		return policy_list
	

	def getBDOSTrafficReport(self,pol_dp_ip,pol_attr,net_list):

		pol_name = pol_attr["rsIDSNewRulesName"]
		pol_src_net = pol_attr["rsIDSNewRulesSource"]
		pol_dst_net = pol_attr["rsIDSNewRulesDestination"]

		url = f'https://{self.ip}/mgmt/monitor/reporter/reports-ext/BDOS_BASELINE_RATE_REPORTS'
		BDOS_portocols = ['udp','tcp-syn','tcp-syn-ack','tcp-rst','tcp-ack-fin','tcp-frag','udp-frag','icmp','igmp']
		
		self.BDOSformatRequest['criteria'][5]['lower'] = self.report_duration
		self.BDOSformatRequest['criteria'][6]["filters"][0]['filters'][0]['value'] = pol_dp_ip
		self.BDOSformatRequest['criteria'][6]["filters"][0]['filters'][1]["filters"][0]["value"] = pol_name 
		self.BDOSformatRequest['criteria'][0]['value'] = 'true'
		
		
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
					
					if net_name == pol_src_net:
						if ":" in net_addr:
							ipv6 = True
							#logging.info(f'dp ip is {net_dp_ip},policy {pol_name}, network {net_name} - src net is IPv6')  
							self.BDOSformatRequest['criteria'][0]['value'] = 'false'
							
						if "." in net_addr:
							ipv4 = True
							#logging.info(f'dp ip is {net_dp_ip},policy {pol_name}, network {net_name} - src net is IPv4')  
							self.BDOSformatRequest['criteria'][0]['value'] = 'true'			

					if net_name == pol_dst_net:
						if ":" in net_addr:
							ipv6 = True
							#logging.info(f'dp ip is {net_dp_ip},policy {pol_name}, network {net_name} - dst net is IPv6')
							self.BDOSformatRequest['criteria'][0]['value'] = 'false'
							
						if "." in net_addr:
							ipv4 = True
							#logging.info(f'dp ip is {net_dp_ip},policy {pol_name}, network {net_name} - dst net is IPv4')  
							self.BDOSformatRequest['criteria'][0]['value'] = 'true'								
						

				
		for protocol in BDOS_portocols:
			self.BDOSformatRequest['criteria'][1]["value"] = protocol
			
			if ipv6:
			
				self.BDOSformatRequest['criteria'][0]['value'] = 'false'
				r = self.sess.post(url = url, json = self.BDOSformatRequest , verify=False)
				jsonData = json.loads(r.text)
				

				#print(f'{pol_dp_ip}, policy {pol_name} - executing IPv6 query')

				bdosReportList.append(jsonData['data'])

			if ipv4:
			
				self.BDOSformatRequest['criteria'][0]['value'] = 'true'
				r = self.sess.post(url = url, json = self.BDOSformatRequest , verify=False)
				jsonData = json.loads(r.text)
				
				#print(f'{pol_dp_ip}, policy {pol_name} - executing IPv4 query')
				
				bdosReportList.append(jsonData['data'])

		bdosTrafficReport = {pol_name:bdosReportList}
		
		return bdosTrafficReport

################DNS Query############################

	def getDNStrafficReport(self,pol_dp_ip,pol_attr,net_list):

		pol_name = pol_attr["rsIDSNewRulesName"]
		pol_src_net = pol_attr["rsIDSNewRulesSource"]
		pol_dst_net = pol_attr["rsIDSNewRulesDestination"]

		url = f'https://{self.ip}/mgmt/monitor/reporter/reports-ext/DNS_BASELINE_RATE_REPORTS'  
		DNS_protocols = ['dns-a','dns-aaaa',"dns-mx","dns-text","dns-soa","dns-srv","dns-ptr","dns-naptr","dns-other"]
		
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
					
					if net_name == pol_src_net:
						if ":" in net_addr:
							ipv6 = True
		
						if "." in net_addr:
							ipv4 = True		

					if net_name == pol_dst_net:
						if ":" in net_addr:
							ipv6 = True
							
						if "." in net_addr:
							ipv4 = True							
						
		for protocol in DNS_protocols:

			self.DNSformatRequest['criteria'][1]["value"] = protocol

			if ipv6:
						
				self.DNSformatRequest['criteria'][0]['value'] = 'false'
				r = self.sess.post(url = url, json = self.DNSformatRequest , verify=False)
				jsonData = json.loads(r.text)
				
				print(f'{pol_dp_ip}, policy {pol_name} - executing DNS IPv6 query')

				dnsReportList.append(jsonData['data'])

			if ipv4:

				self.DNSformatRequest['criteria'][0]['value'] = 'true'
				
				r = self.sess.post(url = url, json = self.DNSformatRequest , verify=False)
				jsonData = json.loads(r.text)
				
				print(f'{pol_dp_ip}, policy {pol_name} - executing DNS IPv4 query')
				
				dnsReportList.append(jsonData['data'])				

			r = self.sess.post(url = url, json = self.DNSformatRequest , verify=False)
			jsonData = json.loads(r.text)
			dnsReportList.append(jsonData['data'])

		dnsTrafficReport = {pol_name:dnsReportList}
		
		return dnsTrafficReport


################Traffic stats Bps######################

	def getTrafficStatsBPS(self, dp_ip, policy):
		url = f'https://{self.ip}/mgmt/monitor/reporter/reports-ext/DP_TRAFFIC_UTILIZATION_AGG_REPORTS'
		
		self.trafficformatrequest['aggregation']['criteria'][1]['value'] = 'bps'
		self.trafficformatrequest['aggregation']['criteria'][3]['lower'] = self.report_duration
		self.trafficformatrequest['aggregation']['criteria'][4]['filters'][0]['filters'][0]['value'] = dp_ip
		self.trafficformatrequest['aggregation']['criteria'][4]['filters'][0]['filters'][1]['filters'][0]['value'] = policy

		r = self.sess.post(url = url, json = self.trafficformatrequest , verify=False)
		jsonData = json.loads(r.text)
	
		TrafficReportListBPS = {policy:jsonData['data']}
		# with open('traffic_query.txt', 'w') as f:
		# 	f.write(str(TrafficReportListBPS))
		return TrafficReportListBPS

############################################

################Traffic stats PPS######################

	def getTrafficStatsPPS(self, dp_ip, policy):
		url = f'https://{self.ip}/mgmt/monitor/reporter/reports-ext/DP_TRAFFIC_UTILIZATION_AGG_REPORTS'
		
		self.trafficformatrequest['aggregation']['criteria'][1]['value'] = 'pps'
		self.trafficformatrequest['aggregation']['criteria'][3]['lower'] = self.report_duration
		self.trafficformatrequest['aggregation']['criteria'][4]['filters'][0]['filters'][0]['value'] = dp_ip
		self.trafficformatrequest['aggregation']['criteria'][4]['filters'][0]['filters'][1]['filters'][0]['value'] = policy

		r = self.sess.post(url = url, json = self.trafficformatrequest , verify=False)
		jsonData = json.loads(r.text)
	
		TrafficReportListPPS = {policy:jsonData['data']}
		# with open('traffic_query_pps.txt', 'w') as f:
		# 	f.write(str(TrafficReportListPPS))
		return TrafficReportListPPS

############################################

################Traffic stats CPS######################

	def getTrafficStatsCPS(self, dp_ip, policy):
		url = f'https://{self.ip}/mgmt/monitor/reporter/reports-ext/DP_CONNECTION_HOURLY_STATISTICS'
		
		self.trafficformatrequestCPS['aggregation']['criteria'][2]['lower'] = self.report_duration
		self.trafficformatrequestCPS['aggregation']['criteria'][3]['filters'][0]['filters'][0]['value'] = dp_ip
		self.trafficformatrequestCPS['aggregation']['criteria'][3]['filters'][0]['filters'][1]['filters'][0]['value'] = policy

		r = self.sess.post(url = url, json = self.trafficformatrequestCPS , verify=False)
		jsonData = json.loads(r.text)
	
		trafficreportlistcps = {policy:jsonData['data']}

		# with open('traffic_query_cps.txt', 'w') as f:
		# 	f.write(str(trafficreportlistcps))

		return trafficreportlistcps

############################################
################Traffic stats CEC - Concurrent Established Connections######################

	def getTrafficStatsCEC(self, dp_ip):
		url = f'https://{self.ip}/mgmt/monitor/reporter/reports-ext/DP_CONCURRENT_CONNECTIONS_HOURLY_REPORTS'
		
		self.trafficformatrequestcec['aggregation']['criteria'][0]['lower'] = self.report_duration
		self.trafficformatrequestcec['aggregation']['criteria'][1]['filters'][0]['filters'][0]['value'] = dp_ip

		r = self.sess.post(url = url, json = self.trafficformatrequestcec , verify=False)
		jsonData = json.loads(r.text)
	
		trafficreportlistcec = jsonData['data']

		# with open('traffic_query_cec.txt', 'w') as f:
		# 	f.write(str(trafficreportlistcec))

		return trafficreportlistcec

	def getFullPolicyDictionary(self):
		# Create Full Policies list with attributes dictionary per DefensePro

		full_pol_dic = {}
		for key, val in self.device_list.items():
			full_pol_dic[key] = {}
			full_pol_dic[key]['Name'] = val['Name']
			full_pol_dic[key]['Version'] = val['Version']
			full_pol_dic[key]['Policies'] = self.getPolicyListByDevice(key)
		
		with open('full_pol_dic.json', 'w') as full_pol_dic_file:
			json.dump(full_pol_dic,full_pol_dic_file)

		return full_pol_dic

	def getFullSignatureProfileDictionary(self):
		# Create Full Signature profile list with rules dictionary per DefensePro
		full_sig_dic = {}
		for key in self.device_list:
			full_sig_dic[key] = self.getSignatureProfileListByDevice(key)
		
		with open('full_sig_dic.json', 'w') as full_sig_dic_file:
			json.dump(full_sig_dic,full_sig_dic_file)
			
		return full_sig_dic

	def getFullNetClassDictionary(self):
		# Create Full Network class profile list with networks dictionary per DefensePro

		full_net_dic = {}
		for key in self.device_list:
			full_net_dic[key] = self.getNetClassListByDevice(key)

		with open('full_net_dic.json', 'w') as full_net_dic_file:
			json.dump(full_net_dic,full_net_dic_file)
			
		return full_net_dic

	def getFullBDOSProfConfigDictionary(self):
		# Create Full BDOS Profile config list with all BDOS attributes dictionary per DefensePro

		full_bdosprofconf_dic = {}
		for key, val in self.device_list.items():
			full_bdosprofconf_dic[key] = {}
			full_bdosprofconf_dic[key]['Name'] = val['Name']
			full_bdosprofconf_dic[key]['Version'] = val['Version']
			full_bdosprofconf_dic[key]['Policies'] = self.getBDOSProfileConfigByDevice(key)
		
		with open('full_bdosprofconf_dic.json', 'w') as full_bdosprofconf_dic_file:
			json.dump(full_bdosprofconf_dic,full_bdosprofconf_dic_file)

		return full_bdosprofconf_dic


# Vision(cfg.VISION_IP, cfg.VISION_USER, cfg.VISION_PASS).getBDOSTrafficReport('10.128.221.229','LTE-Mobiles-Sanj')
