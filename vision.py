from requests import Session
import requests
import json
from logging_helper import logging
import config as cfg
import os

raw_data_path = "./Raw Data/"
config_path = "./Config/"


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
		self.device_list = self.getDeviceList()
		logging.info('Collecting DefensePro device list')
		print('Collecting DefensePro device list')		

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

	def getDeviceList(self):
		# Returns list of DP with mgmt IP, type, Name
		devices_url = self.base_url + '/mgmt/system/config/itemlist/alldevices'
		r = self.sess.get(url=devices_url, verify=False)
		json_txt = r.json()

		dev_list = {item['managementIp']: {'Type': item['type'], 'Name': item['name'],
			'Version': item['deviceVersion'], 'ormId': item['ormId']} for item in json_txt if item['type'] == "DefensePro"}
		
		with open(raw_data_path + 'full_dev_list.json', 'w') as full_dev_list_file:
			json.dump(dev_list,full_dev_list_file)

		return dev_list

	def dpconfig_cleanup(self):
		# For every file  in config_path delete it
		for file in os.listdir(config_path):
			os.remove(config_path + file)
	
	def getSignatureProfileListByDevice(self, dp_ip):
		# Returns Signature profile list with rules
		policy_url = self.base_url + "/mgmt/device/byip/" + \
			dp_ip + "/config/rsIDSSignaturesProfilesTable?props=rsIDSSignaturesProfileName,rsIDSSignaturesProfileRuleName,rsIDSSignaturesProfileRuleAttributeType,rsIDSSignaturesProfileRuleAttributeName"
		r = self.sess.get(url=policy_url, verify=False)
		sig_list = r.json()
		
		if sig_list.get("status") == "error":
			logging.info("Signature Profile list get error. DefensePro IP: " + dp_ip + ". Error message: " + sig_list['message'])
			return []
		return sig_list

	def getBDOSProfileConfigByDevice(self, dp_ip):
		# Returns BDOS profile config
		policy_url = self.base_url + "/mgmt/device/byip/" + \
			dp_ip + "/config/rsNetFloodProfileTable"
		r = self.sess.get(url=policy_url, verify=False)
		bdos_config = r.json()
		
		if bdos_config.get("status") == "error":
			logging.info("BDOS Profile list get error. DefensePro IP: " + dp_ip + ". Error message: " + bdos_config['message'])

			return []
		return bdos_config

	def getDNSProfileConfigByDevice(self, dp_ip):
		# Returns DNS profile config
		policy_url = self.base_url + "/mgmt/device/byip/" + \
			dp_ip + "/config/rsDnsProtProfileTable"
		r = self.sess.get(url=policy_url, verify=False)
		dns_config = r.json()
		
		if dns_config.get("status") == "error":
			logging.info("DNS Profile list get error. DefensePro IP: " + dp_ip + ". Error message: " + dns_config['message'])

			return []
		return dns_config

	def getSYNPProfileListByDevice(self, dp_ip):
		# Returns BDOS profile config
		policy_url = self.base_url + "/mgmt/device/byip/" + \
			dp_ip + "/config/rsIDSSynProfilesTable?props=rsIDSSynProfilesName,rsIDSSynProfileServiceName"
		r = self.sess.get(url=policy_url, verify=False)
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
		r = self.sess.get(url=url, verify=False)
		synp_prof_params_list = r.json()
		
		if synp_prof_params_list.get("status") == "error":
			logging.info("SYN Flood Profiles parameters get error. DefensePro IP: " + dp_ip + ". Error message: " + synp_prof_params_list['message'])

			return []
		return synp_prof_params_list

	def getSYNPProtectionsTableByDevice(self, dp_ip):
		# Returns SYNP profile config
		url = self.base_url + "/mgmt/device/byip/" + \
			dp_ip + "/config/rsIDSSYNAttackTable"
		r = self.sess.get(url=url, verify=False)
		synp_protections_table = r.json()
		
		if synp_protections_table.get("status") == "error":
			logging.info("SYN Flood Protections get error. DefensePro IP: " + dp_ip + ". Error message: " + synp_protections_table['message'])

			return []
		return synp_protections_table

	def getConnlimProfileListByDevice(self, dp_ip):
		# Returns Connectlion limit profile config
		policy_url = self.base_url + "/mgmt/device/byip/" + \
			dp_ip + "/config/rsIDSConnectionLimitProfileTable"
		r = self.sess.get(url=policy_url, verify=False)
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
		r = self.sess.get(url=url, verify=False)
		connlim_prof_attacktable_list = r.json()
		
		if connlim_prof_attacktable_list.get("status") == "error":
			logging.info("Connection Limit Profiles parameters get error. DefensePro IP: " + dp_ip + ". Error message: " + connlim_prof_attacktable_list['message'])

			return []
		return connlim_prof_attacktable_list

	def getOOSProfileListByDevice(self, dp_ip):
		# Returns Out of State profile config
		policy_url = self.base_url + "/mgmt/device/byip/" + \
			dp_ip + "/config/rsStatefulProfileTable"
		r = self.sess.get(url=policy_url, verify=False)
		oos_prof_list = r.json()
		
		if oos_prof_list.get("status") == "error":
			logging.info("Out of State Profile list get error. DefensePro IP: " + dp_ip + ". Error message: " + oos_prof_list['message'])
			# print("Connection Limit Profile list get error. DefensePro IP: " + dp_ip + ". Error message: " + oos_prof_list['message'])
			return []
		
		return oos_prof_list

	def getNetClassListByDevice(self, dp_ip):
		#Returns Network Class list with networks

		policy_url = self.base_url + "/mgmt/device/byip/" + \
			dp_ip + "/config/rsBWMNetworkTable/"
		r = self.sess.get(url=policy_url, verify=False)
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
		r = self.sess.get(url=policy_url, verify=False)
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
		r = self.sess.get(url=policy_url, verify=False)

		with open(config_path + f'{dp_ip}_config.txt', 'wb') as f:
			f.write(r.content) #Write to file

		return

	
	def getFullPolicyDictionary(self,key,val):
		# Create Full Policies list with attributes dictionary per DefensePro

		full_pol_dic = {}

		full_pol_dic[key] = {}
		full_pol_dic[key]['Name'] = val['Name']
		full_pol_dic[key]['Version'] = val['Version']
		full_pol_dic[key]['Policies'] = self.getPolicyListByDevice(key)


		with open(raw_data_path + 'full_pol_dic.json', 'w') as full_pol_dic_file:
			json.dump(full_pol_dic,full_pol_dic_file)

		return full_pol_dic

	def getFullSignatureProfileDictionary(self,key,val):
		# Create Full Signature profile list with rules dictionary per DefensePro
		full_sig_dic = {}
		full_sig_dic[key] = self.getSignatureProfileListByDevice(key)


		with open(raw_data_path + 'full_sig_dic.json', 'w') as full_sig_dic_file:
			json.dump(full_sig_dic,full_sig_dic_file)
			
		return full_sig_dic

	def getFullNetClassDictionary(self,key,val):
		# Create Full Network class profile list with networks dictionary per DefensePro
		full_net_dic = {}
		full_net_dic[key] = {}
		

		if self.getNetClassListByDevice(key) == ([]): #If DefensePro is unreachable
			full_net_dic[key]['rsBWMNetworkTable'] = []

		else:

			full_net_dic[key] = self.getNetClassListByDevice(key)
			full_net_dic[key]['Name'] = val['Name']
			

		with open(raw_data_path + 'full_net_dic.json', 'w') as full_net_dic_file:
			json.dump(full_net_dic,full_net_dic_file)
		
		return full_net_dic

	def getFullBDOSProfConfigDictionary(self,key,val):
		# Create Full BDOS Profile config list with all BDOS attributes dictionary per DefensePro

		full_bdosprofconf_dic = {}
		full_bdosprofconf_dic[key] = {}
		full_bdosprofconf_dic[key]['Name'] = val['Name']
		full_bdosprofconf_dic[key]['Version'] = val['Version']
		full_bdosprofconf_dic[key]['Policies'] = self.getBDOSProfileConfigByDevice(key)


		with open(raw_data_path + 'full_bdosprofconf_dic.json', 'w') as full_bdosprofconf_dic_file:
			json.dump(full_bdosprofconf_dic,full_bdosprofconf_dic_file)

		return full_bdosprofconf_dic

	def getFullDNSProfConfigDictionary(self,key,val):
		# Create Full DNS Profile config list with all BDOS attributes dictionary per DefensePro

		full_dnsprofconf_dic = {}
		full_dnsprofconf_dic[key] = {}
		full_dnsprofconf_dic[key]['Name'] = val['Name']
		full_dnsprofconf_dic[key]['Version'] = val['Version']
		full_dnsprofconf_dic[key]['Policies'] = self.getDNSProfileConfigByDevice(key)

		with open(raw_data_path + 'full_dnsprofconf_dic.json', 'w') as full_dnsprofconf_dic_file:
			json.dump(full_dnsprofconf_dic,full_dnsprofconf_dic_file)

		return full_dnsprofconf_dic



	def getFullSYNPConfigDictionary(self,dp_ip,val):
		# Create Full SYNP Profile config list with all BDOS attributes dictionary per DefensePro

		full_synpprofconf_dic = {}
		full_synpprofconf_dic[dp_ip] = {}
		full_synpprofconf_dic[dp_ip]['Name'] = val['Name']
		full_synpprofconf_dic[dp_ip]['Version'] = val['Version']

		synp_prof_list = self.getSYNPProfileListByDevice(dp_ip)
		synp_prof_params_table = self.getSYNPProfileParamsByDevice(dp_ip)
		synp_protections_table = self.getSYNPProtectionsTableByDevice(dp_ip)

		full_synpprofconf_dic[dp_ip]['Profiles'] = {}
		
		if synp_prof_params_table: #If table is not empty
			for synp_prof_param_set in synp_prof_params_table['rsIDSSynProfilesParamsTable']:
				full_synpprofconf_dic[dp_ip]['Profiles'][synp_prof_param_set['rsIDSSynProfilesParamsName']] = {}
				full_synpprofconf_dic[dp_ip]['Profiles'][synp_prof_param_set['rsIDSSynProfilesParamsName']]['Parameters'] = synp_prof_param_set


				full_synpprofconf_dic[dp_ip]['Profiles'][synp_prof_param_set['rsIDSSynProfilesParamsName']]['Protections'] = []

				for synp_prof in synp_prof_list['rsIDSSynProfilesTable']:
					if synp_prof['rsIDSSynProfilesName'] == synp_prof_param_set['rsIDSSynProfilesParamsName']:
					
						for syn_protection in synp_protections_table['rsIDSSYNAttackTable']:
							if syn_protection['rsIDSSYNAttackName'] == synp_prof['rsIDSSynProfileServiceName']:
								full_synpprofconf_dic[dp_ip]['Profiles'][synp_prof_param_set['rsIDSSynProfilesParamsName']]['Protections'].append(syn_protection)
					

		with open(raw_data_path + 'full_synprofconf_dic.json', 'w') as full_synpconf_dic_file:
			json.dump(full_synpprofconf_dic,full_synpconf_dic_file)

		return full_synpprofconf_dic


	def getFullConnlimConfigDictionary(self,dp_ip,val):
		# Create Full Connection Limit Profile config list with all BDOS attributes dictionary per DefensePronnectionLimitProfileName

		full_connlimprofconf_dic = {}
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


		with open(raw_data_path + 'full_connlimprofconf_dic.json', 'w') as full_connlimprofconf_file:
			json.dump(full_connlimprofconf_dic,full_connlimprofconf_file)

		return full_connlimprofconf_dic
	
	def getFullOOSConfigDictionary(self,dp_ip,val):
		# Create Full Out of State Profile config list with all BDOS attributes dictionary per DefensePro

		full_oosprofconf_dic = {}
		full_oosprofconf_dic[dp_ip] = {}
		full_oosprofconf_dic[dp_ip]['Name'] = val['Name']
		full_oosprofconf_dic[dp_ip]['Version'] = val['Version']

		oos_prof_list = self.getOOSProfileListByDevice(dp_ip)


		full_oosprofconf_dic[dp_ip]['Profiles'] = []
		
		if oos_prof_list: #If table is not empty

			for oos_prof in oos_prof_list['rsStatefulProfileTable']:
				
				full_oosprofconf_dic[dp_ip]['Profiles'].append(oos_prof)	


		with open(raw_data_path + 'full_oosprofconf_dic.json', 'w') as full_oosprofconf_file:
			json.dump(full_oosprofconf_dic,full_oosprofconf_file)

		return full_oosprofconf_dic