import config as cfg
import json
from vision import Vision
from dpconfig_parser import DataParser
from dpconfig_mapper import DataMapper
import urllib3
import logging_helper
import sys
import os


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


#Arguments variables

getdatafromvision = True
email = False
test_email_alarm = False
report = []

raw_data_path = "./Raw Data/"
config_path = "./Config/"

if not os.path.exists('log'):
	os.makedirs('log')

if not os.path.exists('Raw Data'):
	os.makedirs('Raw Data')

if not os.path.exists('Reports'):
	os.makedirs('Reports')

if not os.path.exists('Config'):
	os.makedirs('Config')





logging_helper.log_setup(cfg.LOG_FILE_PATH, cfg.SYSLOG_SERVER, cfg.SYSLOG_PORT)


for i in sys.argv:
	#Running script with arguments

	if i.lower() == "--use-cache-data":
		#No data collection from vision- running script using previously collected data
		getdatafromvision = False
		logging_helper.logging.info('Running script using cache data only')
		print('Running script using cache data only')
		
	if i.lower() == "--email":
		#Run script and send report by email.
		email = True
		logging_helper.logging.info('Running script with sending email argument')
		print('Running script with sending email argument')

	if i.lower() == "--test-email":
		#Run script- test sending email only
		logging_helper.logging.info('Running script with test email argument')
		print('Running script with test email argument')
		getdatafromvision = False
		test_email_alarm = True
		nobdosreport = True
		nodpconfigparsing = True


def dpconfig_cleanup():
	# For every file  in config_path and Raw_Data, delete it
	for file in os.listdir(config_path):
		os.remove(config_path + file)

	for file in os.listdir(raw_data_path):
		os.remove(raw_data_path + file)

if not getdatafromvision:

	with open(raw_data_path + 'full_pol_dic.json') as full_pol_dic_file:
		full_pol_dic = json.load(full_pol_dic_file)

	with open(raw_data_path + 'full_sig_dic.json') as full_sig_dic_file:
		full_sig_dic = json.load(full_sig_dic_file)

	with open(raw_data_path + 'full_net_dic.json') as full_net_dic_file:
		full_net_dic = json.load(full_net_dic_file)

	with open(raw_data_path + 'full_bdosprofconf_dic.json') as full_bdosprofconf_dic_file:
		full_bdosprofconf_dic = json.load(full_bdosprofconf_dic_file)

	with open(raw_data_path + 'full_dnsprofconf_dic.json') as full_dnsprofconf_dic_file:
		full_dnsprofconf_dic = json.load(full_dnsprofconf_dic_file)

	with open(raw_data_path + 'full_synprofconf_dic.json') as full_synprofconf_dic_file:
		full_synprofconf_dic = json.load(full_synprofconf_dic_file)

	with open(raw_data_path + 'full_connlimprofconf_dic.json') as full_connlimprofconf_file:
		full_connlimprofconf_dic = json.load(full_connlimprofconf_file)

	with open(raw_data_path + 'full_oosprofconf_dic.json') as full_oosprofconf_file:
		full_oosprofconf_dic = json.load(full_oosprofconf_file)

else: #getdatafromvision = True - collect data from vision

	print('Cleaning up previous DP config files')
	logging_helper.logging.info('Cleaning up previous DP config files')
	dpconfig_cleanup()

	print('Starting data collection from DefensePro')
	print('-' * 50)


	full_pol_dic = {}
	full_sig_dic = {}
	full_net_dic = {}
	full_bdosprofconf_dic = {}
	full_dnsprofconf_dic = {}
	full_synprofconf_dic = {}
	full_connlimprofconf_dic = {}
	full_oosprofconf_dic = {}

	if cfg.CUSTOMERS_JSON: #If customers.json is set to true, use this file to define the scope for the data collection
		print('CUSTOMERS_JSON is set to True - collecting data using the scope from customers.json file')

		if not cfg.CUSTOMERS_JSON_CUST_ID_LIST:		
			print('CUSTOMERS_JSON_CUST_ID_LIST is not defined - collecting data for all customers from customers.json file')
			print('-' * 25)
		else:
			print(f'CUSTOMERS_JSON_CUST_ID_LIST is defined - collecting data for customers {cfg.CUSTOMERS_JSON_CUST_ID_LIST}')
			print('-' * 25)

		with open("customers.json") as customers_file:
			customers = json.load(customers_file)
			
			for customer in customers:
				cust_id = customer['id']

				if not cfg.CUSTOMERS_JSON_CUST_ID_LIST: #If CUSTOMERS_JSON_CUST_ID_LIST is empty, collect all customers
		
					vision_user = customer['user']
					vision_pass = customer['pass']

					for vision_params in customer['visions']:

						vision_ip = vision_params['ip']

						dp_list = vision_params['dps'].split(',')

						v = Vision(vision_ip, vision_user, vision_pass)

						for key, val in v.device_list.items(): #key - DP IP, val - DP Attributes - Type, Name, Version, OrmId
							if key in dp_list:
								print(f'Collecting policies data from Defensepro {key}')
								logging_helper.logging.info(f'Collecting policies data from Defensepro {key}')

								full_pol_dic = v.getFullPolicyDictionary(key,val,full_pol_dic)
								
								print(f'Collecting signature profiles data from Defensepro {key}')
								logging_helper.logging.info(f'Collecting signature profiles data from Defensepro {key}')
								full_sig_dic = v.getFullSignatureProfileDictionary(key,val,full_sig_dic)

								print(f'Collecting network classes data from Defensepro {key}')
								logging_helper.logging.info(f'Collecting network classes data from Defensepro {key}')
								full_net_dic = v.getFullNetClassDictionary(key,val,full_net_dic)

								print(f'Collecting BDOS configuration data from Defensepro {key}')
								logging_helper.logging.info(f'Collecting BDOS configuration data from Defensepro {key}')
								full_bdosprofconf_dic = v.getFullBDOSProfConfigDictionary(key,val,full_bdosprofconf_dic)

								print(f'Collecting DNS configuration data from Defensepro {key}')
								logging_helper.logging.info(f'Collecting DNS configuration data from Defensepro {key}')
								full_dnsprofconf_dic = v.getFullDNSProfConfigDictionary(key,val,full_dnsprofconf_dic)

								print(f'Collecting SynFlood configuration data from Defensepro {key}')
								logging_helper.logging.info(f'Collecting SynFlood configuration data from Defensepro {key}')
								full_synprofconf_dic = v.getFullSYNPConfigDictionary(key,val,full_synprofconf_dic)

								print(f'Collecting Connection Limit configuration data from Defensepro {key}')
								logging_helper.logging.info(f'Collecting Connection Limit configuration data from Defensepro {key}')
								full_connlimprofconf_dic = v.getFullConnlimConfigDictionary(key,val,full_connlimprofconf_dic)

								print(f'Collecting Out of State configuration data from Defensepro {key}')
								logging_helper.logging.info(f'Collecting Out of State configuration data from Defensepro {key}')
								full_oosprofconf_dic = v.getFullOOSConfigDictionary(key,val,full_oosprofconf_dic)

								print(f'Downloading configuration file from Defensepro {key}')
								logging_helper.logging.info(f'Downloading configuration file from Defensepro {key}')
								v.getDPConfigByDevice(key)
								print('-' * 25)

				else: #If CUSTOMERS_JSON_CUST_ID_LIST is not empty, collect only the customers defined in the list	
					if cust_id in cfg.CUSTOMERS_JSON_CUST_ID_LIST:
						vision_user = customer['user']
						vision_pass = customer['pass']

						for vision_params in customer['visions']:

							vision_ip = vision_params['ip']
							dp_list = vision_params['dps'].split(',')

							v = Vision(vision_ip, vision_user, vision_pass)

							for key, val in v.device_list.items(): #key - DP IP, val - DP Attributes - Type, Name, Version, OrmId
								if key in dp_list:

									print(f'Collecting policies data from Defensepro {key}')
									logging_helper.logging.info(f'Collecting policies data from Defensepro {key}')

									full_pol_dic = v.getFullPolicyDictionary(key,val,full_pol_dic)
									
									print(f'Collecting signature profiles data from Defensepro {key}')
									logging_helper.logging.info(f'Collecting signature profiles data from Defensepro {key}')
									full_sig_dic = v.getFullSignatureProfileDictionary(key,val,full_sig_dic)

									print(f'Collecting network classes data from Defensepro {key}')
									logging_helper.logging.info(f'Collecting network classes data from Defensepro {key}')
									full_net_dic = v.getFullNetClassDictionary(key,val,full_net_dic)

									print(f'Collecting BDOS configuration data from Defensepro {key}')
									logging_helper.logging.info(f'Collecting BDOS configuration data from Defensepro {key}')
									full_bdosprofconf_dic = v.getFullBDOSProfConfigDictionary(key,val,full_bdosprofconf_dic)

									print(f'Collecting DNS configuration data from Defensepro {key}')
									logging_helper.logging.info(f'Collecting DNS configuration data from Defensepro {key}')
									full_dnsprofconf_dic = v.getFullDNSProfConfigDictionary(key,val,full_dnsprofconf_dic)

									print(f'Collecting SynFlood configuration data from Defensepro {key}')
									logging_helper.logging.info(f'Collecting SynFlood configuration data from Defensepro {key}')
									full_synprofconf_dic = v.getFullSYNPConfigDictionary(key,val,full_synprofconf_dic)

									print(f'Collecting Connection Limit configuration data from Defensepro {key}')
									logging_helper.logging.info(f'Collecting Connection Limit configuration data from Defensepro {key}')
									full_connlimprofconf_dic = v.getFullConnlimConfigDictionary(key,val,full_connlimprofconf_dic)

									print(f'Collecting Out of State configuration data from Defensepro {key}')
									logging_helper.logging.info(f'Collecting Out of State configuration data from Defensepro {key}')
									full_oosprofconf_dic = v.getFullOOSConfigDictionary(key,val,full_oosprofconf_dic)

									print(f'Downloading configuration file from Defensepro {key}')
									logging_helper.logging.info(f'Downloading configuration file from Defensepro {key}')
									v.getDPConfigByDevice(key)
									print('-' * 25)

	else: #If customers.json is set to false, use the scope defined in config.py variable "DP_IP_SCOPE_LIST"
		print('CUSTOMERS_JSON is set to False - collecting data using the scope from DP_IP_SCOPE_LIST')

		v = Vision(cfg.VISION_IP, cfg.VISION_USER, cfg.VISION_PASS)

		if not cfg.DP_IP_SCOPE_LIST: #If DP_IP_SCOPE_LIST is empty, collect all policies for all DefensePro
			print('DP_IP_SCOPE_LIST is not defined - collecting data from all DefensePro in Vision')
			print('-' * 25)

			for key, val in v.device_list.items(): #key - DP IP, val - DP Attributes - Type, Name, Version, OrmId

				print(f'Collecting policies data from Defensepro {key}')
				logging_helper.logging.info(f'Collecting policies data from Defensepro {key}')

				full_pol_dic = v.getFullPolicyDictionary(key,val,full_pol_dic)
				
				print(f'Collecting signature profiles data from Defensepro {key}')
				logging_helper.logging.info(f'Collecting signature profiles data from Defensepro {key}')
				full_sig_dic = v.getFullSignatureProfileDictionary(key,val,full_sig_dic)

				print(f'Collecting network classes data from Defensepro {key}')
				logging_helper.logging.info(f'Collecting network classes data from Defensepro {key}')
				full_net_dic = v.getFullNetClassDictionary(key,val,full_net_dic)

				print(f'Collecting BDOS configuration data from Defensepro {key}')
				logging_helper.logging.info(f'Collecting BDOS configuration data from Defensepro {key}')
				full_bdosprofconf_dic = v.getFullBDOSProfConfigDictionary(key,val,full_bdosprofconf_dic)

				print(f'Collecting DNS configuration data from Defensepro {key}')
				logging_helper.logging.info(f'Collecting DNS configuration data from Defensepro {key}')
				full_dnsprofconf_dic = v.getFullDNSProfConfigDictionary(key,val,full_dnsprofconf_dic)

				print(f'Collecting SynFlood configuration data from Defensepro {key}')
				logging_helper.logging.info(f'Collecting SynFlood configuration data from Defensepro {key}')
				full_synprofconf_dic = v.getFullSYNPConfigDictionary(key,val,full_synprofconf_dic)

				print(f'Collecting Connection Limit configuration data from Defensepro {key}')
				logging_helper.logging.info(f'Collecting Connection Limit configuration data from Defensepro {key}')
				full_connlimprofconf_dic = v.getFullConnlimConfigDictionary(key,val,full_connlimprofconf_dic)

				print(f'Collecting Out of State configuration data from Defensepro {key}')
				logging_helper.logging.info(f'Collecting Out of State configuration data from Defensepro {key}')
				full_oosprofconf_dic = v.getFullOOSConfigDictionary(key,val,full_oosprofconf_dic)

				print(f'Downloading configuration file from Defensepro {key}')
				logging_helper.logging.info(f'Downloading configuration file from Defensepro {key}')
				v.getDPConfigByDevice(key)
				print('-' * 25)
			

		else: #If DP_IP_SCOPE_LIST is defined (not empty), collect all policies for the DefensePro in the list
			print(f'DP_IP_SCOPE_LIST is defined - collecting data from specific DefensePro from the list {cfg.DP_IP_SCOPE_LIST}')
			print('-' * 25)

			for key, val in v.device_list.items(): #key - DP IP, val - DP Attributes - Type, Name, Version, OrmId

				if key in cfg.DP_IP_SCOPE_LIST:	

					print(f'Collecting policies data from Defensepro {key}')
					logging_helper.logging.info(f'Collecting policies data from Defensepro {key}')

					full_pol_dic = v.getFullPolicyDictionary(key,val,full_pol_dic)
					
					print(f'Collecting signature profiles data from Defensepro {key}')
					logging_helper.logging.info(f'Collecting signature profiles data from Defensepro {key}')
					full_sig_dic = v.getFullSignatureProfileDictionary(key,val,full_sig_dic)

					print(f'Collecting network classes data from Defensepro {key}')
					logging_helper.logging.info(f'Collecting network classes data from Defensepro {key}')
					full_net_dic = v.getFullNetClassDictionary(key,val,full_net_dic)

					print(f'Collecting BDOS configuration data from Defensepro {key}')
					logging_helper.logging.info(f'Collecting BDOS configuration data from Defensepro {key}')
					full_bdosprofconf_dic = v.getFullBDOSProfConfigDictionary(key,val,full_bdosprofconf_dic)

					print(f'Collecting DNS configuration data from Defensepro {key}')
					logging_helper.logging.info(f'Collecting DNS configuration data from Defensepro {key}')
					full_dnsprofconf_dic = v.getFullDNSProfConfigDictionary(key,val,full_dnsprofconf_dic)

					print(f'Collecting SynFlood configuration data from Defensepro {key}')
					logging_helper.logging.info(f'Collecting SynFlood configuration data from Defensepro {key}')
					full_synprofconf_dic = v.getFullSYNPConfigDictionary(key,val,full_synprofconf_dic)

					print(f'Collecting Connection Limit configuration data from Defensepro {key}')
					logging_helper.logging.info(f'Collecting Connection Limit configuration data from Defensepro {key}')
					full_connlimprofconf_dic = v.getFullConnlimConfigDictionary(key,val,full_connlimprofconf_dic)

					print(f'Collecting Out of State configuration data from Defensepro {key}')
					logging_helper.logging.info(f'Collecting Out of State configuration data from Defensepro {key}')
					full_oosprofconf_dic = v.getFullOOSConfigDictionary(key,val,full_oosprofconf_dic)

					print(f'Downloading configuration file from Defensepro {key}')
					logging_helper.logging.info(f'Downloading configuration file from Defensepro {key}')
					v.getDPConfigByDevice(key)
					print('-' * 25)

				else:
					print(f'Skipping data collection for Defensepro {key} - {val["Name"]}. Not in DP_IP_SCOPE_LIST')
					print('-' * 25)


	with open(raw_data_path + 'full_pol_dic.json', 'w') as full_pol_dic_file:
		json.dump(full_pol_dic,full_pol_dic_file)

	with open(raw_data_path + 'full_sig_dic.json', 'w') as full_sig_dic_file:
		json.dump(full_sig_dic,full_sig_dic_file)

	with open(raw_data_path + 'full_net_dic.json', 'w') as full_net_dic_file:
		json.dump(full_net_dic,full_net_dic_file)

	with open(raw_data_path + 'full_bdosprofconf_dic.json', 'w') as full_bdosprofconf_dic_file:
		json.dump(full_bdosprofconf_dic,full_bdosprofconf_dic_file)

	with open(raw_data_path + 'full_dnsprofconf_dic.json', 'w') as full_dnsprofconf_dic_file:
		json.dump(full_dnsprofconf_dic,full_dnsprofconf_dic_file)

	with open(raw_data_path + 'full_synprofconf_dic.json', 'w') as full_synpconf_dic_file:
		json.dump(full_synprofconf_dic,full_synpconf_dic_file)

	with open(raw_data_path + 'full_connlimprofconf_dic.json', 'w') as full_connlimprofconf_file:
		json.dump(full_connlimprofconf_dic,full_connlimprofconf_file)

	with open(raw_data_path + 'full_oosprofconf_dic.json', 'w') as full_oosprofconf_file:
		json.dump(full_oosprofconf_dic,full_oosprofconf_file)

	print('Data collection is complete')
	print('-' * 50)
	logging_helper.logging.info('Data collection is complete')



print('Starting data parsing')
logging_helper.logging.info('Starting data parsing')

if cfg.ANALYZE_CONFIG:
	print('Starting config analysis')
	report.append(DataParser(full_pol_dic,full_sig_dic,full_net_dic,full_bdosprofconf_dic,full_synprofconf_dic,full_connlimprofconf_dic, full_oosprofconf_dic).run())

if cfg.MAP_CONFIG:
	print('Starting config mapping')
	report.append(DataMapper(full_pol_dic,full_sig_dic,full_net_dic,full_bdosprofconf_dic,full_dnsprofconf_dic,full_synprofconf_dic,full_connlimprofconf_dic, full_oosprofconf_dic ).run())
	
if test_email_alarm:
	report = ['test']

if email:
	logging_helper.send_report(report)