import config as cfg
import json
from vision import Vision
import traffic_stats_parser
from dpconfig_parser import DataParser
from dpconfig_mapper import DataMapper
import urllib3
import logging_helper
import sys
import os
import time
import glob
import bdos_parser

start_time = time.time()
timenow = time.strftime('%Y%m%d-%H%M')



urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


#Arguments variables

getdatafromvision = True
email = False
test_email_alarm = False

report = []

if test_email_alarm:
	report = ['test']


raw_data_path = cfg.RAW_DATA_PATH
config_path = cfg.CONFIG_PATH
reports_path = cfg.REPORTS_PATH

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


def get_data_from_vision(dev_list_dp_ip,dev_list_dp_ip_attr,cust_id= 'None'):

	global full_sig_db_dic
	global full_pol_dic
	global full_net_dic
	global full_sig_dic
	global full_bdosprofconf_dic
	global full_dnsprofconf_dic
	global full_synprofconf_dic
	global full_connlimprofconf_dic
	global full_oosprofconf_dic
	global bdos_stats_dict
	global bdos_stats_dict_pps
	global dns_stats_dict
	global traffic_stats_dict_bps
	global traffic_stats_dict_pps
	global traffic_stats_dict_cps
	global traffic_stats_dict_cec
	global full_tfprofconf_dic

	print(f'-' * 50)

	print(f'Collecting policies data from Defensepro {dev_list_dp_ip}')
	logging_helper.logging.info(f'Collecting policies data from Defensepro {dev_list_dp_ip}')
	full_pol_dic = v.getFullPolicyDictionary(dev_list_dp_ip,dev_list_dp_ip_attr,full_pol_dic)

	print(f'Collecting network classes data from Defensepro {dev_list_dp_ip}')
	logging_helper.logging.info(f'Collecting network classes data from Defensepro {dev_list_dp_ip}')
	full_net_dic = v.getFullNetClassDictionary(dev_list_dp_ip,dev_list_dp_ip_attr,full_net_dic)

	print(f'Collecting signature profiles data from Defensepro {dev_list_dp_ip}')
	logging_helper.logging.info(f'Collecting signature profiles data from Defensepro {dev_list_dp_ip}')
	full_sig_dic = v.getFullSignatureProfileDictionary(dev_list_dp_ip,dev_list_dp_ip_attr,full_sig_dic)

	print(f'Collecting BDOS configuration data from Defensepro {dev_list_dp_ip}')
	logging_helper.logging.info(f'Collecting BDOS configuration data from Defensepro {dev_list_dp_ip}')
	full_bdosprofconf_dic = v.getFullBDOSProfConfigDictionary(dev_list_dp_ip,dev_list_dp_ip_attr,full_bdosprofconf_dic)

	print(f'Collecting DNS configuration data from Defensepro {dev_list_dp_ip}')
	logging_helper.logging.info(f'Collecting DNS configuration data from Defensepro {dev_list_dp_ip}')
	full_dnsprofconf_dic = v.getFullDNSProfConfigDictionary(dev_list_dp_ip,dev_list_dp_ip_attr,full_dnsprofconf_dic)

	print(f'Collecting SynFlood configuration data from Defensepro {dev_list_dp_ip}')
	logging_helper.logging.info(f'Collecting SynFlood configuration data from Defensepro {dev_list_dp_ip}')
	full_synprofconf_dic = v.getFullSYNPConfigDictionary(dev_list_dp_ip,dev_list_dp_ip_attr,full_synprofconf_dic)

	print(f'Collecting Connection Limit configuration data from Defensepro {dev_list_dp_ip}')
	logging_helper.logging.info(f'Collecting Connection Limit configuration data from Defensepro {dev_list_dp_ip}')
	full_connlimprofconf_dic = v.getFullConnlimConfigDictionary(dev_list_dp_ip,dev_list_dp_ip_attr,full_connlimprofconf_dic)

	print(f'Collecting Out of State configuration data from Defensepro {dev_list_dp_ip}')
	logging_helper.logging.info(f'Collecting Out of State configuration data from Defensepro {dev_list_dp_ip}')
	full_oosprofconf_dic = v.getFullOOSConfigDictionary(dev_list_dp_ip,dev_list_dp_ip_attr,full_oosprofconf_dic)

	print(f'Collecting Signature DB from the Defensepro {dev_list_dp_ip}')
	logging_helper.logging.info(f'Collecting Signature DB from the Defensepro {dev_list_dp_ip}')
	full_sig_db_dic = v.getFullSigDB(dev_list_dp_ip,dev_list_dp_ip_attr,full_sig_db_dic)

	print(f'Collecting Traffic Filter configuration data from the Defensepro {dev_list_dp_ip}')
	logging_helper.logging.info(f'Collecting Traffic Filter configuration data from the Defensepro {dev_list_dp_ip}')
	full_tfprofconf_dic = v.getFullTFConfigDictionary(dev_list_dp_ip,dev_list_dp_ip_attr,full_tfprofconf_dic)


	if cfg.TRAFFIC_STATS:
		print(f'Collecting BDOS stats data from Defensepro {dev_list_dp_ip}')
		logging_helper.logging.info('Collecting BDOS stats data')
		bdos_stats_dict = v.getBDOSReportFromVision(dev_list_dp_ip,dev_list_dp_ip_attr,full_pol_dic,full_net_dic,bdos_stats_dict,cust_id)

		print(f'Collecting BDOS PPS stats data from Defensepro {dev_list_dp_ip}')
		logging_helper.logging.info('Collecting BDOS PPS stats data')
		bdos_stats_dict_pps = v.getBDOSReportFromVision_PPS(dev_list_dp_ip,dev_list_dp_ip_attr,full_pol_dic,full_net_dic,bdos_stats_dict_pps,cust_id)
	
		print(f'Collecting DNS stats data from Defensepro {dev_list_dp_ip}')
		logging_helper.logging.info('Collecting DNS stats data')
		dns_stats_dict = v.getDNSReportFromVision(dev_list_dp_ip,dev_list_dp_ip_attr,full_pol_dic,full_net_dic,dns_stats_dict,cust_id)

		print(f'Collecting Traffic Utilization data (BPS) from Defensepro {dev_list_dp_ip}')
		logging_helper.logging.info(f'Collecting Traffic Utilization data (BPS) from Defensepro {dev_list_dp_ip}')
		traffic_stats_dict_bps = v.getTrafficUtilizationBPS(dev_list_dp_ip,dev_list_dp_ip_attr,full_pol_dic,traffic_stats_dict_bps)

		print(f'Collecting Traffic Utilization data (PPS) from Defensepro {dev_list_dp_ip}')
		logging_helper.logging.info(f'Collecting Traffic Utilization data (PPS) from Defensepro {dev_list_dp_ip}')
		traffic_stats_dict_pps = v.getTrafficUtilizationPPS(dev_list_dp_ip,dev_list_dp_ip_attr,full_pol_dic,traffic_stats_dict_pps)

		print(f'Collecting Traffic Utilization data (CPS) from Defensepro {dev_list_dp_ip}')
		logging_helper.logging.info(f'Collecting Traffic Utilization data (CPS) from Defensepro {dev_list_dp_ip}')
		traffic_stats_dict_cps = v.getTrafficUtilizationCPS(dev_list_dp_ip,dev_list_dp_ip_attr,full_pol_dic,traffic_stats_dict_cps)

		print(f'Collecting Traffic Utilization data (CEC) from Defensepro {dev_list_dp_ip}')
		logging_helper.logging.info(f'Collecting Traffic Utilization data (CEC) from Defensepro {dev_list_dp_ip}')
		traffic_stats_dict_cec = v.getCEC(dev_list_dp_ip,dev_list_dp_ip_attr,full_pol_dic,traffic_stats_dict_cec)


	print(f'Downloading configuration file from Defensepro {dev_list_dp_ip}')
	logging_helper.logging.info(f'Downloading configuration file from Defensepro {dev_list_dp_ip}')
	v.getDPConfigByDevice(dev_list_dp_ip)




def cleanup_old_report_files(reports_path):
	# This function will delete all report files except the last X files (X = cfg.REPORTS_TO_KEEP defined in config.py)

	reports_to_keep = cfg.REPORTS_TO_KEEP
	prefix_list = ['dpconfig_report_','dpconfig_map_','traffic_stats_']

	for prefix in prefix_list:
		files = glob.glob(reports_path + prefix + '*.csv')
		files.sort(key=os.path.getmtime)

		for file in files[:-reports_to_keep]:
			os.remove(file)



def dpconfig_cleanup():

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

	with open(raw_data_path + 'full_sig_db_dic.json') as full_sig_db_dic_file:
		full_sig_db_dic = json.load(full_sig_db_dic_file)

	with open(raw_data_path + 'full_tfprofconf_dic.json') as full_tfprofconf_dic_file:
		full_tfprofconf_dic = json.load(full_tfprofconf_dic_file)

	if cfg.TRAFFIC_STATS:

		with open(raw_data_path + 'BDOS_traffic_report.json') as full_bdos_stats_file:
			bdos_stats_dict = json.load(full_bdos_stats_file)

		with open(raw_data_path + 'BDOS_traffic_report_PPS.json') as full_bdos_stats_pps_file:
			bdos_stats_dict_pps = json.load(full_bdos_stats_pps_file)

		with open(raw_data_path + 'DNS_traffic_report.json') as full_dns_stats_file:
			dns_stats_dict = json.load(full_dns_stats_file)

		with open(raw_data_path + 'Traffic_report_BPS.json') as traffic_stats_dict_bps_file:
			traffic_stats_dict_bps = json.load(traffic_stats_dict_bps_file)

		with open(raw_data_path + 'Traffic_report_PPS.json') as traffic_stats_dict_pps_file:
			traffic_stats_dict_pps = json.load(traffic_stats_dict_pps_file)

		with open(raw_data_path + 'Traffic_report_CPS.json') as traffic_stats_dict_cps_file:
			traffic_stats_dict_cps = json.load(traffic_stats_dict_cps_file)

		with open(raw_data_path + 'Traffic_report_CEC.json') as traffic_stats_dict_cec_file:
			traffic_stats_dict_cec = json.load(traffic_stats_dict_cec_file)

	
else: #getdatafromvision = True - collect data from vision

	full_pol_dic = {}
	full_sig_dic = {}
	full_net_dic = {}
	full_bdosprofconf_dic = {}
	full_dnsprofconf_dic = {}
	full_synprofconf_dic = {}
	full_connlimprofconf_dic = {}
	full_oosprofconf_dic = {}
	full_sig_db_dic = {}
	full_tfprofconf_dic = {}
	if cfg.TRAFFIC_STATS:
		bdos_stats_dict = {}
		dns_stats_dict = {}
		bdos_stats_dict_pps = {}
		traffic_stats_dict_bps = {}
		traffic_stats_dict_pps = {}
		traffic_stats_dict_cps = {}
		traffic_stats_dict_cec = {}


	print('Cleaning up previous DP config files')
	logging_helper.logging.info('Cleaning up previous DP config files')
	dpconfig_cleanup()

	print('Starting data collection from DefensePro')
	print('-' * 50)


	if cfg.CUSTOMERS_JSON: #If customers.json is set to true, use this file to define the scope for the data collection
		print('CUSTOMERS_JSON is set to True - collecting data using the scope from customers.json file')

		if not cfg.CUSTOMERS_JSON_CUST_ID_LIST:	# if CUSTOMERS_JSON_CUST_ID_LIST is empty, collect all customers
			print('CUSTOMERS_JSON_CUST_ID_LIST is not defined - collecting data for all customers from customers.json file')
			print('-' * 50)
		else:
			print(f'CUSTOMERS_JSON_CUST_ID_LIST is defined - collecting data for customers {cfg.CUSTOMERS_JSON_CUST_ID_LIST}')
			print('-' * 50)

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

						for dev_list_dp_ip, dev_list_dp_ip_attr in v.device_list.items(): #key - DP IP, val - DP Attributes - Type, Name, Version, OrmId
							if dev_list_dp_ip in dp_list:
								
								get_data_from_vision(dev_list_dp_ip,dev_list_dp_ip_attr,cust_id)


				else: #If CUSTOMERS_JSON_CUST_ID_LIST is not empty, collect only the customers defined in the list	
					if cust_id in cfg.CUSTOMERS_JSON_CUST_ID_LIST:
						vision_user = customer['user']
						vision_pass = customer['pass']

						for vision_params in customer['visions']:

							vision_ip = vision_params['ip']
							dp_list = vision_params['dps'].split(',')

							v = Vision(vision_ip, vision_user, vision_pass)

							for dev_list_dp_ip, dev_list_dp_ip_attr in v.device_list.items(): #key - DP IP, val - DP Attributes - Type, Name, Version, OrmId
								if dev_list_dp_ip in dp_list:

									get_data_from_vision(dev_list_dp_ip,dev_list_dp_ip_attr,cust_id)

	else: #If customers.json is set to false, use the scope defined in config.py variable "DP_IP_SCOPE_LIST"
		print('CUSTOMERS_JSON is set to False - collecting data using the scope from DP_IP_SCOPE_LIST')

		v = Vision(cfg.VISION_IP, cfg.VISION_USER, cfg.VISION_PASS)

		if not cfg.DP_IP_SCOPE_LIST: #If DP_IP_SCOPE_LIST is empty, collect all policies for all DefensePro
			print('DP_IP_SCOPE_LIST is not defined - collecting data from all DefensePro in Vision')
			print('-' * 50)

			for dev_list_dp_ip, dev_list_dp_ip_attr in v.device_list.items(): #key - DP IP, val - DP Attributes - Type, Name, Version, OrmId

				get_data_from_vision(dev_list_dp_ip,dev_list_dp_ip_attr,cust_id= 'None')
			

		else: #If DP_IP_SCOPE_LIST is defined (not empty), collect all policies for the DefensePro in the list
			print(f'DP_IP_SCOPE_LIST is defined - collecting data from specific DefensePro from the list {cfg.DP_IP_SCOPE_LIST}')
			print('-' * 50)

			for dev_list_dp_ip, dev_list_dp_ip_attr in v.device_list.items(): #key - DP IP, val - DP Attributes - Type, Name, Version, OrmId

				if dev_list_dp_ip in cfg.DP_IP_SCOPE_LIST:	

					get_data_from_vision(dev_list_dp_ip,dev_list_dp_ip_attr,cust_id= 'None')

				else:
					print(f'Skipping data collection for Defensepro {dev_list_dp_ip} - {dev_list_dp_ip_attr["Name"]}. Not in DP_IP_SCOPE_LIST')
					print('-' * 50)


	with open(raw_data_path + 'full_pol_dic.json', 'w') as full_pol_dic_file:
		json.dump(full_pol_dic,full_pol_dic_file)

	with open(raw_data_path + 'full_net_dic.json', 'w') as full_net_dic_file:
		json.dump(full_net_dic,full_net_dic_file)

	with open(raw_data_path + 'full_sig_dic.json', 'w') as full_sig_dic_file:
		json.dump(full_sig_dic,full_sig_dic_file)

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

	with open(raw_data_path + 'full_sig_db_dic.json', 'w') as full_sigdb_file:
		json.dump(full_sig_db_dic,full_sigdb_file)

	with open(raw_data_path + 'full_tfprofconf_dic.json', 'w') as full_tfprofconf_dic_file:
		json.dump(full_tfprofconf_dic,full_tfprofconf_dic_file)

	if cfg.TRAFFIC_STATS:

		with open(raw_data_path + 'BDOS_traffic_report.json', 'w') as outfile:
			json.dump(bdos_stats_dict,outfile)

		with open(raw_data_path + 'BDOS_traffic_report_PPS.json', 'w') as bdos_pps_file:
			json.dump(bdos_stats_dict_pps,bdos_pps_file)

		with open(raw_data_path + 'DNS_traffic_report.json', 'w') as outfile:
			json.dump(dns_stats_dict,outfile)

		with open(raw_data_path + 'Traffic_report_BPS.json', 'w') as outfile:
			json.dump(traffic_stats_dict_bps,outfile)

		with open(raw_data_path + 'Traffic_report_PPS.json', 'w') as outfile:
			json.dump(traffic_stats_dict_pps,outfile)

		with open(raw_data_path + 'Traffic_report_CPS.json', 'w') as outfile:
			json.dump(traffic_stats_dict_cps,outfile)

		with open(raw_data_path + 'Traffic_report_CEC.json', 'w') as outfile:
			json.dump(traffic_stats_dict_cec,outfile)


	print('Data collection is complete')
	print('-' * 50)
	logging_helper.logging.info('Data collection is complete')


data_collection_time = time.time() - start_time


print('Starting data parsing')
logging_helper.logging.info('Starting data parsing')



if cfg.ANALYZE_CONFIG and not test_email_alarm:
	logging_helper.logging.info('Starting config analysis')
	print('Starting config analysis')
	report.append(DataParser(timenow,full_pol_dic,full_sig_dic,full_net_dic,full_bdosprofconf_dic,full_synprofconf_dic,full_connlimprofconf_dic, full_oosprofconf_dic, full_sig_db_dic).run())
	print('DP config analysis is complete')
	logging_helper.logging.info('DP config analysis is complete')
	
if cfg.MAP_CONFIG and not test_email_alarm:
	print('Starting config mapping')
	report.append(DataMapper(timenow,full_pol_dic,full_sig_dic,full_net_dic,full_bdosprofconf_dic,full_dnsprofconf_dic,full_synprofconf_dic,full_connlimprofconf_dic, full_oosprofconf_dic,full_tfprofconf_dic ).run())

if cfg.TRAFFIC_STATS:
	
	logging_helper.logging.info('Parsing traffic/BDOS/DNS data')
	print ('Start parsing traffic/BDOS/DNS data')
	report.append(traffic_stats_parser.parse(timenow))
	print ('Parsing traffic/BDOS/DNS data is complete')

if cfg.ANALYZE_BDOS_BASELINES:
	print('Starting BDOS baselines analysis')
	logging_helper.logging.info('Starting BDOS baselines analysis')
	report.extend(bdos_parser.parse())

	print('BDOS baselines analysis is complete')
	logging_helper.logging.info('BDOS baselines analysis is complete')

if email:
	logging_helper.send_report(report)


cleanup_old_report_files(reports_path)


full_cycle_time = time.time() - start_time
delta_time = full_cycle_time - data_collection_time

print(f"--- Data collection {data_collection_time} seconds ---")

print(f"--- Data parsing only {delta_time} seconds ---")

print(f"--- Full cycle {full_cycle_time} seconds. ---")