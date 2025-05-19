import config as cfg
import csv
import logging_helper
import time


reports_path = cfg.REPORTS_PATH

class DataMapper():
	def __init__(self, timenow,full_pol_dic, full_sig_dic, full_net_dic, full_bdosprofconf_dic, full_dnsprofconf_dic, full_synprofconf_dic, full_connlimprofconf_dic,full_oosprofconf_dic,full_tfprofconf_dic):
		self.full_pol_dic = full_pol_dic
		self.full_sig_dic = full_sig_dic
		self.full_net_dic = full_net_dic
		self.full_bdosprofconf_dic = full_bdosprofconf_dic
		self.full_dnsprofconf_dic = full_dnsprofconf_dic
		self.full_synprofconf_dic = full_synprofconf_dic
		self.full_connlimprofconf_dic = full_connlimprofconf_dic
		self.full_oosprofconf_dic = full_oosprofconf_dic
		self.full_tfprofconf_dic = full_tfprofconf_dic
		self.na_list = ['']
		self.timenow = timenow


		with open(reports_path + f'dpconfig_map_{self.timenow}.csv', mode='w', newline="") as dpconfigmap_report:
			dp_configmap_writer = csv.writer(dpconfigmap_report, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
			dp_configmap_writer.writerow(['DefensePro Name' , 'DefensePro IP' ,	'DefensePro Version' , 'Policy Name', 'Policy Priority' ,'Policy State','Policy Block/Report', 'Policy Packet Reporting',\
				 'SRC Network Profile Name','SRC Network Addresses','DST Network Profile Name','DST Network Addresses',\
				 'Signature Profile Name','Out of State Profile Name', 'Out of State Block/Report','Out of State Activation Threshold','Out of State Termination Threshold','Out of State Enable SYN-ACK','Anti-Scanning Profile Name', 'EAAF Profile Name',\
					'Geolocaation Profile','Connection Limit Profile Name','Connection Limit Profile Protections and settings','SYN Flood Protection Profile',\
						'SYN Flood Profile Action','SYN Flood Network Authentication Method','SYN Flood HTTP Authentication','SYN Flood Protection Settings',\
							'Traffic Filter Profile Name', 'Traffic Filter Block/Report','Traffic Filter Rules','BDOS Profile Name','BDOS Profile Block/Report','BDOS Profile Bandwidth','BDOS TCP Quota',\
							'BDOS UDP Quota','BDOS UDP-Frag Quota','BDOS ICMP Quota','BDOS Transparent Optimization','BDOS Packet Reporting','BDOS Learning Suppression',\
								'BDOS Footprint Strictness','BDOS UDP Packet Rate Detection Sensitivity','BDOS Burst-Attack Protection','DNS Profile Name',\
									'DNS Block/Report','DNS Expected QPS','DNS Max Allowed QPS','DNS A Status','DNS A Quota','DNS MX Status','DNS MX Quota','DNS PTR Status',\
									'DNS PTR Quota','DNS AAAA Status','DNS AAAA Quota','DNS Text Status','DNS Text Quota','DNS SOA Status','DNS SOA Quota','DNS Naptr Status',\
										'DNS Naptr Quota','DNS SRV Status','DNS SRV Quota','DNS Other Status','DNS Other Quota','DNS Packet Reporting',\
											'DNS Learning Suppression','DNS Footprint Strictness'])


	
	def isDPAvailable(self, dp_ip,dp_attr):
		# DP is considerd unavailable if DP is unreachable or no policy exists

		try:
			if not dp_attr['Policies']:
				print(f'{dp_ip} is unavailable')
				return False
		except:
			pass

		try:
			if dp_attr['Policies'] == None:
				print(f'{dp_ip} is unavailable')
				return False
		except:
			pass

		try:	
			if not dp_attr['Profiles']:
				print(f'{dp_ip} is unavailable')
				return False
		except:
			pass

		return True


	def map_synp_profile(self,dp_ip,pol_synp_prof_name):
		#This function maps the SYNP profiles to dpconfig_map.csv
		synp_settings = []
		synp_prot_values = ''

		if pol_synp_prof_name == "": # If SYNP profile is not configured, pad all SYNP fields with N/A values
			synp_settings.append('')
			synp_settings = synp_settings + self.na_list *4
			
		else:
			for synp_dp_ip, synp_dp_attr in self.full_synprofconf_dic.items():

				if synp_dp_attr['Profiles']:
					for synp_prof_key, syn_prof_val in synp_dp_attr['Profiles'].items():
						synp_prof_name = synp_prof_key

						if dp_ip == synp_dp_ip and pol_synp_prof_name.lower() == synp_prof_name.lower():

							synp_settings.append(synp_prof_name) # Append SYN Flood Protection Profile Name
							
							############# SYN Flood Protection Action Block/Report #############

							if 'rsIDSSynProfilesAction' in syn_prof_val['Parameters']:
								if syn_prof_val['Parameters']['rsIDSSynProfilesAction'] == '0':
										synp_settings.append('Report Only')
								elif syn_prof_val['Parameters']['rsIDSSynProfilesAction'] == '1':
									synp_settings.append('Block and Report')

							else:
								synp_settings.append('N/A in this version')



							############# SYN Flood Protection Authentication Method: #############

							if 'rsIDSSynProfilesParamsAuthType' in syn_prof_val['Parameters']:
								if syn_prof_val['Parameters']['rsIDSSynProfilesParamsAuthType'] == '1':
									if syn_prof_val['Parameters']['rsIDSSynProfileTCPResetStatus'] == '2':
										synp_settings.append('Safe Reset /Disabled "Use TCP Reset for Supported Protocols"')
									elif syn_prof_val['Parameters']['rsIDSSynProfileTCPResetStatus'] == '1':
										synp_settings.append('Safe Reset /Enabled "Use TCP Reset for Supported Protocols"')

								elif syn_prof_val['Parameters']['rsIDSSynProfilesParamsAuthType'] == '2':
									synp_settings.append('Transparent Proxy')

							else:
								synp_settings.append('N/A in this version')

							############# SYN Flood Protection Application Level Authentication #############

							if 'rsIDSSynProfilesParamsWebEnable' in syn_prof_val['Parameters']:
								if syn_prof_val['Parameters']['rsIDSSynProfilesParamsWebEnable'] == '1':
									if syn_prof_val['Parameters']['rsIDSSynProfilesParamsWebMethod'] == '1':
										synp_settings.append('Use HTTP Authentication with 302-Redirect')

									elif syn_prof_val['Parameters']['rsIDSSynProfilesParamsWebMethod'] == '2':
										synp_settings.append('Use HTTP Authentication with JavaScript')

									elif syn_prof_val['Parameters']['rsIDSSynProfilesParamsWebMethod'] == '3':
										synp_settings.append('Use HTTP Authentication with Advanced JavaScript')

								elif syn_prof_val['Parameters']['rsIDSSynProfilesParamsWebEnable'] == '2':
									synp_settings.append('Disabled')

							else:
								synp_settings.append('N/A in this version')
								

							############# SYN Flood Protection Settings #############
							
							for synp_prof_prot in syn_prof_val['Protections']:

								synp_prot_values = synp_prot_values + f'Protection Name: {synp_prof_prot["rsIDSSYNAttackName"]}\r\nProtection ID: {synp_prof_prot["rsIDSSYNAttackId"]}\r\nApplication Port Group: {synp_prof_prot["rsIDSSYNDestinationAppPortGroup"]}\r\nActivation Threshold: {synp_prof_prot["rsIDSSYNAttackActivationThreshold"]}\r\nTermination Threshold: {synp_prof_prot["rsIDSSYNAttackTerminationThreshold"]}\r\n------\r\n'

							synp_settings.append(synp_prot_values)

		return synp_settings


	def map_connlim_profile(self,dp_ip,pol_connlim_prof_name):
		#This function maps the Connection Limit profiles to dpconfig_map.csv
		connlim_settings = [] #this will go to csv report
		connlim_prot_values = ''

		if pol_connlim_prof_name == "": # If Connection Limit profile is not configured, pad all Connlim fields with N/A values
			connlim_settings.append('')
			connlim_settings = connlim_settings + self.na_list
			
		else:
			for connlim_dp_ip, connlim_dp_attr in self.full_connlimprofconf_dic.items():

				if connlim_dp_attr['Profiles']:
					for connlim_prof_key, connlim_prof_val in connlim_dp_attr['Profiles'].items():
						connlim_prof_name = connlim_prof_key

						if dp_ip == connlim_dp_ip and pol_connlim_prof_name == connlim_prof_name:

							connlim_settings.append(connlim_prof_name) # Append Connection limit Protection Profile Name
							

							############# Connection limit Protections Settings #############
							
							for connlim_prof_prot in connlim_prof_val['Protections']:
								
								if 'rsIDSConnectionLimitAttackType' in connlim_prof_prot:
									if connlim_prof_prot['rsIDSConnectionLimitAttackType'] == '1':
										connlim_type = 'Connections per Second'
									if connlim_prof_prot['rsIDSConnectionLimitAttackType'] == '2':
										connlim_type = 'Concurrent Connections'
								else:
									connlim_type = 'N/A in this version'

								if 'rsIDSConnectionLimitAttackPacketReport' in connlim_prof_prot:
									if connlim_prof_prot['rsIDSConnectionLimitAttackPacketReport'] == '1':
										connlim_reporting = 'Enabled'
									if connlim_prof_prot['rsIDSConnectionLimitAttackPacketReport'] == '2':
										connlim_reporting = 'Disabled'
								else:
									connlim_reporting = 'N/A in this version'

								if 'rsIDSConnectionLimitAttackProtocol' in connlim_prof_prot:
									if connlim_prof_prot['rsIDSConnectionLimitAttackProtocol'] == '2':
										connlim_protoctol = 'TCP'
									elif connlim_prof_prot['rsIDSConnectionLimitAttackProtocol'] == '3':
										connlim_protoctol = 'UDP'
								else:
									connlim_protoctol = 'N/A in this version'
									
								if 'rsIDSConnectionLimitAttackTrackingType' in connlim_prof_prot:

									if connlim_prof_prot['rsIDSConnectionLimitAttackTrackingType'] == '2':
										connlim_tracking_type = 'Source Count'
									elif connlim_prof_prot['rsIDSConnectionLimitAttackTrackingType'] == '3':
										connlim_tracking_type = 'Destination Count'
									elif connlim_prof_prot['rsIDSConnectionLimitAttackTrackingType'] == '4':
										connlim_tracking_type = 'Source and Destination Count'
									elif connlim_prof_prot['rsIDSConnectionLimitAttackTrackingType'] == '5':
										connlim_tracking_type = 'Count by Destination IP Address and Port'
								else:
									connlim_tracking_type = 'N/A in this version'


								if 'rsIDSConnectionLimitAttackReportMode' in connlim_prof_prot:
									if connlim_prof_prot["rsIDSConnectionLimitAttackReportMode"] == '0':
										connlim_action = 'Report Only'
									elif connlim_prof_prot["rsIDSConnectionLimitAttackReportMode"] == '10':
										connlim_action = 'Drop'
								else:
									connlim_action = 'N/A in this version'


								connlim_prot_values = connlim_prot_values + f'Protection Name: {connlim_prof_prot["rsIDSConnectionLimitAttackName"]}\r\nProtection ID: {connlim_prof_prot["rsIDSConnectionLimitAttackId"]}\r\nProtection Type: {connlim_type}\r\nProtocol: {connlim_protoctol}\r\nApplication Port: {connlim_prof_prot["rsIDSConnectionLimitAttackAppPort"]}\r\nThreshold: {connlim_prof_prot["rsIDSConnectionLimitAttackThreshold"]}\r\nTracking Type: {connlim_tracking_type}\r\nAction: {connlim_action}\r\nPacket Reporting: {connlim_reporting}\r\n------\r\n'

							connlim_settings.append(connlim_prot_values)
		return connlim_settings

	def map_oos_profile(self,dp_ip,pol_oos_prof_name):
		#This function maps the Out of State profiles to dpconfig_map.csv
		oos_settings = [] #this will go to csv report

		if pol_oos_prof_name == "": # If Out of State profile is not configured, pad all oos fields with N/A values
			oos_settings.append('')
			oos_settings = oos_settings + self.na_list*4
			
		else:
			for oos_dp_ip, oos_dp_attr in self.full_oosprofconf_dic.items():

				if oos_dp_attr['Profiles']:
					for oos_prof in oos_dp_attr['Profiles']:
						oos_prof_name = oos_prof['rsSTATFULProfileName']

						if dp_ip == oos_dp_ip and pol_oos_prof_name == oos_prof_name:

							############# Out of State Profile name #############

							oos_settings.append(oos_prof_name) # Append Out of State Protection Profile Name


							############# Out of State Block/Report #############
							
							if 'rsSTATFULProfileAction' in oos_prof:
								if oos_prof['rsSTATFULProfileAction'] == '1':
									oos_action = 'Block and Report'
								if oos_prof['rsSTATFULProfileAction'] == '0':
									oos_action = 'Report Only'
							else:
								oos_action = 'N/A in this version'	

							oos_settings.append(oos_action) # Append Out of State Protection Profile Name

							############# Out of State Activation Threshold #############

							if 'rsSTATFULProfileactThreshold' in oos_prof: # OOS Activation threshold
								oos_settings.append(oos_prof['rsSTATFULProfileactThreshold']) 
				
							else:
								oos_settings.append('N/A in this version')

							############# Out of State Termination Threshold #############


							if 'rsSTATFULProfiletermThreshold' in oos_prof: # OOS Termination threshold
								oos_settings.append(oos_prof['rsSTATFULProfiletermThreshold']) 
				
							else:
								oos_settings.append('N/A in this version')					

							############# Out of State Allow SYN-ACK #############
							
							if 'rsSTATFULProfilesynAckAllow' in oos_prof:
								if oos_prof['rsSTATFULProfilesynAckAllow'] == '1':
									oos_ack_allow = 'Enabled'
								if oos_prof['rsSTATFULProfilesynAckAllow'] == '2':
									oos_ack_allow = 'Disabled'
							else:
								oos_ack_allow = 'N/A in this version'
							
							oos_settings.append(oos_ack_allow) # Append Out of State Protection Profile Name
							
		return oos_settings


	def map_tf_profile(self,dp_ip,pol_tf_prof_name):
		#This function maps the Traffic Filter to dpconfig_map.csv
		tf_settings = [] #this will go to csv report
		tf_rules = ''

		if pol_tf_prof_name == "": # If TF profile is not configured, pad all TF fields with value defined in na_list variable
			tf_settings.append('')
			tf_settings = tf_settings + self.na_list * 2
			
		else:
			for tf_dp_ip, tf_dp_attr in self.full_tfprofconf_dic.items():

				if tf_dp_attr['Profiles']:
					for tf_prof_key, tf_prof_val in tf_dp_attr['Profiles'].items():
						tf_prof_name = tf_prof_key

						if dp_ip == tf_dp_ip and pol_tf_prof_name == tf_prof_name:

							tf_settings.append(tf_prof_name) # Append Traffic Filter Protection Profile Name

							############# Traffic Filter Protection Profile Action #############

							if 'Action' in tf_prof_val:
								if tf_prof_val['Action'] == '1':
									tf_action = 'Block and Report'
								if tf_prof_val['Action'] == '0':
									tf_action = 'Report Only'

							tf_settings.append(tf_action) # Append Traffic Filter Protection Profile Action

							############## Traffic Filters Settings #############
							if tf_prof_val['Rules']:
								for tf_prof_rule in tf_prof_val['Rules']:

									tf_rules += f'Rule Name: {tf_prof_rule["rsNewTrafficFilterName"]}'
									tf_rules += f'\r\nProtection ID: {tf_prof_rule["rsNewTrafficFilterID"]}'

									# Rule Enabled/Disabled
									if 'rsNewTrafficFilterState' in tf_prof_rule: # Show rule enabled or disabled:
										if tf_prof_rule['rsNewTrafficFilterState'] == '1':
											tf_enabled = 'Enabled'
										else:
											tf_enabled = 'Disabled'
										tf_rules += f'\r\nRule State: {tf_enabled}'			

									# Rule Priority
									if 'rsNewTrafficFilterPriority' in tf_prof_rule: # Show rule priority:
										tf_priority = tf_prof_rule['rsNewTrafficFilterPriority']
										tf_rules += f'\r\nRule Priority: {tf_priority}'									

									# FILTER MODE
									if 'rsNewTrafficFilterMatchCriteria' in tf_prof_rule: # Apply Traffic Filter To:
										if tf_prof_rule['rsNewTrafficFilterMatchCriteria'] == '1':
											tf_match = 'Matching Traffic'							
										if tf_prof_rule['rsNewTrafficFilterMatchCriteria'] == '2':
											tf_match = 'Non-Matching Traffic'
											tf_rules += f'\r\nApply Traffic Filter To: {tf_match}'	

									# BASIC FILTER CRITERIA

									if 'rsNewTrafficFilterSrcNetwork' in tf_prof_rule: # Source Network:
										if tf_prof_rule['rsNewTrafficFilterSrcNetwork'] != 'As in Policy':
											tf_src_net = tf_prof_rule['rsNewTrafficFilterSrcNetwork']						
											tf_rules += f'\r\nSource Network: {tf_src_net}'

									if 'rsNewTrafficFilterDstNetwork' in tf_prof_rule: # Destination Network:
										if tf_prof_rule['rsNewTrafficFilterDstNetwork'] != 'As in Policy':
											tf_dst_net = tf_prof_rule['rsNewTrafficFilterDstNetwork']						
											tf_rules += f'\r\nDestination Network: {tf_dst_net}'


									if 'rsNewTrafficFilterProtocol' in tf_prof_rule: #Protocol:
										if tf_prof_rule['rsNewTrafficFilterProtocol'] == '0':
											tf_protocol = 'Any Supported Protocol'
										if tf_prof_rule['rsNewTrafficFilterProtocol'] == '1':
											tf_protocol = 'TCP'

										if tf_prof_rule['rsNewTrafficFilterProtocol'] == '2':
											tf_protocol = 'UDP'
										if tf_prof_rule['rsNewTrafficFilterProtocol'] == '3':
											tf_protocol = 'ICMP'
										if tf_prof_rule['rsNewTrafficFilterProtocol'] == '4':
											tf_protocol = 'IGMP'
										if tf_prof_rule['rsNewTrafficFilterProtocol'] == '6':
											tf_protocol = 'ICMPv6'
										if tf_prof_rule['rsNewTrafficFilterProtocol'] == '7':
											tf_protocol = 'GRE'
										if tf_prof_rule['rsNewTrafficFilterProtocol'] == '8':
											tf_protocol = 'IP-in-IP'
										if tf_prof_rule['rsNewTrafficFilterProtocol'] == '9':
											tf_protocol = f'Other Protocol(s) (Protocol Number: {tf_prof_rule["rsNewTrafficFilterProtocol"]})'

										tf_rules += f'\r\nProtocol: {tf_protocol}'


									if 'rsNewTrafficFilterSrcPort' in tf_prof_rule: # Source Port:
										if tf_prof_rule['rsNewTrafficFilterSrcPort'] != 'Any':
											tf_src_port = tf_prof_rule['rsNewTrafficFilterSrcPort']						
											tf_rules += f'\r\nSource Port: {tf_src_port}'

									if 'rsNewTrafficFilterDstPort' in tf_prof_rule: # Destination Port:
										if tf_prof_rule['rsNewTrafficFilterDstPort'] != 'Any':
											tf_dst_port = tf_prof_rule['rsNewTrafficFilterDstPort']						
											tf_rules += f'\r\nDestination Port: {tf_dst_port}'

									if 'rsNewTrafficFilterPacketSize' in tf_prof_rule: # Packet size:
										if tf_prof_rule['rsNewTrafficFilterPacketSize'] != '':
											tf_packet_size = tf_prof_rule['rsNewTrafficFilterPacketSize']						
											tf_rules += f'\r\nPacket Size: {tf_packet_size}'

									# ADVANCED FILTER CRITERIA

										###################### TCP Flags #################################

									tf_tcp_flags = []


									if 'rsNewTrafficFilterTCPFlagsSyn' in tf_prof_rule: # SYN Enabled:
										if tf_prof_rule['rsNewTrafficFilterTCPFlagsSyn'] == '1':
											tf_tcp_flags.append('SYN')
									if 'rsNewTrafficFilterTCPFlagsAck' in tf_prof_rule: # ACK Enabled:
										if tf_prof_rule['rsNewTrafficFilterTCPFlagsAck'] == '1':
											tf_tcp_flags.append('ACK')
									if 'rsNewTrafficFilterTCPFlagsRst' in tf_prof_rule: # RST Enabled:
										if tf_prof_rule['rsNewTrafficFilterTCPFlagsRst'] == '1':
											tf_tcp_flags.append('RST')		
									if 'rsNewTrafficFilterTCPFlagsSynAck' in tf_prof_rule: # SYN+ACK Enabled:
										if tf_prof_rule['rsNewTrafficFilterTCPFlagsSynAck'] == '1':
											tf_tcp_flags.append('SYN+ACK')		
									if 'rsNewTrafficFilterTCPFlagsFinAck' in tf_prof_rule: # FIN+ACK Enabled:
										if tf_prof_rule['rsNewTrafficFilterTCPFlagsFinAck'] == '1':
											tf_tcp_flags.append('FIN+ACK')		
									if 'rsNewTrafficFilterTCPFlagsPshAck' in tf_prof_rule: # PSH+ACK Enabled:
										if tf_prof_rule['rsNewTrafficFilterTCPFlagsPshAck'] == '1':
											tf_tcp_flags.append('PSH+ACK')	

									if tf_tcp_flags:

										tf_rules += f'\r\nTCP Flags: {(", ".join(map(str, tf_tcp_flags)))}'


									if 'rsNewTrafficFilterTTL' in tf_prof_rule: # Context Tag:
										if tf_prof_rule['rsNewTrafficFilterTTL'] != '':
											tf_ttl = tf_prof_rule['rsNewTrafficFilterTTL']						
											tf_rules += f'\r\nTime to Live (TTL): {tf_ttl}'

									if 'rsNewTrafficFilterVLAN' in tf_prof_rule: # Context Tag:
										if tf_prof_rule['rsNewTrafficFilterVLAN'] != 'Any':
											tf_context_tag = tf_prof_rule['rsNewTrafficFilterVLAN']						
											tf_rules += f'\r\nContext Tag: {tf_context_tag}'


									if 'rsNewTrafficFilterFragOffset' in tf_prof_rule: # Fragment Offset:
										if tf_prof_rule['rsNewTrafficFilterFragOffset'] != '':
											tf_frag_offset = tf_prof_rule['rsNewTrafficFilterFragOffset']						
											tf_rules += f'\r\nFragment Offset: {tf_frag_offset}'

									if 'rsNewTrafficFilterSequenceNum' in tf_prof_rule: # TCP Sequence Number:
										if tf_prof_rule['rsNewTrafficFilterSequenceNum'] != '':
											tf_seq_num = tf_prof_rule['rsNewTrafficFilterSequenceNum']						
											tf_rules += f'\r\nTCP Sequence Number: {tf_seq_num}'

									if 'rsNewTrafficFilterTOS' in tf_prof_rule: # Type of Service (ToS) / DSCP:
										if tf_prof_rule['rsNewTrafficFilterTOS'] != '':
											tf_tos = tf_prof_rule['rsNewTrafficFilterTOS']						
											tf_rules += f'\r\nType of Service (ToS) / DSCP: {tf_tos}'

									if 'rsNewTrafficFilterFragId' in tf_prof_rule: # Fragment ID:
										if tf_prof_rule['rsNewTrafficFilterFragId'] != '':
											tf_frag_id = tf_prof_rule['rsNewTrafficFilterFragId']						
											tf_rules += f'\r\nFragment ID: {tf_frag_id}'

									if 'rsNewTrafficFilterRegex' in tf_prof_rule: # Regular Expression:
										if tf_prof_rule['rsNewTrafficFilterRegex'] != '':
											tf_reg_exp = tf_prof_rule['rsNewTrafficFilterRegex']						
											tf_rules += f'\r\nRegular Expression: {tf_reg_exp}'



									# FILTER THRESHOLD


									if 'rsNewTrafficFilterThresholdUsed' in tf_prof_rule: # Threshold
										if tf_prof_rule['rsNewTrafficFilterThresholdUsed'] == '2':
											tf_threshold_used = 'PPS'
											tf_threshold = tf_prof_rule['rsNewTrafficFilterThresholdPPS']
										if tf_prof_rule['rsNewTrafficFilterThresholdUsed'] == '1':
											tf_threshold_used = 'Kbps'
											tf_threshold = tf_prof_rule['rsNewTrafficFilterThresholdBPS']
										tf_rules += f'\r\nThrehold({tf_threshold_used}): {tf_threshold}'


									if 'rsNewTrafficFilterAttackTrackingType' in tf_prof_rule: # Tracking Mode

										if tf_prof_rule['rsNewTrafficFilterAttackTrackingType'] == '0':
											tf_tracking_mode = 'All'
										if tf_prof_rule['rsNewTrafficFilterAttackTrackingType'] == '2':
											tf_tracking_mode = 'Per Source'										
										if tf_prof_rule['rsNewTrafficFilterAttackTrackingType'] == '3':
											tf_tracking_mode = 'Per Destination'
										if tf_prof_rule['rsNewTrafficFilterAttackTrackingType'] == '4':
											tf_tracking_mode = 'Per Source and Destination Pair'
										if tf_prof_rule['rsNewTrafficFilterAttackTrackingType'] == '5':
											tf_tracking_mode = 'Track Returning Traffic from Destination and Suspend Corresponding Sources'

										tf_rules = tf_rules + f'\r\nTracking Mode: {tf_tracking_mode}'


									# Source Prefix Length

									if 'rsNewTrafficFilterSrcSubPrefixIPv4' in tf_prof_rule: # Source Prefix Length IPv4:
										if tf_prof_rule['rsNewTrafficFilterSrcSubPrefixIPv4'] != '32':
											tf_src_prefix = tf_prof_rule['rsNewTrafficFilterSrcSubPrefixIPv4']						
											tf_rules += f'\r\nSource Prefix Length IPv4: {tf_src_prefix}'

									if 'rsNewTrafficFilterSrcSubPrefixIPv6' in tf_prof_rule: # Source Prefix Length IPv6:
										if tf_prof_rule['rsNewTrafficFilterSrcSubPrefixIPv6'] != '128':
											tf_src_prefix_ipv6 = tf_prof_rule['rsNewTrafficFilterSrcSubPrefixIPv6']						
											tf_rules += f'\r\nSource Prefix Length IPv6: {tf_src_prefix_ipv6}'


									if 'rsNewTrafficFilterDstSubPrefixIPv4' in tf_prof_rule: # Destination Prefix Length IPv4:
										if tf_prof_rule['rsNewTrafficFilterDstSubPrefixIPv4'] != '32':
											tf_dst_prefix = tf_prof_rule['rsNewTrafficFilterDstSubPrefixIPv4']						
											tf_rules += f'\r\nDestination Prefix Length IPv4: {tf_dst_prefix}'

									if 'rsNewTrafficFilterDstSubPrefixIPv6' in tf_prof_rule: # Destination Prefix Length IPv6:
										if tf_prof_rule['rsNewTrafficFilterDstSubPrefixIPv6'] != '128':
											tf_dst_prefix_ipv6 = tf_prof_rule['rsNewTrafficFilterDstSubPrefixIPv6']						
											tf_rules += f'\r\nDestination Prefix Length IPv6: {tf_dst_prefix_ipv6}'

									# REPORTING SETTINGS

									if 'rsNewTrafficFilterPacketReport' in tf_prof_rule: #Packet Reporting
										if tf_prof_rule['rsNewTrafficFilterPacketReport'] == '1':
											tf_packet_reporting = 'Enabled'
										if tf_prof_rule['rsNewTrafficFilterPacketReport'] == '2':
											tf_packet_reporting = 'Disabled'

										tf_rules += f'\r\nPacket Reporting: {tf_packet_reporting}'

									tf_rules += '\r\n------\r\n'



							tf_settings.append(tf_rules)

		return tf_settings

	def map_src_net_classes(self,dp_ip,pol_src_net_name):
		#This function maps the Source networks to dpconfig_map.csv
		src_net_classes_settings = [] #this will go to csv report
		src_net_classes_list = ''

		for netclass_dp_ip, net_class_dp_attr in self.full_net_dic.items():
				
				for net_class_block in net_class_dp_attr['rsBWMNetworkTable']:
					net_class_name = net_class_block['rsBWMNetworkName']
					if dp_ip == netclass_dp_ip and net_class_name == pol_src_net_name:
						src_net_classes_list = src_net_classes_list + f"{net_class_block['rsBWMNetworkAddress']}/{net_class_block['rsBWMNetworkMask']}\r\n"

		src_net_classes_settings.append(pol_src_net_name)
		src_net_classes_settings.append(src_net_classes_list)

		return src_net_classes_settings

	def map_dst_net_classes(self,dp_ip,pol_dst_net_name):
		#This function maps the Destination networks to dpconfig_map.csv
		dst_net_classes_settings = [] #this will go to csv report
		dst_net_classes_list = ''

		for netclass_dp_ip, net_class_dp_attr in self.full_net_dic.items():
				
				for net_class_block in net_class_dp_attr['rsBWMNetworkTable']:
					net_class_name = net_class_block['rsBWMNetworkName']
					if dp_ip == netclass_dp_ip and net_class_name == pol_dst_net_name:
						dst_net_classes_list = dst_net_classes_list + f"{net_class_block['rsBWMNetworkAddress']}/{net_class_block['rsBWMNetworkMask']}\r\n"

		dst_net_classes_settings.append(pol_dst_net_name)
		dst_net_classes_settings.append(dst_net_classes_list)

		return dst_net_classes_settings

	def map_bdos_profile(self,dp_ip,pol_bdos_prof_name):
		#This function maps the bdos profiles to dpconfig_map.csv
		bdos_settings = []

		if pol_bdos_prof_name == "": # If BDOS profile is not configured, pad all bdos fields with N/A values
			bdos_settings.append('')
			bdos_settings = bdos_settings + self.na_list *12
			

		for bdos_dp_ip, bdos_dp_attr in self.full_bdosprofconf_dic.items():

			if bdos_dp_attr['Policies']:
				for bdos_prof in bdos_dp_attr['Policies']['rsNetFloodProfileTable']:
					bdos_prof_name = bdos_prof['rsNetFloodProfileName']
					
					if dp_ip == bdos_dp_ip and pol_bdos_prof_name == bdos_prof_name:
						bdos_settings.append(bdos_prof_name)
						
						########## Block/Report check#########
						if 'rsNetFloodProfileAction' in bdos_prof:
							if bdos_prof['rsNetFloodProfileAction'] == '0':
								bdos_settings.append('Report')
							elif bdos_prof['rsNetFloodProfileAction'] == '1':
								bdos_settings.append('Block and Report')
							
						else:
							bdos_settings.append('N/A in this version')
						########## Map BDOS Bandwidth and Quota #########
						bdos_settings.append(bdos_prof['rsNetFloodProfileBandwidthIn']) # Bandwidth
						bdos_settings.append(bdos_prof['rsNetFloodProfileTcpInQuota'])
						bdos_settings.append(bdos_prof['rsNetFloodProfileUdpInQuota'])
						bdos_settings.append(bdos_prof['rsNetFloodProfileUdpFragInQuota'])
						bdos_settings.append(bdos_prof['rsNetFloodProfileIcmpInQuota'])
						

						########## BDOS Transparent optimization check#########
						if 'rsNetFloodProfileTransparentOptimization' in bdos_prof:
							if bdos_prof['rsNetFloodProfileTransparentOptimization'] == '1':
								bdos_settings.append('Enabled')
							if bdos_prof['rsNetFloodProfileTransparentOptimization'] == '2':
								bdos_settings.append('Disabled')
						else:
							bdos_settings.append('N/A in this version')
						#####################################


						########## BDOS Packet reporting check#########
						if 'rsNetFloodProfilePacketReportStatus' in bdos_prof:
							if bdos_prof['rsNetFloodProfilePacketReportStatus'] == '1':
								bdos_settings.append('Enabled')
							if bdos_prof['rsNetFloodProfilePacketReportStatus'] == '2':
								bdos_settings.append('Disabled')
						else:
							bdos_settings.append('N/A in this version')
						#####################################

						########## BDOS Learning Suppression mapping #########
						if 'rsNetFloodProfileLearningSuppressionThreshold' in bdos_prof:
							bdos_settings.append(bdos_prof['rsNetFloodProfileLearningSuppressionThreshold'])
						else:
							bdos_settings.append('N/A in this version')

						########## BDOS Footprint Strictness #########
						if 'rsNetFloodProfileFootprintStrictness' in bdos_prof:
							if bdos_prof['rsNetFloodProfileFootprintStrictness'] == '0':
								bdos_settings.append('Low')
							if bdos_prof['rsNetFloodProfileFootprintStrictness'] == '1':
								bdos_settings.append('Medium')
							if bdos_prof['rsNetFloodProfileFootprintStrictness'] == '2':
								bdos_settings.append('High')
						else:
							bdos_settings.append('N/A in this version')
						#####################################

						########## BDOS UDP Packet Rate Detection Sensitivity #########
						if 'rsNetFloodProfileLevelOfReuglarzation' in bdos_prof:
							if bdos_prof['rsNetFloodProfileLevelOfReuglarzation'] == '1':
								bdos_settings.append('Ignore or Disable')
							if bdos_prof['rsNetFloodProfileLevelOfReuglarzation'] == '2':
								bdos_settings.append('Low')
							if bdos_prof['rsNetFloodProfileLevelOfReuglarzation'] == '3':
								bdos_settings.append('Medium')
							if bdos_prof['rsNetFloodProfileLevelOfReuglarzation'] == '4':
								bdos_settings.append('High')
						else:
							bdos_settings.append('N/A in this version')
						#####################################

						########## BDOS Burst-Attack Protection #########
						if 'rsNetFloodProfileBurstEnabled' in bdos_prof:
							if bdos_prof['rsNetFloodProfileBurstEnabled'] == '1':
								bdos_settings.append('Enabled')
							if bdos_prof['rsNetFloodProfileBurstEnabled'] == '2':
								bdos_settings.append('Disabled')
						else:
							bdos_settings.append('N/A in this version')

		return bdos_settings


	def map_dns_profile(self,dp_ip,pol_dns_prof_name):
		#This function maps the bdos profiles to dpconfig_map.csv
		dns_settings = []
		

		if pol_dns_prof_name == "" or pol_dns_prof_name == "null":
			dns_settings.append('')
			
			dns_settings = dns_settings + self.na_list *24



		for dns_dp_ip, dns_dp_attr in self.full_dnsprofconf_dic.items():

			if dns_dp_attr['Policies']:
				for dns_prof in dns_dp_attr['Policies']['rsDnsProtProfileTable']:
					dns_prof_name = dns_prof['rsDnsProtProfileName']
					
					if dp_ip == dns_dp_ip and pol_dns_prof_name == dns_prof_name:
						dns_settings.append(dns_prof_name)
						
						########## DNS Block/Report check#########
						if 'rsDnsProtProfileAction' in dns_prof:
							if dns_prof['rsDnsProtProfileAction'] == '0':
								dns_settings.append('Report')
							elif dns_prof['rsDnsProtProfileAction'] == '1':
								dns_settings.append('Block and Report')
							
						else:
							dns_settings.append('N/A in this version')


						########## Map DNS QPS and Quota #########
						dns_settings.append(dns_prof['rsDnsProtProfileExpectedQps']) # Bandwidth
						dns_settings.append(dns_prof['rsDnsProtProfileMaxAllowQps'])

						if dns_prof['rsDnsProtProfileDnsAStatus'] == '1':
							dns_settings.append('Enabled')
						elif dns_prof['rsDnsProtProfileDnsAStatus'] == '2':
							dns_settings.append('Disabled')

						dns_settings.append(dns_prof['rsDnsProtProfileDnsAQuota'])


						if dns_prof['rsDnsProtProfileDnsMxStatus'] == '1':
							dns_settings.append('Enabled')
						elif dns_prof['rsDnsProtProfileDnsMxStatus'] == '2':
							dns_settings.append('Disabled')

						dns_settings.append(dns_prof['rsDnsProtProfileDnsMxQuota'])


						if dns_prof['rsDnsProtProfileDnsPtrStatus'] == '1':
							dns_settings.append('Enabled')
						elif dns_prof['rsDnsProtProfileDnsPtrStatus'] == '2':
							dns_settings.append('Disabled')
						dns_settings.append(dns_prof['rsDnsProtProfileDnsPtrQuota'])

						if dns_prof['rsDnsProtProfileDnsAaaaStatus'] == '1':
							dns_settings.append('Enabled')
						elif dns_prof['rsDnsProtProfileDnsAaaaStatus'] == '2':
							dns_settings.append('Disabled')
						dns_settings.append(dns_prof['rsDnsProtProfileDnsAaaaQuota'])

						if dns_prof['rsDnsProtProfileDnsTextStatus'] == '1':
							dns_settings.append('Enabled')
						elif dns_prof['rsDnsProtProfileDnsTextStatus'] == '2':
							dns_settings.append('Disabled')
						dns_settings.append(dns_prof['rsDnsProtProfileDnsTextQuota'])

						if dns_prof['rsDnsProtProfileDnsSoaStatus'] == '1':
							dns_settings.append('Enabled')
						elif dns_prof['rsDnsProtProfileDnsSoaStatus'] == '2':
							dns_settings.append('Disabled')
						dns_settings.append(dns_prof['rsDnsProtProfileDnsSoaQuota'])

						if dns_prof['rsDnsProtProfileDnsNaptrStatus'] == '1':
							dns_settings.append('Enabled')
						elif dns_prof['rsDnsProtProfileDnsNaptrStatus'] == '2':
							dns_settings.append('Disabled')
						dns_settings.append(dns_prof['rsDnsProtProfileDnsNaptrQuota'])

						if dns_prof['rsDnsProtProfileDnsSrvStatus'] == '1':
							dns_settings.append('Enabled')
						elif dns_prof['rsDnsProtProfileDnsSrvStatus'] == '2':
							dns_settings.append('Disabled')
						dns_settings.append(dns_prof['rsDnsProtProfileDnsSrvQuota'])

						if dns_prof['rsDnsProtProfileDnsOtherStatus'] == '1':
							dns_settings.append('Enabled')
						elif dns_prof['rsDnsProtProfileDnsOtherStatus'] == '2':
							dns_settings.append('Disabled')
						dns_settings.append(dns_prof['rsDnsProtProfileDnsOtherQuota'])


						########## DNS Packet reporting check#########
						if 'rsDnsProtProfilePacketReportStatus' in dns_prof:
							if dns_prof['rsDnsProtProfilePacketReportStatus'] == '1':
								dns_settings.append('Enabled')
							if dns_prof['rsDnsProtProfilePacketReportStatus'] == '2':
								dns_settings.append('Disabled')
						else:
							dns_settings.append('N/A')
						#####################################

						########## DNS Learning Suppression mapping #########
						if 'rsDnsProtProfileLearningSuppressionThreshold' in dns_prof:
							dns_settings.append(dns_prof['rsDnsProtProfileLearningSuppressionThreshold'])
						else:
							dns_settings.append('N/A in this version')

						########## DNS Footprint Strictness #########
						if 'rsDnsProtProfileFootprintStrictness' in dns_prof:
							if dns_prof['rsDnsProtProfileFootprintStrictness'] == '0':
								dns_settings.append('Low')
							if dns_prof['rsDnsProtProfileFootprintStrictness'] == '1':
								dns_settings.append('Medium')
							if dns_prof['rsDnsProtProfileFootprintStrictness'] == '2':
								dns_settings.append('High')
						else:
							dns_settings.append('N/A in this version')
						#####################################

		return dns_settings	


			


	def map_policy(self,dp_name,dp_ver,dp_ip,pol_name,pol_priority,policy):
		policy_settings = [] # this list will go to the csv file
		policy_settings.append(dp_name)
		policy_settings.append(dp_ip)
		policy_settings.append(dp_ver)
		policy_settings.append(pol_name)
		policy_settings.append(pol_priority)

		if 'rsIDSNewRulesState' in policy: # Check if policy Enabled/Disabled
			if policy['rsIDSNewRulesState'] == '2':
				policy_settings.append('Disabled')
			elif policy['rsIDSNewRulesState'] == '1':
				policy_settings.append('Enabled')

		else:
			policy_settings.append('N/A in this version')

		if 'rsIDSNewRulesAction' in policy: # Check policy block/report action
			if policy['rsIDSNewRulesAction'] == '0':
				policy_settings.append('Report')
			elif policy['rsIDSNewRulesAction'] == '1':
				policy_settings.append('Block and Report')

		else:
			policy_settings.append('N/A')

		if 'rsIDSNewRulesPacketReportingStatus'	in policy: # Check packet reporting enabled/Disabled
			if policy['rsIDSNewRulesPacketReportingStatus'] == '1':
				policy_settings.append('Enabled')
			elif policy['rsIDSNewRulesPacketReportingStatus'] == '2':
				policy_settings.append('Disabled')
		else:
			policy_settings.append('N/A in this version')


		############Mapping Source Networks##########

		

		pol_src_net_name = policy['rsIDSNewRulesSource'] # Get source network profile name

		if pol_src_net_name != "any" and pol_src_net_name != "any_ipv4" and pol_src_net_name != "any_ipv6":
			net_classes_src_map= self.map_src_net_classes(dp_ip,pol_src_net_name)
			policy_settings = policy_settings + net_classes_src_map # Map source networks

		else:

			if pol_src_net_name == "any":
				policy_settings.append('any')
				policy_settings.append('any IPv4/IPv6')
			
			elif pol_src_net_name == "any_ipv4":
				policy_settings.append('any_ipv4')
				policy_settings.append('any IPv4')

			elif pol_src_net_name == "any_ipv6":
				policy_settings.append('any_ipv6')
				policy_settings.append('any IPv6')

		############Mapping Destination Networks##########

		
		pol_dst_net_name = policy['rsIDSNewRulesDestination'] # Get destination network profile name

		if pol_dst_net_name != "any" and pol_dst_net_name != "any_ipv4" and pol_dst_net_name != "any_ipv6":
			net_classes_dst_map= self.map_dst_net_classes(dp_ip,pol_dst_net_name)
			policy_settings = policy_settings + net_classes_dst_map # Map destination networks

		else:

			if pol_dst_net_name == "any":
				policy_settings.append('any')
				policy_settings.append('any IPv4/IPv6')
			
			elif pol_dst_net_name == "any_ipv4":
				policy_settings.append('any_ipv4')
				policy_settings.append('any IPv4')

			elif pol_dst_net_name == "any_ipv6":
				policy_settings.append('any_ipv6')
				policy_settings.append('any IPv6')


		############Mapping Signature Profile##########
		if 'rsIDSNewRulesProfileAppsec' in policy: # Check if BDOS profile is configured
			pol_sig_prof_name = policy['rsIDSNewRulesProfileAppsec']

			if pol_sig_prof_name == "":
				policy_settings.append('')
			else:
				policy_settings.append(pol_sig_prof_name)

		else:
			policy_settings.append('N/A in this version')
		###############################################

		############Mapping Out of State Profile##########
		if 'rsIDSNewRulesProfileStateful' in policy: # Check if OOS profile is configured
			pol_oos_prof_name = policy['rsIDSNewRulesProfileStateful']
			policy_settings = policy_settings + self.map_oos_profile(dp_ip,pol_oos_prof_name)


		else:
			policy_settings.append('N/A in this version')
		##################################################

		############Mapping Anti-Scanning Profile##########
		if 'rsIDSNewRulesProfileScanning' in policy: # Check if AS profile is configured
			pol_as_prof_name = policy['rsIDSNewRulesProfileScanning']

			if pol_as_prof_name == "":
				policy_settings.append('')
			else:
				policy_settings.append(pol_as_prof_name)

		else:
			policy_settings.append('N/A in this version')
		###############################################

		############Mapping ERT Active Attackers Feed Profile##########
		if 'rsIDSNewRulesProfileErtAttackersFeed' in policy: # Check if ERT Active Attackers Feed profile is configured
			pol_eaaf_prof_name = policy['rsIDSNewRulesProfileErtAttackersFeed']

			if pol_eaaf_prof_name == "":
				policy_settings.append('')
			else:
				policy_settings.append(pol_eaaf_prof_name)

		else:
			policy_settings.append('N/A in this version')
		###############################################

		############Mapping Geolocation  Feed Profile##########
		if 'rsIDSNewRulesProfileGeoFeed' in policy: # Check if Geolocation  profile is configured
			pol_geo_prof_name = policy['rsIDSNewRulesProfileGeoFeed']

			if pol_geo_prof_name == "":
				policy_settings.append('')
			else:
				policy_settings.append(pol_geo_prof_name)

		else:
			policy_settings.append('N/A in this version')
		######################################################


		############Mapping Connection Limit Protection Profile##########
		if 'rsIDSNewRulesProfileConlmt' in policy: # Check if Connection Limit  profile is configured
			pol_connlim_prof_name = policy['rsIDSNewRulesProfileConlmt']
			policy_settings = policy_settings + self.map_connlim_profile(dp_ip,pol_connlim_prof_name)

		else:
			policy_settings.append('N/A in this version')
		###############################################

		############Mapping SYN Flood Protection Profile##########
		if 'rsIDSNewRulesProfileSynprotection' in policy: # Check if SYN Flood Protection profile is configured
			pol_synp_prof_name = policy['rsIDSNewRulesProfileSynprotection']
			policy_settings = policy_settings + self.map_synp_profile(dp_ip,pol_synp_prof_name)

		else:
			policy_settings.append('N/A in this version')
		###############################################


		############Mapping Traffic Filter Profile##########
		if 'rsIDSNewRulesProfileTrafficFilters' in policy: # Check if Tfaffic Filter profile is configured
			pol_tf_prof_name = policy['rsIDSNewRulesProfileTrafficFilters']
			policy_settings = policy_settings + self.map_tf_profile(dp_ip,pol_tf_prof_name)

		else:
			policy_settings.append('N/A in this version')			
		###################################################


		############Mapping BDOS Profile################
		if 'rsIDSNewRulesProfileNetflood' in policy: # Check if BDOS profile is configured
			pol_bdos_prof_name = policy['rsIDSNewRulesProfileNetflood']
			policy_settings = policy_settings + self.map_bdos_profile(dp_ip,pol_bdos_prof_name)
				
		else:
			policy_settings.append('N/A')
		###############################################



		############Mapping DNS Profile################
		if 'rsIDSNewRulesProfileDNS' in policy: # Check if BDOS profile is configured
			pol_dns_prof_name = policy['rsIDSNewRulesProfileDNS']
			policy_settings = policy_settings + self.map_dns_profile(dp_ip,pol_dns_prof_name)

		else:
			policy_settings.append('N/A')
		###############################################





		with open(reports_path + f'dpconfig_map_{self.timenow}.csv', mode='a', newline="") as dpconfigmap_report:
			dp_configmap_writer = csv.writer(dpconfigmap_report, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
			dp_configmap_writer.writerow(policy_settings)

		policy_settings.clear()





	def run(self):
		for dp_ip,dp_attr in self.full_pol_dic.items():
			dp_name = dp_attr['Name']
			dp_ver = dp_attr['Version']


			if self.isDPAvailable(dp_ip,dp_attr):

				for policy in dp_attr['Policies']['rsIDSNewRulesTable']: #key is rsIDSNewRulesTable, value is list of dictionary objects (each object is a dictionary which contains policy name and its attributes )
					pol_name = policy['rsIDSNewRulesName']
					pol_priority = policy['rsIDSNewRulesPriority']
					# pol_bdos_prof_name = policy['rsIDSNewRulesProfileNetflood']
					if pol_name != 'null':
						self.map_policy(dp_name,dp_ver,dp_ip,pol_name,pol_priority,policy)

	


		report = reports_path + f'dpconfig_map_{self.timenow}.csv'
		logging_helper.logging.info('Config mapping is complete')
		print('Config mapping is complete')

		return report

