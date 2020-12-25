#!/usr/bin/env python3
import scapy.all as scapy
import optparse
#Made by Somil Tyagi aka Wh1teR0se, Website:somil.xyz
def scan(ip):
	arp_request = scapy.ARP(pdst = ip)
	broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
	arp_request_broadcast = broadcast/arp_request
	#arp_request_broadcast.show()
	answered_list = scapy.srp(arp_request_broadcast,timeout=1,verbose=False)[0]
	
	client_list = []
	
	for item in answered_list:
		client_dict = {'ip':item[1].psrc,'mac':item[1].hwsrc}
		client_list.append(client_dict)
	return client_list

def print_table(result_list):
	design = '-'*50
	print(f'IP-ADDRESS \t\t\t MAC-ADDRESS\n{design}')
	for client in result_list:
		print(f'{client["ip"]}\t\t\t {client["mac"]}')
		 
		 
def get_arguments():
	parser = optparse.OptionParser()
	parser.add_option('-t','--target',dest = 'target', help = "Target IP/ Target IP Range")
	(options,arguments) = parser.parse_args()
	return options



value = get_arguments()
scan_result = scan(value.target)
print_table(scan_result)
