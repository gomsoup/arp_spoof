import pcapy
from impacket.ImpactDecoder import *
from uuid import getnode as get_mac
import string
import threading
import sys

def recv_pkts(hdr, data):
    packet = EthDecoder().decode(data)
    print packet


def get_my_mac(interface):
   	#maybe later
   	return get_mac()


def main():
	if len(sys.argv) < 3:
		print "USAGE : python send_arp.py <interface> <sender_ip> <target_ip> ...."
		sys.exit(0);

	interface = sys.argv[1]

	pcapy.findalldevs()
	max_bytes = 2048
	non_promiscuous = True
	read_timeout = 100
	pc = pcapy.open_live(interface, max_bytes, non_promiscuous, read_timeout)
	pc.setfilter('tcp')

	my_mac = get_my_mac(interface)
	print "mac : " + hex(my_mac)

	packet_limit = -1 


if __name__=='__main__':
	main()
	sys.exit(0)