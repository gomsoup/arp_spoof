#include <iostream>
#include <string>
#include <unistd.h>
#include <cstdlib>
#include <cstring>

#include <arpa/inet.h>
#include <sys/ioctl.h>

#include <netinet/if_ether.h>

#include <net/ethernet.h>
#include <net/if_arp.h>
#include <net/if.h>
#include <cstdint>

#include <pcap.h>

#define ETHER_HEAD_LEN 14
#define ARP_LEN 28
#define IP_SIZE 4

using namespace std;




void get_my_mac(char *interface, u_int8_t *mac){

	/*  Get My MAC Address
		coded by https://stackoverflow.com/questions/1779715/how-to-get-mac-address-of-your-machine-using-a-c-program */

	struct bpf_program fp;
	struct ifreq ifr;
	u_int8_t target_mac[ETH_ALEN] = {0x00, }; // for inet_ntop
	u_int8_t broadcast[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

	memset(&ifr, 0, sizeof(ifr));
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, interface, sizeof(ifr.ifr_name));

	if ((ioctl(fd, SIOCGIFHWADDR, &ifr) == 0) && fd != -1){
		memcpy(mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
		printf("MAC Device : %s\n", interface);
		printf("Mac : %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n\n" , mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	}
	else{
		printf("Get MAC address failure\n");
		exit(1);
	}
}


class arp{
private:
	u_short hrd = htons(ARPHRD_ETHER);
	u_short pro = htons(ETH_P_IP);
	u_char hln = ETHER_ADDR_LEN;
	u_char pln = sizeof(in_addr_t);
	u_short op;
	u_char sha[6];
	u_long spa;
	u_char tha[6];
	u_long tpa;

public:
	arp(){

	}
	arp(u_short sop, u_char **ssha, in_addr sspa, u_char **stha, in_addr stpa){
		op = htons(sop); 

		memcpy(sha, *ssha, ETH_ALEN);
		memcpy(&spa, &sspa, IP_SIZE);
		memcpy(tha, *stha, ETH_ALEN);
		memcpy(&tpa, &stpa, IP_SIZE);
	}
};


class ether{
public:

//private:
	u_int8_t ether_dhost[ETH_ALEN];
	u_int8_t ether_shost[ETH_ALEN];
	u_int16_t ether_type;


//public:
	ether(){

	}
	ether(u_int8_t **dhost, u_int8_t **shost, u_int16_t type){
		memcpy(ether_dhost, *dhost, ETH_ALEN);
		memcpy(ether_shost, *shost, ETH_ALEN);
		ether_type = type;
	}

};

class pcap{
public:
	char *interface;
	u_int8_t mac[ETH_ALEN];

	pcap_t *p;
	char errbuf[PCAP_ERRBUF_SIZE] = { 0x00, };

	struct bpf_program fp;
	bpf_u_int32 net, mask;
	struct pcap_pkthdr *recv_header;
	u_int8_t *recv_packet;
	struct ether_header *recv_ether;
	struct ether_arp *recv_arp;

	pcap(){

	}
	pcap(char *interface){
		this->interface = interface;
		get_my_mac(interface, mac);
	}


	void pcap_arp_sniff_initialize(){
		p = pcap_open_live(interface, 94, 0, 100, errbuf);

		if(p == NULL){
			cout << "pcap_open_live failed" << endl;
			cout << "errbuf : " << errbuf << endl;
			exit(1);
		}
	}

	u_char *pcap_arp_sniff_initialize_sendpacket(u_char *packet, char *filter_type){
		if (pcap_sendpacket(p, packet, (ETHER_HEAD_LEN + ARP_LEN)) == -1){
			cout << "pcap_sendpacket failed" << endl;
			exit(1);
		} 

		if( pcap_lookupnet(interface, &net, &mask, errbuf) == -1){
			printf("pcap_lookupnet failed\n");
			printf("errvbuf : %s\n", errbuf);
		}

		// Configure filter to capture only ARP 
		if(pcap_compile(p, &fp, filter_type, 0, net) == -1){
			printf("pcap_compile failed\n");
			exit(1);
		}
		if(pcap_setfilter(p, &fp) == -1){
			printf("pcap_setfilter failed\n");
			exit(1);
		}

		// Recv reply data
		if(pcap_next_ex(p, &recv_header, (const u_char **)&recv_packet) != 1){
			printf("pcap_next_ex failed\n");	
			exit(1);
		}
		else
			printf("ARP reply data arrived\n");

		return recv_packet;

	}

	void pcap_arp_spoof_initialize(){

	}

};



class spoof{
	ether *eth = new ether;
	arp *arph = new arp;
	u_char *packet = new u_char[ETHER_HEAD_LEN + ARP_LEN];

};


class sniff{
	ether *eth;
	arp *arph;
	pcap *p;
	u_char arp_packet[ETHER_HEAD_LEN + ARP_LEN];
	u_char *recv_packet;
	u_short send_ip; u_char sender_mac[ETH_ALEN];
	u_short target_ip; u_char target_mac[ETH_ALEN];

public:
	void ethernet_data_intialize(u_int8_t *dhost, u_int8_t *shost, u_int16_t type){
		eth = new ether(&dhost, &shost, type);

		cout << "eth->dhost" << hex << eth->ether_dhost << endl;
		cout << "eth->shost" << hex << eth->ether_shost << endl;
		cout << "eth->ether_type" << hex << eth->ether_type << endl;

	}
	void arp_data_initialize(u_short sop, u_int8_t *ssha, in_addr sspa, u_int8_t *stha, in_addr stpa){
		arph = new arp(sop, &ssha, sspa, &stha, stpa);
	}

	void packet_send_for_initialize(char *interface){
		memcpy(arp_packet, eth, ETHER_HEAD_LEN);
		memcpy(arp_packet+ETHER_HEAD_LEN, arph, ARP_LEN);

		p = new pcap(interface);
		p->pcap_arp_sniff_initialize();
		recv_packet = p->pcap_arp_sniff_initialize_sendpacket(arp_packet, "arp");

	}
};




int main(int argc, char* argv[]){

	if(argc < 3 || (argc % 2) != 0){
		cout << "USAGE : ./arp_spoof <interface> <send_ip 0> <target_ip 0> ..." << endl;
		exit(0);
	} 

	char *interface = argv[1];
	u_int8_t mac[ETH_ALEN] = {0x00, }; 
	u_int8_t broadcast[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

	struct sockaddr_in sender_ip;
	struct sockaddr_in target_ip;

	inet_aton(argv[2], &sender_ip.sin_addr);
	inet_aton(argv[3], &target_ip.sin_addr);
	get_my_mac(interface, mac);

	sniff s;
	s.ethernet_data_intialize(mac, broadcast, htons(ETHERTYPE_ARP));
	s.arp_data_initialize(htons(ARPOP_REQUEST), mac, sender_ip.sin_addr, broadcast, target_ip.sin_addr);
	s.packet_send_for_initialize(interface);

	return 0;
}


