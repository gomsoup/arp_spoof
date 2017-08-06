all: arp_spoof

arp_spoof: arp_spoof.cpp
	g++ -o arp_spoof arp_spoof.cpp -lpcap -std=c++11 -g -fpermissive -Wwrite-strings

clean:
	rm -rf *.o arp_spoof
