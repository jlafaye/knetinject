default: pcap_inject mclient mserver

pcap_inject: pcap_inject.o
	$(CC) -lpcap pcap_inject.o -o pcap_inject

mclient: mclient.o

mserver: mserver.o

clean:
	rm -f mclient
	rm -f mserver
	rm -f *.o
