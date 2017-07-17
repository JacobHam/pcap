all : pcap_test.o pcap_test

pcap_test.o : pcap_test.c
	gcc -c pcap_test.c

pcap_test : pcap_test.o
	gcc -o pcap_test pcap_test.o -lpcap

clean:
	rm -rf pcap_test
