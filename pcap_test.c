#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#define SIZE_ETHERNET 14
#define ETH_ADDR_LEN	6
#define MAX_LOOP 10

void pcap_view(unsigned char *, const struct pcap_pkthdr *, const unsigned char *);
struct eth_header {

	u_char eth_dhost[ETH_ADDR_LEN];
	u_char eth_shost[ETH_ADDR_LEN];
	u_short eth_type;
};
struct ip_header {

	u_char ip_verLength;
	u_char ip_serviceType;
	u_short ip_length;
	u_short ip_identification;
	u_short ip_fragment;

	u_char ip_ttl;
	u_char ip_pro;
	u_short ip_checksum;

	struct in_addr ip_src, ip_dst;

};
#define IP_HL(ip)	(((ip)->ip_verLength)&0x0f)
#define IP_V(ip)	(((ip)->ip_verLength) >> 4)
struct tcp_header {
	u_short tcp_srcPort;
	u_short tcp_dstPort;
	u_int tcp_seqNumber;
	u_int tcp_ackNumber;
	u_char tcp_Offx2;
	u_char tcp_Flags;
	u_short tcp_sizeWindow;
	u_short tcp_checksum;
	u_short tcp_urgentPointer;

};

static int frame_cnt = 1;
#define TH_OFF(tcp)  (((tcp)->tcp_Offx2 & 0xf0) >> 4)
#define  SWAP(s)   (((((s) & 0xff) << 8) | (((s) >> 8) & 0xff)))  

int main() {

	char errbuf[PCAP_ERRBUF_SIZE];
	char *dev;
	char *net;
	char *mask;
	int check;
	bpf_u_int32 netp; //ip
	bpf_u_int32 maskp; // subnet mask
	struct in_addr addr;

	pcap_t *packet;
	const u_char *pk;
	struct bpf_program fcode;

	dev = pcap_lookupdev(errbuf);
	check = pcap_lookupnet(dev, &netp, &maskp, errbuf);
	printf("* Device      : %s\n", dev);

	if (check == -1) {
		printf("%s\n", errbuf);
		return 0;
	}

	addr.s_addr = netp;
	net = inet_ntoa(addr);

	printf("* iNet        : %s\n", net);

	addr.s_addr = maskp;
	mask = inet_ntoa(addr);

	printf("* Subnet Mask : %s\n", mask);

	puts("=======================================================================");
	packet = pcap_open_live(dev, BUFSIZ, 0, -1, errbuf);
	printf("start capture the live packet......\n");
	if (packet == NULL) {
		printf("%s\n", errbuf);
		return 0;
	}

	check = pcap_compile(packet, &fcode, "port 80", 0, mask);
	printf("pcap file compiled......\n\n");
	if (check  < 0) {
		perror(pcap_geterr(packet));
		return 0;
	}

	check = pcap_setfilter(packet, &fcode);
	printf("pcap filter set completed......\n\n");
	if (check< 0) {
		perror(pcap_geterr(packet));
		return 0;
	}

	check = pcap_loop(packet, MAX_LOOP , pcap_view, 0);
	printf("packet capture loop finished......\n\n");
	if (check < 0) {
		perror(pcap_geterr(packet));
		return 0;
	}
	return 0;
}
void pcap_view(unsigned char *user, const struct pcap_pkthdr *h, const unsigned char *packet) {

	int i, len = h->len;

	const struct eth_header *eth;
	const struct ip_header *ip;
	const struct tcp_header *tcp;
	const char *data;

	u_int size_ip;
	u_int size_tcp;

	eth = (struct eth_header*)(packet);
	puts("=======================================================================");
	printf("[%d] Destination Mac Address-------: ", frame_cnt);
	for (i = 0; i<6; printf(":"),i++) {
		printf("%02x", eth->eth_dhost[i]);
		if(i>4) break;
	}
	printf("\n");

	printf("[%d] Source Mac Address------------: ", frame_cnt);
	for (i = 0; i<6; printf(":"),i++) {
		printf("%02x", eth->eth_shost[i]);
		if(i>4) break;
	}
	printf("\n");
	ip = (struct ip_header*)(packet + SIZE_ETHERNET);

	printf("[%d] Destination IP Address--------: %s\n", frame_cnt, inet_ntoa(ip->ip_dst));
	printf("[%d] Source IP Address-------------: %s\n", frame_cnt, inet_ntoa(ip->ip_src));
	printf("[%d] IP Protocol-------------------: %02x\n", frame_cnt, ip->ip_pro);

	size_ip = IP_HL(ip) * 4;

	tcp = (struct tcp_header*)(packet + SIZE_ETHERNET + size_ip);
	printf("[%d] Destination TCP Port----------: %d\n", frame_cnt, SWAP(tcp->tcp_dstPort));
	printf("[%d] Source TCP Port---------------: %d\n", frame_cnt, SWAP(tcp->tcp_srcPort));

	size_tcp = TH_OFF(tcp) * 4;

	data = (u_char*)(packet + SIZE_ETHERNET + size_ip + size_tcp);
	printf("[%d] Data--------------------------: %s\n", frame_cnt, data);
	puts("=======================================================================");
	printf("\n");
	
	frame_cnt++;
	return;

}
