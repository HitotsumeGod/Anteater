#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "anteater.h"

int ipv4 = 0;
int ipv6 = 0;
int sonos = 0;
int tcp = 0;
int udp = 0;
int icmp = 0;

bool print_minimal(char *buf) {

	struct ethhdr *ethh;
	union network_hdr *nhdr;
	struct sockaddr_in src, dest;
	socklen_t addrsiz;
	size_t iphdrlen;

	addrsiz = sizeof(struct sockaddr_in);
	if ((nhdr = malloc(sizeof(union network_hdr))) == NULL) {
		errno = MALLOC_ERR;
		return false;
	}
	ethh = (struct ethhdr *) buf;
	switch (ntohs(ethh -> h_proto)) {
	case ETH_P_IP:
		ipv4++;
		nhdr -> iph = (struct iphdr *) (buf + sizeof(struct ethhdr));
		switch (nhdr -> iph -> protocol) {
		case IPPROTO_TCP:
			tcp++;
			break;
		case IPPROTO_UDP:
			udp++;
			break;
		}
		break;
	case ETH_P_IPV6:
		ipv6++;
		nhdr -> ip6h = (struct ip6_hdr *) (buf + sizeof(struct ethhdr));
		switch (nhdr -> ip6h ->ip6_nxt) {
		case IPPROTO_TCP:
			tcp++;
			break;
		case IPPROTO_UDP:
			udp++;
			break;
		}
		break;
	case ETH_P_SONOS:
		sonos++;
		break;
	}
	printf("IPV4: %d IPV6: %d SONOS: %d   |   ICMP: %d TCP: %d UDP: %d\r", ipv4, ipv6, sonos, icmp, tcp, udp);
	free(nhdr);
	free(buf);
	return true;

}

bool print_frame(char *frame, size_t fullsiz) {

	struct ethhdr *ethh;
	struct sockaddr_in src, dest;
	union network_hdr *nhdr;
	union transport_hdr *thdr;
	uint32_t flow;
	uint16_t nto;
	size_t iphdrlen, tcphdrlen, psiz;
	char *payload, addrstorage[INET_ADDRSTRLEN], addr6storage[INET6_ADDRSTRLEN];

	if ((nhdr = malloc(sizeof(union network_hdr))) == NULL || (thdr = malloc(sizeof(union transport_hdr))) == NULL) {
		errno = MALLOC_ERR;
		return false;
	}
	ethh = (struct ethhdr *) frame;
	nto = ntohs(ethh -> h_proto);
	printf("     ##########BEGIN PACKET ##########\n\n");
	printf("     - - - - - Start of Ethernet Header - - - - -\n");
	printf("     |Ethernet Source Address is %02X-%02X-%02X-%02X-%02X-%02X\n", ethh -> h_source[0], ethh -> h_source[1], ethh -> h_source[2], ethh -> h_source[3], ethh -> h_source[4], ethh -> h_source[5]);
	printf("     |Ethernet Destination Address is %02X-%02X-%02X-%02X-%02X-%02X\n", ethh -> h_dest[0], ethh -> h_dest[1], ethh -> h_dest[2], ethh -> h_dest[3], ethh -> h_dest[4], ethh -> h_dest[5]);
	printf("     |Ethernet Protocol is 0x%04X\n\n", nto);
	switch (nto) {
	case ETH_P_IP:
		nhdr -> iph = (struct iphdr *) (frame + sizeof(struct ethhdr));
		src.sin_addr.s_addr = nhdr -> iph -> saddr;
		dest.sin_addr.s_addr = nhdr -> iph -> daddr;
		if (inet_ntop(AF_INET, &(src.sin_addr), addrstorage, sizeof(addrstorage)) == NULL) {
			perror("inet_ntop err");
			return EXIT_FAILURE;
		}
		iphdrlen = nhdr -> iph -> ihl * 4;
		printf("     - - - - - Start of IP Header - - - - -\n");
		printf("     |IP Version is %u\n", nhdr -> iph -> version);
		printf("     |IP Header Length is %u\n", nhdr -> iph -> ihl);
		printf("     |IP Type of Service is %u\n", nhdr -> iph -> tos);
		printf("     |IP Total Length is %u\n", ntohs(nhdr -> iph -> tot_len));
		printf("     |IP ID is %u\n", ntohs(nhdr -> iph -> id));
		printf("     |IP Fragment Offset is %u\n", ntohs(nhdr -> iph -> frag_off));
		printf("     |IP Time to Live is %u\n", nhdr -> iph -> ttl);
		printf("     |IP Protocol is %u\n", nhdr -> iph -> protocol);
		printf("     |IP Checksum is %u\n", ntohs(nhdr -> iph -> check));
		printf("     |IP Source Address is %s\n", addrstorage);
		if (inet_ntop(AF_INET, &(dest.sin_addr), addrstorage, sizeof(addrstorage)) == NULL) {
			perror("inet_ntop err");
			return EXIT_FAILURE;
		}
		printf("     |IP Destination Address is %s\n\n", addrstorage);
		switch (nhdr -> iph -> protocol) {
		case IPPROTO_TCP:
			thdr -> tcph = (struct tcphdr *) (frame + sizeof(struct ethhdr) + iphdrlen);
			tcphdrlen = thdr -> tcph -> doff * 4;
			payload = frame + sizeof(struct ethhdr) + iphdrlen + tcphdrlen;
			psiz = fullsiz - sizeof(struct ethhdr) - iphdrlen - tcphdrlen;
			printf("     - - - - - Start of TCP Header - - - - -\n");
			printf("     |TCP Source Port is %u\n", ntohs(thdr -> tcph -> th_sport));
			printf("     |TCP Destination Port is %u\n", ntohs(thdr -> tcph -> th_dport));
			printf("     |TCP Sequence # is %u\n", ntohl(thdr -> tcph -> th_seq));
			printf("     |TCP Ack # is %u\n", ntohl(thdr -> tcph -> th_ack));
			printf("     |TCP Data Offset is %u\n", thdr -> tcph -> th_off);
			printf("     |TCP Reserved is %u\n", thdr -> tcph -> res1);
			printf("     |TCP Control Bits are as follows: URG: %u ACK: %u PSH: %u RST: %u SYN: %u FIN: %u\n", thdr -> tcph -> urg, thdr -> tcph -> ack, thdr -> tcph -> psh, thdr -> tcph -> rst, thdr -> tcph -> syn, thdr -> tcph -> fin);
			printf("     |TCP Window is %u\n", ntohs(thdr -> tcph -> window));
			printf("     |TCP Checksum is %u\n", ntohs(thdr -> tcph -> check));
			printf("     |TCP Urgent Pointer is %u\n\n", ntohs(thdr -> tcph -> urg_ptr));
			break;
		case IPPROTO_UDP:
			thdr -> udph = (struct udphdr *) (frame + sizeof(struct ethhdr) + iphdrlen);
			payload = frame + sizeof(struct ethhdr) + iphdrlen + sizeof(struct udphdr);
			psiz = fullsiz - sizeof(struct ethhdr) - iphdrlen - sizeof(struct udphdr);
			printf("     - - - - - Start of UDP Header - - - - -\n");
			printf("     |UDP Source Port is %u\n", ntohs(thdr -> udph -> uh_sport));
			printf("     |UDP Destination Port is %u\n", ntohs(thdr -> udph -> uh_dport));
			printf("     |UDP Segment Length is %u\n", ntohs(thdr -> udph -> uh_ulen));
			printf("     |UDP Checksum is %u\n\n", ntohs(thdr -> udph -> uh_sum));
			break;
		default:
			psiz = 0;
		}
		break;
	case ETH_P_IPV6:
		nhdr -> ip6h = (struct ip6_hdr *) (frame + sizeof(struct ethhdr));
		flow = ntohl(nhdr -> ip6h -> ip6_flow);
		if (inet_ntop(AF_INET6, &(nhdr -> ip6h -> ip6_src), addr6storage, sizeof(addr6storage)) == NULL) {
			perror("inet_ntop err at src");
			return EXIT_FAILURE;
		}
		printf("     - - - - - Start of IP Header - - - - -\n");
		printf("     |IP Version is %u\n", (flow & 0xF0000000) >> 28);
		printf("     |IP Traffic Class is %u\n", (flow & 0x0FF00000 << 1) >> 24);
		printf("     |IP Flow Label is %u\n", flow & 0x000FFFFF);
		printf("     |IP Payload Length is %u\n", ntohs(nhdr -> ip6h -> ip6_plen));
		printf("     |IP Next Header is %u\n", nhdr -> ip6h -> ip6_nxt);
		printf("     |IP Hop Limit is %u\n", nhdr -> ip6h -> ip6_hlim);
		printf("     |IP Source Address is %s\n", addr6storage);
		if (inet_ntop(AF_INET6, &(nhdr -> ip6h -> ip6_dst), addr6storage, sizeof(addr6storage)) == NULL) {
			perror("inet_ntop err");
			return EXIT_FAILURE;
		}
		printf("     |IP Destination Address is %s\n\n", addr6storage);
		switch (nhdr -> ip6h -> ip6_nxt) {
		case IPPROTO_TCP:
			thdr -> tcph = (struct tcphdr *) (frame + sizeof(struct ethhdr) + sizeof(struct ip6_hdr));
			tcphdrlen = thdr -> tcph -> doff * 4;
			payload = frame + sizeof(struct ethhdr) + sizeof(struct ip6_hdr) + tcphdrlen;
			psiz = fullsiz - sizeof(struct ethhdr) - sizeof(struct ip6_hdr) - tcphdrlen;
			printf("     - - - - - Start of TCP Header - - - - -\n");
			printf("     |TCP Source Port is %u\n", ntohs(thdr -> tcph -> th_sport));
			printf("     |TCP Destination Port is %u\n", ntohs(thdr -> tcph -> th_dport));
			printf("     |TCP Sequence # is %u\n", ntohl(thdr -> tcph -> th_seq));
			printf("     |TCP Ack # is %u\n", ntohl(thdr -> tcph -> th_ack));
			printf("     |TCP Data Offset is %u\n", thdr -> tcph -> th_off);
			printf("     |TCP Reserved is %u\n", thdr -> tcph -> res1);
			printf("     |TCP Control Bits are as follows: URG: %u ACK: %u PSH: %u RST: %u SYN: %u FIN: %u\n", thdr -> tcph -> urg, thdr -> tcph -> ack, thdr -> tcph -> psh, thdr -> tcph -> rst, thdr -> tcph -> syn, thdr -> tcph -> fin);
			printf("     |TCP Window is %u\n", ntohs(thdr -> tcph -> window));
			printf("     |TCP Checksum is %u\n", ntohs(thdr -> tcph -> check));
			printf("     |TCP Urgent Pointer is %u\n\n", ntohs(thdr -> tcph -> urg_ptr));
			break;
		case IPPROTO_UDP:
			thdr -> udph = (struct udphdr *) (frame + sizeof(struct ethhdr) + sizeof(struct ip6_hdr));
			payload = frame + sizeof(struct ethhdr) + sizeof(struct ip6_hdr) + sizeof(struct udphdr);
			psiz = fullsiz - sizeof(struct ethhdr) - sizeof(struct ip6_hdr) - sizeof(struct udphdr);
			printf("     - - - - - Start of UDP Header - - - - -\n");
			printf("     |UDP Source Port is %u\n", ntohs(thdr -> udph -> uh_sport));
			printf("     |UDP Destination Port is %u\n", ntohs(thdr -> udph -> uh_dport));
			printf("     |UDP Segment Length is %u\n", ntohs(thdr -> udph -> uh_ulen));
			printf("     |UDP Checksum is %u\n\n", ntohs(thdr -> udph -> uh_sum));
			break;
		}
		break;
	}
	free(nhdr);
	free(thdr);
	free(frame);
	return true;

}
