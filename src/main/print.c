#include <stdlib.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "anteater.h"

#define PAYLOAD_SPACING 18

int ipv4 = 0;
int ipv6 = 0;
int sonos = 0;
int tcp = 0;
int udp = 0;
int icmp = 0;
int icmpv6 = 0;

bool print_minimal(char *buf, FILE *stream) {

	struct ethhdr *ethh;
	union network_hdr *nhdr;
	struct sockaddr_in src, dest;
	socklen_t addrsiz;
	size_t iphdrlen;

	if (!stream)
		stream = stdout;
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
		case IPPROTO_ICMP:
			icmp++;
			break;
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
		case IPPROTO_ICMPV6:
			icmpv6++;
			break;
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
	fprintf(stream, "IPV4: %d IPV6: %d SONOS: %d   |   ICMP: %d ICMPV6: %d TCP: %d UDP: %d\r", ipv4, ipv6, sonos, icmp, icmpv6, tcp, udp);
	free(nhdr);
	free(buf);
	return true;

}

bool print_frame(struct ethhdr *ethh, FILE *stream) {
	
	fprintf(stream, "     - - - - - Start of Ethernet Header - - - - -\n");
	fprintf(stream, "     |Ethernet Source Address is %02X-%02X-%02X-%02X-%02X-%02X\n", ethh -> h_source[0], ethh -> h_source[1], ethh -> h_source[2], ethh -> h_source[3], ethh -> h_source[4], ethh -> h_source[5]);
	fprintf(stream, "     |Ethernet Destination Address is %02X-%02X-%02X-%02X-%02X-%02X\n", ethh -> h_dest[0], ethh -> h_dest[1], ethh -> h_dest[2], ethh -> h_dest[3], ethh -> h_dest[4], ethh -> h_dest[5]);
	fprintf(stream, "     |Ethernet Protocol is 0x%04X\n\n", ntohs(ethh -> h_proto));
	return true;

}

bool print_ip_dgram(struct iphdr *iph, FILE *stream) {

	struct sockaddr_in src, dest;
	char addrstorage[INET_ADDRSTRLEN];

	src.sin_addr.s_addr = iph -> saddr;
	dest.sin_addr.s_addr = iph -> daddr;
	if (inet_ntop(AF_INET, &(src.sin_addr), addrstorage, sizeof(addrstorage)) == NULL) {
		errno = INET_TRANS_ERR;
		return false;
	}
	fprintf(stream, "     - - - - - Start of IP Header - - - - -\n");
	fprintf(stream, "     |IP Version is %u\n", iph -> version);
	fprintf(stream, "     |IP Header Length is %u\n", iph -> ihl);
	fprintf(stream, "     |IP Type of Service is %u\n", iph -> tos);
	fprintf(stream, "     |IP Total Length is %u\n", ntohs(iph -> tot_len));
	fprintf(stream, "     |IP ID is %u\n", ntohs(iph -> id));
	fprintf(stream, "     |IP Fragment Offset is %u\n", ntohs(iph -> frag_off));
	fprintf(stream, "     |IP Time to Live is %u\n", iph -> ttl);
	fprintf(stream, "     |IP Protocol is %u\n", iph -> protocol);
	fprintf(stream, "     |IP Checksum is %u\n", ntohs(iph -> check));
	fprintf(stream, "     |IP Source Address is %s\n", addrstorage);
	if (inet_ntop(AF_INET, &(dest.sin_addr), addrstorage, sizeof(addrstorage)) == NULL) {
		errno = INET_TRANS_ERR;
		return false;
	}
	fprintf(stream, "     |IP Destination Address is %s\n\n", addrstorage);
	return true;

}

bool print_ipv6_dgram(struct ip6_hdr *ip6h, FILE *stream) {

	uint32_t flow;
	char addr6storage[INET6_ADDRSTRLEN];

	flow = ntohl(ip6h -> ip6_flow);
	if (inet_ntop(AF_INET6, &(ip6h -> ip6_src), addr6storage, sizeof(addr6storage)) == NULL) {
		errno = INET_TRANS_ERR;
		return false;
	}
	fprintf(stream, "     - - - - - Start of IP Header - - - - -\n");
	fprintf(stream, "     |IP Version is %u\n", (flow & 0xF0000000) >> 28);
	fprintf(stream, "     |IP Traffic Class is %u\n", (flow & 0x0FF00000 << 1) >> 24);
	fprintf(stream, "     |IP Flow Label is %u\n", flow & 0x000FFFFF);
	fprintf(stream, "     |IP Payload Length is %u\n", ntohs(ip6h -> ip6_plen));
	fprintf(stream, "     |IP Next Header is %u\n", ip6h -> ip6_nxt);
	fprintf(stream, "     |IP Hop Limit is %u\n", ip6h -> ip6_hlim);
	fprintf(stream, "     |IP Source Address is %s\n", addr6storage);
	if (inet_ntop(AF_INET6, &(ip6h -> ip6_dst), addr6storage, sizeof(addr6storage)) == NULL) {
		errno = INET_TRANS_ERR;
		return false;
	}
	fprintf(stream, "     |IP Destination Address is %s\n\n", addr6storage);
	return true;

}

bool print_icmp_packet(struct icmphdr *icmph, FILE *stream) {

	fprintf(stream, "     - - - - - Start of ICMP Header - - - - -\n");
	fprintf(stream, "     |ICMP Type is %u\n", icmph -> type);
	fprintf(stream, "     |ICMP Code is %u\n", icmph -> code);
	fprintf(stream, "     |ICMP Checksum is %u\n\n", ntohs(icmph -> checksum));
	switch (icmph -> type) {
	case ICMP_DEST_UNREACH:
		//nhdr -> iph = (struct iphdr *) (frame + sizeof(struct ethhdr) + iphdrlen + sizeof(struct icmphdr));
		break;
	case ICMP_TIME_EXCEEDED:
		break;
	case ICMP_PARAMETERPROB:
		break;
	case ICMP_SOURCE_QUENCH:
		break;
	case ICMP_REDIRECT:
		break;
	case ICMP_ECHO:
		break;
	case ICMP_ECHOREPLY:
		break;
	case ICMP_TIMESTAMP:
		break;
	case ICMP_TIMESTAMPREPLY:
		break;
	case ICMP_INFO_REQUEST:
		break;
	case ICMP_INFO_REPLY:
		break;
	}
	return true;

}

bool print_icmpv6_packet(struct icmp6_hdr *icmp6h, FILE *stream) {

	fprintf(stream, "     - - - - - Start of ICMP6 Header - - - - -\n");
	fprintf(stream, "     |ICMP6 Type is %u\n", icmp6h -> icmp6_type);
	fprintf(stream, "     |ICMP6 Code is %u\n", icmp6h -> icmp6_code);
	fprintf(stream, "     |ICMP6 Checksum is %u\n", ntohs(icmp6h -> icmp6_cksum));
	switch (icmp6h -> icmp6_type) {
	case ICMP6_DST_UNREACH:
		break;
	case ICMP6_PACKET_TOO_BIG:
		break;
	case ICMP6_TIME_EXCEEDED:
		break;
	case ICMP6_PARAM_PROB:
		break;
	case ICMP6_ECHO_REQUEST:
		break;
	case ICMP6_ECHO_REPLY:
		break;
	}
	return true;

}

bool print_tcp_packet(struct tcphdr *tcph, FILE *stream) {

	fprintf(stream, "     - - - - - Start of TCP Header - - - - -\n");
	fprintf(stream, "     |TCP Source Port is %u\n", ntohs(tcph -> th_sport));
	fprintf(stream, "     |TCP Destination Port is %u\n", ntohs(tcph -> th_dport));
	fprintf(stream, "     |TCP Sequence # is %u\n", ntohl(tcph -> th_seq));
	fprintf(stream, "     |TCP Ack # is %u\n", ntohl(tcph -> th_ack));
	fprintf(stream, "     |TCP Data Offset is %u\n", tcph -> th_off);
	fprintf(stream, "     |TCP Reserved is %u\n", tcph -> res1);
	fprintf(stream, "     |TCP Control Bits are as follows: URG: %u ACK: %u PSH: %u RST: %u SYN: %u FIN: %u\n", tcph -> urg, tcph -> ack, tcph -> psh, tcph -> rst, tcph -> syn, tcph -> fin);
	fprintf(stream, "     |TCP Window is %u\n", ntohs(tcph -> window));
	fprintf(stream, "     |TCP Checksum is %u\n", ntohs(tcph -> check));
	fprintf(stream, "     |TCP Urgent Pointer is %u\n\n", ntohs(tcph -> urg_ptr));
	return true;

}

bool print_udp_packet(struct udphdr *udph, FILE *stream) {

	fprintf(stream, "     - - - - - Start of UDP Header - - - - -\n");
	fprintf(stream, "     |UDP Source Port is %u\n", ntohs(udph -> uh_sport));
	fprintf(stream, "     |UDP Destination Port is %u\n", ntohs(udph -> uh_dport));
	fprintf(stream, "     |UDP Segment Length is %u\n", ntohs(udph -> uh_ulen));
	fprintf(stream, "     |UDP Checksum is %u\n\n", ntohs(udph -> uh_sum));
	return true;

}

bool print_payload(char *payload, size_t psiz, FILE *stream) {

	int counter;

	fprintf(stream, "     - - - - - Start of Packet Payload - - - - -\n     ");
	for (int i = counter = 0; i < psiz; i++) {
		if (counter == i - PAYLOAD_SPACING) {
			fprintf(stream, "\n     ");
			counter = i;
		}
		fprintf(stream, "%02X ", (unsigned char) *(payload + i));
	}
	fprintf(stream, "\n\n");
	return true;

}
