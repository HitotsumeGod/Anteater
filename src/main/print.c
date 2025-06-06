#include <stdio.h>
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
int loop_c = 0;

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
	union network_hdr *nhdr;
	union transport_hdr *thdr;
	uint16_t nto;
	size_t iphdrlen, tcphdrlen, psiz;
	char *payload;

	if ((nhdr = malloc(sizeof(union network_hdr))) == NULL || (thdr = malloc(sizeof(union transport_hdr))) == NULL) {
		errno = MALLOC_ERR;
		return false;
	}
	ethh = (struct ethhdr *) frame;
	nto = ntohs(ethh -> h_proto);
	printf("     ##########BEGIN PACKET %d##########\n\n", loop_c++);
	printf("     - - - - - Start of Ethernet Header - - - - -\n");
	printf("     |Ethernet Source Address is %02X-%02X-%02X-%02X-%02X-%02X\n", ethh -> h_source[0], ethh -> h_source[1], ethh -> h_source[2], ethh -> h_source[3], ethh -> h_source[4], ethh -> h_source[5]);
	printf("     |Ethernet Destination Address is %02X-%02X-%02X-%02X-%02X-%02X\n", ethh -> h_dest[0], ethh -> h_dest[1], ethh -> h_dest[2], ethh -> h_dest[3], ethh -> h_dest[4], ethh -> h_dest[5]);
	printf("     |Ethernet Protocol is 0x%04X\n\n", nto);
	switch (nto) {
	case ETH_P_IP:
		nhdr -> iph = (struct iphdr *) (frame + sizeof(struct ethhdr));
		iphdrlen = nhdr -> iph -> ihl * 4;
		if (!print_ip_dgram(nhdr -> iph));
			return false;
		switch (nhdr -> iph -> protocol) {
		case IPPROTO_TCP:
			thdr -> tcph = (struct tcphdr *) (frame + sizeof(struct ethhdr) + iphdrlen);
			tcphdrlen = thdr -> tcph -> doff * 4;
			payload = frame + sizeof(struct ethhdr) + iphdrlen + tcphdrlen;
			psiz = fullsiz - sizeof(struct ethhdr) - iphdrlen - tcphdrlen;
			if (!print_tcp_packet(thdr -> tcph))
				return false;
			break;
		case IPPROTO_UDP:
			thdr -> udph = (struct udphdr *) (frame + sizeof(struct ethhdr) + iphdrlen);
			payload = frame + sizeof(struct ethhdr) + iphdrlen + sizeof(struct udphdr);
			psiz = fullsiz - sizeof(struct ethhdr) - iphdrlen - sizeof(struct udphdr);
			if (!print_udp_packet(thdr -> udph))
				return false;
			break;
		case IPPROTO_ICMP:
			thdr -> icmph = (struct icmphdr *) (frame + sizeof(struct ethhdr) + iphdrlen);
			payload = frame + sizeof(struct ethhdr) + iphdrlen + sizeof(struct icmphdr);
			psiz = fullsiz - sizeof(struct ethhdr) - iphdrlen - sizeof(struct icmphdr);
			if (!print_icmp_packet(thdr -> icmph))
				return false;
		default:
			payload = NULL;
			psiz = 0;
		}
		break;
	case ETH_P_IPV6:
		nhdr -> ip6h = (struct ip6_hdr *) (frame + sizeof(struct ethhdr));
		if (!print_ipv6_dgram(nhdr -> ip6h))
			return false;
		switch (nhdr -> ip6h -> ip6_nxt) {
		case IPPROTO_ICMPV6:
			thdr -> icmp6h = (struct icmp6_hdr *) (frame + sizeof(struct ethhdr) + sizeof(struct ip6_hdr));
			payload = frame + sizeof(struct ethhdr) + sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr);
			psiz = fullsiz - sizeof(struct ethhdr) - sizeof(struct ip6_hdr) - sizeof(struct icmp6_hdr);
			if (!print_icmp6_packet(thdr -> icmp6h))
				return false;
			break;
		case IPPROTO_TCP:
			thdr -> tcph = (struct tcphdr *) (frame + sizeof(struct ethhdr) + sizeof(struct ip6_hdr));
			tcphdrlen = thdr -> tcph -> doff * 4;
			payload = frame + sizeof(struct ethhdr) + sizeof(struct ip6_hdr) + tcphdrlen;
			psiz = fullsiz - sizeof(struct ethhdr) - sizeof(struct ip6_hdr) - tcphdrlen;
			if (!print_tcp_packet(thdr -> tcph))
				return false;
			break;
		case IPPROTO_UDP:
			thdr -> udph = (struct udphdr *) (frame + sizeof(struct ethhdr) + sizeof(struct ip6_hdr));
			payload = frame + sizeof(struct ethhdr) + sizeof(struct ip6_hdr) + sizeof(struct udphdr);
			psiz = fullsiz - sizeof(struct ethhdr) - sizeof(struct ip6_hdr) - sizeof(struct udphdr);
			if (!print_udp_packet(thdr -> udph))
				return false;
			break;
		default:
			psiz = 0;
		}
		break;
	}
	if (psiz > 0)
		if (!print_payload(payload, psiz))
			return false;
	else
		printf("     EMPTY PACKET PAYLOAD\n\n");
	printf("     ##########END PACKET %d##########\n\n", loop_c);
	free(nhdr);
	free(thdr);
	free(frame);
	return true;

}

bool print_ip_dgram(struct iphdr *iph) {

	struct sockaddr_in src, dest;
	char addrstorage[INET_ADDRSTRLEN];

	src.sin_addr.s_addr = iph -> saddr;
	dest.sin_addr.s_addr = iph -> daddr;
	if (inet_ntop(AF_INET, &(src.sin_addr), addrstorage, sizeof(addrstorage)) == NULL) {
		errno = INET_TRANS_ERR;
		return false;
	}
	printf("     - - - - - Start of IP Header - - - - -\n");
	printf("     |IP Version is %u\n", iph -> version);
	printf("     |IP Header Length is %u\n", iph -> ihl);
	printf("     |IP Type of Service is %u\n", iph -> tos);
	printf("     |IP Total Length is %u\n", ntohs(iph -> tot_len));
	printf("     |IP ID is %u\n", ntohs(iph -> id));
	printf("     |IP Fragment Offset is %u\n", ntohs(iph -> frag_off));
	printf("     |IP Time to Live is %u\n", iph -> ttl);
	printf("     |IP Protocol is %u\n", iph -> protocol);
	printf("     |IP Checksum is %u\n", ntohs(iph -> check));
	printf("     |IP Source Address is %s\n", addrstorage);
	if (inet_ntop(AF_INET, &(dest.sin_addr), addrstorage, sizeof(addrstorage)) == NULL) {
		errno = INET_TRANS_ERR;
		return false;
	}
	printf("     |IP Destination Address is %s\n\n", addrstorage);
	return true;

}

bool print_ipv6_dgram(struct ip6_hdr *ip6h) {

	uint32_t flow;
	char addr6storage[INET6_ADDRSTRLEN];

	flow = ntohl(ip6h -> ip6_flow);
	if (inet_ntop(AF_INET6, &(ip6h -> ip6_src), addr6storage, sizeof(addr6storage)) == NULL) {
		errno = INET_TRANS_ERR;
		return false;
	}
	printf("     - - - - - Start of IP Header - - - - -\n");
	printf("     |IP Version is %u\n", (flow & 0xF0000000) >> 28);
	printf("     |IP Traffic Class is %u\n", (flow & 0x0FF00000 << 1) >> 24);
	printf("     |IP Flow Label is %u\n", flow & 0x000FFFFF);
	printf("     |IP Payload Length is %u\n", ntohs(ip6h -> ip6_plen));
	printf("     |IP Next Header is %u\n", ip6h -> ip6_nxt);
	printf("     |IP Hop Limit is %u\n", ip6h -> ip6_hlim);
	printf("     |IP Source Address is %s\n", addr6storage);
	if (inet_ntop(AF_INET6, &(ip6h -> ip6_dst), addr6storage, sizeof(addr6storage)) == NULL) {
		errno = INET_TRANS_ERR;
		return false;
	}
	printf("     |IP Destination Address is %s\n\n", addr6storage);
	return true;

}

bool print_icmp_packet(struct icmphdr *icmph) {

	printf("     - - - - - Start of ICMP Header - - - - -\n");
	printf("     |ICMP Type is %u\n", icmph -> type);
	printf("     |ICMP Code is %u\n", icmph -> code);
	printf("     |ICMP Checksum is %u\n\n", ntohs(icmph -> checksum));
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

bool print_icmp6_packet(struct icmp6_hdr *icmp6h) {

	printf("     - - - - - Start of ICMP6 Header - - - - -\n");
	printf("     |ICMP6 Type is %u\n", icmp6h -> icmp6_type);
	printf("     |ICMP6 Code is %u\n", icmp6h -> icmp6_code);
	printf("     |ICMP6 Checksum is %u\n", ntohs(icmp6h -> icmp6_cksum));
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

bool print_tcp_packet(struct tcphdr *tcph) {

	printf("     - - - - - Start of TCP Header - - - - -\n");
	printf("     |TCP Source Port is %u\n", ntohs(tcph -> th_sport));
	printf("     |TCP Destination Port is %u\n", ntohs(tcph -> th_dport));
	printf("     |TCP Sequence # is %u\n", ntohl(tcph -> th_seq));
	printf("     |TCP Ack # is %u\n", ntohl(tcph -> th_ack));
	printf("     |TCP Data Offset is %u\n", tcph -> th_off);
	printf("     |TCP Reserved is %u\n", tcph -> res1);
	printf("     |TCP Control Bits are as follows: URG: %u ACK: %u PSH: %u RST: %u SYN: %u FIN: %u\n", tcph -> urg, tcph -> ack, tcph -> psh, tcph -> rst, tcph -> syn, tcph -> fin);
	printf("     |TCP Window is %u\n", ntohs(tcph -> window));
	printf("     |TCP Checksum is %u\n", ntohs(tcph -> check));
	printf("     |TCP Urgent Pointer is %u\n\n", ntohs(tcph -> urg_ptr));
	return true;

}

bool print_udp_packet(struct udphdr *udph) {

	printf("     - - - - - Start of UDP Header - - - - -\n");
	printf("     |UDP Source Port is %u\n", ntohs(udph -> uh_sport));
	printf("     |UDP Destination Port is %u\n", ntohs(udph -> uh_dport));
	printf("     |UDP Segment Length is %u\n", ntohs(udph -> uh_ulen));
	printf("     |UDP Checksum is %u\n\n", ntohs(udph -> uh_sum));
	return true;

}

bool print_payload(char *payload, size_t psiz) {

	int counter;

	printf("     - - - - - Start of Packet Payload - - - - -\n");
	printf("     ");
	for (int i = counter = 0; i < psiz; i++) {
		if (counter == i - PAYLOAD_SPACING) {
			printf("\n     ");
			counter = i;
		}
		printf("%02X ", (unsigned char) *(payload + i));
	}
	printf("\n\n");
	return true;

}