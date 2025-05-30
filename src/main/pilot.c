#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "anteater.h"

int main(int argc, char *argv) {

	struct org_packet *o;
	struct sockaddr_in src, dest;
	struct sockaddr_storage ss;
	socklen_t ss_siz;
	ssize_t full_siz, iphdrlen, tcphdrlen;
	uint16_t nto;
	int rsock, loop_c, counter, icmp, isp, tcp, udp, nohop, smp; 
	char buf[MAXBUF], dummy[INET_ADDRSTRLEN];
	bool __print;

	if (argc == 1) 
		__print = false;
	else
		__print = true;
	if ((rsock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
		perror("sock err");
		return EXIT_FAILURE;
	}
	ss_siz = sizeof(ss);
	icmp = isp = tcp = udp = nohop = smp = loop_c = 0;
	while (1) {
		if ((o = malloc(sizeof(struct org_packet))) == NULL || (o -> nhdr = malloc(sizeof(union network_hdr))) == NULL) {
			perror("malloc err");
			return EXIT_FAILURE;
		}
		if ((o -> thdr = malloc(sizeof(union transport_hdr))) == NULL) {
			perror("malloc err");
			return EXIT_FAILURE;
		}
		if ((full_siz = recvfrom(rsock, buf, sizeof(buf), 0, (struct sockaddr *) &ss, &ss_siz)) < 0) {
			perror("recv err");
			return EXIT_FAILURE;
		}
		o -> ethh = (struct ethhdr *) buf;
		nto = ntohs(o -> ethh -> h_proto);
		if (__print) {
			printf("\n");
			printf("     ##########BEGIN PACKET %d##########\n\n", loop_c);
			printf("     - - - - - Start of Ethernet Header - - - - -\n");
			printf("     |Ethernet Source Address is %02X-%02X-%02X-%02X-%02X-%02X\n", o -> ethh -> h_source[0], o -> ethh -> h_source[1], o -> ethh -> h_source[2], o -> ethh -> h_source[3], o -> ethh -> h_source[4], o -> ethh -> h_source[5]);
			printf("     |Ethernet Destination Address is %02X-%02X-%02X-%02X-%02X-%02X\n", o -> ethh -> h_dest[0], o -> ethh -> h_dest[1], o -> ethh -> h_dest[2], o -> ethh -> h_dest[3], o -> ethh -> h_dest[4], o -> ethh -> h_dest[5]);
			printf("     |Ethernet Protocol is 0x%04X\n\n", nto);
		}
		if (nto == ETH_P_IP) {
			o -> nhdr -> iph = (struct iphdr *) (buf + sizeof(struct ethhdr));
			iphdrlen = o -> nhdr -> iph -> ihl * 4;
			src.sin_addr.s_addr = o -> nhdr -> iph -> saddr;
			dest.sin_addr.s_addr = o -> nhdr -> iph -> daddr;
			if (__print) {
				printf("     - - - - - Start of IP Header - - - - -\n");
				printf("     |IP Version is %u\n", o -> nhdr -> iph -> version);
				printf("     |IP Header Length is %u\n", o -> nhdr -> iph -> ihl);
				printf("     |IP Type of Service is %u\n", o -> nhdr -> iph -> tos);
				printf("     |IP Total Length is %u\n", ntohs(o -> nhdr -> iph -> tot_len));
				printf("     |IP ID is %u\n", ntohs(o -> nhdr -> iph -> tot_len));
				printf("     |IP Fragment Offset is %u\n", ntohs(o -> nhdr -> iph -> frag_off));
				printf("     |IP Time to Live is %u\n", o -> nhdr -> iph -> ttl);
				printf("     |IP Protocol is %u\n", o -> nhdr -> iph -> protocol);
				printf("     |IP Checksum is %u\n", ntohs(o -> nhdr -> iph -> check));
				printf("     |IP Source Address is %s\n", inet_ntop(AF_INET, &(src.sin_addr), dummy, sizeof(dummy)));
				printf("     |IP Destination Address is %s\n\n", inet_ntop(AF_INET, &(dest.sin_addr), dummy, sizeof(dummy)));
			}
		} else if (nto == ETH_P_IPV6) {
			o -> nhdr -> ip6h = (struct ipv6hdr *) (buf + sizeof(struct ethhdr));
			if (__print) {
				printf("     - - - - - Start of IP Header - - - - -\n");
				printf("     |IP Version is %u\n", o -> nhdr -> ip6h -> version);
				printf("     |IP Traffic Class is %u%u\n", o -> nhdr -> ip6h -> flow_lbl[0], o -> nhdr -> ip6h -> priority);
				printf("     |IP Flow Label is %u%u\n", o -> nhdr -> ip6h -> flow_lbl[1], o -> nhdr -> ip6h -> flow_lbl[2]);
				printf("     |IP Payload Length is %u\n", ntohs(o -> nhdr -> ip6h -> payload_len));
				printf("     |IP Next Header is %u\n", o -> nhdr -> ip6h -> nexthdr);
				printf("     |IP Hop Limit is %u\n", o -> nhdr -> ip6h -> hop_limit);
				printf("     |IP Source Address is %s\n", inet_ntop(AF_INET6, &(o -> nhdr -> ip6h -> saddr), dummy, sizeof(dummy)));
				printf("     |IP Destination Address is %s\n\n", inet_ntop(AF_INET6, &(o -> nhdr -> ip6h -> daddr), dummy, sizeof(dummy)));
			}
		} else {
			free(o -> nhdr);	
			free(o -> thdr);
			free(o);
			loop_c++;
			continue;
		}
		switch (o -> nhdr -> iph -> protocol) {
		case 1:
			icmp++;
			o -> thdr -> icmph = (struct icmphdr *) (buf + sizeof(struct ethhdr) + iphdrlen);
			o -> payload = buf + sizeof(struct ethhdr) + iphdrlen + sizeof(struct icmphdr);
			o -> psiz = full_siz - sizeof(struct ethhdr) - iphdrlen - sizeof(struct icmphdr);
			if (__print) {
				printf("     - - - - - Start of ICMP Header - - - - -\n");
				printf("     ICMP Type is %u\n", o -> thdr -> icmph -> type);
				printf("     ICMP Code is %u\n", o -> thdr -> icmph -> code);
				printf("     ICMP Checksum is %u\n\n", ntohs(o -> thdr -> icmph -> checksum));
				switch (o -> thdr -> icmph -> type) {
				case ICMP_ECHOREPLY:
					break;
				case ICMP_DEST_UNREACH:
					;
					break;
				case ICMP_TIME_EXCEEDED:
					;
					break;
				case ICMP_PARAMETERPROB:
					;
					break;
				}
			}
			break;
		case 5:
			isp++;
			o -> payload = NULL;
			o -> psiz = 0;
			break;
		case 6:
			tcp++;
			o -> thdr -> tcph = (struct tcphdr *) (buf + sizeof(struct ethhdr) + iphdrlen);
			tcphdrlen = o -> thdr -> tcph -> doff * 4;
			o -> payload = buf + sizeof(struct ethhdr) + iphdrlen + tcphdrlen;
			o -> psiz = full_siz - sizeof(struct ethhdr) - iphdrlen - tcphdrlen;
			if (__print) {
				printf("     - - - - - Start of TCP Header - - - - -\n");
				printf("     |TCP Source Port is %u\n", ntohs(o -> thdr -> tcph -> source));
				printf("     |TCP Destination Port is %u\n", ntohs(o -> thdr -> tcph -> dest));
				printf("     |TCP Sequence # is %u\n", ntohs(o -> thdr -> tcph -> seq));
				printf("     |TCP Ack # is %u\n", ntohs(o -> thdr -> tcph -> ack_seq));
				printf("     |TCP Data Offset is %u\n", o -> thdr -> tcph -> doff);
				printf("     |TCP Reserved is %u\n", o -> thdr -> tcph -> res1);
				printf("     |TCP Control Bits are as follows: URG: %u ACK: %u PSH: %u RST: %u SYN: %u FIN: %u\n", o -> thdr -> tcph -> urg, o -> thdr -> tcph -> ack, o -> thdr -> tcph -> psh, o -> thdr -> tcph -> rst, o -> thdr -> tcph -> syn, o -> thdr -> tcph -> fin);
				printf("     |TCP Window is %u\n", ntohs(o -> thdr -> tcph -> window));
				printf("     |TCP Checksum is %u\n", ntohs(o -> thdr -> tcph -> check));
				printf("     |TCP Urgent Pointer is %u\n\n", ntohs(o -> thdr -> tcph -> urg_ptr));
			}
			break;
		case 17:
			udp++;
			o -> thdr -> udph = (struct udphdr *) (buf + sizeof(struct ethhdr) + iphdrlen);
			o -> payload = buf + sizeof(struct ethhdr) + iphdrlen + sizeof(struct udphdr);
			o -> psiz = full_siz - sizeof(struct ethhdr) - iphdrlen - sizeof(struct udphdr);
			if (__print) {
				printf("     - - - - - Start of UDP Header - - - - -\n");
				printf("     |UDP Source Port is %u\n", ntohs(o -> thdr -> udph -> source));
				printf("     |UDP Destination Port is %u\n", ntohs(o -> thdr -> udph -> dest));
				printf("     |UDP Datagram Length is %u\n", ntohs(o -> thdr -> udph -> len));
				printf("     |UDP Checksum is %u\n\n", ntohs(o -> thdr -> udph -> check));
			}
			break;
		case 114:
			nohop++;
			break;
		case 121:
			smp++;
			break;
		}
		if (!__print)  
			printf("ICMP: %d ISP: %d TCP: %d UDP: %d NOHOP: %d SMP: %d\r", icmp, isp, tcp, udp, nohop, smp);
		else {
			if (o -> psiz > 0) {
				printf("     - - - - - Start of Datagram Payload - - - - -\n\n");	
				printf("     ");
				for (int i = counter = 0; i < o -> psiz; i++) {
					if (counter == i - PAYLOAD_SPACING) {
						printf("\n     ");
						counter = i;
					}
				printf("%02X ", (unsigned char) *(o -> payload + i));
				}
				printf("\n\n");
			} else 
				printf("     EMPTY DATAGRAM PAYLOAD\n\n");
			printf("     ##########END PACKET %d##########\n\n", loop_c);
			}
		free(o -> nhdr);
		free(o -> thdr);
		free(o);
		loop_c++;
	}
	return 0;

}
