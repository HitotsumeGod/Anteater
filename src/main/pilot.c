#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "anteater.h"

int main(void) {

	org_packet *o;
	struct sockaddr_in src, dest;
	struct sockaddr_storage ss;
	socklen_t ss_siz;
	ssize_t full_siz, iphdrlen, tcphdrlen;
	int rsock, loop_c, counter;
	char buf[MAXBUF], dummy[INET_ADDRSTRLEN];

	if ((rsock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
		perror("sock err");
		return EXIT_FAILURE;
	}
	ss_siz = sizeof(ss);
	loop_c = 0;
	while (1) {
		if ((o = malloc(sizeof(org_packet))) == NULL) {
			perror("malloc err");
			return EXIT_FAILURE;
		}
		if ((full_siz = recvfrom(rsock, buf, sizeof(buf), 0, (struct sockaddr *) &ss, &ss_siz)) < 0) {
			perror("recv err");
			return EXIT_FAILURE;
		}
		o -> ethh = (struct ethhdr *) buf;
		o -> iph = (struct iphdr *) (buf + sizeof(struct ethhdr));
		iphdrlen = o -> iph -> ihl * 4;
		o -> tcph = (struct tcphdr *) (buf + sizeof(struct ethhdr) + iphdrlen);
		tcphdrlen = o -> tcph -> doff * 4;
		o -> payload = buf + sizeof(struct ethhdr) + iphdrlen + tcphdrlen;
		o -> psiz = full_siz - sizeof(struct ethhdr) - iphdrlen - tcphdrlen;
		src.sin_addr.s_addr = o -> iph -> saddr;
		dest.sin_addr.s_addr = o -> iph -> daddr; 
		printf("\n");
		printf("     ##########BEGIN PACKET %d##########\n\n", loop_c);
		printf("     - - - - - Start of Ethernet Header - - - - -\n");
		printf("     |Ethernet Source Address is %02X-%02X-%02X-%02X-%02X-%02X\n", o -> ethh -> h_source[0], o -> ethh -> h_source[1], o -> ethh -> h_source[2], o -> ethh -> h_source[3], o -> ethh -> h_source[4], o -> ethh -> h_source[5]);
		printf("     |Ethernet Destination Address is %02X-%02X-%02X-%02X-%02X-%02X\n", o -> ethh -> h_dest[0], o -> ethh -> h_dest[1], o -> ethh -> h_dest[2], o -> ethh -> h_dest[3], o -> ethh -> h_dest[4], o -> ethh -> h_dest[5]);
		printf("     |Ethernet Protocol is 0x%04X\n\n", ntohs(o -> ethh -> h_proto));
		printf("     - - - - - Start of IP Header - - - - -\n");
		printf("     |IP Version is %u\n", o -> iph -> version);
		printf("     |IP Header Length is %u\n", o -> iph -> ihl);
		printf("     |IP Type of Service is %u\n", o -> iph -> tos);
		printf("     |IP Total Length is %u\n", ntohs(o -> iph -> tot_len));
		printf("     |IP ID is %u\n", ntohs(o -> iph -> tot_len));
		printf("     |IP Fragment Offset is %u\n", ntohs(o -> iph -> frag_off));
		printf("     |IP Time to Live is %u\n", o -> iph -> ttl);
		printf("     |IP Protocol is %u\n", o -> iph -> protocol);
		printf("     |IP Checksum is %u\n", ntohs(o -> iph -> check));
		printf("     |IP Source Address is %s\n", inet_ntop(AF_INET, &(src.sin_addr), dummy, sizeof(dummy)));
		printf("     |IP Destination Address is %s\n\n", inet_ntop(AF_INET, &(dest.sin_addr), dummy, sizeof(dummy)));
		if (o -> iph -> protocol == 6) {
			printf("     - - - - - Start of TCP Header - - - - -\n");
			printf("     |TCP Source Port is %u\n", ntohs(o -> tcph -> source));
			printf("     |TCP Destination Port is %u\n", ntohs(o -> tcph -> dest));
			printf("     |TCP Sequence # is %u\n", ntohs(o -> tcph -> seq));
			printf("     |TCP Ack # is %u\n", ntohs(o -> tcph -> ack_seq));
			printf("     |TCP Data Offset is %u\n", o -> tcph -> doff);
			printf("     |TCP Reserved is %u\n", o -> tcph -> res1);
			printf("     |TCP Control Bits are as follows: URG: %u ACK: %u PSH: %u RST: %u SYN: %u FIN: %u\n", o -> tcph -> urg, o -> tcph -> ack, o -> tcph -> psh, o -> tcph -> rst, o -> tcph -> syn, o -> tcph -> fin);
			printf("     |TCP Window is %u\n", ntohs(o -> tcph -> window));
			printf("     |TCP Checksum is %u\n", ntohs(o -> tcph -> check));
			printf("     |TCP Urgent Pointer is %u\n\n", ntohs(o -> tcph -> urg_ptr));
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
		}
		printf("     ##########END PACKET %d##########\n\n", loop_c);
		free(o);
		loop_c++;
	}
	return 0;

}
