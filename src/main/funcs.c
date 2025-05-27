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

ssize_t recv_dgram(int **sock, char **buf) {

	struct sockaddr_storage ss;
	socklen_t ss_siz;
	ssize_t dtg_siz;
	int lcl_sock;
	char lcl_buf[MAXBUF];

	if (!sock || !buf) {
		errno = BAD_ARGS_ERR;
		return -1;
	}
	lcl_sock = **sock;
	ss_siz = sizeof(ss);
	if ((dtg_siz = recvfrom(lcl_sock, lcl_buf, sizeof(lcl_buf), 0, (struct sockaddr *) &ss, &ss_siz)) < 0) {
		errno = RECV_ERR;
		return -1;
	}
	*buf = lcl_buf;
	return dtg_siz;

}

org_packet *organize_dgram(char *buf, ssize_t sz) {

	org_packet *porg;
	size_t iphdrlen;
	size_t tcphdrlen;

	if (!buf) {
		errno = BAD_ARGS_ERR;
		return NULL;
	}
	if ((porg = malloc(sizeof(org_packet))) == NULL) {
		errno = MALLOC_ERR;
		return NULL;
	}
	porg -> ethh = (struct ethhdr *) buf;
	porg -> iph = (struct iphdr *) (buf + sizeof(struct ethhdr));
	iphdrlen = porg -> iph -> ihl * 4;
	porg -> tcph = (struct tcphdr *) (buf + sizeof(struct ethhdr) + iphdrlen);
	tcphdrlen = porg -> tcph -> doff * 4;
	porg -> psiz = sz - sizeof(struct ethhdr) - iphdrlen - tcphdrlen;
	return porg;

}

org_packet *organize_packet(char *buf, ssize_t sz) {

	org_packet *porg;
	size_t iphdrlen;
	size_t tcphdrlen;

	if (!buf) {
		errno = BAD_ARGS_ERR;
		return NULL;
	}
	if ((porg = malloc(sizeof(org_packet))) == NULL) {
		errno = MALLOC_ERR;
		return NULL;
	}
	porg -> ethh = NULL;
	porg -> iph = (struct iphdr *) buf;
	iphdrlen = porg -> iph -> ihl * 4;
	porg -> tcph = (struct tcphdr *) (buf + iphdrlen);
	tcphdrlen = porg -> tcph -> doff * 4;
	porg -> payload = buf + iphdrlen + tcphdrlen;
	porg -> psiz = sz - iphdrlen - tcphdrlen;
	return porg;

}

bool print_dgram(org_packet *o, int iter) {

	struct sockaddr_in src, dest;
	char dummy[INET_ADDRSTRLEN];
	int counter;

	if (!o) {
		errno = BAD_ARGS_ERR;
		return false;
	}
	src.sin_addr.s_addr = o -> iph -> saddr;
	dest.sin_addr.s_addr = o -> iph -> daddr; 
	printf("\n");
	printf("     ##########BEGIN PACKET %d##########\n\n", iter);
	printf("     - - - - - Start of Ethernet Header - - - - -\n");
	printf("     |Ethernet Source Address is %02X-%02X-%02X-%02X-%02X-02X\n", o -> ethh -> h_source[0], o -> ethh -> h_source[1], o -> ethh -> h_source[2], o -> ethh -> h_source[3], o -> ethh -> h_source[4], o -> ethh -> h_source[5]);
	printf("     |Ethernet Destination Address is %02X-%02X-%02X-%02X-%02X-02X\n", o -> ethh -> h_dest[0], o -> ethh -> h_dest[1], o -> ethh -> h_dest[2], o -> ethh -> h_dest[3], o -> ethh -> h_dest[4], o -> ethh -> h_dest[5]);
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
	}
	printf("     ##########END PACKET %d##########\n\n", iter);
	return true;

}

bool print_packet(org_packet *o, int iter) {

	struct sockaddr_in src, dest;
	char dummy[INET_ADDRSTRLEN];
	int counter;

	if (!o) {
		errno = BAD_ARGS_ERR;
		return false;
	}
	src.sin_addr.s_addr = o -> iph -> saddr;
	dest.sin_addr.s_addr = o -> iph -> daddr;
	printf("\n");
	printf("     ##########BEGIN PACKET %d##########\n\n", iter);
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
	printf("     ##########END PACKET %d##########\n\n", iter);
	free(o);
	return true;

}
