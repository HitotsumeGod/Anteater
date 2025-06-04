#ifndef __ANTEATER_H__
#define __ANTEATER_H__

#include <stddef.h>
#include <stdbool.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include "pec/commonerrors.h"
#include "pec/socketerrors.h"

#define ETH_P_SONOS 0x6970
#define MAXBUF 65535

struct arp_packet {
	uint16_t htype;
	uint16_t ptype;
	uint8_t hlen;
	uint8_t plen;
	uint16_t oper;
#if __BYTE_ORDER == __LITTLE_ENDIAN
	uint16_t sha_2;
	uint32_t sha_1;
#elif __BYTE_ORDER == __BIG_ENDIAN
	uint32_t sha_1;
	uint16_t sha_2;
#endif
	uint32_t spa;
#if __BYTE_ORDER == __LITTLE_ENDIAN
	uint16_t tha_2;
	uint32_t tha_1;
#elif __BYTE_ORDER == __BIG_ENDIAN
	uint32_t tha_1;
	uint16_t tha_2;
#endif
	uint32_t tpa;
};

union network_hdr {
	struct iphdr *iph;
	struct ip6_hdr *ip6h;
	struct arp_packet *arpp;
};

union transport_hdr {
	struct icmphdr *icmph;
	struct icmp6_hdr *icmp6h;
	struct tcphdr *tcph;
	struct udphdr *udph;
};

struct org_packet {
	struct ethhdr *ethh;
	union network_hdr *nhdr;
	union transport_hdr *thdr;
	char *payload;
	size_t psiz;
};

extern ssize_t recv_dgram(int **ref_socket, char **ref_buffer);
extern struct org_packet *organize_dgram(char *buffer, ssize_t bufsiz);
extern struct org_packet *organize_packet(char *buffer, ssize_t bufsiz);
extern bool print_dgram(struct org_packet *dgram, int iteration);
extern bool print_tcp_packet(struct org_packet *packet, int iteration);
extern bool dump_dgram(char *buffer);

#endif //__ANTEATER_H__
