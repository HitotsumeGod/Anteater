#ifndef __ANTEATER_H__
#define __ANTEATER_H__

#include <stdio.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include "netstructs.h"
#include "pec/commonerrors.h"
#include "pec/socketerrors.h"

#define PROG_VERS					"Anteater Packet Analyzer Alpha Version 1.0"
#define ETH_P_SONOS 					0x6970
#define MAXBUF 						65535
#define MASK  						0xFF
#define IPMASK 						0x01
#define IPV6MASK 					0x02
#define ICMPMASK 					0x04
#define ICMPV6MASK 					0x08
#define TCPMASK 					0x10
#define UDPMASK 					0x20
#define PMASK 						0x40
#define ETHMASK						0x80

union network_hdr {
	struct iphdr *iph;
	struct ip6_hdr *ip6h;
};

union transport_hdr {
	struct icmphdr *icmph;
	struct icmp6_hdr *icmp6h;
	struct tcphdr *tcph;
	struct udphdr *udph;
};

extern ssize_t recv_packet(int socket, char **buffer);
extern bool process_frame(char *frame, size_t framesiz, uint8_t optsmask, FILE *stream);
extern bool print_minimal(char *frame, FILE *stream);
extern bool print_frame(struct ethhdr *header, FILE *stream);
extern bool print_ip_dgram(struct iphdr *header, FILE *stream);
extern bool print_ipv6_dgram(struct ip6_hdr *header, FILE *stream);
extern bool print_icmp_packet(struct icmphdr *header, FILE *stream);
extern bool print_icmpv6_packet(struct icmp6_hdr *header, FILE *stream);
extern bool print_tcp_packet(struct tcphdr *header, FILE *stream);
extern bool print_udp_packet(struct udphdr *header, FILE *stream);
extern bool print_payload(char *payload, size_t loadsiz, FILE *stream);

#endif //__ANTEATER_H__
