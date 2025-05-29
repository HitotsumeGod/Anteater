#ifndef __ANTEATER_H__
#define __ANTEATER_H__

#include <stddef.h>
#include <stdbool.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include "pec/commonerrors.h"
#include "pec/socketerrors.h"

#define MAXBUF 65535
#define PAYLOAD_SPACING 18

union network_hdr {
	struct iphdr *iph;
	struct ipv6hdr *ip6h;
};

union transport_hdr {
	struct icmphdr *icmph;
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
