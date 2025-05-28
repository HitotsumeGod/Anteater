#ifndef __ANTEATER_H__
#define __ANTEATER_H__

#include <stddef.h>
#include <stdbool.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include "pec/commonerrors.h"
#include "pec/socketerrors.h"

#define MAXBUF 65535
#define PAYLOAD_SPACING 18

typedef struct {
	struct ethhdr *ethh;
	struct iphdr *iph;
	struct tcphdr *tcph;
	struct udphdr *udph;
	char *payload;
	size_t psiz;
} org_packet;

extern ssize_t recv_dgram(int **ref_socket, char **ref_buffer);
extern org_packet *organize_dgram(char *buffer, ssize_t bufsiz);
extern org_packet *organize_packet(char *buffer, ssize_t bufsiz);
extern bool print_dgram(org_packet *dgram, int iteration);
extern bool print_tcp_packet(org_packet *packet, int iteration);
extern bool dump_dgram(char *buffer);

#endif //__ANTEATER_H__
