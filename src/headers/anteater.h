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

struct org_packet {
	struct ethhdr *ethh;
	union network_hdr *nhdr;
	union transport_hdr *thdr;
	char *payload;
	size_t psiz;
};

enum network_t {
	IPV4,
	IPV6
};

enum transport_t {
	ICMP,
	TCP,
	UDP
};

extern ssize_t recv_frame(int socket, char **buffer);
extern ssize_t recv_dgram(int socket, enum network_t type, char **buffer);
extern ssize_t recv_packet_ip(int socket, enum transport_t type, char **buffer);
extern ssize_t recv_packet_ip6(int socket, enum transport_t type, char **buffer);
extern bool print_minimal(char *frame);
extern bool print_frame(char *frame, size_t framesiz);
extern bool print_dgram(char *dgram, size_t gramsiz);
extern bool print_packet(char *packet, size_t pcksiz);

#endif //__ANTEATER_H__
