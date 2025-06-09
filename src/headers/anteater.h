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

enum network_t {
	IPV4,
	IPV6
};

enum transport_t {
	ICMP,
	TCP,
	UDP
};

struct friggin_packet_options_yo {
	bool print_all;
	bool print_ip;
	bool print_ipv6;
	bool print_sonos;
	bool print_icmp;
	bool print_icmpv6;
	bool print_tcp;
	bool print_udp;
	bool print_payload;
};

extern ssize_t recv_frame(int socket, char **buffer);
extern ssize_t recv_dgram(int socket, enum network_t type, char **buffer);
extern ssize_t recv_packet_ip(int socket, enum transport_t type, char **buffer);
extern ssize_t recv_packet_ip6(int socket, enum transport_t type, char **buffer);
extern bool print_minimal(char *frame);
extern bool print_frame(char *frame, size_t framesiz, struct friggin_packet_options_yo *opts);
extern bool print_ip_dgram(struct iphdr *header);
extern bool print_ipv6_dgram(struct ip6_hdr *header);
extern bool print_icmp_packet(struct icmphdr *header);
extern bool print_icmp6_packet(struct icmp6_hdr *header);
extern bool print_tcp_packet(struct tcphdr *header);
extern bool print_udp_packet(struct udphdr *header);
extern bool print_payload(char *payload, size_t loadsiz);

#endif //__ANTEATER_H__