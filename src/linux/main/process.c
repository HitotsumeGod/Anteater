#include "anteater.h"

int loop_c = 0;

bool process_frame(char *frame, size_t fullsiz, uint8_t type, FILE *stream) {

	struct ethhdr *ethh;
	union network_hdr *nhdr;
	union transport_hdr *thdr;
	uint8_t res;
	uint16_t nto;
	size_t iphdrlen, tcphdrlen, psiz;
	char *payload;

	if (!frame || !fullsiz || !type || !stream) {
		errno = BAD_ARGS_ERR;
		return false;
	}
	psiz = 0;
	res = ETHMASK;
	if ((nhdr = malloc(sizeof(union network_hdr))) == NULL || (thdr = malloc(sizeof(union transport_hdr))) == NULL) {
		errno = MALLOC_ERR;
		return false;
	}
	ethh = (struct ethhdr *) frame;
	nto = ntohs(ethh -> h_proto);
	switch (nto) {
	case ETH_P_IP:
		res |= IPMASK;
		nhdr -> iph = (struct iphdr *) (frame + sizeof(struct ethhdr));
		iphdrlen = nhdr -> iph -> ihl * 4;
		switch (nhdr -> iph -> protocol) {
		case IPPROTO_TCP:
			res |= TCPMASK;
			thdr -> tcph = (struct tcphdr *) (frame + sizeof(struct ethhdr) + iphdrlen);
			tcphdrlen = thdr -> tcph -> doff * 4;
			payload = frame + sizeof(struct ethhdr) + iphdrlen + tcphdrlen;
			psiz = fullsiz - sizeof(struct ethhdr) - iphdrlen - tcphdrlen;
			break;
		case IPPROTO_UDP:
			res |= UDPMASK;
			thdr -> udph = (struct udphdr *) (frame + sizeof(struct ethhdr) + iphdrlen);
			payload = frame + sizeof(struct ethhdr) + iphdrlen + sizeof(struct udphdr);
			psiz = fullsiz - sizeof(struct ethhdr) - iphdrlen - sizeof(struct udphdr);
			break;
		case IPPROTO_ICMP:
			res |= ICMPMASK;
			thdr -> icmph = (struct icmphdr *) (frame + sizeof(struct ethhdr) + iphdrlen);
			payload = frame + sizeof(struct ethhdr) + iphdrlen + sizeof(struct icmphdr);
			psiz = fullsiz - sizeof(struct ethhdr) - iphdrlen - sizeof(struct icmphdr);
			break;
		default:
			payload = NULL;
			psiz = 0;
		}
		break;
	case ETH_P_IPV6:
		res |= IPV6MASK;
		nhdr -> ip6h = (struct ip6_hdr *) (frame + sizeof(struct ethhdr));
		switch (nhdr -> ip6h -> ip6_nxt) {
		case IPPROTO_ICMPV6:
			res |= ICMPV6MASK;
			thdr -> icmp6h = (struct icmp6_hdr *) (frame + sizeof(struct ethhdr) + sizeof(struct ip6_hdr));
			payload = frame + sizeof(struct ethhdr) + sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr);
			psiz = fullsiz - sizeof(struct ethhdr) - sizeof(struct ip6_hdr) - sizeof(struct icmp6_hdr);
			break;
		case IPPROTO_TCP:
			res |= TCPMASK;
			thdr -> tcph = (struct tcphdr *) (frame + sizeof(struct ethhdr) + sizeof(struct ip6_hdr));
			tcphdrlen = thdr -> tcph -> doff * 4;
			payload = frame + sizeof(struct ethhdr) + sizeof(struct ip6_hdr) + tcphdrlen;
			psiz = fullsiz - sizeof(struct ethhdr) - sizeof(struct ip6_hdr) - tcphdrlen;
			break;
		case IPPROTO_UDP:
			res |= UDPMASK;
			thdr -> udph = (struct udphdr *) (frame + sizeof(struct ethhdr) + sizeof(struct ip6_hdr));
			payload = frame + sizeof(struct ethhdr) + sizeof(struct ip6_hdr) + sizeof(struct udphdr);
			psiz = fullsiz - sizeof(struct ethhdr) - sizeof(struct ip6_hdr) - sizeof(struct udphdr);
			break;
		default:
			payload = NULL;
			psiz = 0;
		}
		break;
	case ETH_P_SONOS:
		payload = frame + sizeof(struct ethhdr);
		psiz = fullsiz - sizeof(struct ethhdr);
		break;
	}
	if (type & res) {
		fprintf(stream, "     ##########BEGIN PACKET %d##########\n\n", ++loop_c);
		fprintf(stream, "     ##########END PACKET %d##########\n\n", loop_c);
		if (!print_frame(ethh, stream))
			return false;
		if (res & IPMASK) {
			if (!print_ip_dgram(nhdr -> iph, stream))
				return false;
			if (res & ICMPMASK)
				if (!print_icmp_packet(thdr -> icmph, stream))
					return false;
		} else if (res & IPV6MASK) {
			if (!print_ipv6_dgram(nhdr -> ip6h, stream))
				return false;
			if (res & ICMPV6MASK)
				if (!print_icmpv6_packet(thdr -> icmp6h, stream))
					return false;
		}
		if (res & TCPMASK) {
			if (!print_tcp_packet(thdr -> tcph, stream))
				return false;
		} else if (res & UDPMASK) {
			if (!print_udp_packet(thdr -> udph, stream))
				return false;
		}
		if (psiz > 0) {
			if (!print_payload(payload, psiz, stream))
				return false;
		} else
			fprintf(stream, "     EMPTY PACKET PAYLOAD\n\n");

	}
	free(nhdr);
	free(thdr);
	free(frame);
	return true;

}
