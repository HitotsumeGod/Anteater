#include <stdlib.h>
#include <errno.h>
#include "anteater.h"

int loop_c = 0;

bool process_frame(char *frame, size_t fullsiz, uint8_t opts, FILE *stream) {

	struct ethhdr *ethh;
	union network_hdr *nhdr;
	union transport_hdr *thdr;
	uint16_t nto;
	size_t iphdrlen, tcphdrlen, psiz;
	char *payload;

	psiz = 0;
	if (!stream)
		stream = stdout;
	if ((nhdr = malloc(sizeof(union network_hdr))) == NULL || (thdr = malloc(sizeof(union transport_hdr))) == NULL) {
		errno = MALLOC_ERR;
		return false;
	}
	ethh = (struct ethhdr *) frame;
	nto = ntohs(ethh -> h_proto);
	fprintf(stream, "     ##########BEGIN PACKET %d##########\n\n", loop_c++);
	if (((opts & MASK) & ETHMASK) == ETHMASK)
		if (!print_frame(ethh, stream))
			return false;
	switch (nto) {
	case ETH_P_IP:
		nhdr -> iph = (struct iphdr *) (frame + sizeof(struct ethhdr));
		iphdrlen = nhdr -> iph -> ihl * 4;
		if (((opts & MASK) & IPMASK) == IPMASK)
			if (!print_ip_dgram(nhdr -> iph, stream)) 
				return false;
		switch (nhdr -> iph -> protocol) {
		case IPPROTO_TCP:
			thdr -> tcph = (struct tcphdr *) (frame + sizeof(struct ethhdr) + iphdrlen);
			tcphdrlen = thdr -> tcph -> doff * 4;
			payload = frame + sizeof(struct ethhdr) + iphdrlen + tcphdrlen;
			psiz = fullsiz - sizeof(struct ethhdr) - iphdrlen - tcphdrlen;
			if (((opts & MASK) & TCPMASK) == TCPMASK)
				if (!print_tcp_packet(thdr -> tcph, stream)) {
					return false;
			}
			break;
		case IPPROTO_UDP:
			thdr -> udph = (struct udphdr *) (frame + sizeof(struct ethhdr) + iphdrlen);
			payload = frame + sizeof(struct ethhdr) + iphdrlen + sizeof(struct udphdr);
			psiz = fullsiz - sizeof(struct ethhdr) - iphdrlen - sizeof(struct udphdr);
			if (((opts & MASK) & UDPMASK) == UDPMASK)
				if (!print_udp_packet(thdr -> udph, stream))
					return false;
			break;
		case IPPROTO_ICMP:
			thdr -> icmph = (struct icmphdr *) (frame + sizeof(struct ethhdr) + iphdrlen);
			payload = frame + sizeof(struct ethhdr) + iphdrlen + sizeof(struct icmphdr);
			psiz = fullsiz - sizeof(struct ethhdr) - iphdrlen - sizeof(struct icmphdr);
			if (((opts & MASK) & ICMPMASK) == ICMPMASK)
				if (!print_icmp_packet(thdr -> icmph, stream))
					return false;
			break;
		default:
			payload = NULL;
			psiz = 0;
		}
		break;
	case ETH_P_IPV6:
		nhdr -> ip6h = (struct ip6_hdr *) (frame + sizeof(struct ethhdr));
		if (((opts & MASK) & IPV6MASK) == IPV6MASK)
			if (!print_ipv6_dgram(nhdr -> ip6h, stream))
				return false;
		switch (nhdr -> ip6h -> ip6_nxt) {
		case IPPROTO_ICMPV6:
			thdr -> icmp6h = (struct icmp6_hdr *) (frame + sizeof(struct ethhdr) + sizeof(struct ip6_hdr));
			payload = frame + sizeof(struct ethhdr) + sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr);
			psiz = fullsiz - sizeof(struct ethhdr) - sizeof(struct ip6_hdr) - sizeof(struct icmp6_hdr);
			if (((opts & MASK) & ICMPV6MASK) == ICMPV6MASK)
				if (!print_icmpv6_packet(thdr -> icmp6h, stream))
					return false;
			break;
		case IPPROTO_TCP:
			thdr -> tcph = (struct tcphdr *) (frame + sizeof(struct ethhdr) + sizeof(struct ip6_hdr));
			tcphdrlen = thdr -> tcph -> doff * 4;
			payload = frame + sizeof(struct ethhdr) + sizeof(struct ip6_hdr) + tcphdrlen;
			psiz = fullsiz - sizeof(struct ethhdr) - sizeof(struct ip6_hdr) - tcphdrlen;
			if (((opts & MASK) & TCPMASK) == TCPMASK)
				if (!print_tcp_packet(thdr -> tcph, stream))
					return false;
			break;
		case IPPROTO_UDP:
			thdr -> udph = (struct udphdr *) (frame + sizeof(struct ethhdr) + sizeof(struct ip6_hdr));
			payload = frame + sizeof(struct ethhdr) + sizeof(struct ip6_hdr) + sizeof(struct udphdr);
			psiz = fullsiz - sizeof(struct ethhdr) - sizeof(struct ip6_hdr) - sizeof(struct udphdr);
			if (((opts & MASK) & UDPMASK) == UDPMASK)
				if (!print_udp_packet(thdr -> udph, stream))
					return false;
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
	if (((opts & MASK) & PMASK) == PMASK)
		if (psiz > 0) {
			if (!print_payload(payload, psiz, stream))
				return false;
		} else
			fprintf(stream, "     EMPTY PACKET PAYLOAD\n\n");
	fprintf(stream, "     ##########END PACKET %d##########\n\n", loop_c);
	free(nhdr);
	free(thdr);
	free(frame);
	return true;

}

bool process_ip_dgram(char *dgram, size_t fullsiz, uint8_t opts, FILE *stream) {

	struct iphdr *iph;
	union transport_hdr *thdr;
	size_t iphdrlen, tcphdrlen, psiz;
	char *payload;

	psiz = 0;
	if (!stream)
		stream = stdout;
	if ((thdr = malloc(sizeof(union transport_hdr))) == NULL) {
		errno = MALLOC_ERR;
		return false;
	}
	iph = (struct iphdr *) dgram;
	iphdrlen = iph -> ihl * 4;
	fprintf(stream, "     ##########BEGIN PACKET %d##########\n\n", loop_c++);
	if (((opts & MASK) & IPMASK) == IPMASK)
		if (!print_ip_dgram(iph, stream))
			return false;
	switch (iph -> protocol) {
	case IPPROTO_TCP:
		thdr -> tcph = (struct tcphdr *) (dgram + iphdrlen);
		tcphdrlen = thdr -> tcph -> doff * 4;
		payload = dgram + iphdrlen + tcphdrlen;
		psiz = fullsiz - iphdrlen - tcphdrlen;
		if (((opts & MASK) & TCPMASK) == TCPMASK)
			if (!print_tcp_packet(thdr -> tcph, stream)) {
				return false;
		}
		break;
	case IPPROTO_UDP:
		thdr -> udph = (struct udphdr *) (dgram + iphdrlen);
		payload = dgram + iphdrlen + sizeof(struct udphdr);
		psiz = fullsiz - iphdrlen - sizeof(struct udphdr);
		if (((opts & MASK) & UDPMASK) == UDPMASK)
			if (!print_udp_packet(thdr -> udph, stream))
				return false;
		break;
	case IPPROTO_ICMP:
		thdr -> icmph = (struct icmphdr *) (dgram + iphdrlen);
		payload = dgram + iphdrlen + sizeof(struct icmphdr);
		psiz = fullsiz - iphdrlen - sizeof(struct icmphdr);
		if (((opts & MASK) & ICMPMASK) == ICMPMASK)
			if (!print_icmp_packet(thdr -> icmph, stream))
				return false;
		break;
	default:
		payload = NULL;
		psiz = 0;
	}	
	if (((opts & MASK) & PMASK) == PMASK)
		if (psiz > 0) {
			if (!print_payload(payload, psiz, stream))
				return false;
		} else
			fprintf(stream, "     EMPTY PACKET PAYLOAD\n\n");
	fprintf(stream, "     ##########END PACKET %d##########\n\n", loop_c);
	free(thdr);
	free(dgram);
	return true;

}

bool process_ipv6_dgram(char *dgram, size_t fullsiz, uint8_t opts, FILE *stream) {

	struct ip6_hdr *ip6h;
	union transport_hdr *thdr;
	size_t iphdrlen, tcphdrlen, psiz;
	char *payload;

	psiz = 0;
	if (!stream)
		stream = stdout;
	if ((thdr = malloc(sizeof(union transport_hdr))) == NULL) {
		errno = MALLOC_ERR;
		return false;
	}
	ip6h = (struct ip6_hdr *) dgram;
	fprintf(stream, "     ##########BEGIN PACKET %d##########\n\n", loop_c++);
	if (((opts & MASK) & IPV6MASK) == IPV6MASK)
		if (!print_ipv6_dgram(ip6h, stream))
			return false;
	switch (ip6h -> ip6_nxt) {
	case IPPROTO_ICMPV6:
		thdr -> icmp6h = (struct icmp6_hdr *) (dgram + sizeof(struct ip6_hdr));
		payload = dgram + sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr);
		psiz = fullsiz - sizeof(struct ip6_hdr) - sizeof(struct icmp6_hdr);
		if (((opts & MASK) & ICMPV6MASK) == ICMPV6MASK)
			if (!print_icmpv6_packet(thdr -> icmp6h, stream))
				return false;
		break;
	case IPPROTO_TCP:
		thdr -> tcph = (struct tcphdr *) (dgram + sizeof(struct ip6_hdr));
		tcphdrlen = thdr -> tcph -> doff * 4;
		payload = dgram + sizeof(struct ip6_hdr) + tcphdrlen;
		psiz = fullsiz - sizeof(struct ip6_hdr) - tcphdrlen;
		if (((opts & MASK) & TCPMASK) == TCPMASK)
			if (!print_tcp_packet(thdr -> tcph, stream))
				return false;
		break;
	case IPPROTO_UDP:
		thdr -> udph = (struct udphdr *) (dgram + sizeof(struct ip6_hdr));
		payload = dgram + sizeof(struct ip6_hdr) + sizeof(struct udphdr);
		psiz = fullsiz - sizeof(struct ip6_hdr) - sizeof(struct udphdr);
		if (((opts & MASK) & UDPMASK) == UDPMASK)
			if (!print_udp_packet(thdr -> udph, stream))
				return false;
		break;
	default:
		payload = NULL;
		psiz = 0;
	}
	if (((opts & MASK) & PMASK) == PMASK)
		if (psiz > 0) {
			if (!print_payload(payload, psiz, stream))
				return false;
		} else
			fprintf(stream, "     EMPTY PACKET PAYLOAD\n\n");
	fprintf(stream, "     ##########END PACKET %d##########\n\n", loop_c);
	free(thdr);
	free(dgram);
	return true;

}

bool process_icmp_packet(char *packet, size_t fullsiz, uint8_t opts, FILE *stream) {

	struct icmphdr *icmph;
	int psiz;
	char *payload;

	if (!stream)
		stream = stdout;
	icmph = (struct icmphdr *) packet;
	payload = packet + sizeof(struct icmphdr);
	psiz = fullsiz - sizeof(struct icmphdr);
	fprintf(stream, "     ##########BEGIN PACKET %d##########\n\n", loop_c++);
	if (((opts & MASK) & ICMPMASK) == ICMPMASK)
		if (!print_icmp_packet(icmph, stream))
			return false;
	if (((opts & MASK) & PMASK) == PMASK)
		if (psiz > 0) {
			if (!print_payload(payload, psiz, stream))
				return false;
		} else
			fprintf(stream, "     EMPTY PACKET PAYLOAD\n\n");
	fprintf(stream, "     ##########END PACKET %d##########\n\n", loop_c);
	free(packet);
	return true;

}

bool process_icmpv6_packet(char *packet, size_t fullsiz, uint8_t opts, FILE *stream) {

	struct icmp6_hdr *icmp6h;
	int psiz;
	char *payload;

	if (!stream)
		stream = stdout;
	icmp6h = (struct icmp6_hdr *) packet;
	payload = packet + sizeof(struct icmp6_hdr);
	psiz = fullsiz - sizeof(struct icmp6_hdr);
	fprintf(stream, "     ##########BEGIN PACKET %d##########\n\n", loop_c++);
	if (((opts & MASK) & ICMPV6MASK) == ICMPV6MASK)
		if (!print_icmpv6_packet(icmp6h, stream))
			return false;
	if (((opts & MASK) & PMASK) == PMASK)
		if (psiz > 0) {
			if (!print_payload(payload, psiz, stream))
				return false;
		} else
			fprintf(stream, "     EMPTY PACKET PAYLOAD\n\n");
	fprintf(stream, "     ##########END PACKET %d##########\n\n", loop_c);
	free(packet);
	return true;

}

bool process_tcp_packet(char *packet, size_t fullsiz, uint8_t opts, FILE *stream) {

	struct tcphdr *tcph;
	int tcphdrlen, psiz;
	char *payload;

	if (!stream)
		stream = stdout;
	tcph = (struct tcphdr *) packet;
	tcphdrlen = tcph -> doff * 4;
	payload = packet + tcphdrlen;
	psiz = fullsiz - tcphdrlen;
	fprintf(stream, "     ##########BEGIN PACKET %d##########\n\n", loop_c++);
	if (((opts & MASK) & TCPMASK) == TCPMASK)
		if (!print_tcp_packet(tcph, stream)) {
			return false;
	}
	if (((opts & MASK) & PMASK) == PMASK)
		if (psiz > 0) {
			if (!print_payload(payload, psiz, stream))
				return false;
		} else
			fprintf(stream, "     EMPTY PACKET PAYLOAD\n\n");
	fprintf(stream, "     ##########END PACKET %d##########\n\n", loop_c);
	free(packet);
	return true;

}

bool process_udp_packet(char *packet, size_t fullsiz, uint8_t opts, FILE *stream) {

	struct udphdr *udph;
	int psiz;
	char *payload;

	if (!stream)
		stream = stdout;
	udph = (struct udphdr *) packet;
	payload = packet + sizeof(struct udphdr);
	psiz = fullsiz - sizeof(struct udphdr);
	fprintf(stream, "     ##########BEGIN PACKET %d##########\n\n", loop_c++);
	if (((opts & MASK) & UDPMASK) == UDPMASK)
		if (!print_udp_packet(udph, stream))
			return false;
	if (((opts & MASK) & PMASK) == PMASK)
		if (psiz > 0) {
			if (!print_payload(payload, psiz, stream))
				return false;
		} else
			fprintf(stream, "     EMPTY PACKET PAYLOAD\n\n");
	fprintf(stream, "     ##########END PACKET %d##########\n\n", loop_c);
	free(packet);
	return true;

}
