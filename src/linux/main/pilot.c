#include "anteater.h"

#ifdef _STRING_H
#define SE(s, b) strcmp(s, b)
#endif

int print_help(void);
void sighand(int signal);

int print_help(void)
{
	printf("     %s\n", "Options are:");
	printf("     %s\n", "Packet Types: -all, -ip, -ipv6, -icmp, -icmpv6, -tcp, -udp");
	printf("     %s\n", "Output: -file <output file>");
	printf("\n");
	return EXIT_FAILURE;
}

void sighand(int sig)
{
	if (sig == SIGINT)
		exit(EXIT_SUCCESS);
}

int main(int argc, char *argv[])
{
	struct pframe *res;
	int sock, total;
	char *buf;
	ssize_t fullsiz;
	uint8_t type;
	struct sigaction sga;
	FILE *ff;
	bool bare;

	fprintf(stdout, "\n     ~~~%s~~~\n\n", PROG_VERS);
	if (argc > 4)
		return print_help();
	if (getuid() != 0) {
		fprintf(stdout, "     \x1B[1mTERMINAL ERROR:\x1B[0m\n");
		fprintf(stdout, "     This program MUST be ran as root to work!!!\n");
		fprintf(stdout, "     Don't believe me? Feel free to look up \"raw sockets require root\".\n");
		fprintf(stdout, "     Please run with root privileges next time!\n\n");
		return EXIT_FAILURE;
	}
	ff = stdout;
	bare = false;
	total = 1;
	if (argc == 1)
		type = ETHMASK;
	else {
		if (SE(argv[1], "-all") == 0 || SE(argv[1], "-eth") == 0)
			type = ETHMASK;
		else if (SE(argv[1], "-ip") == 0)
			type = IPMASK;
		else if (SE(argv[1], "-ipv6") == 0)
			type = IPV6MASK;
		else if (SE(argv[1], "-icmp") == 0)
			type = ICMPMASK;
		else if (SE(argv[1], "-icmpv6") == 0)
			type = ICMPV6MASK;
		else if (SE(argv[1], "-tcp") == 0)
			type = TCPMASK;
		else if (SE(argv[1], "-udp") == 0)
			type = UDPMASK;
		else
			type = 0x00;
		for (int i = 0; i < argc; i++)
			if (SE(argv[i], "-bare") == 0) {
				bare = true;
				break;
			}
	}
	if (argc == 2) {
		if (SE(argv[1], "-file") == 0)
			return print_help();
	} else if (argc == 3) {
		if (SE(argv[1], "-file") == 0) {
			if ((ff = fopen(argv[2], "w")) == NULL) {
				perror("fopen err");
				return EXIT_FAILURE;
			}
			type = ETHMASK;
		} else if (SE(argv[2], "-file") == 0)
			return print_help();
	} else if (argc == 4) {
		if (SE(argv[2], "-file") == 0) {
			if ((ff = fopen(argv[3], "w")) == NULL) {
				perror("fopen err");
				return EXIT_FAILURE;
			}
			type = ETHMASK;		
		}
	}
	memset(&sga, 0, sizeof(sga));
	sga.sa_handler = &sighand;
	if (sigaction(SIGINT, &sga, NULL) == -1) {
		perror("sigact err");
		exit(EXIT_FAILURE);
	}
	if ((sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
		perror("sock err");
		return EXIT_FAILURE;
	}
	while (true) {
		if ((fullsiz = recv_packet(sock, &buf)) == -1) {
			fprintf(stderr, "recv_packet error : %d\n", errno);
			return EXIT_FAILURE;
		}
		if ((res = process_frame(buf, fullsiz, type, ff)) == NULL) {
			fprintf(stderr, "process_frame err : %d\n", errno);
			return EXIT_FAILURE;
		}
		if (type & res -> nature) {
			fprintf(ff, "     ##########BEGIN PACKET %d##########\n\n", total);
			if (bare) {
				if (!print_bare(buf, fullsiz, ff)) {
					fprintf(stderr, "print_bare error : %d\n", errno);
					return EXIT_FAILURE;
				}
			} else {
				if (!print_frame(res -> ethh, ff))
					return EXIT_FAILURE;
				if (res -> nature & IPMASK) {
					if (!print_ip_dgram(res -> nhdr -> iph, ff))
						return EXIT_FAILURE;
					if (res -> nature & ICMPMASK)
						if (!print_icmp_packet(res -> thdr -> icmph, ff))
							return EXIT_FAILURE;
				} else if (res -> nature & IPV6MASK) {
					if (!print_ipv6_dgram(res -> nhdr -> ip6h, ff))
						return EXIT_FAILURE;
					if (res -> nature & ICMPV6MASK)
						if (!print_icmpv6_packet(res -> thdr -> icmp6h, ff))
							return EXIT_FAILURE;
				}
				if (res -> nature & TCPMASK) {
					if (!print_tcp_packet(res -> thdr -> tcph, ff))
						return EXIT_FAILURE;
				} else if (res -> nature & UDPMASK) {
					if (!print_udp_packet(res -> thdr -> udph, ff))
						return EXIT_FAILURE;
				}
				if (res -> psiz > 0) {
					if (!print_payload(res -> payload, res -> psiz, ff))
						return EXIT_FAILURE;
				} else
					fprintf(ff, "     EMPTY PACKET PAYLOAD\n\n");
			}
			fprintf(ff, "     ##########END PACKET %d##########\n\n", total++);
			fprintf(ff, "     ---------------------------------\n\n");
		}
		free(res -> ethh);
		free(res -> nhdr);
		free(res -> thdr);
		free(res);
	}
	return 0;
}
