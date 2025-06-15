#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include "anteater.h"

#ifdef _STRING_H
#define SE(s, b) strcmp(s, b)
#endif

int main(int argc, char *argv[]) {

	int sock;
	char *buf;
	ssize_t fullsiz;
	uint8_t opts;
	FILE *ff;

	fprintf(stdout, "\n     ~~~%s~~~\n\n", PROG_VERS);
	if (1) {
		fprintf(stdout, "     \x1B[1mTERMINAL ERROR:\x1B[0m\n");
		fprintf(stdout, "     This program MUST be ran as root to work!!!\n");
		fprintf(stdout, "     Don't believe me? Feel free to look up \"raw sockets require root\".\n");
		fprintf(stdout, "     Please run with root privileges next time!\n\n");
		return EXIT_FAILURE;
	}
	ff = NULL;
	opts = 0x00;
	for (int i = 1; i < argc; i++)
		if (SE("-all", argv[i]) == 0) {
			opts = MASK;
			break;
		} else if (SE("-ip", argv[i]) == 0)
			opts |= IPMASK;
		else if (SE("-ip6", argv[i]) == 0)
			opts |= IPV6MASK;
		else if (SE("-icmp", argv[i]) == 0)
			opts |= ICMPMASK;
		else if (SE("-icmp6", argv[i]) == 0)
			opts |= ICMPV6MASK;
		else if (SE("-tcp", argv[i]) == 0)
			opts |= TCPMASK;
		else if (SE("-udp", argv[i]) == 0)
			opts |= UDPMASK;
		else if (SE("-p", argv[i]) == 0)
			opts |= PMASK;
		else if (SE("-eth", argv[i]) == 0)
			opts |= ETHMASK;
		else if (SE("-file", argv[i]) == 0)
			if ((ff = fopen(argv[++i], "w")) == NULL) {
				perror("fopen err");
				return EXIT_FAILURE;
			}
	if ((sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
		perror("sock err");
		return EXIT_FAILURE;
	}
	while (1) {
		if ((fullsiz = recv_packet(sock, &buf)) == -1) {
			perror("recv_frame err : ");
			return EXIT_FAILURE;
		}
		if (!process_frame(buf, fullsiz, opts, ff)) {
			perror("print_frame err : ");
			return EXIT_FAILURE;
		}
	}
	return 0;

}
