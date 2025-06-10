#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "anteater.h"

#ifdef _STRING_H
#define SE(s, b) strcmp(s, b)
#endif

void usage(void);
void sighand(int signal);

void usage(void) {

	printf("Usage err\n");

}

void sighand(int sig) {

	if (sig == SIGINT)
		exit(EXIT_SUCCESS);

}

int main(int argc, char *argv[]) {

	int sock;
	char *buf;
	ssize_t fullsiz;
	uint8_t opts;
	struct sigaction sga;
	
	int ii = 0;
	opts = 0x00;
	memset(&sga, 0, sizeof(sga));
	sga.sa_handler = &sighand;
	if (sigaction(SIGINT, &sga, NULL) == -1) {
		perror("sigact err");
		exit(EXIT_FAILURE);
	}
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
	if ((sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
		perror("sock err");
		return EXIT_FAILURE;
	}
	while (ii++ < 20) {
		if ((fullsiz = recv_packet(sock, &buf)) == -1) {
			perror("recv_frame err : ");
			return EXIT_FAILURE;
		}
		if (!process_frame(buf, fullsiz, opts, NULL)) {
			perror("print_frame err : ");
			return EXIT_FAILURE;
		}
	}
	return 0;

}
