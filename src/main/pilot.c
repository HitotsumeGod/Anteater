#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "anteater.h"

void sighand(int signal);

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
	
	opts = 0x00;
	memset(&sga, 0, sizeof(sga));
	sga.sa_handler = &sighand;
	if (sigaction(SIGINT, &sga, NULL) == -1) {
		perror("sigact err");
		exit(EXIT_FAILURE);
	}
	if ((sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
		errno = SOCKET_ERR;
		return EXIT_FAILURE;
	}
	for (int i = 1; i < argc; i++)
		if (strcmp("-all", argv[i]) == 0) {
			opts = MASK;
			break;
		} else if (strcmp("-ip", argv[i]) == 0)
			opts |= IPMASK;
		else if (strcmp("-ip6", argv[i]) == 0)
			opts |= IPV6MASK;
		else if (strcmp("-icmp", argv[i]) == 0)
			opts |= ICMPMASK;
		else if (strcmp("-icmp6", argv[i]) == 0)
			opts |= ICMPV6MASK;
		else if (strcmp("-tcp", argv[i]) == 0)
			opts |= TCPMASK;
		else if (strcmp("-udp", argv[i]) == 0)
			opts |= UDPMASK;
		else if (strcmp("-p", argv[i]) == 0)
			opts |= PMASK;
		else if (strcmp("-min", argv[i]) == 0) {
			while (1) {
				if ((fullsiz = recv_frame(sock, &buf)) == -1) {
					perror("recv_frame err : ");
					return EXIT_FAILURE;
				}
				if (!print_minimal(buf)) {
					perror("print_min err : ");
					return EXIT_FAILURE;
				}
			}
			return 0;
		}
	while (1) {
		if ((fullsiz = recv_frame(sock, &buf)) == -1) {
			perror("recv_frame err : ");
			return EXIT_FAILURE;
		}
		if (!print_frame(buf, fullsiz, opts)) {
			perror("print_frame err : ");
			return EXIT_FAILURE;
		}
	}
	return 0;

}
