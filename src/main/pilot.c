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
	
	if (argc > 1)
		if (SE("-m", argv[1]) != 0) {
			usage();
			return EXIT_FAILURE;
		}
	opts = 0x00;
	memset(&sga, 0, sizeof(sga));
	sga.sa_handler = &sighand;
	if (sigaction(SIGINT, &sga, NULL) == -1) {
		perror("sigact err");
		exit(EXIT_FAILURE);
	}
	for (int i = 3; i < argc; i++)
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
	if (argc == 1 || SE("ether", argv[2]) == 0) {
		if ((sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
			perror("sock err");
			return EXIT_FAILURE;
		}
		while (1) {
			if ((fullsiz = recv_packet(sock, &buf)) == -1) {
				perror("recv_frame err : ");
				return EXIT_FAILURE;
			}
			if (!process_frame(buf, fullsiz, opts, NULL)) {
				perror("print_frame err : ");
				return EXIT_FAILURE;
			}
		}
	} else if (SE("ipv4", argv[2]) == 0) {
		if ((sock = socket(AF_INET, SOCK_RAW, IPPROTO_IP)) == -1) {
			perror("sock err");
			return EXIT_FAILURE;
		}
		while (1) {
			if ((fullsiz = recv_packet(sock, &buf)) == -1) {
				perror("recv_frame err : ");
				return EXIT_FAILURE;
			}
			if (!process_ip_dgram(buf, fullsiz, opts, NULL)) {
				perror("print_frame err : ");
				return EXIT_FAILURE;
			}
		}		
	} else if (SE("ipv6", argv[2]) == 0) {
		if ((sock = socket(AF_INET6, SOCK_RAW, IPPROTO_IPV6)) == -1) {
			perror("sock err");
			return EXIT_FAILURE;
		}
		while (1) {
			if ((fullsiz = recv_packet(sock, &buf)) == -1) {
				perror("recv_frame err : ");
				return EXIT_FAILURE;
			}
			if (!process_ipv6_dgram(buf, fullsiz, opts, NULL)) {
				perror("print_frame err : ");
				return EXIT_FAILURE;
			}
		}		
	} else if (SE("icmp", argv[2]) == 0) {
		if ((sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1) {
			perror("sock err");
			return EXIT_FAILURE;
		}
		while (1) {
			if ((fullsiz = recv_packet(sock, &buf)) == -1) {
				perror("recv_frame err : ");
				return EXIT_FAILURE;
			}
			if (!process_icmp_packet(buf, fullsiz, opts, NULL)) {
				perror("print_frame err : ");
				return EXIT_FAILURE;
			}
		}		
	} else if (SE("icmp6", argv[2]) == 0) {
		if ((sock = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMP)) == -1) {
			perror("sock err");
			return EXIT_FAILURE;
		}
		while (1) {
			if ((fullsiz = recv_packet(sock, &buf)) == -1) {
				perror("recv_frame err : ");
				return EXIT_FAILURE;
			}
			if (!process_icmpv6_packet(buf, fullsiz, opts, NULL)) {
				perror("print_frame err : ");
				return EXIT_FAILURE;
			}
		}		
	} else if (SE("tcp", argv[2]) == 0) {
		if ((sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1) {
			perror("sock err");
			return EXIT_FAILURE;
		}
		while (1) {
			if ((fullsiz = recv_packet(sock, &buf)) == -1) {
				perror("recv_frame err : ");
				return EXIT_FAILURE;
			}
			printf("0x%02X\n", opts);
			if (!process_tcp_packet(buf, fullsiz, opts, NULL)) {
				perror("print_frame err : ");
				return EXIT_FAILURE;
			}
		}		
	} else if (SE("tcp6", argv[2]) == 0) {
		if ((sock = socket(AF_INET6, SOCK_RAW, IPPROTO_TCP)) == -1) {
			perror("sock err");
			return EXIT_FAILURE;
		}
		while (1) {
			if ((fullsiz = recv_packet(sock, &buf)) == -1) {
				perror("recv_frame err : ");
				return EXIT_FAILURE;
			}
			if (!process_tcp_packet(buf, fullsiz, opts, NULL)) {
				perror("print_frame err : ");
				return EXIT_FAILURE;
			}
		}		
	} else if (SE("udp", argv[2]) == 0) {
		if ((sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP)) == -1) {
			perror("sock err");
			return EXIT_FAILURE;
		}
		while (1) {
			if ((fullsiz = recv_packet(sock, &buf)) == -1) {
				perror("recv_frame err : ");
				return EXIT_FAILURE;
			}
			if (!process_udp_packet(buf, fullsiz, opts, NULL)) {
				perror("print_frame err : ");
				return EXIT_FAILURE;
			}
		}		
	} else if (SE("udp6", argv[2]) == 0) {
		if ((sock = socket(AF_INET6, SOCK_RAW, IPPROTO_UDP)) == -1) {
			perror("sock err");
			return EXIT_FAILURE;
		}
		while (1) {
			if ((fullsiz = recv_packet(sock, &buf)) == -1) {
				perror("recv_frame err : ");
				return EXIT_FAILURE;
			}
			if (!process_udp_packet(buf, fullsiz, opts, NULL)) {
				perror("print_frame err : ");
				return EXIT_FAILURE;
			}
		}
	}
	return 0;

}
