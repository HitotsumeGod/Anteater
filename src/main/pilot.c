#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "anteater.h"

int main(int argc, char *argv[]) {

	char *buf;
	int sock;
	ssize_t fullsiz;

	int ii = 0;
	struct friggin_packet_options_yo sw = { false, false, false, false, false, false, false, false, false };
	for (int i = 1; i < argc; i++)
		if (strcmp("-all", argv[i]) == 0) {
			sw.print_all = true;
			break;
		} else if (strcmp("-ip", argv[i]) == 0)
			sw.print_ip = true;
		else if (strcmp("-ip6", argv[i]) == 0)
			sw.print_ipv6 = true;
		else if (strcmp("-icmp", argv[i]) == 0)
			sw.print_icmp = true;
		else if (strcmp("-icmp6", argv[i]) == 0)
			sw.print_icmpv6 = true;
		else if (strcmp("-tcp", argv[i]) == 0)
			sw.print_tcp = true;
		else if (strcmp("-udp", argv[i]) == 0)
			sw.print_udp = true;
		else if (strcmp("-p", argv[i]) == 0)
			sw.print_payload = true;
	if ((sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
		errno = SOCKET_ERR;
		return -1;
	}
	while (1) {
		if ((fullsiz = recv_frame(sock, &buf)) == -1) {
			printf("Error 1 : %d\n", errno);
			return -1;
		}
		if (!print_frame(buf, fullsiz, &sw)) {
			printf("Error 2 : %d\n", errno);
			return -1;
		}
	}
	return 0;

}
