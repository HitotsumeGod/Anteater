#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/ether.h>
#include "anteater.h"

int main(void) {

	char *buf;
	int sock;
	ssize_t fullsiz;

	int i = 0;
	if ((sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
		errno = SOCKET_ERR;
		return -1;
	}
	while (i++ < 50) {
		if ((fullsiz = recv_frame(sock, &buf)) == -1) {
			printf("Error 1 : %d\n", errno);
			return -1;
		}
		if (!print_frame(buf, fullsiz)) {
			printf("Error 2 : %d\n", errno);
			return -1;
		}
	}
	return 0;

}
