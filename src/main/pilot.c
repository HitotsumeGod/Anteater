#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "anteater.h"

int main(void) {

	org_packet *pog;
	int *sock = malloc(sizeof(int)), i;
	char *buf;
	ssize_t sz;

	*sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	i = 0;
	while (1) {
		if ((sz = recv_dgram(&sock, &buf)) == -1) { 
			printf("Error code : %d\n", errno);
			return EXIT_FAILURE;
		}
		if ((pog = organize_dgram(buf, sz)) == NULL) {
			printf("Error code : %d\n", errno);
			return EXIT_FAILURE;
		}
		if (print_dgram(pog, i) == false) {
			printf("Error code : %d\n", errno);
			return EXIT_FAILURE;
		}
		i++;
	}
	free(sock);
	return 0;

}
