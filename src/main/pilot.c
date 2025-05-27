#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "anteater.h"

int main(void) {

	org_packet *pog;
	int *sock = malloc(sizeof(int)), i;
	char *buf;
	ssize_t sz;

	*sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	i = 0;
	while (i < 5) {
		if ((sz = receive_packet(&sock, &buf)) == -1) { 
			printf("Error code : %d\n", errno);
			return EXIT_FAILURE;
		}
		if ((pog = organize_packet(buf, sz)) == NULL) {
			printf("Error code : %d\n", errno);
			return EXIT_FAILURE;
		}
		if (print_packet(pog, i) == false) {
			printf("Error code : %d\n", errno);
			return EXIT_FAILURE;
		}
		i++;
	}
	free(sock);
	return 0;

}
