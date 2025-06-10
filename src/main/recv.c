#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "anteater.h"

ssize_t recv_packet(int sock, char **buf) {

	char *recvbuf;
	ssize_t frame_siz;

	if (sock <= 0) {
		errno = SOCKET_ERR;
		return EXIT_FAILURE;
	}
	if ((recvbuf = malloc(sizeof(char) * MAXBUF)) == NULL) {
		errno = MALLOC_ERR;
		return EXIT_FAILURE;
	}
	if ((frame_siz = recvfrom(sock, recvbuf, MAXBUF, 0, NULL, NULL)) == -1) {
		errno = RECV_ERR;
		return EXIT_FAILURE;
	}
	*buf = recvbuf;
	return frame_siz;

}