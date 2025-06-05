#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "anteater.h"

ssize_t recv_frame(int sock, char **buf) {

	char *recvbuf;
	ssize_t frame_siz;

	if (!sock) 
		if ((sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
			errno = SOCKET_ERR;
			return -1;
		}
	if ((recvbuf = malloc(sizeof(char) * MAXBUF)) == NULL) {
		errno = MALLOC_ERR;
		return -1;
	}
	if ((frame_siz = recvfrom(sock, recvbuf, MAXBUF, 0, NULL, NULL)) == -1) {
		printf("%d\n", errno);
		errno = RECV_ERR;
		return -1;
	}
	*buf = recvbuf;
	return frame_siz;

}

ssize_t recv_dgram(int sock, enum network_t net, char **buf) {
	
	char *recvbuf;
	ssize_t dgram_siz;

	if (!socket) 
		switch (net) {
		case IPV4:
			if ((sock = socket(AF_INET, SOCK_RAW, 0)) == -1) {
				errno = SOCKET_ERR;
				return -1;
			}
			break;
		case IPV6:
			if ((sock = socket(AF_INET6, SOCK_RAW, 0)) == -1) {
				errno = SOCKET_ERR;
				return -1;
			}
			break;
		default:
			errno = BAD_ARGS_ERR;
			return -1;
		}
	if ((recvbuf = malloc(sizeof(char) * MAXBUF)) == NULL) {
		errno = MALLOC_ERR;
		return -1;
	}
	if ((dgram_siz = recvfrom(sock, recvbuf, MAXBUF, 0, NULL, NULL)) < 0) {
		errno = RECV_ERR;
		return -1;
	}
	*buf = recvbuf;
	return dgram_siz;

}

ssize_t recv_packet_ip(int sock, enum transport_t trans, char **buf) {

	char *recvbuf;
	ssize_t packet_siz;

	if (!socket) 
		switch (trans) {
		case TCP:
			if ((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
				errno = SOCKET_ERR;
				return -1;
			}
			break;
		case UDP:
			if ((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
				errno = SOCKET_ERR;
				return -1;
			}
			break;
		default:
			errno = BAD_ARGS_ERR;
			return -1;
		}
	if ((recvbuf = malloc(sizeof(char) * MAXBUF)) == NULL) {
		errno = MALLOC_ERR;
		return -1;
	}
	if ((packet_siz = recvfrom(sock, recvbuf, MAXBUF, 0, NULL, NULL)) < 0) {
		errno = RECV_ERR;
		return -1;
	}
	*buf = recvbuf;
	return packet_siz;


}

ssize_t recv_packet_ip6(int sock, enum transport_t trans, char **buf) {

	char *recvbuf;
	ssize_t packet_siz;

	if (!socket) 
		switch (trans) {
		case TCP:
			if ((sock = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP)) == -1) {
				errno = SOCKET_ERR;
				return -1;
			}
			break;
		case UDP:
			if ((sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
				errno = SOCKET_ERR;
				return -1;
			}
			break;
		default:
			errno = BAD_ARGS_ERR;
			return -1;
		}
	if ((recvbuf = malloc(sizeof(char) * MAXBUF)) == NULL) {
		errno = MALLOC_ERR;
		return -1;
	}
	if ((packet_siz = recvfrom(sock, recvbuf, MAXBUF, 0, NULL, NULL)) < 0) {
		errno = RECV_ERR;
		return -1;
	}
	*buf = recvbuf;
	return packet_siz;

}
