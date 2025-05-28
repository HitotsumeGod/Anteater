#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>

#define HOST "google.com"
#define PORT "80"

int main(void) {

	struct addrinfo sai, *spai;
	char *msg, recvbuf[10000];
	int sock;
	size_t b;
	
	msg = "GET /index.html HTTP/1.1\r\nHost: www.google.com\r\nConnection: close\r\n\r\n";
	memset(&sai, 0, sizeof(sai));
	sai.ai_family = AF_INET;
	sai.ai_socktype = SOCK_STREAM;
	getaddrinfo(HOST, PORT, &sai, &spai);
	sock = socket(spai -> ai_family, spai -> ai_socktype, spai -> ai_protocol);
	connect(sock, spai -> ai_addr, spai -> ai_addrlen);
	freeaddrinfo(spai);
	send(sock, msg, strlen(msg), 0);
	b = recv(sock, recvbuf, sizeof(recvbuf), 0);
	for (int i = 0; i < b; i++)
		printf("%c", recvbuf[i]);
	return 0;

}
