#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "anteater.h"

#define fname "hexdumps"

void dump(FILE *fp, char *todump, size_t dumpsize);
void dump_pr(FILE *fp, char *todump, size_t dumpsize);
void sighand(int signal);

void dump(FILE *fp, char *buf, size_t dumpsiz) {

	int counter = 0;
	
	for (int i = 0; i < dumpsiz; i++) {
		if (counter == i - PAYLOAD_SPACING) {
			fprintf(fp, "\n");
			counter = i;
		}
		fprintf(fp, "%02X ", (unsigned char) *(buf + i));
	}

}

void dump_pr(FILE *fp, char *buf, size_t dumpsiz) {

	fprintf(fp, "\t");
	for (int i = 0; i < dumpsiz; i++) 
		if (fprintf(fp, "%c", *(buf + i)) == -1) {
			perror("fprintf err");
			exit(EXIT_FAILURE);
		}
	fprintf(fp, "\n");

}

void sighand(int sig) {

	if (sig == SIGINT) {
		exit(EXIT_SUCCESS);
	}

}

int main(int argc, char *argv) {

	FILE *ff;
	org_packet *o;
	struct sigaction sga;
	struct sockaddr_in src, dest;
	struct sockaddr_storage ss;
	socklen_t ss_siz;
	ssize_t full_siz, iphdrlen, tcphdrlen;
	int rsock, loop_c, counter, icmp, isp, tcp, udp, nohop, smp, http;
	char *tbuf, minibuf[3], hostbuf[100], buf[MAXBUF], dummy[INET_ADDRSTRLEN];

	memset(&sga, 0, sizeof(sga));
	sga.sa_handler = &sighand;
	if (sigaction(SIGINT, &sga, NULL) == -1) {
		perror("sigact err");
		exit(EXIT_FAILURE);
	}
	if ((ff = fopen(fname, "w")) == NULL) {
		perror("fopen err");
		return EXIT_FAILURE;
	}
	if ((rsock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
		perror("sock err");
		return EXIT_FAILURE;
	}
	ss_siz = sizeof(ss);
	icmp = isp = tcp = udp = nohop = smp = http = loop_c = 0;
	memset(hostbuf, 0, sizeof(hostbuf));
	while (1) {
		if ((o = malloc(sizeof(org_packet))) == NULL) {
			perror("malloc err");
			return EXIT_FAILURE;
		}
		if ((full_siz = recvfrom(rsock, buf, sizeof(buf), 0, (struct sockaddr *) &ss, &ss_siz)) < 0) {
			perror("recv err");
			return EXIT_FAILURE;
		}
		o -> ethh = (struct ethhdr *) buf;
		o -> iph = (struct iphdr *) (buf + sizeof(struct ethhdr));
		iphdrlen = o -> iph -> ihl * 4;
		src.sin_addr.s_addr = o -> iph -> saddr;
		dest.sin_addr.s_addr = o -> iph -> daddr;
		switch (o -> iph -> protocol) {
		case 1:
			icmp++;
			o -> tcph = NULL;
			o -> udph = NULL;
			o -> payload = NULL;
			o -> psiz = 0;
			break;
		case 5:
			isp++;
			o -> tcph = NULL;
			o -> udph = NULL;
			o -> payload = NULL;
			o -> psiz = 0;
			break;
		case 6:
			tcp++;
			o -> udph = NULL;
			o -> tcph = (struct tcphdr *) (buf + sizeof(struct ethhdr) + iphdrlen);
			tcphdrlen = o -> tcph -> doff * 4;
			o -> payload = buf + sizeof(struct ethhdr) + iphdrlen + tcphdrlen;
			o -> psiz = full_siz - sizeof(struct ethhdr) - iphdrlen - tcphdrlen;
			for (int i = 0, ii = 0; i < o -> psiz; i++) 
				if (buf[i] == 'H' && buf[i+1] == 'o' && buf[i+2] == 's' && buf[i+3] == 't') {
					if (http > 4)
						exit(EXIT_SUCCESS);
					http++;
					tbuf = buf + i;
					while (*tbuf != '\r')
						hostbuf[ii++] = *tbuf++;
					fprintf(ff, "From %s\n", inet_ntop(AF_INET, &(src.sin_addr), dummy, sizeof(dummy)));
					dump_pr(ff, hostbuf, ii);
				}
			break;
		case 17:
			udp++;
			o -> tcph = NULL;
			o -> udph = (struct udphdr *) (buf + sizeof(struct ethhdr) + iphdrlen);
			o -> payload = buf + sizeof(struct ethhdr) + iphdrlen + sizeof(struct udphdr);
			o -> psiz = full_siz - sizeof(struct ethhdr) - iphdrlen - sizeof(struct udphdr);
			break;
		case 114:
			nohop++;
			break;
		case 121:
			smp++;
			break;
		}
		printf("Total Packets Received: %d   HTTP Packets Received %d\r", icmp + isp + tcp + udp + nohop + smp, http);
		free(o);
		loop_c++;
	}
	return 0;

}
