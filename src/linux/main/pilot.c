#include "anteater.h"

#ifdef _STRING_H
#define SE(s, b) strcmp(s, b)
#endif

int print_help(void);
void sighand(int signal);

int print_help(void)
{
	printf("     %s\n", "Options are:");
	printf("     %s\n", "Packet Types: -all, -ip, -ipv6, -icmp, -icmpv6, -tcp, -udp");
	printf("     %s\n", "Output: -file <output file>");
	printf("\n");
	return EXIT_FAILURE;
}

void sighand(int sig)
{
	if (sig == SIGINT)
		exit(EXIT_SUCCESS);
}

int main(int argc, char *argv[])
{
	int sock, control;
	char *buf;
	ssize_t fullsiz;
	uint8_t type;
	struct sigaction sga;
	FILE *ff;

	fprintf(stdout, "\n     ~~~%s~~~\n\n", PROG_VERS);
	if (argc > 4)
		return print_help();
	if (getuid() != 0) {
		fprintf(stdout, "     \x1B[1mTERMINAL ERROR:\x1B[0m\n");
		fprintf(stdout, "     This program MUST be ran as root to work!!!\n");
		fprintf(stdout, "     Don't believe me? Feel free to look up \"raw sockets require root\".\n");
		fprintf(stdout, "     Please run with root privileges next time!\n\n");
		return EXIT_FAILURE;
	}
	ff = stdout;
	if (argc == 1)
		type = ETHMASK;
	else {
		if (SE(argv[1], "-all") == 0 || SE(argv[1], "-eth") == 0)
			type = ETHMASK;
		else if (SE(argv[1], "-ip") == 0)
			type = IPMASK;
		else if (SE(argv[1], "-ipv6") == 0)
			type = IPV6MASK;
		else if (SE(argv[1], "-icmp") == 0)
			type = ICMPMASK;
		else if (SE(argv[1], "-icmpv6") == 0)
			type = ICMPV6MASK;
		else if (SE(argv[1], "-tcp") == 0)
			type = TCPMASK;
		else if (SE(argv[1], "-udp") == 0)
			type = UDPMASK;
		else
			type = 0x00;
	}
	if (argc == 2) {
		if (SE(argv[1], "-file") == 0)
			return print_help();
	} else if (argc == 3) {
		if (SE(argv[1], "-file") == 0) {
			if ((ff = fopen(argv[2], "w")) == NULL) {
				perror("fopen err");
				return EXIT_FAILURE;
			}
			type = ETHMASK;
		} else if (SE(argv[2], "-file") == 0)
			return print_help();
	} else if (argc == 4) {
		if (SE(argv[2], "-file") == 0) {
			if ((ff = fopen(argv[3], "w")) == NULL) {
				perror("fopen err");
				return EXIT_FAILURE;
			}
			type = ETHMASK;		
		}
	}
	memset(&sga, 0, sizeof(sga));
	sga.sa_handler = &sighand;
	if (sigaction(SIGINT, &sga, NULL) == -1) {
		perror("sigact err");
		exit(EXIT_FAILURE);
	}
	if ((sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
		perror("sock err");
		return EXIT_FAILURE;
	}
	control = 10;
	//set control to decrement to test with valgrind memcheck
	while (control++) {
		if ((fullsiz = recv_packet(sock, &buf)) == -1) {
			perror("recv_frame err : ");
			return EXIT_FAILURE;
		}
		if (!process_frame(buf, fullsiz, type, ff)) {
			perror("print_frame err : ");
			return EXIT_FAILURE;
		}
	}
	return 0;
}
