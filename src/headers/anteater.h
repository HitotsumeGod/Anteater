#ifndef __ANTEATER_H__
#define __ANTEATER_H__

#include <stddef.h>
#include <stdbool.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include "pec/commonerrors.h"
#include "pec/socketerrors.h"

#define MAXBUF 65535
#define PAYLOAD_SPACING 18

typedef struct {
	struct iphdr *iph;
	struct tcphdr *tcph;
	char *payload;
	size_t psiz;
} org_packet;

extern ssize_t receive_packet(int **ref_socket, char **ref_buffer);
extern org_packet *organize_packet(char *buffer, ssize_t bufsiz);
extern bool print_packet(org_packet *packet, int iteration);
extern bool dump_packet(char *buffer);

#endif //__ANTEATER_H__
