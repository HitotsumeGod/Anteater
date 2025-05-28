#ifndef __ANTEATER_H__
#define __ANTEATER_H__

#include <stddef.h>
#include <stdbool.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include "pec/commonerrors.h"
#include "pec/socketerrors.h"

#define MAXBUF 65535
#define PAYLOAD_SPACING 18

typedef struct {
	struct ethhdr *ethh;
	struct iphdr *iph;
	struct tcphdr *tcph;
	struct udphdr *udph;
	char *payload;
	size_t psiz;
} org_packet;

extern bool dump_hex(FILE *dumpfile, char *dump, size_t dumpsz);
extern bool dump_text(FILE *dumpfile, char *dump, size_t dumpsz);

#endif //__ANTEATER_H__
