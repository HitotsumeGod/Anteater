#ifndef __NETSTRUCTS_H__
#define __NETSTRUCTS_H__

#include "winheaders.h"

#define ETH_ALEN		6
#define ETH_P_IP 		0x0800
#define ETH_P_IPV6 		0x86DD
#define ETH_P_SONOS 		0x6970
#define ETH_P_ALL 		0x0003
#define IPPROTO_IP 		0
#define IPPROTO_TCP 		6
#define IPPROTO_UDP 		17
#define ICMP_ECHOREPLY		0	/* Echo Reply			*/
#define ICMP_DEST_UNREACH	3	/* Destination Unreachable	*/
#define ICMP_SOURCE_QUENCH	4	/* Source Quench		*/
#define ICMP_REDIRECT		5	/* Redirect (change route)	*/
#define ICMP_ECHO		8	/* Echo Request			*/
#define ICMP_TIME_EXCEEDED	11	/* Time Exceeded		*/
#define ICMP_PARAMETERPROB	12	/* Parameter Problem		*/
#define ICMP_TIMESTAMP		13	/* Timestamp Request		*/
#define ICMP_TIMESTAMPREPLY	14	/* Timestamp Reply		*/
#define ICMP_INFO_REQUEST	15	/* Information Request		*/
#define ICMP_INFO_REPLY		16	/* Information Reply		*/
#define ICMP_ADDRESS		17	/* Address Mask Request		*/
#define ICMP_ADDRESSREPLY	18	/* Address Mask Reply		*/
#define ICMP6_DST_UNREACH       1
#define ICMP6_PACKET_TOO_BIG    2
#define ICMP6_TIME_EXCEEDED     3
#define ICMP6_PARAM_PROB        4
#define ICMP6_ECHO_REQUEST      128
#define ICMP6_ECHO_REPLY        129
#define MLD_LISTENER_QUERY      130
#define MLD_LISTENER_REPORT     131
#define MLD_LISTENER_REDUCTION  132
#define ICMPV6_EXT_ECHO_REQUEST	160
#define ICMPV6_EXT_ECHO_REPLY	161

struct ethhdr {
	UCHAR h_dest[ETH_ALEN];
	UCHAR h_source[ETH_ALEN];
	WORD  h_proto;
};

struct iphdr {
	UINT32 ihl:4;
	UINT32 version:4;
	UINT8  tos;
	UINT16 tot_len;
	UINT16 id;
	UINT16 frag_off;
	UINT8  ttl;
	UINT8  protocol;
	UINT16 check;
	UINT32 saddr;
	UINT32 daddr;
};

struct ip6_hdr
  {
    union
      {
	struct ip6_hdrctl
	  {
	    UINT32 ip6_un1_flow;   /* 4 bits version, 8 bits TC,
					20 bits flow-ID */
	    UINT16 ip6_un1_plen;   /* payload length */
	    UINT8  ip6_un1_nxt;    /* next header */
	    UINT8  ip6_un1_hlim;   /* hop limit */
	  } ip6_un1;
	UINT8 ip6_un2_vfc;       /* 4 bits version, top 4 bits tclass */
      } ip6_ctlun;
    UINT8 ip6_src[16];      /* source address */
    UINT8 ip6_dst[16];      /* destination address */
  };

#define ip6_vfc   ip6_ctlun.ip6_un2_vfc
#define ip6_flow  ip6_ctlun.ip6_un1.ip6_un1_flow
#define ip6_plen  ip6_ctlun.ip6_un1.ip6_un1_plen
#define ip6_nxt   ip6_ctlun.ip6_un1.ip6_un1_nxt
#define ip6_hlim  ip6_ctlun.ip6_un1.ip6_un1_hlim
#define ip6_hops  ip6_ctlun.ip6_un1.ip6_un1_hlim

struct tcphdr {
	UINT16 th_sport;
	UINT16 th_dport;
	UINT32 th_seq;
	UINT32 th_ack;
	UINT8 th_x2:4;
	UINT8 th_off:4;
	UINT8 th_flags;
	UINT16 th_win;
	UINT16 th_sum;
	UINT16 th_urp;
	UINT16 res1:4;
	UINT16 doff:4;
	UINT16 fin:1;
	UINT16 syn:1;
	UINT16 rst:1;
	UINT16 psh:1;
	UINT16 ack:1;
	UINT16 urg:1;
	UINT16 res2:2;
};

struct udphdr {
	UINT16 uh_sport;
	UINT16 uh_dport;
	UINT16 uh_ulen;
	UINT16 uh_sum;
};

#endif //__NETSTRUCTS_H__
