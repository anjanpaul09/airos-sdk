#ifndef PROTO_DHCP_H
#define PROTO_DHCP_H

#include <linux/types.h>

#define BOOTP_OPCODE_REQ        1
#define BOOTP_OPCODE_REPLY      2

#define BOOTP_HWTYPE_ETHERNET   1

#define DHCP_OPTION_PAD         0
#define DHCP_OPTION_HOSTNAME    12
#define DHCP_OPTION_LEASE_TIME  51
#define DHCP_OPTION_MSG_TYPE    53
#define DHCP_OPTION_REQ_PARAM   55
#define DHCP_OPTION_RELAYAGENT  82
#define DHCP_OPTION_END         255

#define DHCP_MSG_TYPE_DISCOVER  1
#define DHCP_MSG_TYPE_OFFER     2
#define DHCP_MSG_TYPE_REQUEST   3
#define DHCP_MSG_TYPE_DECLINE   4
#define DHCP_MSG_TYPE_ACK       5
#define DHCP_MSG_TYPE_NACK      6
#define DHCP_MSG_TYPE_RELEASE   7
#define DHCP_MSG_TYPE_INFORM    8

#define DHCP_MAGIC_COOKIE       "\x63\x82\x53\x63"

struct dhcp_hdr {
    uint8_t opcode;
    uint8_t hwtype;
    uint8_t hwlen;
    uint8_t hops;
    uint32_t tid;
    uint16_t sec;
    uint16_t flags;
    uint8_t ciaddr[4];
    uint8_t yiaddr[4];
    uint8_t siaddr[4];
    uint8_t giaddr[4];
    uint8_t chaddr[16];
    uint8_t sname[64];
    uint8_t file[128];
    uint8_t magic[4];
    uint8_t options[];
} __attribute__ ((packed));

#endif /* PROTO_DHCP_H */
