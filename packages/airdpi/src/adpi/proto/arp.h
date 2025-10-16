#ifndef PROTO_ARP_H
#define PROTO_ARP_H

#include <linux/types.h>

#define ARP_HWTYPE_ETHERNET 1
#define ARP_PROTO_IP        0x800

#define ARP_HWLEN_IPv4      4

#define ARP_OPCODE_REQ      1
#define ARP_OPCODE_REPLY    2

struct arp_hdr {
    uint16_t hw_type;
    uint16_t proto;
    uint8_t hw_len;
    uint8_t proto_len;
    uint16_t opcode;
} __attribute__ ((packed));

/* ARP packet used for IPv4 */
struct arp_ipv4_pkt {
    struct arp_hdr hdr;
    uint8_t src_mac[MAC_ADDR_LEN];
    uint32_t sip;
    uint8_t target_mac[MAC_ADDR_LEN];
    uint32_t tip;
} __attribute ((packed));
#endif /*PROTO_ARP_H*/
