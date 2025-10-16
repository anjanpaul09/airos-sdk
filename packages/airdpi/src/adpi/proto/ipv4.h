#ifndef PROTO_IPv4_H
#define PROTO_IPv4_H

#define IPv4_ADDR_LEN   4

#define IP_PROTO_ICMP    1
#define IP_PROTO_IGMP    2
#define IP_PROTO_TCP     6
#define IP_PROTO_UDP     17

#define IPV4_DF 0x4000
#define IPV4_MF 0x2000

/* IP options */
#define IPOPT_COPY		0x80
#define	IPOPT_CONTROL		0x00
#
#define IPOPT_RA	(20|IPOPT_CONTROL|IPOPT_COPY)

struct ipv4_hdr {
#ifdef __KERNEL__
#if defined(__LITTLE_ENDIAN_BITFIELD)
    uint8_t hlen:4;
    uint8_t ver:4;
#elif defined (__BIG_ENDIAN_BITFIELD)
    uint8_t ver:4;
    uint8_t hlen:4;
#endif
#else
#if __BYTE_ORDER == __LITTLE_ENDIAN
    uint8_t hlen:4;
    uint8_t ver:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
    uint8_t ver:4;
    uint8_t hlen:4;
#else
    error "undefined endianess"
#endif
#endif
    uint8_t tos;
    uint16_t tlen;
    uint16_t id;
    uint16_t flags_offs;
    uint8_t ttl;
    uint8_t proto;
    uint16_t csum;
    uint32_t sip;
    uint32_t dip;
} __attribute__ ((packed));

#endif /* PROTO_IPv4_H */
