#ifndef PROTO_UDP_H
#define PROTO_UDP_H

#define UDP_PORT_BOOTPS 67
#define UDP_PORT_BOOTPC 68
#define UDP_PORT_DNS 53
#define UDP_PORT_MDNS 5353

struct udp_hdr {
    uint16_t sport;
    uint16_t dport;
    uint16_t len;
    uint16_t csum;
};

#endif /* PROTO_UDP_H */
