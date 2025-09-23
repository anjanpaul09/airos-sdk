#ifndef PROTO_TCP_H
#define PROTO_TCP_H

#define TCP_PORT_HTTP   80
#define TCP_PORT_HTTPS  443

struct tcp_hdr {
    uint16_t sport;
    uint16_t dport;
    uint32_t seq;
    uint32_t ack_seq;
#ifdef __KERNEL__
#if defined(__LITTLE_ENDIAN_BITFIELD)
    uint16_t res1:4;
    uint16_t doff:4;
    uint16_t fin:1;
    uint16_t syn:1;
    uint16_t rst:1;
    uint16_t psh:1;
    uint16_t ack:1;
    uint16_t urg:1;
    uint16_t ece:1;
    uint16_t cwr:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
    uint16_t doff:4;
    uint16_t res1:4;
    uint16_t cwr:1;
    uint16_t ece:1;
    uint16_t urg:1;
    uint16_t ack:1;
    uint16_t psh:1;
    uint16_t rst:1;
    uint16_t syn:1;
    uint16_t fin:1;
#endif
#else
#if __BYTE_ORDER == __LITTLE_ENDIAN
    uint16_t res1:4;
    uint16_t doff:4;
    uint16_t fin:1;
    uint16_t syn:1;
    uint16_t rst:1;
    uint16_t psh:1;
    uint16_t ack:1;
    uint16_t urg:1;
    uint16_t ece:1;
    uint16_t cwr:1;
#elif __BYTE_ORDER == __BIG_ENDIAN
    uint16_t doff:4;
    uint16_t res1:4;
    uint16_t cwr:1;
    uint16_t ece:1;
    uint16_t urg:1;
    uint16_t ack:1;
    uint16_t psh:1;
    uint16_t rst:1;
    uint16_t syn:1;
    uint16_t fin:1;
#else
    error "undefined endianess"
#endif
#endif
    uint16_t window;
    uint16_t csum;
    uint16_t urg_ptr;
} __attribute__ ((packed));

#endif /* PROTO_TCP_H */
