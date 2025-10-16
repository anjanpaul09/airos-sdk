#ifndef PROTO_DNS_H
#define PROTO_DNS_H

#include <linux/types.h>
#define DNS_MSG_QUERY      0
#define DNS_MSG_QUERY_RSP  1
#define DNS_CNAME_PTR      0xc0

enum {
  DNS_RR_TYPE_A     = 1,  // host address
  DNS_RR_TYPE_NS    = 2,  // authotitative name server
  DNS_RR_TYPE_MD    = 3,  // mail destination
  DNS_RR_TYPE_MF    = 4,  // mail forwarder
  DNS_RR_TYPE_CNAME = 5   // canonical name for an alias
};

enum {
  DNS_RR_CLASS_IN = 1,  // Internet
  DNS_RR_CLASS_CS = 2,  // CSNET class(Obsolete)
  DNS_RR_CLASS_CH = 3,  // CHAOS class
  DNS_RR_CLASS_HS = 4   // Hesiod
};

enum {
  DNS_RCODE_NO_ERROR = 0,
  DNS_RCODE_FORMAT_ERROR = 1,
  DNS_RCODE_SERVER_FAILURE = 2,
  DNS_RCODE_NAME_ERROR = 3
};

#define DNS_SIZE_OF_TYPE  2
#define DNS_SIZE_OF_CLASS 2

// dns_rr is used to parse query as well as answers after the name has been parsed in the given section
struct dns_rr {
  uint16_t type;
  uint16_t class;
  uint32_t ttl;
  uint16_t dlen; // data len
} __attribute__ ((packed));

struct dns_hdr
{
    uint16_t id;           /* identification number */
#ifdef __KERNEL__
#if defined (__BIG_ENDIAN_BITFIELD)
    uint8_t qr:1;          /* response flag */
    uint8_t opcode:4;      /* purpose of message */
    uint8_t aa:1;          /* authoritive answer */
    uint8_t tc:1;          /* truncated message */
    uint8_t rd:1;          /* recursion desired */
    uint8_t ra:1;          /* recursion available */
    uint8_t unused:3;      /* unused bits (MBZ as of 4.9.3a3) */
    uint8_t rcode:4;       /* response code */
#elif defined(__LITTLE_ENDIAN_BITFIELD)
    uint8_t rd:1;          /* recursion desired */
    uint8_t tc:1;          /* truncated message */
    uint8_t aa:1;          /* authoritive answer */
    uint8_t opcode:4;      /* purpose of message */
    uint8_t qr:1;          /* response flag */
    uint8_t rcode:4;       /* response code */
    uint8_t unused:3;      /* unused bits (MBZ as of 4.9.3a3) */
    uint8_t ra:1;          /* recursion available */
#else
#error "undefined endianess"
#endif
#else
#if __BYTE_ORDER == __BIG_ENDIAN
    uint8_t qr:1;          /* response flag */
    uint8_t opcode:4;      /* purpose of message */
    uint8_t aa:1;          /* authoritive answer */
    uint8_t tc:1;          /* truncated message */
    uint8_t rd:1;          /* recursion desired */
    uint8_t ra:1;          /* recursion available */
    uint8_t unused:3;      /* unused bits (MBZ as of 4.9.3a3) */
    uint8_t rcode:4;       /* response code */
#elif __BYTE_ORDER == __LITTLE_ENDIAN
    uint8_t rd:1;          /* recursion desired */
    uint8_t tc:1;          /* truncated message */
    uint8_t aa:1;          /* authoritive answer */
    uint8_t opcode:4;      /* purpose of message */
    uint8_t qr:1;          /* response flag */
    uint8_t rcode:4;       /* response code */
    uint8_t unused:3;      /* unused bits (MBZ as of 4.9.3a3) */
    uint8_t ra:1;          /* recursion available */
#else
#error "undefined endianess"
#endif
#endif
    uint16_t q_count;      /* number of question entries */
    uint16_t ans_count;    /* number of answer entries */
    uint16_t auth_count;   /* number of authority entries */
    uint16_t add_count;    /* number of resource entries */
} __attribute__ ((packed));
#endif
