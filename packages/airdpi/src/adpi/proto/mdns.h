#ifndef PROTO_MDNS_H
#define PROTO_MDNS_H

#define DNS_CNAME_PTR      0xc0
#define MAX_MDNS_RRS        100 //Maximu service records stored
#define MAX_BONJOUR_RULES   256 //Max rules forward across vlans

#define MDNS_TYPE_A     1
#define MDNS_TYPE_NS    2
#define MDNS_TYPE_CNAME 5
#define MDNS_TYPE_NULL  10
#define MDNS_TYPE_PTR   12
#define MDNS_TYPE_TXT   16
#define MDNS_TYPE_AAAA  28
#define MDNS_TYPE_SRV   33
#define MDNS_TYPE_ALL   255

struct mdns_hdr
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
#endif
#elif __BYTE_ORDER == __BIG_ENDIAN
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
    error "undefined endianess"
#endif
    uint16_t q_count;      /* number of question entries */
    uint16_t ans_count;    /* number of answer entries */
    uint16_t auth_count;   /* number of authority entries */
    uint16_t add_count;    /* number of resource entries */
} __attribute__ ((packed));

// Data for SRV records
struct srv {
    uint16_t priority;
    uint16_t weight;
    uint16_t port;
    char *name;
}; 

typedef struct mdns_pkt_info {
    char ip[16];
    char smac[18];
    uint16_t vlanid;
    uint16_t wlanidx;
} mdns_pkt_info_t;

//Pointers to resource record contents
typedef struct mdns_rr {
    uint32_t last_updated;
    uint8_t in_use:1;
    char name[64];
    char rdata[64];
    uint16_t type;
    uint16_t class;
    uint16_t rdlength;
    int ttl;
    struct mdns_rr *next;
    uint8_t pktidx;
}  mdns_rr_t;

// mdns record list
typedef struct mdns_rr_list {
    mdns_rr_t *head;
} mdns_rr_list_t;

struct dnspacket {
    mdns_rr_list_t *answers;
    mdns_rr_list_t *auths;
    mdns_rr_list_t *addns;
};

typedef struct mdns_cfg_rules {
    uint8_t act;
    char sname[64]; //Service name
    char proto[64]; //Application protocol
    uint16_t vidfrom;
    uint16_t vidto;
} mdns_rules_t;

typedef struct mdns_acl_cfg {
    mdns_rules_t rules[MAX_BONJOUR_RULES];
    uint16_t count; //num of rules added
} mdns_cfg_t;
#endif
