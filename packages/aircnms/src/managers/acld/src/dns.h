#ifndef DNS_H
#define DNS_H

#include <stdint.h>
#include <time.h>
#include <arpa/inet.h>
#include <pcap.h>

/* DNS header structure */
struct dns_header {
    uint16_t id;
    uint16_t flags;
    uint16_t questions;
    uint16_t answers;
    uint16_t authority;
    uint16_t additional;
} __attribute__((packed));

/* DNS flags */
#define DNS_QR_MASK     0x8000  /* Query/Response flag */
#define DNS_OPCODE_MASK 0x7800  /* Operation code */
#define DNS_RCODE_MASK  0x000F  /* Response code */

/* Application data structure */
struct app_data {
    char domain[256];
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t dns_id;
    uint16_t dns_rcode;
    int is_query;
    time_t timestamp;
    uint32_t resolved_ips[16];  /* IP addresses from DNS response (max 16) */
    int ip_count;                /* Number of IPs in resolved_ips */
};

/* Extract domain name from DNS query */
int dns_extract_name(const uint8_t *dns_data, int offset, int max_len, 
                     char *name, int name_size);

/* Parse DNS packet and extract information */
int dns_parse_packet(pcap_t *pcap_handle, const u_char *packet, int packet_len, 
                     struct app_data *app_data);

/* Get DNS response code string */
const char *dns_rcode_to_string(uint16_t rcode);

#endif /* DNS_H */

