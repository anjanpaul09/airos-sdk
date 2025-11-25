/*
 * DNS Packet Parsing Module
 * 
 * Handles DNS packet parsing, domain name extraction, and DNS-related utilities
 */

#include "dns.h"
#include <stdio.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <net/ethernet.h>

/* Extract domain name from DNS query or skip name (if name is NULL) */
int dns_extract_name(const uint8_t *dns_data, int offset, int max_len, 
                     char *name, int name_size)
{
    int pos = offset;
    int name_pos = 0;
    int jumped = 0;
    int jump_count = 0;
    int skip_name = (name == NULL || name_size == 0);
    
    while (pos < max_len && jump_count < 5) {
        uint8_t len = dns_data[pos];
        
        /* Check for compression pointer */
        if ((len & 0xC0) == 0xC0) {
            if (!jumped) {
                offset = pos + 2; /* Remember position after pointer */
            }
            pos = ((len & 0x3F) << 8) | dns_data[pos + 1];
            jumped = 1;
            jump_count++;
            continue;
        }
        
        /* End of name */
        if (len == 0) {
            if (!skip_name && name_pos > 0 && name_pos < name_size) {
                name[name_pos - 1] = '\0'; /* Remove last dot */
            }
            return jumped ? offset : pos + 1;
        }
        
        /* Add dot separator (except for first label) */
        if (!skip_name && name_pos > 0 && name_pos < name_size - 1) {
            name[name_pos++] = '.';
        }
        
        pos++; /* Skip length byte */
        
        /* Copy label or skip it */
        if (skip_name) {
            pos += len;
        } else {
            for (int i = 0; i < len && pos < max_len && name_pos < name_size - 1; i++) {
                name[name_pos++] = (char)dns_data[pos++];
            }
        }
    }
    
    if (!skip_name && name_pos < name_size) {
        name[name_pos] = '\0';
    }
    return jumped ? offset : pos;
}

/* Parse DNS packet and extract information */
int dns_parse_packet(pcap_t *pcap_handle, const u_char *packet, int packet_len, 
                     struct app_data *app_data)
{
    struct iphdr *ip_hdr;
    struct udphdr *udp_hdr;
    struct dns_header *dns_hdr;
    int ip_offset = 0;
    int ip_hdr_len;
    int dns_offset;
    uint16_t protocol_type;
    
    /* Check minimum packet size */
    if (packet_len < sizeof(struct iphdr) + sizeof(struct udphdr) + 
                     sizeof(struct dns_header)) {
        return -1;
    }
    
    /* Handle different data link types */
    int datalink = pcap_datalink(pcap_handle);
    
    if (datalink == DLT_EN10MB) {
        /* Ethernet header */
        if (packet_len < sizeof(struct ethhdr) + sizeof(struct iphdr) + 
                         sizeof(struct udphdr) + sizeof(struct dns_header)) {
            return -1;
        }
        struct ethhdr *eth_hdr = (struct ethhdr *)packet;
        protocol_type = ntohs(eth_hdr->h_proto);
        if (protocol_type == ETH_P_IP) {
            ip_offset = sizeof(struct ethhdr);
        } else {
            return -1; /* Not IPv4 */
        }
    } else if (datalink == DLT_LINUX_SLL) {
        /* Linux cooked socket (SLL) - 16 bytes header */
        /* Protocol type is at offset 14 (2 bytes) */
        if (packet_len < 16 + sizeof(struct iphdr) + sizeof(struct udphdr) + 
                         sizeof(struct dns_header)) {
            return -1;
        }
        protocol_type = ntohs(*(uint16_t *)(packet + 14));
        if (protocol_type == ETH_P_IP) {
            ip_offset = 16; /* SLL header is 16 bytes */
        } else {
            return -1; /* Not IPv4 */
        }
    } else {
        /* Try to parse as raw IP (no link layer header) */
        ip_offset = 0;
        protocol_type = ETH_P_IP; /* Assume IPv4 */
    }
    
    ip_hdr = (struct iphdr *)(packet + ip_offset);
    
    /* Check if it's IPv4 UDP */
    if (ip_hdr->version != 4 || ip_hdr->protocol != IPPROTO_UDP) {
        return -1;
    }
    
    ip_hdr_len = ip_hdr->ihl * 4;
    udp_hdr = (struct udphdr *)(packet + ip_offset + ip_hdr_len);
    
    /* Check if it's DNS (port 53) */
    uint16_t src_port = ntohs(udp_hdr->uh_sport);
    uint16_t dst_port = ntohs(udp_hdr->uh_dport);
    
    if (src_port != 53 && dst_port != 53) {
        return -1;
    }
    
    /* Get DNS header */
    dns_offset = ip_offset + ip_hdr_len + sizeof(struct udphdr);
    dns_hdr = (struct dns_header *)(packet + dns_offset);
    
    /* Fill app data */
    inet_ntop(AF_INET, &ip_hdr->saddr, app_data->src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &ip_hdr->daddr, app_data->dst_ip, INET_ADDRSTRLEN);
    app_data->src_port = src_port;
    app_data->dst_port = dst_port;
    app_data->dns_id = ntohs(dns_hdr->id);
    
    uint16_t flags = ntohs(dns_hdr->flags);
    app_data->is_query = !(flags & DNS_QR_MASK);
    app_data->dns_rcode = flags & DNS_RCODE_MASK;
    
    /* Extract domain name from query */
    if (app_data->is_query) {
        uint16_t questions = ntohs(dns_hdr->questions);
        if (questions > 0) {
            int name_offset = dns_offset + sizeof(struct dns_header);
            dns_extract_name(packet, name_offset, packet_len, 
                           app_data->domain, sizeof(app_data->domain));
        }
        app_data->ip_count = 0;
    } else {
        /* Parse DNS response to extract IP addresses */
        uint16_t questions = ntohs(dns_hdr->questions);
        uint16_t answers = ntohs(dns_hdr->answers);
        const uint8_t *dns_data = (const uint8_t *)dns_hdr;
        int pos = sizeof(struct dns_header);  /* Start after DNS header */
        int max_pos = packet_len - dns_offset;
        int i;
        
        app_data->ip_count = 0;
        
        /* Extract domain name from question section */
        if (questions > 0) {
            int name_end = dns_extract_name(dns_data, pos, max_pos, 
                                           app_data->domain, sizeof(app_data->domain));
            if (name_end > 0 && name_end <= max_pos) {
                pos = name_end;
                if (pos + 4 <= max_pos) {
                    pos += 4; /* Skip QTYPE + QCLASS */
                } else {
                    return 0; /* Can't continue, but packet is valid DNS */
                }
            } else {
                return 0; /* Failed to extract name, but packet is valid DNS */
            }
        }
        
        /* Parse answers section for A records (IPv4 addresses) */
        for (i = 0; i < answers && pos < max_pos && app_data->ip_count < 16; i++) {
            /* Skip name in answer (may be pointer or name) */
            int name_end = dns_extract_name(dns_data, pos, max_pos, 
                                           NULL, 0); /* Don't need the name, just skip it */
            if (name_end <= 0 || name_end > max_pos) break;
            pos = name_end;
            
            if (pos + 10 > max_pos) break; /* TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2) */
            
            uint16_t type = ntohs(*(uint16_t *)(dns_data + pos));
            uint16_t rdlength = ntohs(*(uint16_t *)(dns_data + pos + 8));
            pos += 10;
            
            /* Type 1 = A record (IPv4) */
            if (type == 1 && rdlength == 4 && pos + 4 <= max_pos) {
                uint32_t ip = ntohl(*(uint32_t *)(dns_data + pos));
                app_data->resolved_ips[app_data->ip_count++] = ip;
            }
            pos += rdlength;
        }
    }
    
    return 0;
}

/* Get DNS response code string */
const char *dns_rcode_to_string(uint16_t rcode)
{
    switch (rcode) {
        case 0: return "NOERROR";
        case 1: return "FORMERR";
        case 2: return "SERVFAIL";
        case 3: return "NXDOMAIN";
        case 4: return "NOTIMP";
        case 5: return "REFUSED";
        default: return "UNKNOWN";
    }
}

