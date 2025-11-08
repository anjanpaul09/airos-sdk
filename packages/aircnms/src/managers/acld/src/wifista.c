/*
 * WiFi Client Table Module
 * 
 * Maintains a table of WiFi clients tracking MAC addresses, IP addresses,
 * hostnames, and WiFi interfaces. Based on wifi_client_table_plugin.c
 */

#include "wifista.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <net/ethernet.h>

/* Define ARP constants */
#ifndef ARPHRD_ETHER
#define ARPHRD_ETHER 1
#endif

/* ARP header structure */
struct arp_header {
    uint16_t ar_hrd;    /* Hardware type */
    uint16_t ar_pro;    /* Protocol type */
    uint8_t ar_hln;     /* Hardware length */
    uint8_t ar_pln;     /* Protocol length */
    uint16_t ar_op;     /* Operation */
} __attribute__((packed));

/* Helper Functions */

/**
 * Compare MAC addresses
 */
static int mac_equal(const uint8_t *mac1, const uint8_t *mac2)
{
    return memcmp(mac1, mac2, ETH_ALEN) == 0;
}

/**
 * Check if MAC address is broadcast or multicast
 */
static int is_broadcast_mac(const uint8_t *mac)
{
    static const uint8_t broadcast_mac[ETH_ALEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    return mac_equal(mac, broadcast_mac) || (mac[0] & 0x01);
}

/**
 * Check if MAC address is likely a WiFi client (not infrastructure)
 */
static int is_likely_wifi_client(const uint8_t *mac)
{
    if (is_broadcast_mac(mac)) {
        return 0;
    }
    
    static const uint8_t zero_mac[ETH_ALEN] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    if (mac_equal(mac, zero_mac)) {
        return 0;
    }
    
    return 1;
}

/**
 * Convert MAC address to string
 */
void wifista_mac_to_string(const uint8_t *mac, char *str)
{
    sprintf(str, "%02x:%02x:%02x:%02x:%02x:%02x",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

/* Initialize WiFi client table */
struct wifi_table_data *wifista_init(void)
{
    struct wifi_table_data *data = calloc(1, sizeof(struct wifi_table_data));
    if (!data) {
        return NULL;
    }
    
    data->start_time = time(NULL);
    data->client_count = 0;
    data->total_clients_seen = 0;
    data->total_packets = 0;
    data->total_bytes = 0;
    data->debug_mode = 0;
    
    memset(data->clients, 0, sizeof(data->clients));
    
    return data;
}

/* Cleanup WiFi client table */
void wifista_cleanup(struct wifi_table_data *data)
{
    if (data) {
        free(data);
    }
}

/* Find client by MAC address */
struct wifi_client *wifista_find_by_mac(struct wifi_table_data *data, const uint8_t *mac)
{
    if (!data || !mac) {
        return NULL;
    }
    
    for (int i = 0; i < data->client_count; i++) {
        if (data->clients[i].is_active && mac_equal(data->clients[i].mac_addr, mac)) {
            return &data->clients[i];
        }
    }
    return NULL;
}

/* Add or update client */
struct wifi_client *wifista_add_or_update(struct wifi_table_data *data,
                                          const uint8_t *mac,
                                          const struct in_addr *ip,
                                          const char *hostname,
                                          const char *interface)
{
    if (!data || !mac) {
        return NULL;
    }
    
    struct wifi_client *client = wifista_find_by_mac(data, mac);
    time_t now = time(NULL);
    
    if (client) {
        /* Update existing client */
        client->last_seen = now;
        
        if (ip && ip->s_addr != 0 && client->ip_addr.s_addr != ip->s_addr) {
            client->ip_addr = *ip;
        }
        
        if (hostname && strlen(hostname) > 0 && strcmp(client->hostname, hostname) != 0) {
            strncpy(client->hostname, hostname, MAX_HOSTNAME_LEN - 1);
            client->hostname[MAX_HOSTNAME_LEN - 1] = '\0';
        }
        
        if (interface && strlen(interface) > 0 && strcmp(client->wifi_interface, interface) != 0) {
            strncpy(client->wifi_interface, interface, MAX_INTERFACE_LEN - 1);
            client->wifi_interface[MAX_INTERFACE_LEN - 1] = '\0';
        }
        
        return client;
    }
    
    /* Add new client if we have space */
    if (data->client_count < MAX_CLIENTS) {
        client = &data->clients[data->client_count];
        memset(client, 0, sizeof(struct wifi_client));
        
        memcpy(client->mac_addr, mac, ETH_ALEN);
        client->first_seen = now;
        client->last_seen = now;
        client->is_active = 1;
        client->packet_count = 0;
        client->bytes_count = 0;
        
        if (ip && ip->s_addr != 0) {
            client->ip_addr = *ip;
        }
        
        if (hostname && strlen(hostname) > 0) {
            strncpy(client->hostname, hostname, MAX_HOSTNAME_LEN - 1);
            client->hostname[MAX_HOSTNAME_LEN - 1] = '\0';
        }
        
        if (interface && strlen(interface) > 0) {
            strncpy(client->wifi_interface, interface, MAX_INTERFACE_LEN - 1);
            client->wifi_interface[MAX_INTERFACE_LEN - 1] = '\0';
        } else {
            strcpy(client->wifi_interface, "unknown");
        }
        
        data->client_count++;
        data->total_clients_seen++;
        
        if (data->debug_mode) {
            char mac_str[18];
            wifista_mac_to_string(mac, mac_str);
            printf("[WIFISTA] New client: %s", mac_str);
            if (ip && ip->s_addr != 0) {
                printf(" (%s)", inet_ntoa(*ip));
            }
            if (hostname && strlen(hostname) > 0) {
                printf(" [%s]", hostname);
            }
            printf("\n");
        }
        
        return client;
    }
    
    return NULL; /* Table full */
}

/* Process ARP packet */
void wifista_process_arp(struct wifi_table_data *data, const u_char *packet, int packet_len)
{
    if (!data || packet_len < sizeof(struct ethhdr) + sizeof(struct arp_header)) {
        return;
    }
    
    /* Ethernet header not used directly; avoid unused warning */
    (void)packet;
    struct arp_header *arp_hdr = (struct arp_header *)(packet + sizeof(struct ethhdr));
    
    /* Check if it's IPv4 ARP */
    if (ntohs(arp_hdr->ar_hrd) != ARPHRD_ETHER ||
        ntohs(arp_hdr->ar_pro) != ETH_P_IP ||
        arp_hdr->ar_hln != ETH_ALEN ||
        arp_hdr->ar_pln != 4) {
        return;
    }
    
    uint8_t *arp_data = (uint8_t *)(arp_hdr + 1);
    
    /* Extract sender MAC and IP */
    uint8_t *sender_mac = arp_data;
    struct in_addr sender_ip;
    memcpy(&sender_ip.s_addr, arp_data + ETH_ALEN, 4);
    
    /* Process sender */
    if (is_likely_wifi_client(sender_mac) && sender_ip.s_addr != 0) {
        struct wifi_client *client = wifista_add_or_update(data, sender_mac, &sender_ip, NULL, NULL);
        if (client) {
            client->packet_count++;
            client->bytes_count += packet_len;
        }
    }
    
    /* Process target (in ARP replies) */
    uint16_t arp_operation = ntohs(arp_hdr->ar_op);
    if (arp_operation == 2) { /* ARP reply */
        uint8_t *target_mac = arp_data + ETH_ALEN + 4;
        struct in_addr target_ip;
        memcpy(&target_ip.s_addr, arp_data + ETH_ALEN + 4 + ETH_ALEN, 4);
        
        if (is_likely_wifi_client(target_mac) && target_ip.s_addr != 0) {
            struct wifi_client *client = wifista_add_or_update(data, target_mac, &target_ip, NULL, NULL);
            if (client) {
                client->packet_count++;
                client->bytes_count += packet_len;
            }
        }
    }
}

/* Process DHCP packet */
void wifista_process_dhcp(struct wifi_table_data *data, const u_char *packet, int packet_len)
{
    if (!data || packet_len < sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + 240) {
        return;
    }
    
    /* We don't need Ethernet header in this function; avoid unused warning */
    (void)packet;
    struct iphdr *ip_hdr = (struct iphdr *)(packet + sizeof(struct ethhdr));
    struct udphdr *udp_hdr = (struct udphdr *)(packet + sizeof(struct ethhdr) + (ip_hdr->ihl * 4));
    
    uint8_t *dhcp_data = (uint8_t *)udp_hdr + sizeof(struct udphdr);
    
    /* Extract client MAC (chaddr field at offset 28) */
    uint8_t *client_mac = dhcp_data + 28;
    
    /* Extract IP fields */
    struct in_addr your_ip;
    memcpy(&your_ip.s_addr, dhcp_data + 16, 4); /* yiaddr */
    
    /* Determine best IP to use */
    struct in_addr best_ip = {0};
    if (your_ip.s_addr != 0) {
        best_ip = your_ip;
    }
    
    /* Extract hostname from DHCP options (option 12 or 0x0C) */
    char hostname[MAX_HOSTNAME_LEN] = {0};
    int hostname_found = 0;
    
    /* DHCP options start at offset 240 */
    uint8_t *options = dhcp_data + 240;
    int options_len = packet_len - sizeof(struct ethhdr) - (ip_hdr->ihl * 4) - sizeof(struct udphdr) - 240;
    
    for (int i = 0; i < options_len - 1; i++) {
        if (options[i] == 0x0C) { /* Hostname option */
            uint8_t hostname_len = options[i + 1];
            if (hostname_len > 0 && hostname_len < MAX_HOSTNAME_LEN && i + 2 + hostname_len <= options_len) {
                memcpy(hostname, &options[i + 2], hostname_len);
                hostname[hostname_len] = '\0';
                hostname_found = 1;
                break;
            }
        } else if (options[i] == 0xFF) { /* End option */
            break;
        } else if (options[i] == 0x00) { /* Pad option */
            continue;
        } else {
            /* Skip option */
            i += options[i + 1] + 1;
        }
    }
    
    if (is_likely_wifi_client(client_mac)) {
        struct wifi_client *client = wifista_add_or_update(data, client_mac, 
                                                           best_ip.s_addr ? &best_ip : NULL,
                                                           hostname_found ? hostname : NULL,
                                                           NULL);
        if (client) {
            client->packet_count++;
            client->bytes_count += packet_len;
        }
    }
}

/* Process general IP packet */
void wifista_process_ip(struct wifi_table_data *data, const u_char *packet, int packet_len, const char *interface)
{
    if (!data || packet_len < sizeof(struct ethhdr) + sizeof(struct iphdr)) {
        return;
    }
    
    struct ethhdr *eth_hdr = (struct ethhdr *)packet;
    struct iphdr *ip_hdr = (struct iphdr *)(packet + sizeof(struct ethhdr));
    
    if (ip_hdr->version != 4) {
        return;
    }
    
    /* Track source MAC with its IP address */
    if (is_likely_wifi_client(eth_hdr->h_source)) {
        struct in_addr src_ip;
        src_ip.s_addr = ip_hdr->saddr;
        
        struct wifi_client *client = wifista_add_or_update(data, eth_hdr->h_source, &src_ip, NULL, interface);
        if (client) {
            client->packet_count++;
            client->bytes_count += packet_len;
            client->last_seen = time(NULL);
        }
    }
}

/* Cleanup stale clients */
void wifista_cleanup_stale(struct wifi_table_data *data)
{
    if (!data) {
        return;
    }
    
    time_t now = time(NULL);
    int removed = 0;
    
    for (int i = 0; i < data->client_count; i++) {
        if (data->clients[i].is_active && 
            (now - data->clients[i].last_seen) > CLIENT_TIMEOUT_SECONDS) {
            data->clients[i].is_active = 0;
            removed++;
        }
    }
    
    /* Compact the array */
    if (removed > 0) {
        int write_idx = 0;
        for (int read_idx = 0; read_idx < data->client_count; read_idx++) {
            if (data->clients[read_idx].is_active) {
                if (write_idx != read_idx) {
                    data->clients[write_idx] = data->clients[read_idx];
                }
                write_idx++;
            }
        }
        data->client_count = write_idx;
    }
}

/* Print client table */
void wifista_print_table(struct wifi_table_data *data)
{
    if (!data) {
        return;
    }
    
    time_t now = time(NULL);
    time_t uptime = now - data->start_time;
    
    printf("\n╔═══════════════════════════════════════════════════════════════════════════════╗\n");
    printf("║                            WiFi Client Table                                  ║\n");
    printf("╠═══════════════════════════════════════════════════════════════════════════════╣\n");
    printf("║ Uptime: %lld seconds | Active Clients: %d | Total Seen: %d                   ║\n",
           (long long)uptime, data->client_count, data->total_clients_seen);
    printf("║ Total Packets: %u | Total Bytes: %llu                                       ║\n",
           data->total_packets, (long long unsigned)data->total_bytes);
    printf("╠═══════════════════════════════════════════════════════════════════════════════╣\n");
    
    if (data->client_count == 0) {
        printf("║                              No active clients                               ║\n");
    } else {
        printf("║ MAC Address       │ IP Address      │ Hostname         │ Interface │ Age  ║\n");
        printf("╟───────────────────┼─────────────────┼──────────────────┼───────────┼──────╢\n");
        
        for (int i = 0; i < data->client_count; i++) {
            struct wifi_client *client = &data->clients[i];
            if (!client->is_active) continue;
            
            char mac_str[18];
            wifista_mac_to_string(client->mac_addr, mac_str);
            
            char ip_str[16] = "unknown";
            if (client->ip_addr.s_addr != 0) {
                strcpy(ip_str, inet_ntoa(client->ip_addr));
            }
            
            char hostname[17];
            if (strlen(client->hostname) > 0) {
                strncpy(hostname, client->hostname, 16);
                hostname[16] = '\0';
            } else {
                strcpy(hostname, "unknown");
            }
            
            long long age = now - client->first_seen;
            
            printf("║ %-17s │ %-15s │ %-16s │ %-9s │ %4llds ║\n",
                   mac_str, ip_str, hostname, client->wifi_interface, age);
        }
    }
    
    printf("╚═══════════════════════════════════════════════════════════════════════════════╝\n\n");
}

/* Get statistics */
void wifista_get_stats(struct wifi_table_data *data, int *total_clients, int *active_clients, 
                       uint32_t *total_packets, uint64_t *total_bytes)
{
    if (!data) {
        return;
    }
    
    if (total_clients) {
        *total_clients = data->total_clients_seen;
    }
    if (active_clients) {
        *active_clients = data->client_count;
    }
    if (total_packets) {
        *total_packets = data->total_packets;
    }
    if (total_bytes) {
        *total_bytes = data->total_bytes;
    }
}

