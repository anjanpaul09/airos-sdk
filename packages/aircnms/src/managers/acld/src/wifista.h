#ifndef WIFISTA_H
#define WIFISTA_H

#include <stdint.h>
#include <time.h>
#include <arpa/inet.h>
#include <net/ethernet.h>

#define MAX_CLIENTS 256
#define MAX_HOSTNAME_LEN 64
#define MAX_INTERFACE_LEN 16
#define CLIENT_TIMEOUT_SECONDS 300  /* 5 minutes timeout */

/* WiFi Client Entry Structure */
struct wifi_client {
    uint8_t mac_addr[ETH_ALEN];           /* MAC address (6 bytes) */
    struct in_addr ip_addr;               /* IP address */
    char hostname[MAX_HOSTNAME_LEN];      /* Hostname from DHCP/NetBIOS */
    char wifi_interface[MAX_INTERFACE_LEN]; /* WiFi interface name */
    time_t first_seen;                    /* When client was first discovered */
    time_t last_seen;                     /* Last packet seen from this client */
    uint32_t packet_count;                /* Number of packets from this client */
    uint64_t bytes_count;                 /* Total bytes from this client */
    int is_active;                        /* Active flag */
};

/* WiFi Client Table Data */
struct wifi_table_data {
    struct wifi_client clients[MAX_CLIENTS];
    int client_count;
    int total_clients_seen;
    time_t start_time;
    uint32_t total_packets;
    uint64_t total_bytes;
    int debug_mode;
};

/* Initialize WiFi client table */
struct wifi_table_data *wifista_init(void);

/* Cleanup WiFi client table */
void wifista_cleanup(struct wifi_table_data *data);

/* Find client by MAC address */
struct wifi_client *wifista_find_by_mac(struct wifi_table_data *data, const uint8_t *mac);

/* Add or update client */
struct wifi_client *wifista_add_or_update(struct wifi_table_data *data,
                                          const uint8_t *mac,
                                          const struct in_addr *ip,
                                          const char *hostname,
                                          const char *interface);

/* Process ARP packet */
void wifista_process_arp(struct wifi_table_data *data, const u_char *packet, int packet_len);

/* Process DHCP packet */
void wifista_process_dhcp(struct wifi_table_data *data, const u_char *packet, int packet_len);

/* Process general IP packet */
void wifista_process_ip(struct wifi_table_data *data, const u_char *packet, int packet_len, const char *interface);

/* Cleanup stale clients */
void wifista_cleanup_stale(struct wifi_table_data *data);

/* Print client table */
void wifista_print_table(struct wifi_table_data *data);

/* Get statistics */
void wifista_get_stats(struct wifi_table_data *data, int *total_clients, int *active_clients, 
                       uint32_t *total_packets, uint64_t *total_bytes);

/* Convert MAC to string */
void wifista_mac_to_string(const uint8_t *mac, char *str);

#endif /* WIFISTA_H */

