#ifndef APP_MONITOR_H
#define APP_MONITOR_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include "ds_tree.h"

/* Maximum length for application name */
#define APP_NAME_MAX_LEN 64

/* Application usage entry */
struct app_usage_entry {
    char app_name[APP_NAME_MAX_LEN];  /* Application name (e.g., "whatsapp") */
    uint64_t usage_bytes;              /* Total usage in bytes */
    uint64_t last_update;              /* Last update timestamp */
    
    /* Domain mapping - for DNS-based identification */
    char domain[256];                  /* Domain name */
    
    /* Tree node for ds_tree */
    ds_tree_node_t node;
};

/* Application monitor context */
struct app_monitor {
    ds_tree_t app_tree;                /* Tree sorted by usage (descending) */
    ds_tree_t domain_tree;             /* Tree for domain->app mapping */
    ds_tree_t ip_tree;                 /* Tree for IP->domain mapping */
    int total_apps;                    /* Total number of tracked apps */
    time_t start_time;                 /* Monitor start time */
};

/* Domain to application mapping entry */
struct domain_map_entry {
    char domain[256];                  /* Domain name (key) */
    char app_name[APP_NAME_MAX_LEN];  /* Application name */
    
    /* Tree node for domain lookup */
    ds_tree_node_t node;
};

/* IP to domain mapping entry */
struct ip_domain_entry {
    uint32_t ip;                       /* IP address (network byte order) */
    char domain[256];                  /* Domain name */
    time_t last_seen;                  /* Last time this mapping was seen */
    
    /* Tree node for IP lookup */
    ds_tree_node_t node;
};


/* Initialize application monitor */
int app_monitor_init(struct app_monitor *monitor);

/* Cleanup application monitor */
void app_monitor_cleanup(struct app_monitor *monitor);

/* Update application usage from domain and bytes */
int app_monitor_update_usage(struct app_monitor *monitor, 
                            const char *domain, 
                            uint64_t bytes);

/* Get top N applications by usage */
int app_monitor_get_top_n(struct app_monitor *monitor, 
                         struct app_usage_entry **entries, 
                         int n);

/* Print top 10 applications in requested format */
void app_monitor_print_top10(struct app_monitor *monitor);

/* Map domain to application name */
const char *app_monitor_domain_to_app(const char *domain);

/* Add domain to application mapping */
int app_monitor_add_domain_mapping(struct app_monitor *monitor,
                                  const char *domain,
                                  const char *app_name);

/* Add IP to domain mapping (from DNS response) */
int app_monitor_add_ip_mapping(struct app_monitor *monitor,
                              uint32_t ip,
                              const char *domain);

/* Get domain from IP address */
const char *app_monitor_get_domain_from_ip(struct app_monitor *monitor, uint32_t ip);

/* Update usage from IP address and bytes (TX+RX combined) */
int app_monitor_update_usage_from_ip(struct app_monitor *monitor,
                                     uint32_t ip,
                                     uint64_t tx_bytes,
                                     uint64_t rx_bytes);

#endif /* APP_MONITOR_H */

