/*
 * Application Usage Monitor
 * 
 * Tracks top 10 applications/websites by data usage
 * Uses libds (ds_tree) to maintain sorted list
 * 
 * Note: Current implementation tracks DNS packet sizes as a proxy for usage.
 * For accurate application usage tracking, this should be enhanced to:
 * 1. Capture all IP traffic (not just DNS)
 * 2. Map IP addresses to domains using DNS responses
 * 3. Track actual bytes transferred per flow
 */

#include "app_monitor.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <arpa/inet.h>

/* Compare function for app usage tree (keyed by app_name for lookup) */
static int app_usage_cmp(const void *a, const void *b)
{
    const char *key_a = (const char *)a;
    const char *key_b = (const char *)b;
    
    return strcmp(key_a, key_b);
}

/* Compare function for domain mapping tree (sorted by domain name) */
static int domain_map_cmp(const void *a, const void *b)
{
    const struct domain_map_entry *entry_a = (const struct domain_map_entry *)a;
    const struct domain_map_entry *entry_b = (const struct domain_map_entry *)b;
    
    return strcmp(entry_a->domain, entry_b->domain);
}

/* Compare function for IP mapping tree (keyed by IP address) */
static int ip_domain_cmp(const void *a, const void *b)
{
    const uint32_t *ip_a = (const uint32_t *)a;
    const uint32_t *ip_b = (const uint32_t *)b;
    
    if (*ip_a < *ip_b) return -1;
    if (*ip_a > *ip_b) return 1;
    return 0;
}

/* Convert domain to application name */
static void domain_to_app_name(const char *domain, char *app_name, size_t app_name_size)
{
    char domain_copy[256];
    
    /* Make a copy for case-insensitive matching */
    strncpy(domain_copy, domain, sizeof(domain_copy) - 1);
    domain_copy[sizeof(domain_copy) - 1] = '\0';
    
    /* Convert to lowercase */
    for (int i = 0; domain_copy[i]; i++) {
        domain_copy[i] = tolower(domain_copy[i]);
    }
    
    /* Extract base domain (remove www. and subdomains) */
    const char *base_domain = domain_copy;
    if (strncmp(base_domain, "www.", 4) == 0) {
        base_domain += 4;
    }
    
    /* Find the main domain part (before first dot after www) */
    const char *first_dot = strchr(base_domain, '.');
    if (first_dot) {
        char main_part[64];
        size_t len = first_dot - base_domain;
        if (len < sizeof(main_part)) {
            strncpy(main_part, base_domain, len);
            main_part[len] = '\0';
            base_domain = main_part;
        }
    }
    
    /* Map common domains to application names */
    if (strstr(domain_copy, "whatsapp") != NULL || strstr(domain_copy, "wa.me") != NULL) {
        strncpy(app_name, "whatsapp", app_name_size - 1);
    } else if (strstr(domain_copy, "facebook") != NULL || strstr(domain_copy, "fb.com") != NULL) {
        strncpy(app_name, "facebook", app_name_size - 1);
    } else if (strstr(domain_copy, "instagram") != NULL) {
        strncpy(app_name, "instagram", app_name_size - 1);
    } else if (strstr(domain_copy, "youtube") != NULL || strstr(domain_copy, "youtu.be") != NULL) {
        strncpy(app_name, "youtube", app_name_size - 1);
    } else if (strstr(domain_copy, "twitter") != NULL || strstr(domain_copy, "x.com") != NULL) {
        strncpy(app_name, "twitter", app_name_size - 1);
    } else if (strstr(domain_copy, "tiktok") != NULL) {
        strncpy(app_name, "tiktok", app_name_size - 1);
    } else if (strstr(domain_copy, "netflix") != NULL) {
        strncpy(app_name, "netflix", app_name_size - 1);
    } else if (strstr(domain_copy, "amazon") != NULL) {
        strncpy(app_name, "amazon", app_name_size - 1);
    } else if (strstr(domain_copy, "google") != NULL) {
        strncpy(app_name, "google", app_name_size - 1);
    } else if (strstr(domain_copy, "microsoft") != NULL || strstr(domain_copy, "microsoft.com") != NULL) {
        strncpy(app_name, "microsoft", app_name_size - 1);
    } else if (strstr(domain_copy, "linkedin") != NULL) {
        strncpy(app_name, "linkedin", app_name_size - 1);
    } else if (strstr(domain_copy, "reddit") != NULL) {
        strncpy(app_name, "reddit", app_name_size - 1);
    } else if (strstr(domain_copy, "snapchat") != NULL) {
        strncpy(app_name, "snapchat", app_name_size - 1);
    } else if (strstr(domain_copy, "zoom") != NULL) {
        strncpy(app_name, "zoom", app_name_size - 1);
    } else if (strstr(domain_copy, "discord") != NULL) {
        strncpy(app_name, "discord", app_name_size - 1);
    } else {
        /* Use base domain as app name (capitalize first letter) */
        if (strlen(base_domain) > 0 && strlen(base_domain) < app_name_size) {
            strncpy(app_name, base_domain, app_name_size - 1);
            app_name[0] = toupper(app_name[0]);
        } else {
            strncpy(app_name, "unknown", app_name_size - 1);
        }
    }
    
    app_name[app_name_size - 1] = '\0';
}

/* Initialize application monitor */
int app_monitor_init(struct app_monitor *monitor)
{
    if (!monitor) {
        return -1;
    }
    
    memset(monitor, 0, sizeof(*monitor));
    
    /* Initialize app usage tree (sorted by usage descending) */
    ds_tree_init(&monitor->app_tree, app_usage_cmp, struct app_usage_entry, node);
    
    /* Initialize domain mapping tree (sorted by domain name) */
    ds_tree_init(&monitor->domain_tree, domain_map_cmp, struct domain_map_entry, node);
    
    /* Initialize IP to domain mapping tree (keyed by IP address) */
    ds_tree_init(&monitor->ip_tree, ip_domain_cmp, struct ip_domain_entry, node);
    
    monitor->start_time = time(NULL);
    monitor->total_apps = 0;
    
    /* Pre-populate common domain mappings */
    app_monitor_add_domain_mapping(monitor, "whatsapp.com", "whatsapp");
    app_monitor_add_domain_mapping(monitor, "wa.me", "whatsapp");
    app_monitor_add_domain_mapping(monitor, "facebook.com", "facebook");
    app_monitor_add_domain_mapping(monitor, "fb.com", "facebook");
    app_monitor_add_domain_mapping(monitor, "instagram.com", "instagram");
    app_monitor_add_domain_mapping(monitor, "youtube.com", "youtube");
    app_monitor_add_domain_mapping(monitor, "youtu.be", "youtube");
    app_monitor_add_domain_mapping(monitor, "twitter.com", "twitter");
    app_monitor_add_domain_mapping(monitor, "x.com", "twitter");
    app_monitor_add_domain_mapping(monitor, "tiktok.com", "tiktok");
    app_monitor_add_domain_mapping(monitor, "netflix.com", "netflix");
    app_monitor_add_domain_mapping(monitor, "amazon.com", "amazon");
    app_monitor_add_domain_mapping(monitor, "google.com", "google");
    app_monitor_add_domain_mapping(monitor, "microsoft.com", "microsoft");
    app_monitor_add_domain_mapping(monitor, "linkedin.com", "linkedin");
    app_monitor_add_domain_mapping(monitor, "reddit.com", "reddit");
    app_monitor_add_domain_mapping(monitor, "snapchat.com", "snapchat");
    app_monitor_add_domain_mapping(monitor, "zoom.us", "zoom");
    app_monitor_add_domain_mapping(monitor, "discord.com", "discord");
    
    return 0;
}

/* Cleanup application monitor */
void app_monitor_cleanup(struct app_monitor *monitor)
{
    if (!monitor) {
        return;
    }
    
    /* Free all app usage entries */
    struct app_usage_entry *app_entry, *app_tmp;
    ds_tree_foreach_safe(&monitor->app_tree, app_entry, app_tmp) {
        ds_tree_remove(&monitor->app_tree, app_entry);
        free(app_entry);
    }
    
    /* Free all domain mapping entries */
    struct domain_map_entry *domain_entry, *domain_tmp;
    ds_tree_foreach_safe(&monitor->domain_tree, domain_entry, domain_tmp) {
        ds_tree_remove(&monitor->domain_tree, domain_entry);
        free(domain_entry);
    }
    
    /* Free all IP mapping entries */
    struct ip_domain_entry *ip_entry, *ip_tmp;
    ds_tree_foreach_safe(&monitor->ip_tree, ip_entry, ip_tmp) {
        ds_tree_remove(&monitor->ip_tree, ip_entry);
        free(ip_entry);
    }
    
    memset(monitor, 0, sizeof(*monitor));
}

/* Map domain to application name */
const char *app_monitor_domain_to_app(const char *domain)
{
    static char app_name[APP_NAME_MAX_LEN];
    
    if (!domain || domain[0] == '\0') {
        return "unknown";
    }
    
    domain_to_app_name(domain, app_name, sizeof(app_name));
    return app_name;
}

/* Add domain to application mapping */
int app_monitor_add_domain_mapping(struct app_monitor *monitor,
                                  const char *domain,
                                  const char *app_name)
{
    if (!monitor || !domain || !app_name) {
        return -1;
    }
    
    /* Check if mapping already exists */
    struct domain_map_entry *existing = ds_tree_find(&monitor->domain_tree, domain);
    if (existing) {
        /* Update existing mapping */
        strncpy(existing->app_name, app_name, APP_NAME_MAX_LEN - 1);
        existing->app_name[APP_NAME_MAX_LEN - 1] = '\0';
        return 0;
    }
    
    /* Create new mapping entry */
    struct domain_map_entry *entry = calloc(1, sizeof(*entry));
    if (!entry) {
        return -1;
    }
    
    strncpy(entry->domain, domain, sizeof(entry->domain) - 1);
    entry->domain[sizeof(entry->domain) - 1] = '\0';
    strncpy(entry->app_name, app_name, APP_NAME_MAX_LEN - 1);
    entry->app_name[APP_NAME_MAX_LEN - 1] = '\0';
    
    ds_tree_insert(&monitor->domain_tree, entry, entry->domain);
    
    return 0;
}

/* Update application usage from domain and bytes */
int app_monitor_update_usage(struct app_monitor *monitor, 
                            const char *domain, 
                            uint64_t bytes)
{
    if (!monitor || !domain || bytes == 0) {
        return -1;
    }
    
    /* Get application name from domain */
    const char *app_name = app_monitor_domain_to_app(domain);
    
    /* Find app entry by name (tree is keyed by app_name) */
    struct app_usage_entry *entry = ds_tree_find(&monitor->app_tree, app_name);
    
    if (!entry) {
        /* Create new app entry */
        entry = calloc(1, sizeof(*entry));
        if (!entry) {
            return -1;
        }
        
        strncpy(entry->app_name, app_name, APP_NAME_MAX_LEN - 1);
        entry->app_name[APP_NAME_MAX_LEN - 1] = '\0';
        strncpy(entry->domain, domain, sizeof(entry->domain) - 1);
        entry->domain[sizeof(entry->domain) - 1] = '\0';
        entry->usage_bytes = 0;
        entry->last_update = time(NULL);
        
        /* Insert keyed by app_name for fast lookup */
        ds_tree_insert(&monitor->app_tree, entry, entry->app_name);
        monitor->total_apps++;
    }
    
    /* Update usage */
    entry->usage_bytes += bytes;
    entry->last_update = time(NULL);
    
    return 0;
}

/* Compare function for qsort - sort by usage descending */
static int compare_usage_desc(const void *a, const void *b)
{
    const struct app_usage_entry *entry_a = *(const struct app_usage_entry **)a;
    const struct app_usage_entry *entry_b = *(const struct app_usage_entry **)b;
    
    if (entry_a->usage_bytes > entry_b->usage_bytes) {
        return -1;
    } else if (entry_a->usage_bytes < entry_b->usage_bytes) {
        return 1;
    }
    return 0;
}

/* Get top N applications by usage */
int app_monitor_get_top_n(struct app_monitor *monitor, 
                         struct app_usage_entry **entries, 
                         int n)
{
    if (!monitor || !entries || n <= 0) {
        return 0;
    }
    
    /* Collect all entries from tree */
    struct app_usage_entry *all_entries[256]; /* Max 256 apps */
    int total_count = 0;
    struct app_usage_entry *entry;
    
    ds_tree_foreach(&monitor->app_tree, entry) {
        if (total_count < 256) {
            all_entries[total_count++] = entry;
        }
    }
    
    if (total_count == 0) {
        return 0;
    }
    
    /* Sort by usage descending */
    qsort(all_entries, total_count, sizeof(struct app_usage_entry *), compare_usage_desc);
    
    /* Copy top N to output */
    int count = (total_count < n) ? total_count : n;
    for (int i = 0; i < count; i++) {
        entries[i] = all_entries[i];
    }
    
    return count;
}

/* Add IP to domain mapping (from DNS response) */
int app_monitor_add_ip_mapping(struct app_monitor *monitor,
                              uint32_t ip,
                              const char *domain)
{
    if (!monitor || !domain || domain[0] == '\0') {
        return -1;
    }
    
    /* Check if mapping already exists */
    struct ip_domain_entry *entry = ds_tree_find(&monitor->ip_tree, &ip);
    if (entry) {
        /* Update existing mapping */
        strncpy(entry->domain, domain, sizeof(entry->domain) - 1);
        entry->domain[sizeof(entry->domain) - 1] = '\0';
        entry->last_seen = time(NULL);
        return 0;
    }
    
    /* Create new mapping entry */
    entry = calloc(1, sizeof(*entry));
    if (!entry) {
        return -1;
    }
    
    entry->ip = ip;
    strncpy(entry->domain, domain, sizeof(entry->domain) - 1);
    entry->domain[sizeof(entry->domain) - 1] = '\0';
    entry->last_seen = time(NULL);
    
    ds_tree_insert(&monitor->ip_tree, entry, &entry->ip);
    
    return 0;
}

/* Get domain from IP address (ip is in host byte order) */
const char *app_monitor_get_domain_from_ip(struct app_monitor *monitor, uint32_t ip)
{
    if (!monitor) {
        return NULL;
    }
    
    /* IP is in host byte order, find matching entry */
    struct ip_domain_entry *entry = ds_tree_find(&monitor->ip_tree, &ip);
    if (entry) {
        return entry->domain;
    }
    
    return NULL;
}

/* Update usage from IP address and bytes (TX+RX combined) */
int app_monitor_update_usage_from_ip(struct app_monitor *monitor,
                                     uint32_t ip,
                                     uint64_t tx_bytes,
                                     uint64_t rx_bytes)
{
    if (!monitor) {
        return -1;
    }
    
    /* Get domain from IP */
    const char *domain = app_monitor_get_domain_from_ip(monitor, ip);
    char ip_str[INET_ADDRSTRLEN];
    const char *use_domain = domain;
    
    if (!domain || domain[0] == '\0') {
        /* No domain mapping found - use IP as fallback (ip is in host byte order) */
        struct in_addr addr;
        addr.s_addr = htonl(ip);  /* Convert to network byte order for inet_ntop */
        inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));
        use_domain = ip_str;
    }
    
    /* Combine TX and RX bytes */
    uint64_t total_bytes = tx_bytes + rx_bytes;
    
    /* Update usage using domain (use_domain is either domain or ip_str, both valid) */
    return app_monitor_update_usage(monitor, use_domain, total_bytes);
}

/* Print top 10 applications in requested format */
void app_monitor_print_top10(struct app_monitor *monitor)
{
    if (!monitor) {
        return;
    }
    
    struct app_usage_entry *top_entries[10];
    int count = app_monitor_get_top_n(monitor, top_entries, 10);
    
    if (count == 0) {
        printf("No application usage data available\n");
        return;
    }
    
    /* Print header */
    printf("application   usage(MB)\n");
    
    /* Print top applications */
    for (int i = 0; i < count; i++) {
        double usage_mb = (double)top_entries[i]->usage_bytes / (1024.0 * 1024.0);
        printf("%-12s  %.2fMB\n", top_entries[i]->app_name, usage_mb);
    }
}

