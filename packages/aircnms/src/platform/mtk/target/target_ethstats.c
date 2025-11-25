#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <dirent.h>
#include "stats_report.h"
#include "info_events.h"

/* ===== Utility Functions ===== */

static uint64_t read_u64(const char *path)
{
    FILE *fp = fopen(path, "r");
    if (!fp) return 0;

    uint64_t val = 0;
    fscanf(fp, "%llu", &val);
    fclose(fp);
    return val;
}

static void read_str(const char *path, char *buf, size_t size)
{
    FILE *fp = fopen(path, "r");
    if (!fp) {
        snprintf(buf, size, "unknown");
        return;
    }
    fgets(buf, size, fp);
    buf[strcspn(buf, "\n")] = 0;
    fclose(fp);
}

/* Identify valid Ethernet interfaces in OpenWrt */
static int is_valid_eth(const char *ifname)
{
    if (strncmp(ifname, "eth", 3) == 0) return 1;
    if (strncmp(ifname, "lan", 3) == 0) return 1;       // DSA ports
    if (strcmp(ifname, "wan") == 0) return 1;           // Logical WAN
    return 0;
}

/* Fill stats for one interface */
static void fill_interface_stats(const char *ifname, ethernet_stats_t *e)
{
    memset(e, 0, sizeof(*e));
    snprintf(e->interface, sizeof(e->interface), "%s", ifname);

    char path[128];

    // RX/TX byte/packet counters
    snprintf(path, sizeof(path), "/sys/class/net/%s/statistics/rx_bytes", ifname);
    e->rxBytes = read_u64(path);

    snprintf(path, sizeof(path), "/sys/class/net/%s/statistics/tx_bytes", ifname);
    e->txBytes = read_u64(path);

    snprintf(path, sizeof(path), "/sys/class/net/%s/statistics/rx_packets", ifname);
    e->rxPackets = read_u64(path);

    snprintf(path, sizeof(path), "/sys/class/net/%s/statistics/tx_packets", ifname);
    e->txPackets = read_u64(path);

    snprintf(path, sizeof(path), "/sys/class/net/%s/statistics/rx_errors", ifname);
    e->rxErrors = (uint32_t)read_u64(path);

    snprintf(path, sizeof(path), "/sys/class/net/%s/statistics/tx_errors", ifname);
    e->txErrors = (uint32_t)read_u64(path);

    snprintf(path, sizeof(path), "/sys/class/net/%s/statistics/rx_dropped", ifname);
    e->rxDropped = (uint32_t)read_u64(path);

    snprintf(path, sizeof(path), "/sys/class/net/%s/statistics/tx_dropped", ifname);
    e->txDropped = (uint32_t)read_u64(path);

    // Carrier / link status
    snprintf(path, sizeof(path), "/sys/class/net/%s/carrier", ifname);
    e->link = (uint32_t)read_u64(path);

    // Speed
    snprintf(path, sizeof(path), "/sys/class/net/%s/speed", ifname);
    uint64_t speed = read_u64(path);
    e->speed = (speed == (uint64_t)-1 ? 0 : speed);

    // Duplex mode
    snprintf(path, sizeof(path), "/sys/class/net/%s/duplex", ifname);
    read_str(path, e->duplex, sizeof(e->duplex));
}


/* ===== Main Function Required ===== */

bool get_all_ethernet_stats(vif_record_t *record)
{
    if (!record)
        return false;

    record->stats.n_ethernet = 0;

    DIR *d = opendir("/sys/class/net");
    if (!d)
        return false;

    struct dirent *de;
    while ((de = readdir(d)) != NULL) {

        /* skip non-directory, non-symlink entries */
        if (de->d_type != DT_LNK && de->d_type != DT_DIR)
            continue;

        const char *ifname = de->d_name;

        if (!is_valid_eth(ifname))
            continue;

        if (record->stats.n_ethernet >= MAX_ETHERNET)
            break;

        ethernet_stats_t *entry =
            &record->stats.ethernet[record->stats.n_ethernet];

        fill_interface_stats(ifname, entry);
        record->stats.n_ethernet++;
    }

    closedir(d);
    return true;
}

bool get_all_ethernet_info(vif_info_event_t *vif_info)
{
    if (!vif_info)
        return false;

    vif_info->n_ethernet = 0;

    DIR *d = opendir("/sys/class/net");
    if (!d)
        return false;

    struct dirent *de;
    while ((de = readdir(d)) != NULL) {

        /* skip non-directory, non-symlink entries */
        if (de->d_type != DT_LNK && de->d_type != DT_DIR)
            continue;

        const char *ifname = de->d_name;

        if (!is_valid_eth(ifname))
            continue;

        if (vif_info->n_ethernet >= MAX_ETHERNET)
            break;

        snprintf(vif_info->ethernet[vif_info->n_ethernet].interface, sizeof(vif_info->ethernet[vif_info->n_ethernet].interface), ifname);
        snprintf(vif_info->ethernet[vif_info->n_ethernet].name, sizeof(vif_info->ethernet[vif_info->n_ethernet].name), ifname);
        snprintf(vif_info->ethernet[vif_info->n_ethernet].type, sizeof(vif_info->ethernet[vif_info->n_ethernet].type), ifname);
        
        vif_info->n_ethernet++;
    }

    closedir(d);
    return true;
}
