#ifndef REPORT_TARGET_H
#define REPORT_TARGET_H

#include <stdint.h>
#include <stdbool.h>

#define MAX_BSSID_LEN 18   // Max length for BSSID (XX:XX:XX:XX:XX:XX)
#define SSID_MAX_LEN 32
#define HOSTNAME_MAX_LEN 64
#define IPADDR_MAX_LEN 16
#define MAX_VIF 32
#define MAX_RADIO 2
#define MAX_CLIENTS 200
#define MAX_NEIGHBOUR 100

/* statistics type  */
typedef enum
{
    NETSTATS_T_NEIGHBOR  = 1,
    NETSTATS_T_CLIENT    = 2,
    NETSTATS_T_DEVICE    = 3,
    NETSTATS_T_VIF       = 4
} NETSTATS_STATS_TYPE;


typedef enum {
    DEVICE_LOAD_AVG_ONE = 0,
    DEVICE_LOAD_AVG_FIVE,
    DEVICE_LOAD_AVG_FIFTEEN,
    DEVICE_LOAD_AVG_QTY
} device_load_avg_t;

/* Memory utilization: [kB] */
typedef struct {
    uint32_t mem_total;
    uint32_t mem_used;
    uint32_t swap_total;
    uint32_t swap_used;
    uint32_t mem_util_percent;
} device_memutil_t;

/* CPU utilization: [percent] */
typedef struct {
    uint32_t cpu_util;
} device_cpuutil_t;

typedef enum
{
    DEVICE_FS_TYPE_ROOTFS = 0,
    DEVICE_FS_TYPE_TMPFS = 1,
    DEVICE_FS_TYPE_QTY
} device_fs_type_t;


/* Filesystem utilization per FS-type: [kB] */
typedef struct {
    device_fs_type_t  fs_type;
    uint32_t fs_total;
    uint32_t fs_used;
    uint32_t fs_util_percent; /* filesystem usage percentage */
} device_fsutil_t;

/* wifi info */
typedef struct {
    uint64_t uplink_mb;
    uint64_t downlink_mb;
    uint64_t total_traffic_mb;
    uint32_t num_sta;
} device_wifiutil_t;

/* System-wide device metrics */
typedef struct {
    double load[DEVICE_LOAD_AVG_QTY];
    uint32_t uptime;
    device_memutil_t mem_util;
    device_cpuutil_t cpu_util;
    device_fsutil_t fs_util[DEVICE_FS_TYPE_QTY];
    device_wifiutil_t w_util;
} device_record_t;

typedef struct {
    device_record_t record;
    uint64_t timestamp_ms;
} device_report_data_t;

#define MAX_ETHERNET 8
#define INTERFACE_NAME_LEN 16

/* Radio Info (static configuration) */
typedef struct {
    char band[8];           // Band (e.g., "BAND2G", "BAND5G")
    uint8_t channel;        // Channel number
    uint8_t txpower;        // TX power
} radio_info_t;

/* Radio Stats (dynamic metrics) */
typedef struct {
    char band[8];          // Band (e.g., "BAND2G", "BAND5G")
    uint8_t channel_utilization;  // Channel utilization percentage
} radio_stats_t;

/* VIF Info (static configuration) */
typedef struct {
    char radio[8];         // Radio band (e.g., "BAND2G", "BAND5G")
    char ssid[SSID_MAX_LEN]; // SSID name
} vif_info_t;

/* VIF Stats (dynamic metrics) */
typedef struct {
    char radio[8];          // Radio band (e.g., "BAND2G", "BAND5G")
    char ssid[SSID_MAX_LEN]; // SSID name
    uint32_t statNumSta;    // Number of stations
    long statUplinkMb;      // Uplink traffic in MB
    long statDownlinkMb;    // Downlink traffic in MB
} vif_stats_t;

/* Ethernet Info (static configuration) */
typedef struct {
    char interface[INTERFACE_NAME_LEN];  // Interface name (e.g., "eth0")
    char name[32];                       // Interface display name (e.g., "WAN", "LAN1")
    char type[16];                       // Interface type (e.g., "wan", "lan")
} ethernet_info_t;

/* Ethernet Stats (dynamic metrics) */
typedef struct {
    char interface[INTERFACE_NAME_LEN];  // Interface name (e.g., "eth0")
    uint64_t rxBytes;                   // Received bytes
    uint64_t txBytes;                    // Transmitted bytes
    uint64_t rxPackets;                  // Received packets
    uint64_t txPackets;                  // Transmitted packets
    uint32_t rxErrors;                   // Receive errors
    uint32_t txErrors;                   // Transmit errors
    uint32_t rxDropped;                  // Receive dropped packets
    uint32_t txDropped;                  // Transmit dropped packets
    uint32_t speed;                       // Link speed in Mbps
    char duplex[8];                      // Duplex mode ("full" or "half")
    uint32_t link;                        // Link status (1 = up, 0 = down)
} ethernet_stats_t;

/* VIF Info Record - Moved to info_events.h, removed from here */

/* VIF Stats Record - Stats only (info moved to info_events) */
typedef struct {
    int n_radio;                     // Number of radios
    radio_stats_t radio[MAX_RADIO];  // Radio stats array
    int n_vif;                       // Number of VIFs
    vif_stats_t vif[MAX_VIF];        // VIF stats array
    int n_ethernet;                  // Number of ethernet interfaces
    ethernet_stats_t ethernet[MAX_ETHERNET];  // Ethernet stats array
} vif_stats_record_t;

/* VIF Record - Stats only (info moved to info_events.h for netevd) */
typedef struct {
    vif_stats_record_t stats; // VIF stats only
} vif_record_t;

typedef struct {
    vif_record_t record;
    uint64_t timestamp_ms;
} vif_report_data_t;

/* Radio Type Enumeration */
typedef enum {
    RADIO_TYPE_NONE = 0,            
    RADIO_TYPE_2G,
    RADIO_TYPE_5G,
    RADIO_TYPE_5GL, 
    RADIO_TYPE_5GU,
    RADIO_TYPE_6G
} radio_type_t;

/* Client Capability */
typedef struct {
    char phy[8];            // PHY type (e.g., "HE")
    char roaming[16];        // Roaming capability (e.g., "11kr")
    char mcs[8];            // MCS value
    char nss[8];            // NSS value
    char ps[8];             // Power save
    char wmm[8];            // WMM
    char mu_mimo[8];        // MU-MIMO
    char ofdma[8];          // OFDMA
    char bw[8];             // Bandwidth
} client_capability_t;

/* Client Stats (sta_stats) - Only stats, no info */
typedef struct {
    uint64_t duration_ms;   // Duration in milliseconds
    int32_t rssi;           // RSSI value
    int32_t snr;            // SNR value
    uint32_t tx_rate_mbps;  // TX rate in Mbps
    uint32_t rx_rate_mbps;  // RX rate in Mbps
    uint64_t tx_bytes;      // Transmitted bytes
    uint64_t rx_bytes;      // Received bytes
    uint64_t tx_packets;    // Transmitted packets
    uint64_t rx_packets;    // Received packets
    uint32_t tx_retries;    // TX retries
    uint32_t tx_failures;   // TX failures
    uint32_t tx_phy_rate;   // TX PHY rate
    uint32_t rx_phy_rate;   // RX PHY rate
    int32_t signal_avg;     // Average signal strength
} sta_stats_t;

/* Client Record - Stats only (info moved to info_events.h for netevd) */
typedef struct {
    uint8_t macaddr[6];     // MAC address in uint8_t array format
    sta_stats_t stats;      // Station stats only
} client_record_t;

typedef struct {
    uint64_t timestamp_ms;
    int n_client;
    int capacity;                // NEW: Track allocated capacity
    client_record_t *record;     // CHANGED: Dynamic pointer instead of array
    //client_record_t record[MAX_CLIENTS];
} client_report_data_t;


typedef struct {
    radio_type_t radio_type;
    char bssid[MAX_BSSID_LEN];  // BSSID of the neighbor AP
    char ssid[SSID_MAX_LEN];    // SSID of the neighbor AP
    int32_t rssi;              // Signal strength (RSSI)
    uint64_t tsf;               // Timing Synchronization Function timestamp
    uint32_t chan_width;        // Channel width
    uint32_t channel;           // Channel number
} neighbor_record_t;

typedef struct {
    uint64_t timestamp_ms;
    int n_entry;
    neighbor_record_t record[MAX_NEIGHBOUR];
} neighbor_report_data_t;


/*main stats */
typedef struct stats
{
    int                             type;
    int                             size;
    union {
        client_report_data_t      client;
        device_report_data_t      device;
        vif_report_data_t         vif;
        neighbor_report_data_t    neighbor;
    } u;
} netstats_stats_t;


#endif // REPORT_TARGET_H

