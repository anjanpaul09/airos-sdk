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
    SM_T_NEIGHBOR  = 1,
    SM_T_CLIENT    = 2,
    SM_T_DEVICE    = 3,
    SM_T_VIF       = 4
} SM_STATS_TYPE;


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

/* Virtual Interface (VIF) Statistics */
typedef struct {
    char radio[8];
    char ssid[SSID_MAX_LEN];
    uint32_t num_sta;
    long uplink_mb;
    long downlink_mb;
} vif_stats_t;

typedef struct {
    char band[8];    
    char ssid[SSID_MAX_LEN];
    uint8_t channel;
    uint8_t txpower;
    uint8_t channel_utilization;
} radio_stats_t;

/* VIF Record */
typedef struct {
    int n_vif;
    vif_stats_t vif[MAX_VIF];
    int n_radio;
    radio_stats_t radio[MAX_RADIO];
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

/* Client Record */
typedef struct {
    uint8_t macaddr[6];     // MAC address in uint8_t array format
    char hostname[HOSTNAME_MAX_LEN]; // Hostname of the client
    char ipaddr[IPADDR_MAX_LEN];     // IP Address as string
    char ssid[SSID_MAX_LEN];         // SSID of connected network
    char osinfo[64];    
    char client_type[16];
    uint64_t rx_bytes;       // Received bytes
    uint64_t tx_bytes;       // Transmitted bytes
    int32_t rssi;
    uint32_t is_connected;
    uint64_t duration_ms;
    radio_type_t radio_type;
    uint32_t channel;
} client_record_t;

typedef struct {
    uint64_t timestamp_ms;
    int n_client;
    client_record_t record[MAX_CLIENTS];
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
} sm_stats_t;


#endif // REPORT_TARGET_H

