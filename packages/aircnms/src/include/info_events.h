#ifndef INFO_EVENTS_H
#define INFO_EVENTS_H

#include <stdint.h>
#include <stdbool.h>
#include "stats_report.h"

/* Client Info Event Structure */
typedef struct {
    uint8_t macaddr[6];              // MAC address in uint8_t array format
    char hostname[HOSTNAME_MAX_LEN]; // Hostname of the client
    char ipaddr[IPADDR_MAX_LEN];     // IP Address as string
    char ssid[SSID_MAX_LEN];         // SSID of connected network
    char band[8];                    // Band (e.g., "BAND2G", "BAND5G")
    uint32_t channel;                // Channel number
    char client_type[16];           // Client type (e.g., "wireless")
    char osinfo[256];                // OS information
    uint64_t start_time;            // Start time in milliseconds
    uint64_t end_time;              // End time in milliseconds
    client_capability_t capability; // Client capability
    bool is_connected;
} client_info_event_t;

/* VIF Info Event Structure */
typedef struct {
    char serialNum[32];              // Serial number
    char macAddr[18];                // MAC address
    int n_radio;                     // Number of radios
    radio_info_t radio[MAX_RADIO];   // Radio info array
    int n_vif;                       // Number of VIFs
    vif_info_t vif[MAX_VIF];         // VIF info array
    int n_ethernet;                  // Number of ethernet interfaces
    ethernet_info_t ethernet[MAX_ETHERNET];  // Ethernet info array
} vif_info_event_t;

/* Device Info Event Structure */
typedef struct {
    char serialNum[32];              // Serial number
    char macAddr[18];                // MAC address
    char deviceType[16];             // Device type (e.g., "router")
    char model[32];                  // Model (e.g., "MT7621")
    char firmwareVersion[32];        // Firmware version
    char manufacturer[32];          // Manufacturer (e.g., "AirCNMS")
    char egressIp[16];               // Egress IP address
    char mgmtIp[16];                 // Management IP address
    char latitude[32];               // Latitude
    char longitude[32];              // Longitude
} device_info_event_t;

/* Info Event Types */
typedef enum {
    INFO_EVENT_CLIENT = 1,
    INFO_EVENT_VIF = 2,
    INFO_EVENT_DEVICE = 3
} info_event_type_t;

/* Generic Info Event Structure */
typedef struct {
    info_event_type_t type;
    uint64_t timestamp_ms;
    union {
        client_info_event_t client;
        vif_info_event_t vif;
        device_info_event_t device;
    } u;
} info_event_t;

#endif // INFO_EVENTS_H

