#include <linux/types.h>  // Then include Linux headers
//#include <linux/netdevice.h>
#include <linux/ioctl.h> 

#define MAX_MAC_ADDR_LEN       6
#define MAX_DOMAINS 10
#define MAX_DOMAIN_NAME_LEN 256

#define SIMPLE_HASH(str) ({ \
    unsigned int hash = 5381; \
    const char *s = str; \
    while (*s) { \
        hash = ((hash << 5) + hash) + (unsigned char)(*s); \
        s++; \
    } \
    hash; \
})

#define IFNAME_HASH(ifname) (SIMPLE_HASH(ifname) % 8)

/* remove client */
struct adpi_add_sta_entry {
    char ifname[12];
    uint8_t macaddr[MAX_MAC_ADDR_LEN];
};

/* remove client */
struct adpi_del_sta_entry {
    char ifname[12];
    uint8_t macaddr[MAX_MAC_ADDR_LEN];
};

struct adpi_ratelimit_bucket {
    uint8_t macaddr[MAX_MAC_ADDR_LEN];
    uint32_t uplink_bytes_per_sec;     // Uplink rate limit
    uint32_t uplink_size;               // Uplink burst size
    uint32_t downlink_bytes_per_sec;   // Downlink rate limit
    uint32_t downlink_size;             // Downlink burst size
    int wlan_idx;                       // Index or ID of the WLAN
};

struct adpi_domain_entry {
    char domain[MAX_DOMAIN_NAME_LEN];
    uint32_t count;
};

struct adpi_client_entry {
    uint32_t ip;
    uint8_t macaddr[6];
    char hostname[32];
};

struct adpi_client_info {
    int count;
    struct adpi_client_entry entry[32];
};

struct sta_info {
    uint32_t ip;
    uint8_t macaddr[6];
    char hostname[32];
    char ifname[12];
    char os_name[256];
    uint8_t is_wireless;
};

struct adpi_sta_data {
    uint8_t macaddr[6];
    uint8_t result_valid;
    uint8_t reserved;
    struct sta_info info;
};


#define IOCTL_ADPI_TYPE_STA_ADD_ENTRY                  1
#define IOCTL_ADPI_TYPE_STA_DEL_ENTRY                  2
#define IOCTL_ADPI_TYPE_RATELIMIT_WLAN                 3
#define IOCTL_ADPI_TYPE_RATELIMIT_WLAN_USER            4
#define IOCTL_ADPI_TYPE_RATELIMIT_WLAN_PER_USER        5
#define IOCTL_ADPI_TYPE_GET_AP_TOP_DOMAINS             6
#define IOCTL_ADPI_TYPE_GET_ALL_CLIENTS                7
#define IOCTL_ADPI_TYPE_GET_RATELIMIT_WLAN_USER        8
#define IOCTL_ADPI_TYPE_GET_RATELIMIT_WLAN             9
#define IOCTL_ADPI_TYPE_GET_STA_DATA                   10

#define IOCTL_ADPI_STA_ADD_ENTRY             _IOW(IOCTL_ADPI_TYPE_STA_ADD_ENTRY, 1, struct adpi_add_sta_entry)
#define IOCTL_ADPI_STA_DEL_ENTRY             _IOW(IOCTL_ADPI_TYPE_STA_DEL_ENTRY, 1, struct adpi_del_sta_entry)
#define IOCTL_ADPI_RATELIMIT_WLAN            _IOW(IOCTL_ADPI_TYPE_RATELIMIT_WLAN, 1, struct adpi_ratelimit_bucket)
#define IOCTL_ADPI_RATELIMIT_WLAN_USER       _IOW(IOCTL_ADPI_TYPE_RATELIMIT_WLAN_USER, 1, struct adpi_ratelimit_bucket)
#define IOCTL_ADPI_RATELIMIT_WLAN_PER_USER   _IOW(IOCTL_ADPI_TYPE_RATELIMIT_WLAN_PER_USER, 1, struct adpi_ratelimit_bucket)
#define IOCTL_ADPI_GET_AP_TOP_DOMAINS        _IOW(IOCTL_ADPI_TYPE_GET_AP_TOP_DOMAINS, 1, struct adpi_domain_entry)
#define IOCTL_ADPI_GET_ALL_CLIENTS           _IOW(IOCTL_ADPI_TYPE_GET_ALL_CLIENTS, 1, struct adpi_client_info)
#define IOCTL_ADPI_GET_RATELIMIT_WLAN_USER   _IOW(IOCTL_ADPI_TYPE_GET_RATELIMIT_WLAN_USER, 1, struct adpi_ratelimit_bucket)
#define IOCTL_ADPI_GET_RATELIMIT_WLAN        _IOW(IOCTL_ADPI_TYPE_GET_RATELIMIT_WLAN, 1, struct adpi_ratelimit_bucket)
#define IOCTL_ADPI_GET_STA_DATA              _IOW(IOCTL_ADPI_TYPE_GET_STA_DATA, 1, struct adpi_sta_data)
#define IOCTL_ADPI_BLOCK_DOMAIN              _IOW('A', 0x20, char[MAX_DOMAIN_NAME_LEN])
#define IOCTL_ADPI_UNBLOCK_DOMAIN            _IOW('A', 0x21, char[MAX_DOMAIN_NAME_LEN])
