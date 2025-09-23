#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/fs.h>
#include <linux/skbuff.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/if_arp.h>
#include <linux/version.h>
#include <linux/miscdevice.h>
#include <linux/export.h>
#include "air_common.h"
#include "air_vif.h"
#include "queue.h"

#ifndef __AIR_COPLANE_H__
#define __AIR_COPLANE_H__

#define MAX_MAC_ADDR_LEN         6
#define MAX_NWID_LEN             32
#define BRIDGE_DEV_PREFIX      "br-lan"
#define TUNNEL_DEV_PREFIX      "bcp"
#define PPPOE_DEV_PREFIX       "ppp"
#define WIRELESS_RADIO_PREFIX  "wifi"
#define WIRELESS_VAP_PREFIX    "ath"
#define ETHERNET_DEV_PREFIX    "eth"
#define MAX_VAPS                 8
#define MAX_STA_HOSTNAME         32
#define MAX_EXPIRE_TS_MS       3000
#define MAX_DNS_LENGTH         256
#define MAX_NUM_DNS            10
#define MAX_WLANS              8

#define IPv4FORMAT      "%u.%u.%u.%u"
#define IPv4BYTES(x)    ((const uint8_t *)x)[0],((const uint8_t *)x)[1],((const uint8_t *)x)[2],((const uint8_t *)x)[3]

#define WLAN_STA_HASHSIZE       100
#define WLAN_STA_DOMAIN_NAME_HASHSIZE 10
#define IEEE80211_ADDR_LEN      6
#define WLAN_STA_HASH(addr)  \
    (((const u_int8_t *)(addr))[MAX_MAC_ADDR_LEN - 1] % WLAN_STA_HASHSIZE)

#define IEEE80211_ADDR_EQ(a1,a2)        (memcmp(a1, a2, MAX_MAC_ADDR_LEN) == 0)
#define IEEE80211_ADDR_COPY(dst,src)    memcpy(dst, src, MAX_MAC_ADDR_LEN)


/* Supported STA Bands*/
typedef enum {
    IEEE80211_2G_BAND,
    IEEE80211_5G_BAND,
    IEEE80211_INVALID_BAND
} IEEE80211_STA_BAND;

enum airpro_radio_mapping {
    AIRPRO_RADIO_24 = 0,
    AIRPRO_RADIO_5 = 1,
    AIRPRO_RADIO_6 = 2,
};

enum wlan_opmode {
    WLAN_M_STA         = 1,
    WLAN_M_IBSS        = 0,
    WLAN_M_AHDEMO      = 3,
    WLAN_M_HOSTAP      = 6,
    WLAN_M_MONITOR     = 8,
    WLAN_M_WDS         = 2,
    WLAN_M_BTAMP       = 9,
    WLAN_M_P2P_GO      = 33,
    WLAN_M_P2P_CLIENT  = 34,
    WLAN_M_P2P_DEVICE  = 35,
    WLAN_OPMODE_MAX    = WLAN_M_BTAMP,
    WLAN_M_ANY         = 0xFF
};

/* radio like wifi0 , wifi1, eth0, eth1 */
struct nw_iface {
    struct net_device *dev;
    int iface_type; //PHY_ETH, PHY_WLAN
    char iface_name[16];
    TAILQ_ENTRY(nw_iface) ni_next;
};

/* Configuration per WLAN user */
struct ratelimit_config {
    uint32_t bytes_per_sec; /* Token rate, bytes per second */
    uint32_t size; /* bucket size in bytes */
};

struct ratelimit_bucket {
    unsigned long last_update; /* Last time bucket was updated */
    unsigned long tokens; /* Tokens in bucket. This is unsigned long so we can use cmpxchg */
    uint32_t tokens_per_jiffy; /* Tokens earned per jiffy, zero if no rate limiting */
    uint32_t max_tokens; /* burst size */
    unsigned int dropped; /* Packets dropped */
};

struct wlan_sta {
    uint8_t            src_mac[MAX_MAC_ADDR_LEN];
    uint8_t            dest_mac[MAX_MAC_ADDR_LEN];
    uint8_t            bssid[MAX_MAC_ADDR_LEN];
    uint8_t            hostname[16+1];
    uint8_t            ss[1024]; //for os name and desc
    uint8_t            ipv4_addr[20];
    uint8_t            domain_name_count;
    uint8_t            channel;
    uint8_t            webs_ow_idx;//overwrite index after top 10
    uint64_t           tx_bytes;
    uint64_t           rx_bytes;
    uint64_t           tx_pkts;
    uint64_t           rx_pkts;
    int                wlan_id; /* wlan-id of sta 0... (MAX_WLANS-1) */
    int                rssi;
    char               ifname[8];
    char               ssid[32+1];
    int                bw;
    int                phymode;
    int                txratekbps;
    int                rxratekbps;
    struct ratelimit_bucket *rl[AIR_RL_DIR_MAX];
    char domain_name[10][MAX_DNS_LENGTH];
    TAILQ_ENTRY(wlan_sta) ws_next;
    LIST_ENTRY(wlan_sta) ws_hash;
};

struct wlan_sta_rc {
    uint32_t ul_bytes_per_sec;
    uint8_t rl_ul_update;
    uint32_t dl_bytes_per_sec;
    uint8_t rl_dl_update;
    uint8_t macaddr[MAX_MAC_ADDR_LEN];
    TAILQ_ENTRY(wlan_sta_rc) rc_next;
    LIST_ENTRY(wlan_sta_rc) rc_hash;
};

struct wlan_client_list {
    spinlock_t wlan_client_lock;
    TAILQ_HEAD( ,wlan_sta) wlan_coplane_sta_list;
    ATH_LIST_HEAD(, wlan_sta) wlan_coplane_sta_hash[WLAN_STA_HASHSIZE];
};

struct airpro_coplane {
    spinlock_t nw_iface_lock;
    TAILQ_HEAD( ,nw_iface) nw_iface_list;

    struct wlan_client_list wlan_client;
    
    struct timer_list airpro_sta_unreg_timer;

    /*RATE CONTROL STA LIST */
    spinlock_t wlan_sta_rc_lock;
    TAILQ_HEAD( ,wlan_sta_rc) wlan_sta_rc_list;
    ATH_LIST_HEAD(, wlan_sta_rc) wlan_sta_rc_hash[WLAN_STA_HASHSIZE];

};

#define OS_SPIN_NW_IFACE_LOCK_INIT(lock) spin_lock_init((lock))
#define OS_SPIN_NW_IFACE_LOCK_DEINIT(lock) 
#define OS_SPIN_NW_IFACE_LOCK(lock) spin_lock_bh((lock))
#define OS_SPIN_NW_IFACE_UNLOCK(lock) spin_unlock_bh((lock))

#define OS_SPIN_WLAN_STA_LOCK_INIT(lock) spin_lock_init((lock))
#define OS_SPIN_WLAN_STA_LOCK_DEINIT(lock) 
#define OS_SPIN_WLAN_STA_LOCK(lock) spin_lock_bh((lock))
#define OS_SPIN_WLAN_STA_UNLOCK(lock) spin_unlock_bh((lock))

#define OS_SPIN_WLAN_RC_LOCK_INIT(lock) spin_lock_init((lock))
#define OS_SPIN_WLAN_RC_LOCK_DEINIT(lock) 
#define OS_SPIN_WLAN_RC_LOCK(lock) spin_lock_bh((lock))
#define OS_SPIN_WLAN_RC_UNLOCK(lock) spin_unlock_bh((lock))

#endif

