#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <linux/version.h>
#include <linux/timer.h>
#include <linux/miscdevice.h>
#include <linux/init.h>
#include <linux/time.h>
#include <linux/hashtable.h> // Added for hash table support
#include "queue.h"

#ifndef __AIR_VIF_H__
#define __AIR_VIF_H__

#define NETLINK_USER 31
#define CLIENT_HASHSIZE       100
#define MAX_DOMAINS 10
#define MAX_DOMAIN_NAME_LEN 256
#define MAX_BLOCKED_IPS 16
#define MAX_BLOCKED_DOMAINS 100

struct air_vif;

enum air_skb_direct {
    AIR_SKB_PREROUTE = 0,
    AIR_SKB_POSTROUTE = 1
};

enum {
    AIR_RL_DIR_UPLINK,
    AIR_RL_DIR_DOWNLINK,
    AIR_RL_DIR_MAX
};

struct blocked_ip {
    __be32 ip;
    struct hlist_node node;
};

struct blocked_domain {
    char domain[MAX_DOMAIN_NAME_LEN];
    struct hlist_head ip_list;
    struct hlist_node node;
    int active;
};

struct client_node {
    u32 ip;
    u64 ts;
    u8 macaddr[6];
    char hostname[32];
    char fingerprint[256];
    char ifname[12];
    u32 lease_time;
    u32 rxbytes;
    u32 txbytes;
    u32 connected_tms;
    struct ratelimit_bucket *rl[AIR_RL_DIR_MAX];
    TAILQ_ENTRY(client_node) nl;
    LIST_ENTRY(client_node) nh;
};

struct client {
    spinlock_t lock;
    TAILQ_HEAD( ,client_node) client_list;
    ATH_LIST_HEAD(, client_node) client_hash[CLIENT_HASHSIZE];
};

struct domain_entry {
    char domain[MAX_DOMAIN_NAME_LEN];
    uint32_t count;
};

struct air_vif {
    /* client node */
    struct client nc;

    // Array to store the top 10 domains for this VIF
    struct domain_entry top_domains[MAX_DOMAINS];
    // Lock to protect the top domain data
    spinlock_t domain_lock;
    // Hash table for blocked domains
    DECLARE_HASHTABLE(blocked_domains, 8); // 2^8 = 256 buckets

    struct timer_list air_active_node_timer;
    struct sock *nl_sk;
};

struct client_node *client_reg_table_lookup(uint8_t *macaddr);
struct client_node *client_reg_table_alloc(char *macaddr);

#define OS_SPIN_LOCK_INIT(lock) spin_lock_init((lock))
#define OS_SPIN_LOCK_DEINIT(lock)
#define OS_SPIN_LOCK(lock) spin_lock_bh((lock))
#define OS_SPIN_UNLOCK(lock) spin_unlock_bh((lock))

#define MAX_MAC_ADDR_LEN 6
#define MAX_HOSTNAME_LEN 16
#define MAX_IP_LEN 16
#define CLIENT_HASH(addr)  \
    (((const u_int8_t *)(addr))[MAX_MAC_ADDR_LEN - 1] % CLIENT_HASHSIZE)

#define IEEE80211_ADDR_EQ(a1,a2)        (memcmp(a1, a2, MAX_MAC_ADDR_LEN) == 0)
#define IEEE80211_ADDR_COPY(dst,src)    memcpy(dst, src, MAX_MAC_ADDR_LEN)
#define IEEE80211_HOSTNAME_COPY(dst,src)    memcpy(dst, src, MAX_HOSTNAME_LEN)
#define IEEE80211_IP_COPY(dst,src) memcpy(dst,src,MAX_IP_LEN)

static inline unsigned long hash_string(const char *str) {
    unsigned long hash = 5381;
    int c;
    while ((c = *str++))
        hash = ((hash << 5) + hash) + c;
    return hash;
}

/* function declearation */
int send_nl_event(char *msg);
void netlink_exit(void);
#endif
