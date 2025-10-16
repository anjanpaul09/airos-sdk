#include <linux/netdevice.h>
#include <linux/netfilter_bridge.h>
#include <net/netfilter/nf_conntrack.h>
#include <linux/hashtable.h>
#include <net/cfg80211.h>
#include <linux/export.h>
#include "air_coplane.h"
#include "air_ioctl.h"
#include "air_api.h"

struct airpro_coplane *coplane = NULL;
extern struct ratelimit_bucket *wlan_rl[MAX_WLANS][AIR_RL_DIR_MAX];
extern struct ratelimit_bucket *user_wlan_rl[MAX_WLANS][AIR_RL_DIR_MAX];

static unsigned int air_hookfunc_preroute(void* priv, struct sk_buff* skb, const struct nf_hook_state* st);
static unsigned int air_hookfunc_postroute(void* priv, struct sk_buff* skb, const struct nf_hook_state* st);
unsigned int air_ingress_hook(struct sk_buff *skb, const struct nf_hook_state* st);
unsigned int air_egress_hook(struct sk_buff *skb, const struct nf_hook_state* st);
long air_device_ioctl(struct file *file, unsigned int cmd, unsigned long arg);
struct wlan_sta *sta_table_lookup(uint8_t *macaddr, int dir, uint8_t ifindex);

int air_active_node_init_timer(void);
int air_vif_node_sysctl_register(void);
int air_vif_node_sysctl_unregister(void);
void packet_counter_reset(struct timer_list *t);
int netlink_init(void);

/* kprobes removed: use ops/API callbacks instead */

static struct nf_hook_ops g_hook_preroute = {
    .hook = air_hookfunc_preroute,
    .hooknum = NF_BR_PRE_ROUTING, // Bridge pre-routing hook
    .pf = NFPROTO_BRIDGE,         // Protocol family for bridge packets
    .priority = NF_BR_PRI_FIRST, // High priority
};

static struct nf_hook_ops g_hook_postroute = {
    .hook = air_hookfunc_postroute,
    .hooknum = NF_BR_POST_ROUTING,
    .pf = NFPROTO_BRIDGE,
    .priority = NF_BR_PRI_LAST,
};

static unsigned int air_hookfunc_preroute(void* priv, struct sk_buff* skb, const struct nf_hook_state* st)
{
    return air_ingress_hook(skb, st);
}

static unsigned int air_hookfunc_postroute(void* priv, struct sk_buff* skb, const struct nf_hook_state* st)
{
    return air_egress_hook(skb, st);
}

int remove_client_from_coplane_table(uint8_t *macaddr)
{
    struct wlan_sta *sta, *sta_next;
    int hash;

    hash = WLAN_STA_HASH(macaddr);

    if (!TAILQ_EMPTY(&coplane->wlan_client.wlan_coplane_sta_list)) {
        TAILQ_FOREACH_SAFE(sta, &coplane->wlan_client.wlan_coplane_sta_list, ws_next, sta_next) {
            if (memcmp(sta->src_mac, macaddr, ETH_ALEN) == 0) {
                TAILQ_REMOVE(&coplane->wlan_client.wlan_coplane_sta_list, sta, ws_next);
                LIST_REMOVE(sta, ws_hash);
                kfree(sta);
                return 0;       
            }
        }
    }
    
    return -1;
}

int remove_client_from_reg_table(uint8_t *macaddr, char *ifname)
{
    struct client_node *cn;
    int hash;

    // Check in vif client hash table
    hash = CLIENT_HASH(macaddr);

    LIST_FOREACH(cn, &coplane->reg.client_hash[hash], nh) {
        if (!strcmp(cn->ifname, ifname) &&
            memcmp(cn->macaddr, macaddr, ETH_ALEN) == 0) {

            LIST_REMOVE(cn, nh);
            TAILQ_REMOVE(&coplane->reg.client_list, cn, nl);
            kfree(cn);
            printk("Client removed from reg table: %02x:%02x:%02x:%02x:%02x:%02x\n",
                   macaddr[0], macaddr[1], macaddr[2],
                   macaddr[3], macaddr[4], macaddr[5]);
            return 0;
        }
    }

    return -1; // Client not found
}

/* sta ops now implemented in sta_ops.c */

/* ops registration/get now implemented in air_ops.c */

/* blocked domain helpers moved to ioctl.c */

/* air_device_ioctl() moved to ioctl.c */

/* kprobe handlers removed */

static const struct file_operations air_misc_fops = {

    .compat_ioctl = air_device_ioctl,
    .unlocked_ioctl = air_device_ioctl

};

static struct miscdevice air_miscdev = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = "air",
    .fops = &air_misc_fops,
};

/* airdpi ops instance to expose to mac80211/cfg80211 via airdpi_register_ops */
static const struct airdpi_ops airdpi_g_ops = {
    .sta_add = airdpi_sta_add,
    .sta_del = airdpi_sta_del,
};

int air_init_netfilter_hook(void)
{
    int status;

    printk("Registering g_hook_preroute\n");
    if ((status = nf_register_net_hook(&init_net, &g_hook_preroute))) {
        printk("[AirPro][DPI] Registering g_hook_preroute failed with code %d\n", status);
        return status;
    }
    printk("g_hook_preroute hook success\n");
    printk("Registering g_hook_postroute\n");

    if ((status = nf_register_net_hook(&init_net, &g_hook_postroute))) {
        nf_unregister_net_hook(&init_net, &g_hook_preroute);
        printk("Registering g_hook_postroute failed with code %d\n", status);
        return status;
    }
    printk("g_hook_postroute hook success\n");
    
    return 0;
}

int air_vif_module_init(void)
{
    int i;

    coplane = kmalloc(sizeof(struct airpro_coplane), GFP_KERNEL);
    if (!coplane) {
        return -1;
    }
    memset(coplane, 0, sizeof(struct airpro_coplane));

    TAILQ_INIT(&coplane->nw_iface_list);
    TAILQ_INIT(&coplane->wlan_client.wlan_coplane_sta_list);
    TAILQ_INIT(&coplane->wlan_sta_rc_list);
    OS_SPIN_NW_IFACE_LOCK_INIT(&coplane->nw_iface_lock);
    OS_SPIN_WLAN_STA_LOCK_INIT(&coplane->wlan_client.wlan_client_lock);
    OS_SPIN_WLAN_RC_LOCK_INIT(&coplane->wlan_sta_rc_lock);

    hash_init(coplane->blocked_domains);

    TAILQ_INIT(&coplane->reg.client_list);
    OS_SPIN_LOCK_INIT(&coplane->reg.lock);

    spin_lock_init(&coplane->domain_lock);
    // Initialize the top_domains array
    for (i = 0; i < MAX_DOMAINS; i++) {
        coplane->top_domains[i].domain[0] = '\0';
        coplane->top_domains[i].count = 0;
    }

    //air_active_node_init_timer(vif);
    if (air_vif_node_sysctl_register() < 0) {
        printk("reg sysctl failed..\n");
    }

    if (misc_register(&air_miscdev)) {
        printk("misc reg failed!!!\n");
        return -EINVAL;
    }

    if (air_init_netfilter_hook()) {
        return -EINVAL;
    }

    /* Register airdpi ops so backports/mac80211 can call us safely */
    if (airdpi_register_ops(&airdpi_g_ops)) {
        printk("AIRDPI: failed to register ops\n");
    } else {
        printk("AIRDPI: ops registered\n");
    }

    //netlink_init();

    printk("air coplane init %p\n", coplane);
    
    return 0;
}

int air_vif_module_exit(void)
{
    struct blocked_domain *bd;
    struct blocked_ip *bi;
    struct hlist_node *pos, *n;
    int bkt;
    unsigned long flags;

    air_vif_node_sysctl_unregister();
    nf_unregister_net_hook(&init_net, &g_hook_preroute);
    nf_unregister_net_hook(&init_net, &g_hook_postroute);
    //del_timer(&vif->air_active_node_timer);
    misc_deregister(&air_miscdev);

    /* Unregister ops */
    airdpi_unregister_ops(&airdpi_g_ops);

    /* kprobe removed */

    spin_lock_irqsave(&coplane->domain_lock, flags);
    hash_for_each(coplane->blocked_domains, bkt, bd, node) {
        hlist_for_each_safe(pos, n, &bd->ip_list) {
            bi = hlist_entry(pos, struct blocked_ip, node);
            hlist_del(&bi->node);
            kfree(bi);
        }
        hash_del(&bd->node);
        kfree(bd);
    }
    spin_unlock_irqrestore(&coplane->domain_lock, flags);

    /* no separate vif allocation anymore */
    kfree(coplane);
    //netlink_exit();

    printk("air coplane deinit\n");

    return 0;
}

static int __init vifmodule_init(void)
{
    air_vif_module_init();

    return 0;
}

static void __exit vifmodule_exit(void)
{
    air_vif_module_exit();
}

module_init(vifmodule_init);
module_exit(vifmodule_exit);
MODULE_LICENSE("GPL");
