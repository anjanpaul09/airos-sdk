#include <linux/netdevice.h>
#include <linux/netfilter_bridge.h>
#include <net/netfilter/nf_conntrack.h>
#include <linux/hashtable.h>
#include <net/cfg80211.h>
#include <linux/kprobes.h>
#include "air_vif.h"
#include "air_coplane.h"
#include "air_ioctl.h"

struct timer_list my_timer; // Timer for resetting the counter
struct air_vif *vif;
struct airpro_coplane *coplane = NULL;
extern struct ratelimit_bucket *wlan_rl[MAX_WLANS][AIR_RL_DIR_MAX];
extern struct ratelimit_bucket *user_wlan_rl[MAX_WLANS][AIR_RL_DIR_MAX];

static unsigned int air_hookfunc_preroute(void* priv, struct sk_buff* skb, const struct nf_hook_state* st);
static unsigned int air_hookfunc_postroute(void* priv, struct sk_buff* skb, const struct nf_hook_state* st);
unsigned int air_ingress_hook(struct sk_buff *skb, const struct nf_hook_state* st);
unsigned int air_egress_hook(struct sk_buff *skb, const struct nf_hook_state* st);
static long air_device_ioctl(struct file *file, unsigned int cmd, unsigned long arg);

int air_active_node_init_timer(struct air_vif *vif);
int air_vif_node_sysctl_register(struct air_vif *vif);
int air_vif_node_sysctl_unregister(void);
void packet_counter_reset(struct timer_list *t);
int netlink_init(void);

static struct kprobe kp_new_sta = {
    .symbol_name = "cfg80211_new_sta",
};

static struct kprobe kp_del_sta = {
    .symbol_name = "cfg80211_del_sta_sinfo",
};

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

    LIST_FOREACH(cn, &vif->nc.client_hash[hash], nh) {
        if (!strcmp(cn->ifname, ifname) &&
            memcmp(cn->macaddr, macaddr, ETH_ALEN) == 0) {

            LIST_REMOVE(cn, nh);
            TAILQ_REMOVE(&vif->nc.client_list, cn, nl);
            kfree(cn);
            printk("Client removed from vif table: %02x:%02x:%02x:%02x:%02x:%02x\n",
                   macaddr[0], macaddr[1], macaddr[2],
                   macaddr[3], macaddr[4], macaddr[5]);
            return 0;
        }
    }

    return -1; // Client not found
}

static int add_blocked_domain(struct air_vif *vif, const char *domain) {
    struct blocked_domain *bd;
    unsigned long flags;

    bd = kmalloc(sizeof(*bd), GFP_KERNEL);
    if (!bd) return -ENOMEM;

    strncpy(bd->domain, domain, MAX_DOMAIN_NAME_LEN - 1);
    bd->domain[MAX_DOMAIN_NAME_LEN - 1] = '\0';
    bd->active = 1;
    INIT_HLIST_HEAD(&bd->ip_list); // Initialize ip_list

    spin_lock_irqsave(&vif->domain_lock, flags);
    hash_add(vif->blocked_domains, &bd->node, hash_string(bd->domain));
    spin_unlock_irqrestore(&vif->domain_lock, flags);

    return 0;
}

static int remove_blocked_domain(struct air_vif *vif, const char *domain) {
    struct blocked_domain *bd;
    struct blocked_ip *bi;
    struct hlist_node *pos, *n;
    unsigned long flags;
    int found = 0;

    spin_lock_irqsave(&vif->domain_lock, flags);
    hash_for_each_possible(vif->blocked_domains, bd, node, hash_string(domain)) {
        if (strcmp(bd->domain, domain) == 0) {
            bd->active = 0;
            hlist_for_each_safe(pos, n, &bd->ip_list) {
                bi = hlist_entry(pos, struct blocked_ip, node);
                hlist_del(&bi->node);
                kfree(bi);
            }
            hash_del(&bd->node);
            kfree(bd);
            found = 1;
            break;
        }
    }
    spin_unlock_irqrestore(&vif->domain_lock, flags);

    return found ? 0 : -ENOENT;
}

static long air_device_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    switch (cmd) {
    case IOCTL_ADPI_STA_ADD_ENTRY: {
            struct client_node *cn = NULL;
            struct adpi_add_sta_entry entry;
            if (copy_from_user(&entry, (void __user *)arg, sizeof(entry))) {
                return -EFAULT;
            }
            cn = client_reg_table_lookup(entry.macaddr);
            if (!cn) {
                cn = client_reg_table_alloc(entry.macaddr);
            }
            if (cn) {
                if (cn->ifname[0] == '\0') {
                    strncpy(cn->ifname, entry.ifname, sizeof(cn->ifname) - 1);
                    cn->ifname[sizeof(cn->ifname) - 1] = '\0';
                }
            }
        } break;
    case IOCTL_ADPI_STA_DEL_ENTRY: {
            struct adpi_del_sta_entry entry;
            if (copy_from_user(&entry, (void __user *)arg, sizeof(entry))) {
                return -EFAULT;
            }
            if (!remove_client_from_reg_table(entry.macaddr, entry.ifname)) {
                remove_client_from_coplane_table(entry.macaddr);
                printk("IOCTL: Client removed from vif table: %02x:%02x:%02x:%02x:%02x:%02x\n",
                       entry.macaddr[0], entry.macaddr[1], entry.macaddr[2],
                       entry.macaddr[3], entry.macaddr[4], entry.macaddr[5]);
            }
        } break;
        case IOCTL_ADPI_RATELIMIT_WLAN: {
                struct adpi_ratelimit_bucket crb;
                struct ratelimit_bucket *rb = NULL, *old_rb;
                size_t dir;

                if (copy_from_user(&crb, (void *)arg, sizeof(crb)))
                    return -EFAULT;
                if (crb.wlan_idx >= MAX_WLANS)
                    return -EINVAL;
                if (crb.direction != AIR_RL_DIR_DOWNLINK && crb.direction != AIR_RL_DIR_UPLINK)
                    return -EINVAL;
                
                dir = crb.direction == AIR_RL_DIR_UPLINK ? AIR_RL_DIR_UPLINK : AIR_RL_DIR_DOWNLINK;

                printk("WLAN RL AIRDPI: ifindex=%d, rate=%d, size=%d, dir=%d\n", 
                                         crb.wlan_idx, crb.bytes_per_sec, crb.size, crb.direction);
                if (crb.bytes_per_sec != 0) {
                    
                    if (!(rb = kmalloc(sizeof(*rb), GFP_USER))) {
                        return -ENOMEM;
                    }
                    rb->tokens = crb.size; /* start with full bucket */
                    rb->last_update = jiffies;
                    rb->tokens_per_jiffy = crb.bytes_per_sec/HZ;
                    rb->max_tokens = crb.size;
                    rb->dropped = 0;
                } else {
                    // If bytes_per_sec is zero, clear rate limiting
                   dir = crb.direction == AIR_RL_DIR_UPLINK ? AIR_RL_DIR_UPLINK : AIR_RL_DIR_DOWNLINK;
                   rb = NULL;  // No rate limiting, set rb to NULL
                   printk("Clearing rate limit for wlan_idx=%d, dir=%d\n", crb.wlan_idx, crb.direction);
                } /* else rb == NULL and clear ratelimiting */

                old_rb = wlan_rl[crb.wlan_idx][dir];
                wlan_rl[crb.wlan_idx][dir] = rb;
                if (old_rb) {
                    synchronize_net(); /* wait for current packet processing to complete before freeing old bucket */
                    kfree(old_rb);
                }
            }
            break;
        case IOCTL_ADPI_RATELIMIT_WLAN_PER_USER: {  // for wlan per user ratelimit
                struct adpi_ratelimit_bucket crb;
                struct ratelimit_bucket *rb = NULL, *old_rb;
                size_t dir;

                if (copy_from_user(&crb, (void *)arg, sizeof(crb)))
                    return -EFAULT;
                if (crb.wlan_idx >= MAX_WLANS)
                    return -EINVAL;
                if (crb.direction != AIR_RL_DIR_DOWNLINK && crb.direction != AIR_RL_DIR_UPLINK)
                    return -EINVAL;
                
                dir = crb.direction == AIR_RL_DIR_UPLINK ? AIR_RL_DIR_UPLINK : AIR_RL_DIR_DOWNLINK;

                printk("WLAN PER USER RL AIRDPI: ifindex=%d, rate=%d, size=%d, dir=%d\n", 
                                         crb.wlan_idx, crb.bytes_per_sec, crb.size, crb.direction);
                if (crb.bytes_per_sec != 0) {
                    
                    if (!(rb = kmalloc(sizeof(*rb), GFP_USER))) {
                        return -ENOMEM;
                    }
                    rb->tokens = crb.size; /* start with full bucket */
                    rb->last_update = jiffies;
                    rb->tokens_per_jiffy = crb.bytes_per_sec/HZ;
                    rb->max_tokens = crb.size;
                    rb->dropped = 0;
                } else {
                    // If bytes_per_sec is zero, clear rate limiting
                   dir = crb.direction == AIR_RL_DIR_UPLINK ? AIR_RL_DIR_UPLINK : AIR_RL_DIR_DOWNLINK;
                   rb = NULL;  // No rate limiting, set rb to NULL
                   printk("Clearing rate limit for wlan_idx=%d, dir=%d\n", crb.wlan_idx, crb.direction);
                } /* else rb == NULL and clear ratelimiting */

                old_rb = user_wlan_rl[crb.wlan_idx][dir];
                user_wlan_rl[crb.wlan_idx][dir] = rb;
                if (old_rb) {
                    synchronize_net(); /* wait for current packet processing to complete before freeing old bucket */
                    kfree(old_rb);
                }
            }
            break;
        case IOCTL_ADPI_RATELIMIT_WLAN_USER: {
                struct adpi_ratelimit_bucket crb;
                struct ratelimit_bucket *rb = NULL;
                struct wlan_sta *sta;
                int hash;

                if (copy_from_user(&crb, (void *)arg, sizeof(crb)))
                    return -EFAULT;
                if (crb.wlan_idx >= MAX_WLANS)
                    return -EINVAL;
                if (crb.direction != AIR_RL_DIR_DOWNLINK && crb.direction != AIR_RL_DIR_UPLINK)
                    return -EINVAL;

                printk("USER RL AIRDPI:  rate=%d, size=%d, dir=%d\n"
                                          , crb.bytes_per_sec, crb.size, crb.direction);
                
                if (crb.bytes_per_sec != 0) {  
                    if (!(rb = kmalloc(sizeof(*rb), GFP_USER))) {
                        return -ENOMEM;
                    }
                    rb->tokens = crb.size; /* start with full bucket */
                    rb->last_update = jiffies;
                    rb->tokens_per_jiffy = crb.bytes_per_sec/HZ;
                    rb->max_tokens = crb.size;
                    rb->dropped = 0;
                } else {
                    // If bytes_per_sec is zero, clear rate limiting
                   rb = NULL;  // No rate limiting, set rb to NULL
                   printk("Clearing rate limit for wlan_idx=%d, dir=%d\n", crb.wlan_idx, crb.direction);
                } 
                
                hash = WLAN_STA_HASH(crb.macaddr);
                OS_SPIN_WLAN_STA_LOCK(&coplane->wlan_client.wlan_client_lock);
                LIST_FOREACH(sta, &coplane->wlan_client.wlan_coplane_sta_hash[hash], ws_hash) {
                    if (IEEE80211_ADDR_EQ(sta->src_mac, crb.macaddr)) {
                        sta->rl[crb.direction] = rb;
                    }
                }
                OS_SPIN_WLAN_STA_UNLOCK(&coplane->wlan_client.wlan_client_lock);

            }
            break;
        case IOCTL_ADPI_GET_AP_TOP_DOMAINS: {
                struct adpi_domain_entry *top_domains_copy;

                top_domains_copy = kmalloc(sizeof(struct adpi_domain_entry) * MAX_DOMAINS, GFP_KERNEL);
                if (!top_domains_copy) {
                    return -ENOMEM; // Handle allocation failure
                }

                spin_lock(&vif->domain_lock);
                memcpy(top_domains_copy, vif->top_domains, sizeof(vif->top_domains));
                spin_unlock(&vif->domain_lock);

                if (copy_to_user((void __user *)arg, top_domains_copy, sizeof(struct adpi_domain_entry) * MAX_DOMAINS)) {
                    kfree(top_domains_copy);
                    return -EFAULT;
                }

                kfree(top_domains_copy);
                return 0;
            }
            break;
        case IOCTL_ADPI_BLOCK_DOMAIN: {
            char domain[MAX_DOMAIN_NAME_LEN];
            if (copy_from_user(domain, (void __user *)arg, sizeof(domain))) {
                return -EFAULT;
            }
            domain[MAX_DOMAIN_NAME_LEN - 1] = '\0';
            if (add_blocked_domain(vif, domain)) {
                printk(KERN_ERR "Failed to add blocked domain: %s\n", domain);
                return -ENOMEM;
            }
            printk(KERN_INFO "Blocked domain added: %s\n", domain);
            break;
        }   
        case IOCTL_ADPI_UNBLOCK_DOMAIN: {
            char domain[MAX_DOMAIN_NAME_LEN];
            if (copy_from_user(domain, (void __user *)arg, sizeof(domain))) {
                return -EFAULT;
            }
            domain[MAX_DOMAIN_NAME_LEN - 1] = '\0';
            if (remove_blocked_domain(vif, domain)) {
                printk(KERN_ERR "Failed to remove blocked domain: %s\n", domain);
                return -ENOENT;
            }
            printk(KERN_INFO "Blocked domain removed: %s\n", domain);
            break;
        }
        case IOCTL_ADPI_GET_ALL_CLIENTS: {
            struct adpi_client_info *client_info;
            struct client_node *node, *tmp;
            int count = 0;

            client_info = kmalloc(sizeof(*client_info), GFP_KERNEL);
            if (!client_info) {
                pr_err("Failed to allocate memory for client_info\n");
                return -ENOMEM;
            }

            pr_info("Allocating client_info memory successfully\n");

            TAILQ_FOREACH_SAFE(node, &vif->nc.client_list, nl, tmp) {
                if (count >= 32) {
                    break; // Limit to 32 entries
                }
                client_info->entry[count].ip = node->ip;
                memcpy(client_info->entry[count].macaddr, node->macaddr, ETH_ALEN);
                strncpy(client_info->entry[count].hostname, node->hostname, sizeof(client_info->entry[count].hostname) - 1);
                pr_info("Client %d: IP = %u, MAC = %pM, Hostname = %s\n", count + 1, node->ip, node->macaddr, node->hostname);
                count++;
            }

            client_info->count = count;
            pr_info("Client count: %d\n", client_info->count);

            if (client_info->count < 0) {
                pr_err("Invalid client count: %d\n", client_info->count);
                kfree(client_info);
                return -EINVAL;
            }

            if (copy_to_user((void __user *)arg, client_info, sizeof(*client_info))) {
                pr_err("Failed to copy client_info to user space\n");
                kfree(client_info);
                return -EFAULT;
            }

            kfree(client_info);
            return 0;
            }
            break;
        case IOCTL_ADPI_GET_RATELIMIT_WLAN_USER: {
            struct adpi_ratelimit_bucket crb;
            struct ratelimit_bucket *rb = NULL;
            struct wlan_sta *sta;
            int hash;

            // Copy data from user space
            if (copy_from_user(&crb, (void *)arg, sizeof(crb))) {
                printk(KERN_ERR "Failed to copy data from user space\n");
                return -EFAULT;
            }

            // Validate direction
            if (crb.direction != AIR_RL_DIR_DOWNLINK && crb.direction != AIR_RL_DIR_UPLINK) {
                printk(KERN_ERR "Invalid direction value: %d\n", crb.direction);
                return -EINVAL;
            }

            printk(KERN_INFO "GET Rate limit AIRDPI: dir=%d, mac=%02x:%02x:%02x:%02x:%02x:%02x\n",
                crb.direction, crb.macaddr[0], crb.macaddr[1], crb.macaddr[2],
                crb.macaddr[3], crb.macaddr[4], crb.macaddr[5]);

            // Hash the MAC address to find the corresponding station
            hash = WLAN_STA_HASH(crb.macaddr);
            rb = NULL; // Default to NULL in case the station isn't found

            // Lock to safely iterate over the station list
            OS_SPIN_WLAN_STA_LOCK(&coplane->wlan_client.wlan_client_lock);
            LIST_FOREACH(sta, &coplane->wlan_client.wlan_coplane_sta_hash[hash], ws_hash) {
                if (IEEE80211_ADDR_EQ(sta->src_mac, crb.macaddr)) {
                    rb = sta->rl[crb.direction];
                    break;
                }
            }
           OS_SPIN_WLAN_STA_UNLOCK(&coplane->wlan_client.wlan_client_lock);

            // Populate the response structure
            if (rb) {
                crb.bytes_per_sec = rb->tokens_per_jiffy * HZ;
                crb.size = rb->max_tokens;
                printk(KERN_INFO "Rate limit found: rate=%d, size=%d \n",
                crb.bytes_per_sec, crb.size);
            } else {
                // No rate limit set for this station
                crb.bytes_per_sec = 0;
                crb.size = 0;
                printk(KERN_INFO "No rate limit set for MAC %02x:%02x:%02x:%02x:%02x:%02x, dir=%d\n",
                        crb.macaddr[0], crb.macaddr[1], crb.macaddr[2],
                        crb.macaddr[3], crb.macaddr[4], crb.macaddr[5],
                        crb.direction);
            }

            // Copy the result back to user space
            if (copy_to_user((void __user *)arg, &crb, sizeof(crb))) {
                printk(KERN_ERR "Failed to copy data to user space\n");
                return -EFAULT;
            }

            printk(KERN_INFO "GET Rate limit AIRDPI completed successfully\n");
        }
        break;
    case IOCTL_ADPI_GET_RATELIMIT_WLAN: {
            struct adpi_ratelimit_bucket crb;
            struct ratelimit_bucket *rb = NULL;
            size_t dir;

            if (copy_from_user(&crb, (void *)arg, sizeof(crb)))
                return -EFAULT;

            if (crb.wlan_idx >= MAX_WLANS)
                return -EINVAL;

            if (crb.direction != AIR_RL_DIR_DOWNLINK && crb.direction != AIR_RL_DIR_UPLINK)
                return -EINVAL;

            dir = crb.direction == AIR_RL_DIR_UPLINK ? AIR_RL_DIR_UPLINK : AIR_RL_DIR_DOWNLINK;

            // Retrieve the rate limit bucket for the specified WLAN and direction
            rb = wlan_rl[crb.wlan_idx][dir];

            if (rb) {
                crb.bytes_per_sec = rb->tokens_per_jiffy * HZ;  // Calculate bytes per second
                crb.size = rb->max_tokens;                     // Maximum tokens
            } else {
            // No rate limiting is set
                crb.bytes_per_sec = 0;
                crb.size = 0;
            }

            // Copy the result back to user space
            if (copy_to_user((void __user *)arg, &crb, sizeof(crb)))
                return -EFAULT;

            printk("GET Rate limit AIRDPI: wlan_idx=%d, dir=%d, rate=%d, size=%d \n",
                crb.wlan_idx, crb.direction, crb.bytes_per_sec, crb.size);

        }
        break;
        default: {
            printk("ioctl: unknown ioctl command\n");
            return 0;
        }
     }

    return 0;
}

static int handler_cfg80211_new_sta(struct kprobe *p, struct pt_regs *regs)
{
    struct net_device *dev = (struct net_device *)regs->regs[4];
    const u8 *mac_addr = (const u8 *)regs->regs[5];
    struct station_info *sinfo = (struct station_info *)regs->regs[6];
    struct client_node *cn = NULL;
    //struct adpi_add_sta_entry entry;

    if(!dev || !mac_addr || !sinfo) {
        printk(KERN_ERR "ADPI: Invalid input in handler_cfg80211_new_sta\n");
    }

    printk("ADPI: new sta dev - %s\n", dev->name);

    printk("ADPI: new sta mac - %02x:%02x:%02x:%02x:%02x:%02x\n",
            mac_addr[0], mac_addr[1], mac_addr[2],
            mac_addr[3], mac_addr[4], mac_addr[5]);
    
    cn = client_reg_table_lookup((uint8_t *) mac_addr);
    if (!cn) {
        cn = client_reg_table_alloc((uint8_t *) mac_addr);
    }
    if (cn) {
        if (cn->ifname[0] == '\0') {
            strncpy(cn->ifname, dev->name, sizeof(cn->ifname) - 1);
            cn->ifname[sizeof(cn->ifname) - 1] = '\0';
        }
    }

   return 0;
}

static int handler_cfg80211_del_sta(struct kprobe *p, struct pt_regs *regs)
{
    struct net_device *dev = (struct net_device *)regs->regs[4];
    const u8 *mac_addr = (const u8 *)regs->regs[5];
    struct station_info *sinfo = (struct station_info *)regs->regs[6];
    //struct adpi_del_sta_entry entry;

    if(!dev || !mac_addr || !sinfo) {
        printk(KERN_ERR "ADPI: Invalid input in handler_cfg80211_del_sta\n");
    }

    printk("ADPI: new del dev - %s\n", dev->name);

    printk("ADPI: new del mac - %02x:%02x:%02x:%02x:%02x:%02x\n",
            mac_addr[0], mac_addr[1], mac_addr[2],
            mac_addr[3], mac_addr[4], mac_addr[5]);
            
    if (!remove_client_from_reg_table((uint8_t *) mac_addr, dev->name)) {
        remove_client_from_coplane_table((uint8_t *) mac_addr);
    }

    return 0;
}

static const struct file_operations air_misc_fops = {

    .compat_ioctl = air_device_ioctl,
    .unlocked_ioctl = air_device_ioctl

};

static struct miscdevice air_miscdev = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = "air",
    .fops = &air_misc_fops,
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

static int kprobe_init(void)
{
    int ret;

    printk("Registering kprobe new sta\n");
    kp_new_sta.pre_handler = handler_cfg80211_new_sta;

    ret = register_kprobe(&kp_new_sta);
    if (ret < 0) {
        pr_err("register_kprobe failed for cfg80211_new_sta, returned %d\n", ret);
        return ret;
    }
    pr_info("Planted kprobe at %s\n", kp_new_sta.symbol_name);

    printk("Registering kprobe del sta\n");
    kp_del_sta.pre_handler = handler_cfg80211_del_sta;

    ret = register_kprobe(&kp_del_sta);
    if (ret < 0) {
        pr_err("register_kprobe failed for cfg80211_del_sta_info, returned %d\n", ret);
        return ret;
    }
    pr_info("Planted kprobe at %s\n", kp_del_sta.symbol_name);

    return 0;
}

static void kprobe_exit(void)
{
    unregister_kprobe(&kp_new_sta);
    unregister_kprobe(&kp_del_sta);
    pr_info("kprobes unregistered\n");
}

int air_vif_module_init(void)
{
    int i;
    vif = kmalloc(sizeof(struct air_vif), GFP_KERNEL);
    if (!vif) {
    return -ENOMEM;
    }
    memset(vif, 0, sizeof(struct air_vif));

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

    hash_init(vif->blocked_domains);

    kprobe_init();

    //timer_setup(&my_timer, packet_counter_reset, 0);
    //mod_timer(&my_timer, jiffies + msecs_to_jiffies(1000));

    TAILQ_INIT(&vif->nc.client_list);
    OS_SPIN_LOCK_INIT(&vif->nc.lock);

    spin_lock_init(&vif->domain_lock);
    // Initialize the top_domains array
    for (i = 0; i < MAX_DOMAINS; i++) {
        vif->top_domains[i].domain[0] = '\0'; // Empty string
        vif->top_domains[i].count = 0;
    }

    //air_active_node_init_timer(vif);
    if (air_vif_node_sysctl_register(vif) < 0) {
        printk("reg sysctl failed..\n");
    }

    if (misc_register(&air_miscdev)) {
        printk("misc reg failed!!!\n");
        return -EINVAL;
    }

    if (air_init_netfilter_hook()) {
        return -EINVAL;
    }

    //netlink_init();

    printk("air vif init %p\n", vif);
    
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

    kprobe_exit();

    spin_lock_irqsave(&vif->domain_lock, flags);
    hash_for_each(vif->blocked_domains, bkt, bd, node) {
        hlist_for_each_safe(pos, n, &bd->ip_list) {
            bi = hlist_entry(pos, struct blocked_ip, node);
            hlist_del(&bi->node);
            kfree(bi);
        }
        hash_del(&bd->node);
        kfree(bd);
    }
    spin_unlock_irqrestore(&vif->domain_lock, flags);

    kfree(vif);
    kfree(coplane);
    del_timer(&my_timer);
    //netlink_exit();

    printk("air vif deinit\n");

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
