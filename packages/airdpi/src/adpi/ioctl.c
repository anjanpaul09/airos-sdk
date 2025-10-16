#include <linux/kernel.h>
#include <linux/uaccess.h>
#include <linux/netfilter_bridge.h>
#include <linux/etherdevice.h>
#include "air_coplane.h"
#include "air_ioctl.h"

extern struct airpro_coplane *coplane;
extern struct ratelimit_bucket *wlan_rl[MAX_WLANS][AIR_RL_DIR_MAX];
extern struct ratelimit_bucket *user_wlan_rl[MAX_WLANS][AIR_RL_DIR_MAX];

/* Helpers from other units */
int is_blocked_ip(struct airpro_coplane *cp, __be32 ip);

static int add_blocked_domain(struct airpro_coplane *cp, const char *domain);
static int remove_blocked_domain(struct airpro_coplane *cp, const char *domain);

/* blocked domain helpers moved from main.c */
static int add_blocked_domain(struct airpro_coplane *cp, const char *domain)
{
    struct blocked_domain *bd;
    unsigned long flags;

    bd = kmalloc(sizeof(*bd), GFP_KERNEL);
    if (!bd) return -ENOMEM;

    strncpy(bd->domain, domain, MAX_DOMAIN_NAME_LEN - 1);
    bd->domain[MAX_DOMAIN_NAME_LEN - 1] = '\0';
    bd->active = 1;
    INIT_HLIST_HEAD(&bd->ip_list);

    spin_lock_irqsave(&cp->domain_lock, flags);
    hash_add(cp->blocked_domains, &bd->node, hash_string(bd->domain));
    spin_unlock_irqrestore(&cp->domain_lock, flags);

    return 0;
}

static int remove_blocked_domain(struct airpro_coplane *cp, const char *domain)
{
    struct blocked_domain *bd;
    struct blocked_ip *bi;
    struct hlist_node *pos, *n;
    unsigned long flags;
    int found = 0;

    spin_lock_irqsave(&cp->domain_lock, flags);
    hash_for_each_possible(cp->blocked_domains, bd, node, hash_string(domain)) {
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
    spin_unlock_irqrestore(&cp->domain_lock, flags);

    return found ? 0 : -ENOENT;
}

/*
 * IOCTL entrypoint moved from main.c for separation of concerns
 */
long air_device_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    switch (cmd) {
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
                   dir = crb.direction == AIR_RL_DIR_UPLINK ? AIR_RL_DIR_UPLINK : AIR_RL_DIR_DOWNLINK;
                   rb = NULL;  // No rate limiting, set rb to NULL
                   printk("Clearing rate limit for wlan_idx=%d, dir=%d\n", crb.wlan_idx, crb.direction);
                }

                old_rb = wlan_rl[crb.wlan_idx][dir];
                wlan_rl[crb.wlan_idx][dir] = rb;
                if (old_rb) {
                    synchronize_net();
                    kfree(old_rb);
                }
            }
            break;
        case IOCTL_ADPI_RATELIMIT_WLAN_PER_USER: { //all the user will connected to this interface
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
                   dir = crb.direction == AIR_RL_DIR_UPLINK ? AIR_RL_DIR_UPLINK : AIR_RL_DIR_DOWNLINK;
                   rb = NULL;  // No rate limiting, set rb to NULL
                   printk("Clearing rate limit for wlan_idx=%d, dir=%d\n", crb.wlan_idx, crb.direction);
                }

                old_rb = user_wlan_rl[crb.wlan_idx][dir];
                user_wlan_rl[crb.wlan_idx][dir] = rb;
                if (old_rb) {
                    synchronize_net();
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
                    return -ENOMEM;
                }

                spin_lock(&coplane->domain_lock);
                memcpy(top_domains_copy, coplane->top_domains, sizeof(coplane->top_domains));
                spin_unlock(&coplane->domain_lock);

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
            if (add_blocked_domain(coplane, domain)) {
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
            if (remove_blocked_domain(coplane, domain)) {
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

            TAILQ_FOREACH_SAFE(node, &coplane->reg.client_list, nl, tmp) {
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

            if (copy_from_user(&crb, (void *)arg, sizeof(crb))) {
                printk(KERN_ERR "Failed to copy data from user space\n");
                return -EFAULT;
            }

            if (crb.direction != AIR_RL_DIR_DOWNLINK && crb.direction != AIR_RL_DIR_UPLINK) {
                printk(KERN_ERR "Invalid direction value: %d\n", crb.direction);
                return -EINVAL;
            }

            printk(KERN_INFO "GET Rate limit AIRDPI: dir=%d, mac=%02x:%02x:%02x:%02x:%02x:%02x\n",
                crb.direction, crb.macaddr[0], crb.macaddr[1], crb.macaddr[2],
                crb.macaddr[3], crb.macaddr[4], crb.macaddr[5]);

            hash = WLAN_STA_HASH(crb.macaddr);
            rb = NULL;

            OS_SPIN_WLAN_STA_LOCK(&coplane->wlan_client.wlan_client_lock);
            LIST_FOREACH(sta, &coplane->wlan_client.wlan_coplane_sta_hash[hash], ws_hash) {
                if (IEEE80211_ADDR_EQ(sta->src_mac, crb.macaddr)) {
                    rb = sta->rl[crb.direction];
                    break;
                }
            }
            OS_SPIN_WLAN_STA_UNLOCK(&coplane->wlan_client.wlan_client_lock);

            if (rb) {
                crb.bytes_per_sec = rb->tokens_per_jiffy * HZ;
                crb.size = rb->max_tokens;
                printk(KERN_INFO "Rate limit found: rate=%d, size=%d \n",
                crb.bytes_per_sec, crb.size);
            } else {
                crb.bytes_per_sec = 0;
                crb.size = 0;
                printk(KERN_INFO "No rate limit set for MAC %02x:%02x:%02x:%02x:%02x:%02x, dir=%d\n",
                        crb.macaddr[0], crb.macaddr[1], crb.macaddr[2],
                        crb.macaddr[3], crb.macaddr[4], crb.macaddr[5],
                        crb.direction);
            }

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

            rb = wlan_rl[crb.wlan_idx][dir];

            if (rb) {
                crb.bytes_per_sec = rb->tokens_per_jiffy * HZ;
                crb.size = rb->max_tokens;
            } else {
                crb.bytes_per_sec = 0;
                crb.size = 0;
            }

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

/* Duplicate signatures removed: helpers are defined above using airpro_coplane */


