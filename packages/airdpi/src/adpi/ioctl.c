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
            struct ratelimit_bucket *rb_uplink = NULL, *rb_downlink = NULL;
            struct ratelimit_bucket *old_rb_uplink, *old_rb_downlink;

            if (copy_from_user(&crb, (void *)arg, sizeof(crb)))
                return -EFAULT;

            if (crb.wlan_idx >= MAX_WLANS)
                return -EINVAL;

            printk("WLAN RL AIRDPI: ifindex=%d, uplink_rate=%d, uplink_size=%d, "
                    "downlink_rate=%d, downlink_size=%d\n",
                    crb.wlan_idx, crb.uplink_bytes_per_sec, crb.uplink_size,
                    crb.downlink_bytes_per_sec, crb.downlink_size);

            /* Setup uplink rate limit */
            if (crb.uplink_bytes_per_sec != 0) {
                rb_uplink = kmalloc(sizeof(*rb_uplink), GFP_KERNEL);
                if (!rb_uplink)
                    return -ENOMEM;

                rb_uplink->tokens = crb.uplink_size;
                rb_uplink->last_update = jiffies;
                rb_uplink->tokens_per_jiffy = crb.uplink_bytes_per_sec / HZ;
                rb_uplink->max_tokens = crb.uplink_size;
                rb_uplink->dropped = 0;
            } else {
                /* Clear uplink rate limit - rb_uplink is already NULL */
                printk("WLAN RL AIRDPI: Clearing uplink rate limit for wlan_idx=%d\n", crb.wlan_idx);
                rb_uplink = NULL;
            }

            /* Setup downlink rate limit */
            if (crb.downlink_bytes_per_sec != 0) {
                rb_downlink = kmalloc(sizeof(*rb_downlink), GFP_KERNEL);
                if (!rb_downlink) {
                    /* Clean up uplink if downlink allocation fails */
                    if (rb_uplink)
                        kfree(rb_uplink);
                    return -ENOMEM;
                }
                rb_downlink->tokens = crb.downlink_size;
                rb_downlink->last_update = jiffies;
                rb_downlink->tokens_per_jiffy = crb.downlink_bytes_per_sec / HZ;
                rb_downlink->max_tokens = crb.downlink_size;
                rb_downlink->dropped = 0;
            } else {
                /* Clear downlink rate limit - rb_downlink is already NULL */
                printk("WLAN RL AIRDPI: Clearing downlink rate limit for wlan_idx=%d\n", crb.wlan_idx);
                rb_downlink = NULL;
            }

            /* Atomically update both directions */
            old_rb_uplink = wlan_rl[crb.wlan_idx][AIR_RL_DIR_UPLINK];
            old_rb_downlink = wlan_rl[crb.wlan_idx][AIR_RL_DIR_DOWNLINK];

            wlan_rl[crb.wlan_idx][AIR_RL_DIR_UPLINK] = rb_uplink;
            wlan_rl[crb.wlan_idx][AIR_RL_DIR_DOWNLINK] = rb_downlink;

            /* Wait for existing users to finish, then free old buckets */
            synchronize_net();
    
            if (old_rb_uplink)
                kfree(old_rb_uplink);
            if (old_rb_downlink)
                kfree(old_rb_downlink);

        } break;
        case IOCTL_ADPI_RATELIMIT_WLAN_PER_USER: { //all the user will connected to this interface
            struct adpi_ratelimit_bucket crb;
            struct ratelimit_bucket *rb_uplink = NULL, *rb_downlink = NULL;
            struct ratelimit_bucket *old_rb_uplink, *old_rb_downlink;

            if (copy_from_user(&crb, (void *)arg, sizeof(crb)))
                return -EFAULT;

            if (crb.wlan_idx >= MAX_WLANS)
                return -EINVAL;

            printk("WLAN PER USER RL AIRDPI: ifindex=%d, uplink_rate=%d, uplink_size=%d, "
                    "downlink_rate=%d, downlink_size=%d\n",
                    crb.wlan_idx, crb.uplink_bytes_per_sec, crb.uplink_size,
                    crb.downlink_bytes_per_sec, crb.downlink_size);

            /* Setup uplink rate limit */
            if (crb.uplink_bytes_per_sec != 0) {
                rb_uplink = kmalloc(sizeof(*rb_uplink), GFP_KERNEL);
                if (!rb_uplink)
                    return -ENOMEM;

                rb_uplink->tokens = crb.uplink_size;
                rb_uplink->last_update = jiffies;
                rb_uplink->tokens_per_jiffy = crb.uplink_bytes_per_sec / HZ;
                rb_uplink->max_tokens = crb.uplink_size;
                rb_uplink->dropped = 0;
            } else {
                /* Clear uplink rate limit - rb_uplink is already NULL */
                printk("WLAN PER USER RL AIRDPI: Clearing uplink rate limit for wlan_idx=%d\n", crb.wlan_idx);
                rb_uplink = NULL;
            }

            /* Setup downlink rate limit */
            if (crb.downlink_bytes_per_sec != 0) {
                rb_downlink = kmalloc(sizeof(*rb_downlink), GFP_KERNEL);
                if (!rb_downlink) {
                    /* Clean up uplink if downlink allocation fails */
                    if (rb_uplink)
                        kfree(rb_uplink);
                    return -ENOMEM;
                }
                rb_downlink->tokens = crb.downlink_size;
                rb_downlink->last_update = jiffies;
                rb_downlink->tokens_per_jiffy = crb.downlink_bytes_per_sec / HZ;
                rb_downlink->max_tokens = crb.downlink_size;
                rb_downlink->dropped = 0;
            } else {
                /* Clear downlink rate limit - rb_downlink is already NULL */
                printk("WLAN PER USER RL AIRDPI: Clearing downlink rate limit for wlan_idx=%d\n", crb.wlan_idx);
                rb_downlink = NULL;
            }

            /* Atomically update both directions */
            old_rb_uplink = user_wlan_rl[crb.wlan_idx][AIR_RL_DIR_UPLINK];
            old_rb_downlink = user_wlan_rl[crb.wlan_idx][AIR_RL_DIR_DOWNLINK];

            user_wlan_rl[crb.wlan_idx][AIR_RL_DIR_UPLINK] = rb_uplink;
            user_wlan_rl[crb.wlan_idx][AIR_RL_DIR_DOWNLINK] = rb_downlink;

            /* Wait for existing users to finish, then free old buckets */
            synchronize_net();
    
            if (old_rb_uplink)
                kfree(old_rb_uplink);
            if (old_rb_downlink)
                kfree(old_rb_downlink);
        } break;
        case IOCTL_ADPI_RATELIMIT_WLAN_USER: {
            struct adpi_ratelimit_bucket crb;
            struct ratelimit_bucket *rb_uplink = NULL, *rb_downlink = NULL;
            struct ratelimit_bucket *old_rb_uplink = NULL, *old_rb_downlink = NULL;
            struct wlan_sta *sta;
            int hash;
            int sta_found = 0;

            if (copy_from_user(&crb, (void *)arg, sizeof(crb)))
                return -EFAULT;

            if (crb.wlan_idx >= MAX_WLANS)
                return -EINVAL;

            printk("USER RL AIRDPI: wlan_idx=%d, mac=%02x:%02x:%02x:%02x:%02x:%02x, "
                    "uplink_rate=%d, uplink_size=%d, downlink_rate=%d, downlink_size=%d\n",
                    crb.wlan_idx, crb.macaddr[0], crb.macaddr[1], crb.macaddr[2],
                    crb.macaddr[3], crb.macaddr[4], crb.macaddr[5],
                    crb.uplink_bytes_per_sec, crb.uplink_size,
                    crb.downlink_bytes_per_sec, crb.downlink_size);

            /* Setup uplink rate limit */
            if (crb.uplink_bytes_per_sec != 0) {
                rb_uplink = kmalloc(sizeof(*rb_uplink), GFP_KERNEL);
                if (!rb_uplink)
                    return -ENOMEM;

                rb_uplink->tokens = crb.uplink_size;
                rb_uplink->last_update = jiffies;
                rb_uplink->tokens_per_jiffy = crb.uplink_bytes_per_sec / HZ;
                rb_uplink->max_tokens = crb.uplink_size;
                rb_uplink->dropped = 0;
            } else {
                /* Clear uplink rate limit */
                printk("USER RL AIRDPI: Clearing uplink rate limit for wlan_idx=%d, user mac=%02x:%02x:%02x:%02x:%02x:%02x\n",
                        crb.wlan_idx, crb.macaddr[0], crb.macaddr[1], crb.macaddr[2],
                        crb.macaddr[3], crb.macaddr[4], crb.macaddr[5]);
                rb_uplink = NULL;
            }

            /* Setup downlink rate limit */
            if (crb.downlink_bytes_per_sec != 0) {
                rb_downlink = kmalloc(sizeof(*rb_downlink), GFP_KERNEL);
                if (!rb_downlink) {
                    /* Clean up uplink if downlink allocation fails */
                    if (rb_uplink)
                        kfree(rb_uplink);
                    return -ENOMEM;
                }

                rb_downlink->tokens = crb.downlink_size;
                rb_downlink->last_update = jiffies;
                rb_downlink->tokens_per_jiffy = crb.downlink_bytes_per_sec / HZ;
                rb_downlink->max_tokens = crb.downlink_size;
                rb_downlink->dropped = 0;
            } else {
                /* Clear downlink rate limit */
                printk("USER RL AIRDPI: Clearing downlink rate limit for wlan_idx=%d, user mac=%02x:%02x:%02x:%02x:%02x:%02x\n",
                        crb.wlan_idx, crb.macaddr[0], crb.macaddr[1], crb.macaddr[2],
                        crb.macaddr[3], crb.macaddr[4], crb.macaddr[5]);
                rb_downlink = NULL;
            }

            /* Find and update the station */
            hash = WLAN_STA_HASH(crb.macaddr);
    
            OS_SPIN_WLAN_STA_LOCK(&coplane->wlan_client.wlan_client_lock);
    
            LIST_FOREACH(sta, &coplane->wlan_client.wlan_coplane_sta_hash[hash], ws_hash) {
            if (IEEE80211_ADDR_EQ(sta->src_mac, crb.macaddr)) {
                /* Save old rate limiters */
                old_rb_uplink = sta->rl[AIR_RL_DIR_UPLINK];
                old_rb_downlink = sta->rl[AIR_RL_DIR_DOWNLINK];
            
                /* Assign new rate limiters */
                sta->rl[AIR_RL_DIR_UPLINK] = rb_uplink;
                sta->rl[AIR_RL_DIR_DOWNLINK] = rb_downlink;
            
                sta_found = 1;
                break;  /* Found the station, exit loop */
                }
            }
    
            OS_SPIN_WLAN_STA_UNLOCK(&coplane->wlan_client.wlan_client_lock);

            if (!sta_found) {
                printk("Station not found: wlan_idx=%d, mac=%02x:%02x:%02x:%02x:%02x:%02x\n",
                        crb.wlan_idx, crb.macaddr[0], crb.macaddr[1], crb.macaddr[2],
                        crb.macaddr[3], crb.macaddr[4], crb.macaddr[5]);
        
                /* Free newly allocated rate limiters since station wasn't found */
                if (rb_uplink)
                    kfree(rb_uplink);
                if (rb_downlink)
                    kfree(rb_downlink);
        
                return -ENOENT;
            }   

            /* Wait for any in-flight packets to finish using old rate limiters */
            synchronize_net();
    
            /* Free old rate limiters */
            if (old_rb_uplink)
                kfree(old_rb_uplink);
            if (old_rb_downlink)
                kfree(old_rb_downlink);

        } break;
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

            OS_SPIN_LOCK(&coplane->reg.lock);
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
            OS_SPIN_UNLOCK(&coplane->reg.lock);

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
#if 0
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
#endif
        default: {
            printk("ioctl: unknown ioctl command\n");
            return 0;
        }
    }

    return 0;
}
