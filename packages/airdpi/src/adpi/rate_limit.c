#include <linux/netdevice.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>
#include "air_common.h"
#include "air_coplane.h"

extern struct airpro_coplane *coplane;
struct ratelimit_bucket *wlan_rl[MAX_WLANS][AIR_RL_DIR_MAX];
struct ratelimit_bucket *user_wlan_rl[MAX_WLANS][AIR_RL_DIR_MAX];

static int ratelimit_check_update(struct ratelimit_bucket *rl, unsigned long now, size_t len)
{
    // Calculate elapsed time since last token update
    unsigned long elapsed = now - rl->last_update;

    // Replenish tokens if any time has passed
    if (elapsed > 0) {
        unsigned long new_tokens = elapsed * rl->tokens_per_jiffy;
        rl->tokens = min(rl->tokens + new_tokens, (unsigned long)rl->max_tokens);
        rl->last_update = now;
    }

    // Check if the packet size exceeds the available tokens
    if (len > rl->tokens) {
        rl->dropped++;
        return 1; // Drop packet
    }

    // Deduct tokens for this packet
    rl->tokens -= len;

    return 0; // Accept packet
}

int rl_drop_packet(struct wlan_sta *se, size_t len, unsigned int dir)
{
    struct ratelimit_bucket *rl = NULL;
    unsigned long now = jiffies;

    if (dir >= AIR_RL_DIR_MAX) {
        pr_err("Invalid direction: %u\n", dir);
        return 0; // Invalid direction
    }

    if (se) {
        //printk("Checking per-station rate limit: dir=%u, wlan_id=%u\n", dir, se->wlan_id);
        rl = se->rl[dir];
        if (!rl) {
        } else if (ratelimit_check_update(rl, now, len)) {
            return 1; // Drop packet
        }
    }

    if (se && se->wlan_id < MAX_WLANS) {
        //pr_debug("Checking per-WLAN rate limit: wlan_id=%u, dir=%u\n", se->wlan_id, dir);
        rl = user_wlan_rl[se->wlan_id][dir];
        if (!rl) {
        } else if (ratelimit_check_update(rl, now, len)) {
            return 1; // Drop packet
        }
    }


    if (se && se->wlan_id < MAX_WLANS) {
        //pr_debug("Checking per-WLAN rate limit: wlan_id=%u, dir=%u\n", se->wlan_id, dir);
        rl = wlan_rl[se->wlan_id][dir];
        if (!rl) {
        } else if (ratelimit_check_update(rl, now, len)) {
            return 1; // Drop packet
        }
    }

    return 0; // Allow packet
}

