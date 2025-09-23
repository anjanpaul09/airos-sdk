#include "air_vif.h"
#include <linux/version.h>

extern struct air_vif *vif;
#define MAX_STA_DISCONNECT_TIMEOUT 3000

#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,15,0)
void air_active_node_timer_handler(unsigned long *ptr)
{
    struct air_vif *vif = (struct air_vif *)ptr;
    //struct client_node *node, *tmp;
    //struct timeval tv;
    //u64 ts;
#if 0
    do_gettimeofday(&tv);
    ts = ((tv.tv_sec * 1000) + (tv.tv_usec / 1000));

    //OS_SPIN_LOCK(&vif->nc.lock);
    TAILQ_FOREACH_SAFE(node, &vif->nc.client_list, nl, tmp) {
        if ((ts - node->ts) > MAX_STA_DISCONNECT_TIMEOUT) {
             printk("EVENT = %llu\n", (ts - node->ts));
             send_nl_event("hello");
            //TAILQ_REMOVE(&vif->nc.client_list, node, nl);
            //kfree(node);
        }
    }
    //OS_SPIN_UNLOCK(&vif->nc.lock);
#endif
    mod_timer(&vif->air_active_node_timer, jiffies + msecs_to_jiffies(MAX_STA_DISCONNECT_TIMEOUT));
}
#else
void air_active_node_timer_handler(struct timer_list *timer)
{
    struct air_vif *vif = from_timer(vif, timer, air_active_node_timer);
    //struct client_node *node, *tmp;
    //u64 ts;
#if 0
    do_gettimeofday(&tv);
    ts = ((tv.tv_sec * 1000) + (tv.tv_usec / 1000));
    
    //OS_SPIN_LOCK(&vif->nc.lock);
    TAILQ_FOREACH_SAFE(node, &vif->nc.client_list, nl, tmp) {
        if ((ts - node->ts) > MAX_STA_DISCONNECT_TIMEOUT) {
             printk("EVENT = %llu\n", (ts - node->ts));
             send_nl_event("hello");
            //TAILQ_REMOVE(&vif->nc.client_list, node, nl);
            //kfree(node);
        }
    }
    //OS_SPIN_UNLOCK(&vif->nc.lock);
#endif
    mod_timer(&vif->air_active_node_timer, jiffies + msecs_to_jiffies(MAX_STA_DISCONNECT_TIMEOUT));
}
#endif

int air_active_node_init_timer(struct air_vif *vif)
{
#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,15,0)
    init_timer(&vif->air_active_node_timer);
    vif->air_active_node_timer.function = air_active_node_timer_handler;
    vif->air_active_node_timer.data = (unsigned long)vif;
    vif->air_active_node_timer.expires = jiffies + msecs_to_jiffies(1000);
    add_timer(&vif->air_active_node_timer);
#else
    timer_setup(&vif->air_active_node_timer, air_active_node_timer_handler, 0);
    mod_timer(&vif->air_active_node_timer, jiffies + msecs_to_jiffies(1000));
#endif
    return 0;
}

