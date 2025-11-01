#include <jansson.h>
#include "ds.h"
#include "ds_dlist.h"
#include "os_time.h"
#include "log.h"
#include "netconf.h"
#include "unixcomm.h"
#include "memutil.h"

static struct ev_timer  netconf_dequeue_timer;
static int              netconf_dequeue_timer_interval;

bool netconf_process_msg(netconf_item_t *ci)
{
    char data[8192];
    long mlen = ci->size;
    void *mbuf = ci->buf;
    netconf_request_t req = ci->req;
    
    LOG(INFO, "NETCONF: RECIEVED MSG =%s len=%d\n", (char *)mbuf, (int)mlen);

    memcpy(data, mbuf, mlen);
    data[ci->size] = '\0';
    
    if( req.data_type == NETCONF_DATA_CONF || req.data_type == NETCONF_DATA_STATS ) {
        netconf_process_set_msg(data);
    } else if( req.data_type == NETCONF_DATA_ACL) {
        netconf_process_acl_msg(data);
    } else if( req.data_type == NETCONF_DATA_RL) {
        netconf_process_user_rl_msg(data);
    }
    
    return true;
}

void netconf_dequeue_timer_handler(struct ev_loop *loop, ev_timer *timer, int revents)
{
    (void)loop;
    (void)timer;
    (void)revents;
    netconf_queue_msg_process();
}

bool netconf_dequeue_timer_init()
{
    netconf_dequeue_timer_interval = 1;

    ev_timer_init(&netconf_dequeue_timer, netconf_dequeue_timer_handler,
                   netconf_dequeue_timer_interval, netconf_dequeue_timer_interval);
    netconf_dequeue_timer.data = NULL;
    ev_timer_start(EV_DEFAULT, &netconf_dequeue_timer);

    return true;
}


