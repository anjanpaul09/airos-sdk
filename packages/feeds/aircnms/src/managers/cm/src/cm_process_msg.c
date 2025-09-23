#include <jansson.h>
#include "ds.h"
#include "ds_dlist.h"
#include "os_time.h"
#include "log.h"
#include "cm.h"
#include "memutil.h"

static struct ev_timer  cm_dequeue_timer;
static int              cm_dequeue_timer_interval;

bool cm_process_msg(cm_item_t *qi)
{
    char data[5000];
    long mlen = qi->size;
    void *mbuf = qi->buf;
    cm_request_t req = qi->req;
    
    LOG(INFO, "CM: RECIEVED MSG =%s len=%d\n", (char *)mbuf, (int)mlen);

    memcpy(data, mbuf, mlen);
    data[qi->size] = '\0';
    
    if( req.data_type == CM_DATA_CONF || req.data_type == CM_DATA_STATS ) {
        cm_process_set_msg(data);
    } else if( req.data_type == CM_DATA_ACL) {
        cm_process_acl_msg(data);
    } else if( req.data_type == CM_DATA_RL) {
        cm_process_user_rl_msg(data);
    }
    
    return true;
}

void cm_dequeue_timer_handler(struct ev_loop *loop, ev_timer *timer, int revents)
{
    (void)loop;
    (void)timer;
    (void)revents;
    cm_queue_msg_process();
}

bool cm_dequeue_timer_init()
{
    cm_dequeue_timer_interval = 1;

    ev_timer_init(&cm_dequeue_timer, cm_dequeue_timer_handler,
                   cm_dequeue_timer_interval, cm_dequeue_timer_interval);
    cm_dequeue_timer.data = NULL;
    ev_timer_start(EV_DEFAULT, &cm_dequeue_timer);

    return true;
}


