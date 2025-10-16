#include <jansson.h>
#include "ds.h"
#include "ds_dlist.h"
#include "os_time.h"
#include "log.h"
#include "dm.h"
#include "memutil.h"
#include "unixcomm.h"

static struct ev_timer  dm_dequeue_timer;
static int              dm_dequeue_timer_interval;

bool dm_process_msg(dm_item_t *qi)
{
    char data[5000];
    long mlen = qi->size;
    void *mbuf = qi->buf;
    // Minimal inline request
    dm_request_t req = qi->req;
    
    LOG(INFO, "DM: RECIEVED: buf=%s len=%d\n", (char *)mbuf, (int)mlen);

    memcpy(data, mbuf, mlen);
    data[qi->size] = '\0';
    
    if( req.data_type == DATA_CMD) {
        dm_process_cmd_msg(data);
    } 
    
    return true;
}

void dm_dequeue_timer_handler(struct ev_loop *loop, ev_timer *timer, int revents)
{
    (void)loop;
    (void)timer;
    (void)revents;
    dm_queue_msg_process();
}

bool dm_dequeue_timer_init()
{
    dm_dequeue_timer_interval = 1;

    ev_timer_init(&dm_dequeue_timer, dm_dequeue_timer_handler,
                   dm_dequeue_timer_interval, dm_dequeue_timer_interval);
    dm_dequeue_timer.data = NULL;
    ev_timer_start(EV_DEFAULT, &dm_dequeue_timer);

    return true;
}


