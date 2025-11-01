#include "netstats.h"
#include "ds.h"
#include "ds_dlist.h"
#include "ev.h"
#include "log.h"

static struct ev_timer  netstats_dequeue_timer;
static int              netstats_dequeue_timer_interval;

bool netstats_process_msg(netstats_item_t *qi)
{
    LOG(DEBUG, "Processing netstats");
    netstats_publish_stats(qi);    
    return true;
}

void netstats_dequeue_timer_handler(struct ev_loop *loop, ev_timer *timer, int revents)
{
    (void)loop;
    (void)timer;
    (void)revents;

    netstats_queue_msg_process();
}

bool netstats_dequeue_timer_init()
{
    netstats_dequeue_timer_interval = 1;

    ev_timer_init(&netstats_dequeue_timer, netstats_dequeue_timer_handler, netstats_dequeue_timer_interval, netstats_dequeue_timer_interval);
    netstats_dequeue_timer.data = NULL;
    ev_timer_start(EV_DEFAULT, &netstats_dequeue_timer);

    return true;
}
