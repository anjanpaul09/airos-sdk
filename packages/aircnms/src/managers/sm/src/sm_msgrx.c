#include <jansson.h>
#include "ds.h"
#include "ds_dlist.h"
#include "os_time.h"
#include "log.h"
#include "sm.h"
#include "memutil.h"

static struct ev_timer  sm_dequeue_timer;
static int              sm_dequeue_timer_interval;

void sm_init_neighbor_stats_config();

bool sm_process_msg(sm_item_t *qi)
{
    //long mlen = qi->size;
    //void *mbuf = qi->buf;
    printf("Ankit: msg received SM !!!\n");
    
    sm_init_neighbor_stats_config();

    return true;
}

void sm_dequeue_timer_handler(struct ev_loop *loop, ev_timer *timer, int revents)
{
    (void)loop;
    (void)timer;
    (void)revents;

    sm_queue_msg_process();
}

bool sm_dequeue_timer_init()
{
    sm_dequeue_timer_interval = 1;

    ev_timer_init(&sm_dequeue_timer, sm_dequeue_timer_handler, sm_dequeue_timer_interval, sm_dequeue_timer_interval);
    sm_dequeue_timer.data = NULL;
    ev_timer_start(EV_DEFAULT, &sm_dequeue_timer);

    return true;
}
