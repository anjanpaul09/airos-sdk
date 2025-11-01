#include <jansson.h>
#include "ds.h"
#include "ds_dlist.h"
#include "os_time.h"
#include "log.h"
#include "cmdexec.h"
#include "memutil.h"
#include "unixcomm.h"

static struct ev_timer  cmdexec_dequeue_timer;
static int              cmdexec_dequeue_timer_interval;

bool cmdexec_process_msg(cmdexec_item_t *qi)
{
    char data[5000];
    long mlen = qi->size;
    void *mbuf = qi->buf;
    // Minimal inline request
    cmdexec_request_t req = qi->req;
    
    LOG(INFO, "DM: RECIEVED: buf=%s len=%d\n", (char *)mbuf, (int)mlen);

    memcpy(data, mbuf, mlen);
    data[qi->size] = '\0';
    
    if( req.data_type == DATA_CMD) {
        cmdexec_process_cmd_msg(data);
    } 
    
    return true;
}

void cmdexec_dequeue_timer_handler(struct ev_loop *loop, ev_timer *timer, int revents)
{
    (void)loop;
    (void)timer;
    (void)revents;
    cmdexec_queue_msg_process();
}

bool cmdexec_dequeue_timer_init()
{
    cmdexec_dequeue_timer_interval = 1;

    ev_timer_init(&cmdexec_dequeue_timer, cmdexec_dequeue_timer_handler,
                   cmdexec_dequeue_timer_interval, cmdexec_dequeue_timer_interval);
    cmdexec_dequeue_timer.data = NULL;
    ev_timer_start(EV_DEFAULT, &cmdexec_dequeue_timer);

    return true;
}


