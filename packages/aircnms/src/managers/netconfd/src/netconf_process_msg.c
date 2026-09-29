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
    char *data;
    size_t mlen;
    netconf_request_t req;
    bool result = false;

    if (!ci || !ci->buf || ci->size == 0 ||
        ci->size > NETCONF_MAX_QUEUE_SIZE_BYTES) {
        LOG(ERR, "MSG_REJECTED reason=invalid_size");
        return false;
    }

    mlen = ci->size;
    req = ci->req;
    data = MALLOC(mlen + 1);
    if (!data) {
        LOG(ERR, "MSG_REJECTED reason=allocation_failed msglen=%zu", mlen);
        return false;
    }
    memcpy(data, ci->buf, mlen);
    data[mlen] = '\0';
    LOG(INFO, "MSG_PROCESS type=%d msglen=%zu", req.data_type, mlen);

    if (req.data_type == NETCONF_DATA_CONF || req.data_type == NETCONF_DATA_STATS)
        result = netconf_process_set_msg(data);
    else if (req.data_type == NETCONF_DATA_ACL)
        result = netconf_process_acl_msg(data);
    else if (req.data_type == NETCONF_DATA_RL)
        result = netconf_process_user_rl_msg(data);
    else
        LOG(ERR, "MSG_REJECTED reason=unsupported_type type=%d", req.data_type);

    FREE(data);
    return result;
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


