#include "ds.h"
#include "ds_dlist.h"
#include "os_time.h"
#include "log.h"
#include "netconf.h"
#include "memutil.h"
#include <stdint.h>

netconf_queue_t g_netconf_queue;

// log queue
char *g_netconf_log_buf = NULL;
int g_netconf_log_buf_size = 0;
int g_netconf_log_drop_count = 0; // number of dropped lines

// Queue sequence number counter
static uint32_t g_queue_seq = 0;

void netconf_queue_item_free_buf(netconf_item_t *qi)
{
    if (qi) {
        // cleanup
        if (qi->topic) {
            FREE(qi->topic);
            qi->topic = NULL;
        }
        if (qi->buf) {
            FREE(qi->buf);
            qi->buf = NULL;
        }
    }
}

void netconf_queue_item_free(netconf_item_t *qi)
{
    netconf_queue_item_free_buf(qi);
    if (qi) {
        FREE(qi);
    }
}

void netconf_queue_init()
{
    ds_dlist_init(&g_netconf_queue.queue, netconf_item_t, qnode);
}

int netconf_queue_length()
{
    return g_netconf_queue.length;
}

int netconf_queue_size()
{
    return g_netconf_queue.size;
}

bool netconf_queue_head(netconf_item_t **qitem)
{
    *qitem = ds_dlist_head(&g_netconf_queue.queue);
    if (!*qitem) return false;
    return true;
}

bool netconf_queue_tail(netconf_item_t **qitem)
{
    *qitem = ds_dlist_tail(&g_netconf_queue.queue);
    if (!*qitem) return false;
    return true;
}

bool netconf_queue_remove(netconf_item_t *qitem)
{
    if (!qitem) return false;
    ds_dlist_remove(&g_netconf_queue.queue, qitem);
    g_netconf_queue.length--;
    g_netconf_queue.size -= qitem->size;
    netconf_queue_item_free(qitem);
    return true;
}

bool netconf_queue_drop_head()
{
    netconf_item_t *qitem;
    if (!netconf_queue_head(&qitem)) return false;
    return netconf_queue_remove(qitem);
}

bool netconf_queue_make_room(netconf_item_t *qi, netconf_response_t *res)
{
    if (qi->size > NETCONF_MAX_QUEUE_SIZE_BYTES) {
        // message too big to fit in queue
        return false;
    }
    while (g_netconf_queue.length >= NETCONF_MAX_QUEUE_DEPTH
            || g_netconf_queue.size + qi->size > NETCONF_MAX_QUEUE_SIZE_BYTES)
    {
        netconf_queue_drop_head();
        res->qdrop++;
    }
    return true;
}

bool netconf_queue_append_item(netconf_item_t **qitem, netconf_response_t *res)
{
    netconf_item_t *qi = *qitem;
    qi->timestamp = time_monotonic();
    if (!netconf_queue_make_room(qi, res)) {
        return false;
    }
    
    // Assign queue sequence number and log
    g_queue_seq++;
    uint32_t queue_num = g_queue_seq;
    
    const char *data_type_str = "unknown";
    switch (qi->req.data_type) {
        case NETCONF_DATA_CONF: data_type_str = "CONF"; break;
        case NETCONF_DATA_ACL: data_type_str = "ACL"; break;
        case NETCONF_DATA_RL: data_type_str = "RL"; break;
        case NETCONF_DATA_STATS: data_type_str = "STATS"; break;
        default: break;
    }
    
    LOG(INFO, "QUEUE_PUT seq=%u type=%s msglen=%zu qlen=%d", 
        queue_num, data_type_str, qi->size, g_netconf_queue.length + 1);
    
    ds_dlist_insert_tail(&g_netconf_queue.queue, qi);
    g_netconf_queue.length++;
    g_netconf_queue.size += qi->size;
    // take ownership
    *qitem = NULL;
    return true;
}

bool netconf_queue_append_log(netconf_item_t **qitem, netconf_response_t *res)
{
#ifdef CONFIG_LOG_REMOTE
    if (!netconf_log_enabled) {
        g_netconf_log_drop_count++;
        return true;
    }
    netconf_item_t *qi = *qitem;
    int new_size;
    char drop_str[64] = "";
    char *msg = (char*)qi->buf;
    int size = qi->req.data_size;
    // omit terminating nul if present
    if (size > 0 && msg[size - 1] == 0) {
        size--;
    }
    // omit terminating nl if present
    if (size > 0 && msg[size - 1] == '\n') {
        size--;
    }
    if (size == 0) {
        // no message - drop
        res->qdrop++;
        return true;
    }
    if (size >= NETCONF_LOG_QUEUE_SIZE) {
        // too big - drop
        res->qdrop++;
        msg = "--- DROPPED TOO BIG ---";
        size = strlen(msg);
    }
    // size +1 for newline
    new_size = g_netconf_log_buf_size + size + 1;
    if (new_size > NETCONF_LOG_QUEUE_SIZE) {
        // log full - drop and count lines
        char *nl = g_netconf_log_buf;
        g_netconf_log_buf[g_netconf_log_buf_size] = 0;
        while (nl && *nl) {
            g_netconf_log_drop_count++;
            nl = strchr(nl + 1, '\n');
        }
        if (g_netconf_log_drop_count) {
            snprintf(drop_str, sizeof(drop_str), "--- DROPPED %d LINES ---", g_netconf_log_drop_count);
        }
        FREE(g_netconf_log_buf);
        g_netconf_log_buf = NULL;
        g_netconf_log_buf_size = 0;
    }
    new_size = g_netconf_log_buf_size + size;
    if (g_netconf_log_buf_size) new_size++; // for newline
    if (*drop_str) {
        new_size += strlen(drop_str) + 1;
    }
    // resize buf
    g_netconf_log_buf = REALLOC(g_netconf_log_buf, new_size + 1); // +1 for nul term
                                                        // copy drop count
    if (*drop_str) {
        strscpy(g_netconf_log_buf, drop_str, new_size);
        g_netconf_log_buf_size = strlen(g_netconf_log_buf);
    }
    // append newline, if any message already in buf
    if (g_netconf_log_buf_size) {
        g_netconf_log_buf[g_netconf_log_buf_size] = '\n';
        g_netconf_log_buf_size++;
        g_netconf_log_buf[g_netconf_log_buf_size] = 0;
    }
    // append log message
    if (g_netconf_log_buf_size + size <= new_size) {
        memcpy(g_netconf_log_buf + g_netconf_log_buf_size, msg, size);
        g_netconf_log_buf_size = new_size;
        g_netconf_log_buf[g_netconf_log_buf_size] = 0;
    }
#endif
    return true;
}

bool netconf_queue_put(netconf_item_t **qitem, netconf_response_t *res)
{
    bool result;
    if ((*qitem)->req.data_type == NETCONF_DATA_LOG) {
        result = netconf_queue_append_log(qitem, res);
        netconf_queue_item_free(*qitem);
        *qitem = NULL;
    } else {
        result = netconf_queue_append_item(qitem, res);
        if (!result) {
            res->response = NETCONF_RESPONSE_ERROR;
            res->error = NETCONF_ERROR_QUEUE;
        }
    }
    return result;
}

bool netconf_queue_get(netconf_item_t **qitem)
{
    *qitem = ds_dlist_remove_head(&g_netconf_queue.queue);
    if (!*qitem) return false;
    
    g_netconf_queue.length--;
    g_netconf_queue.size -= (*qitem)->size;
    return true;
}

bool netconf_queue_msg_process()
{
    netconf_item_t *qi = NULL;
    netconf_item_t *next = NULL;

    for (qi = ds_dlist_head(&g_netconf_queue.queue); qi != NULL; qi = next) {
        next = ds_dlist_next(&g_netconf_queue.queue, qi);
        
        const char *data_type_str = "unknown";
        switch (qi->req.data_type) {
            case NETCONF_DATA_CONF: data_type_str = "CONF"; break;
            case NETCONF_DATA_ACL: data_type_str = "ACL"; break;
            case NETCONF_DATA_RL: data_type_str = "RL"; break;
            case NETCONF_DATA_STATS: data_type_str = "STATS"; break;
            default: break;
        }
        
        LOG(INFO, "QUEUE_DEQUEUE type=%s msglen=%zu qlen=%d", 
            data_type_str, qi->size, g_netconf_queue.length);
        
        if (netconf_process_msg(qi)) {
            netconf_queue_remove(qi);
        }
    }

    return true;
}
