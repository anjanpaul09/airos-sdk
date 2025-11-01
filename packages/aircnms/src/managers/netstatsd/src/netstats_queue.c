#include "ds.h"
#include "ds_dlist.h"
#include "os_time.h"
#include "log.h"
#include "netstats.h"
#include "memutil.h"

netstats_queue_t g_netstats_queue;

// log queue
char *g_netstats_log_buf = NULL;
int g_netstats_log_buf_size = 0;
int g_netstats_log_drop_count = 0; // number of dropped lines

void netstats_queue_item_free_buf(netstats_item_t *qi)
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

void netstats_queue_item_free(netstats_item_t *qi)
{
    netstats_queue_item_free_buf(qi);
    if (qi) {
        FREE(qi);
    }
}

void netstats_queue_init()
{
    ds_dlist_init(&g_netstats_queue.queue, netstats_item_t, qnode);
}

int netstats_queue_length()
{
    return g_netstats_queue.length;
}

int netstats_queue_size()
{
    return g_netstats_queue.size;
}

bool netstats_queue_head(netstats_item_t **qitem)
{
    *qitem = ds_dlist_head(&g_netstats_queue.queue);
    if (!*qitem) return false;
    return true;
}

bool netstats_queue_tail(netstats_item_t **qitem)
{
    *qitem = ds_dlist_tail(&g_netstats_queue.queue);
    if (!*qitem) return false;
    return true;
}

bool netstats_queue_remove(netstats_item_t *qitem)
{
    if (!qitem) return false;
    ds_dlist_remove(&g_netstats_queue.queue, qitem);
    g_netstats_queue.length--;
    g_netstats_queue.size -= qitem->size;
    netstats_queue_item_free(qitem);
    return true;
}

bool netstats_queue_drop_head()
{
    netstats_item_t *qitem;
    if (!netstats_queue_head(&qitem)) return false;
    return netstats_queue_remove(qitem);
}

bool netstats_queue_make_room(netstats_item_t *qi, netstats_response_t *res)
{
    if (qi->size > NETSTATS_MAX_QUEUE_SIZE_BYTES) {
        // message too big to fit in queue
        return false;
    }
    while (g_netstats_queue.length >= NETSTATS_MAX_QUEUE_DEPTH
            || g_netstats_queue.size + qi->size > NETSTATS_MAX_QUEUE_SIZE_BYTES)
    {
        netstats_queue_drop_head();
        res->qdrop++;
    }
    return true;
}

bool netstats_queue_append_item(netstats_item_t **qitem, netstats_response_t *res)
{
    netstats_item_t *qi = *qitem;
    qi->timestamp = time_monotonic();
    if (!netstats_queue_make_room(qi, res)) {
        return false;
    }
    ds_dlist_insert_tail(&g_netstats_queue.queue, qi);
    g_netstats_queue.length++;
    g_netstats_queue.size += qi->size;
    // take ownership
    *qitem = NULL;
    return true;
}

bool netstats_queue_put(netstats_item_t **qitem, netstats_response_t *res)
{
    bool result;
    if ((*qitem)->req.data_type == NETSTATS_DATA_LOG) {
        //result = netstats_queue_append_log(qitem, res);
        netstats_queue_item_free(*qitem);
        *qitem = NULL;
    } else {
        result = netstats_queue_append_item(qitem, res);
        if (!result) {
            res->response = NETSTATS_RESPONSE_ERROR;
            res->error = NETSTATS_ERROR_QUEUE;
        }
    }
    return result;
}

bool netstats_queue_get(netstats_item_t **qitem)
{
    *qitem = ds_dlist_remove_head(&g_netstats_queue.queue);
    if (!*qitem) return false;
    g_netstats_queue.length--;
    g_netstats_queue.size -= (*qitem)->size;
    return true;
}

bool netstats_queue_msg_process()
{
    netstats_item_t *qi = NULL;
    netstats_item_t *next = NULL;

    for (qi = ds_dlist_head(&g_netstats_queue.queue); qi != NULL; qi = next) {
        next = ds_dlist_next(&g_netstats_queue.queue, qi);
        if (netstats_process_msg(qi)) {
            netstats_queue_remove(qi);
        }
    }

    return true;
}
