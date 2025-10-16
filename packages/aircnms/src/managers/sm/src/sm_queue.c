#include "ds.h"
#include "ds_dlist.h"
#include "os_time.h"
#include "log.h"
#include "sm.h"
#include "memutil.h"

sm_queue_t g_sm_queue;

// log queue
char *g_sm_log_buf = NULL;
int g_sm_log_buf_size = 0;
int g_sm_log_drop_count = 0; // number of dropped lines

void sm_queue_item_free_buf(sm_item_t *qi)
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

void sm_queue_item_free(sm_item_t *qi)
{
    sm_queue_item_free_buf(qi);
    if (qi) {
        FREE(qi);
    }
}

void sm_queue_init()
{
    ds_dlist_init(&g_sm_queue.queue, sm_item_t, qnode);
}

int sm_queue_length()
{
    return g_sm_queue.length;
}

int sm_queue_size()
{
    return g_sm_queue.size;
}

bool sm_queue_head(sm_item_t **qitem)
{
    *qitem = ds_dlist_head(&g_sm_queue.queue);
    if (!*qitem) return false;
    return true;
}

bool sm_queue_tail(sm_item_t **qitem)
{
    *qitem = ds_dlist_tail(&g_sm_queue.queue);
    if (!*qitem) return false;
    return true;
}

bool sm_queue_remove(sm_item_t *qitem)
{
    if (!qitem) return false;
    ds_dlist_remove(&g_sm_queue.queue, qitem);
    g_sm_queue.length--;
    g_sm_queue.size -= qitem->size;
    sm_queue_item_free(qitem);
    return true;
}

bool sm_queue_drop_head()
{
    sm_item_t *qitem;
    if (!sm_queue_head(&qitem)) return false;
    return sm_queue_remove(qitem);
}

bool sm_queue_make_room(sm_item_t *qi, sm_response_t *res)
{
    if (qi->size > SM_MAX_QUEUE_SIZE_BYTES) {
        // message too big to fit in queue
        return false;
    }
    while (g_sm_queue.length >= SM_MAX_QUEUE_DEPTH
            || g_sm_queue.size + qi->size > SM_MAX_QUEUE_SIZE_BYTES)
    {
        sm_queue_drop_head();
        res->qdrop++;
    }
    return true;
}

bool sm_queue_append_item(sm_item_t **qitem, sm_response_t *res)
{
    sm_item_t *qi = *qitem;
    qi->size = qi->req.data_size;
    qi->timestamp = time_monotonic();
    if (!sm_queue_make_room(qi, res)) {
        return false;
    }
    ds_dlist_insert_tail(&g_sm_queue.queue, qi);
    g_sm_queue.length++;
    g_sm_queue.size += qi->size;
    // take ownership
    *qitem = NULL;
    return true;
}

bool sm_queue_append_log(sm_item_t **qitem, sm_response_t *res)
{
#ifdef CONFIG_LOG_REMOTE
    if (!sm_log_enabled) {
        g_sm_log_drop_count++;
        return true;
    }
    sm_item_t *qi = *qitem;
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
    if (size >= SM_LOG_QUEUE_SIZE) {
        // too big - drop
        res->qdrop++;
        msg = "--- DROPPED TOO BIG ---";
        size = strlen(msg);
    }
    // size +1 for newline
    new_size = g_sm_log_buf_size + size + 1;
    if (new_size > SM_LOG_QUEUE_SIZE) {
        // log full - drop and count lines
        char *nl = g_sm_log_buf;
        g_sm_log_buf[g_sm_log_buf_size] = 0;
        while (nl && *nl) {
            g_sm_log_drop_count++;
            nl = strchr(nl + 1, '\n');
        }
        if (g_sm_log_drop_count) {
            snprintf(drop_str, sizeof(drop_str), "--- DROPPED %d LINES ---", g_sm_log_drop_count);
        }
        FREE(g_sm_log_buf);
        g_sm_log_buf = NULL;
        g_sm_log_buf_size = 0;
    }
    new_size = g_sm_log_buf_size + size;
    if (g_sm_log_buf_size) new_size++; // for newline
    if (*drop_str) {
        new_size += strlen(drop_str) + 1;
    }
    // resize buf
    g_sm_log_buf = REALLOC(g_sm_log_buf, new_size + 1); // +1 for nul term
                                                        // copy drop count
    if (*drop_str) {
        strscpy(g_sm_log_buf, drop_str, new_size);
        g_sm_log_buf_size = strlen(g_sm_log_buf);
    }
    // append newline, if any message already in buf
    if (g_sm_log_buf_size) {
        g_sm_log_buf[g_sm_log_buf_size] = '\n';
        g_sm_log_buf_size++;
        g_sm_log_buf[g_sm_log_buf_size] = 0;
    }
    // append log message
    if (g_sm_log_buf_size + size <= new_size) {
        memcpy(g_sm_log_buf + g_sm_log_buf_size, msg, size);
        g_sm_log_buf_size = new_size;
        g_sm_log_buf[g_sm_log_buf_size] = 0;
    }
#endif
    return true;
}

bool sm_queue_put(sm_item_t **qitem, sm_response_t *res)
{
    bool result;
    if ((*qitem)->req.data_type == SM_DATA_LOG) {
        result = sm_queue_append_log(qitem, res);
        sm_queue_item_free(*qitem);
        *qitem = NULL;
    } else {
        result = sm_queue_append_item(qitem, res);
        if (!result) {
            res->response = SM_RESPONSE_ERROR;
            res->error = SM_ERROR_QUEUE;
        }
    }
    return result;
}

bool sm_queue_get(sm_item_t **qitem)
{
    *qitem = ds_dlist_remove_head(&g_sm_queue.queue);
    if (!*qitem) return false;
    g_sm_queue.length--;
    g_sm_queue.size -= (*qitem)->size;
    return true;
}

bool sm_queue_msg_process()
{
    sm_item_t *qi = NULL;
    sm_item_t *next = NULL;

    for (qi = ds_dlist_head(&g_sm_queue.queue); qi != NULL; qi = next) {
        next = ds_dlist_next(&g_sm_queue.queue, qi);
        if (sm_process_msg(qi)) {
            sm_queue_remove(qi);
        }
    }

    return true;
}
