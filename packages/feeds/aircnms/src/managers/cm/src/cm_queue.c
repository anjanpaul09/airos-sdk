#include "ds.h"
#include "ds_dlist.h"
#include "os_time.h"
#include "log.h"
#include "cm.h"
#include "memutil.h"

cm_queue_t g_cm_queue;

// log queue
char *g_cm_log_buf = NULL;
int g_cm_log_buf_size = 0;
int g_cm_log_drop_count = 0; // number of dropped lines

void cm_queue_item_free_buf(cm_item_t *qi)
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

void cm_queue_item_free(cm_item_t *qi)
{
    cm_queue_item_free_buf(qi);
    if (qi) {
        FREE(qi);
    }
}

void cm_queue_init()
{
    ds_dlist_init(&g_cm_queue.queue, cm_item_t, qnode);
}

int cm_queue_length()
{
    return g_cm_queue.length;
}

int cm_queue_size()
{
    return g_cm_queue.size;
}

bool cm_queue_head(cm_item_t **qitem)
{
    *qitem = ds_dlist_head(&g_cm_queue.queue);
    if (!*qitem) return false;
    return true;
}

bool cm_queue_tail(cm_item_t **qitem)
{
    *qitem = ds_dlist_tail(&g_cm_queue.queue);
    if (!*qitem) return false;
    return true;
}

bool cm_queue_remove(cm_item_t *qitem)
{
    if (!qitem) return false;
    ds_dlist_remove(&g_cm_queue.queue, qitem);
    g_cm_queue.length--;
    g_cm_queue.size -= qitem->size;
    cm_queue_item_free(qitem);
    return true;
}

bool cm_queue_drop_head()
{
    cm_item_t *qitem;
    if (!cm_queue_head(&qitem)) return false;
    return cm_queue_remove(qitem);
}

bool cm_queue_make_room(cm_item_t *qi, cm_response_t *res)
{
    if (qi->size > CM_MAX_QUEUE_SIZE_BYTES) {
        // message too big to fit in queue
        return false;
    }
    while (g_cm_queue.length >= CM_MAX_QUEUE_DEPTH
            || g_cm_queue.size + qi->size > CM_MAX_QUEUE_SIZE_BYTES)
    {
        cm_queue_drop_head();
        res->qdrop++;
    }
    return true;
}

bool cm_queue_append_item(cm_item_t **qitem, cm_response_t *res)
{
    cm_item_t *qi = *qitem;
    qi->size = qi->req.data_size;
    qi->timestamp = time_monotonic();
    if (!cm_queue_make_room(qi, res)) {
        return false;
    }
    ds_dlist_insert_tail(&g_cm_queue.queue, qi);
    g_cm_queue.length++;
    g_cm_queue.size += qi->size;
    // take ownership
    *qitem = NULL;
    return true;
}

bool cm_queue_append_log(cm_item_t **qitem, cm_response_t *res)
{
#ifdef CONFIG_LOG_REMOTE
    if (!cm_log_enabled) {
        g_cm_log_drop_count++;
        return true;
    }
    cm_item_t *qi = *qitem;
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
    if (size >= CM_LOG_QUEUE_SIZE) {
        // too big - drop
        res->qdrop++;
        msg = "--- DROPPED TOO BIG ---";
        size = strlen(msg);
    }
    // size +1 for newline
    new_size = g_cm_log_buf_size + size + 1;
    if (new_size > CM_LOG_QUEUE_SIZE) {
        // log full - drop and count lines
        char *nl = g_cm_log_buf;
        g_cm_log_buf[g_cm_log_buf_size] = 0;
        while (nl && *nl) {
            g_cm_log_drop_count++;
            nl = strchr(nl + 1, '\n');
        }
        if (g_cm_log_drop_count) {
            snprintf(drop_str, sizeof(drop_str), "--- DROPPED %d LINES ---", g_cm_log_drop_count);
        }
        FREE(g_cm_log_buf);
        g_cm_log_buf = NULL;
        g_cm_log_buf_size = 0;
    }
    new_size = g_cm_log_buf_size + size;
    if (g_cm_log_buf_size) new_size++; // for newline
    if (*drop_str) {
        new_size += strlen(drop_str) + 1;
    }
    // resize buf
    g_cm_log_buf = REALLOC(g_cm_log_buf, new_size + 1); // +1 for nul term
                                                        // copy drop count
    if (*drop_str) {
        strscpy(g_cm_log_buf, drop_str, new_size);
        g_cm_log_buf_size = strlen(g_cm_log_buf);
    }
    // append newline, if any message already in buf
    if (g_cm_log_buf_size) {
        g_cm_log_buf[g_cm_log_buf_size] = '\n';
        g_cm_log_buf_size++;
        g_cm_log_buf[g_cm_log_buf_size] = 0;
    }
    // append log message
    if (g_cm_log_buf_size + size <= new_size) {
        memcpy(g_cm_log_buf + g_cm_log_buf_size, msg, size);
        g_cm_log_buf_size = new_size;
        g_cm_log_buf[g_cm_log_buf_size] = 0;
    }
#endif
    return true;
}

bool cm_queue_put(cm_item_t **qitem, cm_response_t *res)
{
    bool result;
    if ((*qitem)->req.data_type == CM_DATA_LOG) {
        result = cm_queue_append_log(qitem, res);
        cm_queue_item_free(*qitem);
        *qitem = NULL;
    } else {
        result = cm_queue_append_item(qitem, res);
        if (!result) {
            res->response = CM_RESPONSE_ERROR;
            res->error = CM_ERROR_QUEUE;
        }
    }
    return result;
}

bool cm_queue_get(cm_item_t **qitem)
{
    *qitem = ds_dlist_remove_head(&g_cm_queue.queue);
    if (!*qitem) return false;
    g_cm_queue.length--;
    g_cm_queue.size -= (*qitem)->size;
    return true;
}

bool cm_queue_msg_process()
{
    cm_item_t *qi = NULL;
    cm_item_t *next = NULL;

    for (qi = ds_dlist_head(&g_cm_queue.queue); qi != NULL; qi = next) {
        next = ds_dlist_next(&g_cm_queue.queue, qi);
        if (cm_process_msg(qi)) {
            cm_queue_remove(qi);
        }
    }

    return true;
}
