#include "ds.h"
#include "ds_dlist.h"
#include "os_time.h"
#include "log.h"
#include "dm.h"
#include "memutil.h"


dm_queue_t g_dm_queue;

// log queue
char *g_dm_log_buf = NULL;
int g_dm_log_buf_size = 0;
int g_dm_log_drop_count = 0; // number of dropped lines

void dm_queue_item_free_buf(dm_item_t *qi)
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

void dm_queue_item_free(dm_item_t *qi)
{
    dm_queue_item_free_buf(qi);
    if (qi) {
        FREE(qi);
    }
}

void dm_queue_init()
{
    ds_dlist_init(&g_dm_queue.queue, dm_item_t, qnode);
}

int dm_queue_length()
{
    return g_dm_queue.length;
}

int dm_queue_size()
{
    return g_dm_queue.size;
}

bool dm_queue_head(dm_item_t **qitem)
{
    *qitem = ds_dlist_head(&g_dm_queue.queue);
    if (!*qitem) return false;
    return true;
}

bool dm_queue_tail(dm_item_t **qitem)
{
    *qitem = ds_dlist_tail(&g_dm_queue.queue);
    if (!*qitem) return false;
    return true;
}

bool dm_queue_remove(dm_item_t *qitem)
{
    if (!qitem) return false;
    ds_dlist_remove(&g_dm_queue.queue, qitem);
    g_dm_queue.length--;
    g_dm_queue.size -= qitem->size;
    dm_queue_item_free(qitem);
    return true;
}

bool dm_queue_drop_head()
{
    dm_item_t *qitem;
    if (!dm_queue_head(&qitem)) return false;
    return dm_queue_remove(qitem);
}

bool dm_queue_make_room(dm_item_t *qi, dm_response_t *res)
{
    if (qi->size > DM_MAX_QUEUE_SIZE_BYTES) {
        // message too big to fit in queue
        return false;
    }
    while (g_dm_queue.length >= DM_MAX_QUEUE_DEPTH
            || g_dm_queue.size + qi->size > DM_MAX_QUEUE_SIZE_BYTES)
    {
        dm_queue_drop_head();
        res->qdrop++;
    }
    return true;
}

bool dm_queue_append_item(dm_item_t **qitem, dm_response_t *res)
{
    dm_item_t *qi = *qitem;
    qi->timestamp = time_monotonic();
    if (!dm_queue_make_room(qi, res)) {
        return false;
    }
    ds_dlist_insert_tail(&g_dm_queue.queue, qi);
    g_dm_queue.length++;
    g_dm_queue.size += qi->size;
    // take ownership
    *qitem = NULL;
    return true;
}

bool dm_queue_append_log(dm_item_t **qitem, dm_response_t *res)
{
#ifdef CONFIG_LOG_REMOTE
    if (!dm_log_enabled) {
        g_dm_log_drop_count++;
        return true;
    }
    dm_item_t *qi = *qitem;
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
    if (size >= DM_LOG_QUEUE_SIZE) {
        // too big - drop
        res->qdrop++;
        msg = "--- DROPPED TOO BIG ---";
        size = strlen(msg);
    }
    // size +1 for newline
    new_size = g_dm_log_buf_size + size + 1;
    if (new_size > DM_LOG_QUEUE_SIZE) {
        // log full - drop and count lines
        char *nl = g_dm_log_buf;
        g_dm_log_buf[g_dm_log_buf_size] = 0;
        while (nl && *nl) {
            g_dm_log_drop_count++;
            nl = strchr(nl + 1, '\n');
        }
        if (g_dm_log_drop_count) {
            snprintf(drop_str, sizeof(drop_str), "--- DROPPED %d LINES ---", g_dm_log_drop_count);
        }
        FREE(g_dm_log_buf);
        g_dm_log_buf = NULL;
        g_dm_log_buf_size = 0;
    }
    new_size = g_dm_log_buf_size + size;
    if (g_dm_log_buf_size) new_size++; // for newline
    if (*drop_str) {
        new_size += strlen(drop_str) + 1;
    }
    // resize buf
    g_dm_log_buf = REALLOC(g_dm_log_buf, new_size + 1); // +1 for nul term
                                                        // copy drop count
    if (*drop_str) {
        strscpy(g_dm_log_buf, drop_str, new_size);
        g_dm_log_buf_size = strlen(g_dm_log_buf);
    }
    // append newline, if any message already in buf
    if (g_dm_log_buf_size) {
        g_dm_log_buf[g_dm_log_buf_size] = '\n';
        g_dm_log_buf_size++;
        g_dm_log_buf[g_dm_log_buf_size] = 0;
    }
    // append log message
    if (g_dm_log_buf_size + size <= new_size) {
        memcpy(g_dm_log_buf + g_dm_log_buf_size, msg, size);
        g_dm_log_buf_size = new_size;
        g_dm_log_buf[g_dm_log_buf_size] = 0;
    }
#else
    (void)qitem;  // Mark as unused to suppress warnings
    (void)res;
#endif
    return true;
}

bool dm_queue_put(dm_item_t **qitem, dm_response_t *res)
{
    bool result;
    if ((*qitem)->req.data_type == DATA_LOG) {
        result = dm_queue_append_log(qitem, res);
        dm_queue_item_free(*qitem);
        *qitem = NULL;
    } else {
        result = dm_queue_append_item(qitem, res);
        if (!result) {
            res->response = DM_RESPONSE_ERROR;
            res->error = DM_ERROR_QUEUE;
        }
    }
    return result;
}

bool dm_queue_get(dm_item_t **qitem)
{
    *qitem = ds_dlist_remove_head(&g_dm_queue.queue);
    if (!*qitem) return false;
    g_dm_queue.length--;
    g_dm_queue.size -= (*qitem)->size;
    return true;
}

bool dm_queue_msg_process()
{
    dm_item_t *qi = NULL;
    dm_item_t *next = NULL;

    for (qi = ds_dlist_head(&g_dm_queue.queue); qi != NULL; qi = next) {
        next = ds_dlist_next(&g_dm_queue.queue, qi);
        if (dm_process_msg(qi)) {
            dm_queue_remove(qi);
        }
    }

    return true;
}
