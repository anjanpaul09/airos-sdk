#include "ds.h"
#include "ds_dlist.h"
#include "os_time.h"
#include "log.h"
#include "cmdexec.h"
#include "memutil.h"


cmdexec_queue_t g_cmdexec_queue;

// log queue
char *g_cmdexec_log_buf = NULL;
int g_cmdexec_log_buf_size = 0;
int g_cmdexec_log_drop_count = 0; // number of dropped lines

void cmdexec_queue_item_free_buf(cmdexec_item_t *qi)
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

void cmdexec_queue_item_free(cmdexec_item_t *qi)
{
    cmdexec_queue_item_free_buf(qi);
    if (qi) {
        FREE(qi);
    }
}

void cmdexec_queue_init()
{
    ds_dlist_init(&g_cmdexec_queue.queue, cmdexec_item_t, qnode);
}

int cmdexec_queue_length()
{
    return g_cmdexec_queue.length;
}

int cmdexec_queue_size()
{
    return g_cmdexec_queue.size;
}

bool cmdexec_queue_head(cmdexec_item_t **qitem)
{
    *qitem = ds_dlist_head(&g_cmdexec_queue.queue);
    if (!*qitem) return false;
    return true;
}

bool cmdexec_queue_tail(cmdexec_item_t **qitem)
{
    *qitem = ds_dlist_tail(&g_cmdexec_queue.queue);
    if (!*qitem) return false;
    return true;
}

bool cmdexec_queue_remove(cmdexec_item_t *qitem)
{
    if (!qitem) return false;
    ds_dlist_remove(&g_cmdexec_queue.queue, qitem);
    g_cmdexec_queue.length--;
    g_cmdexec_queue.size -= qitem->size;
    cmdexec_queue_item_free(qitem);
    return true;
}

bool cmdexec_queue_drop_head()
{
    cmdexec_item_t *qitem;
    if (!cmdexec_queue_head(&qitem)) return false;
    return cmdexec_queue_remove(qitem);
}

bool cmdexec_queue_make_room(cmdexec_item_t *qi, cmdexec_response_t *res)
{
    if (qi->size > CMDEXEC_MAX_QUEUE_SIZE_BYTES) {
        // message too big to fit in queue
        return false;
    }
    while (g_cmdexec_queue.length >= CMDEXEC_MAX_QUEUE_DEPTH
            || g_cmdexec_queue.size + qi->size > CMDEXEC_MAX_QUEUE_SIZE_BYTES)
    {
        cmdexec_queue_drop_head();
        res->qdrop++;
    }
    return true;
}

bool cmdexec_queue_append_item(cmdexec_item_t **qitem, cmdexec_response_t *res)
{
    cmdexec_item_t *qi = *qitem;
    qi->timestamp = time_monotonic();
    if (!cmdexec_queue_make_room(qi, res)) {
        return false;
    }
    ds_dlist_insert_tail(&g_cmdexec_queue.queue, qi);
    g_cmdexec_queue.length++;
    g_cmdexec_queue.size += qi->size;
    // take ownership
    *qitem = NULL;
    return true;
}

bool cmdexec_queue_append_log(cmdexec_item_t **qitem, cmdexec_response_t *res)
{
#ifdef CONFIG_LOG_REMOTE
    if (!cmdexec_log_enabled) {
        g_cmdexec_log_drop_count++;
        return true;
    }
    cmdexec_item_t *qi = *qitem;
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
    if (size >= CMDEXEC_LOG_QUEUE_SIZE) {
        // too big - drop
        res->qdrop++;
        msg = "--- DROPPED TOO BIG ---";
        size = strlen(msg);
    }
    // size +1 for newline
    new_size = g_cmdexec_log_buf_size + size + 1;
    if (new_size > CMDEXEC_LOG_QUEUE_SIZE) {
        // log full - drop and count lines
        char *nl = g_cmdexec_log_buf;
        g_cmdexec_log_buf[g_cmdexec_log_buf_size] = 0;
        while (nl && *nl) {
            g_cmdexec_log_drop_count++;
            nl = strchr(nl + 1, '\n');
        }
        if (g_cmdexec_log_drop_count) {
            snprintf(drop_str, sizeof(drop_str), "--- DROPPED %d LINES ---", g_cmdexec_log_drop_count);
        }
        FREE(g_cmdexec_log_buf);
        g_cmdexec_log_buf = NULL;
        g_cmdexec_log_buf_size = 0;
    }
    new_size = g_cmdexec_log_buf_size + size;
    if (g_cmdexec_log_buf_size) new_size++; // for newline
    if (*drop_str) {
        new_size += strlen(drop_str) + 1;
    }
    // resize buf
    g_cmdexec_log_buf = REALLOC(g_cmdexec_log_buf, new_size + 1); // +1 for nul term
                                                        // copy drop count
    if (*drop_str) {
        strscpy(g_cmdexec_log_buf, drop_str, new_size);
        g_cmdexec_log_buf_size = strlen(g_cmdexec_log_buf);
    }
    // append newline, if any message already in buf
    if (g_cmdexec_log_buf_size) {
        g_cmdexec_log_buf[g_cmdexec_log_buf_size] = '\n';
        g_cmdexec_log_buf_size++;
        g_cmdexec_log_buf[g_cmdexec_log_buf_size] = 0;
    }
    // append log message
    if (g_cmdexec_log_buf_size + size <= new_size) {
        memcpy(g_cmdexec_log_buf + g_cmdexec_log_buf_size, msg, size);
        g_cmdexec_log_buf_size = new_size;
        g_cmdexec_log_buf[g_cmdexec_log_buf_size] = 0;
    }
#else
    (void)qitem;  // Mark as unused to suppress warnings
    (void)res;
#endif
    return true;
}

bool cmdexec_queue_put(cmdexec_item_t **qitem, cmdexec_response_t *res)
{
    bool result;
    if ((*qitem)->req.data_type == DATA_LOG) {
        result = cmdexec_queue_append_log(qitem, res);
        cmdexec_queue_item_free(*qitem);
        *qitem = NULL;
    } else {
        result = cmdexec_queue_append_item(qitem, res);
        if (!result) {
            res->response = CMDEXEC_RESPONSE_ERROR;
            res->error = CMDEXEC_ERROR_QUEUE;
        }
    }
    return result;
}

bool cmdexec_queue_get(cmdexec_item_t **qitem)
{
    *qitem = ds_dlist_remove_head(&g_cmdexec_queue.queue);
    if (!*qitem) return false;
    g_cmdexec_queue.length--;
    g_cmdexec_queue.size -= (*qitem)->size;
    return true;
}

bool cmdexec_queue_msg_process()
{
    cmdexec_item_t *qi = NULL;
    cmdexec_item_t *next = NULL;

    for (qi = ds_dlist_head(&g_cmdexec_queue.queue); qi != NULL; qi = next) {
        next = ds_dlist_next(&g_cmdexec_queue.queue, qi);
        if (cmdexec_process_msg(qi)) {
            cmdexec_queue_remove(qi);
        }
    }

    return true;
}
