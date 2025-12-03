#include "ds.h"
#include "ds_dlist.h"
#include "os_time.h"
#include "log.h"
#include "cgw.h"
#include "memutil.h"
#include <pthread.h>

cgw_queue_t g_cgw_queue;
pthread_mutex_t g_cgw_queue_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t  g_cgw_queue_cond  = PTHREAD_COND_INITIALIZER;

// log queue
char *g_cgw_log_buf = NULL;
int g_cgw_log_buf_size = 0;
int g_cgw_log_drop_count = 0; // number of dropped lines

void cgw_queue_item_free_buf(cgw_item_t *qi)
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

void cgw_queue_item_free(cgw_item_t *qi)
{
    cgw_queue_item_free_buf(qi);
    if (qi) {
        FREE(qi);
    }
}

void cgw_queue_init()
{
    ds_dlist_init(&g_cgw_queue.queue, cgw_item_t, qnode);
}

int cgw_queue_length()
{
    return g_cgw_queue.length;
}

int cgw_queue_size()
{
    return g_cgw_queue.size;
}

bool cgw_queue_head(cgw_item_t **qitem)
{
    *qitem = ds_dlist_head(&g_cgw_queue.queue);
    if (!*qitem) return false;
    return true;
}

bool cgw_queue_tail(cgw_item_t **qitem)
{
    *qitem = ds_dlist_tail(&g_cgw_queue.queue);
    if (!*qitem) return false;
    return true;
}

bool cgw_queue_remove(cgw_item_t *qitem)
{
    if (!qitem) return false;
    pthread_mutex_lock(&g_cgw_queue_mutex);
    ds_dlist_remove(&g_cgw_queue.queue, qitem);
    g_cgw_queue.length--;
    g_cgw_queue.size -= qitem->size;
    // SECURITY_FIX: Issue #5 - Free item while holding lock to prevent use-after-free
    cgw_queue_item_free(qitem);
    pthread_mutex_unlock(&g_cgw_queue_mutex);
    return true;
}

bool cgw_queue_drop_head()
{
    cgw_item_t *qitem;
    if (!cgw_queue_head(&qitem)) return false;
    return cgw_queue_remove(qitem);
}

bool cgw_queue_make_room(cgw_item_t *qi, cgw_response_t *res)
{
    if (qi->size > CGW_MAX_QUEUE_SIZE_BYTES) {
        // message too big to fit in queue
        return false;
    }
    while (g_cgw_queue.length >= CGW_MAX_QUEUE_DEPTH
            || g_cgw_queue.size + qi->size > CGW_MAX_QUEUE_SIZE_BYTES)
    {
        cgw_queue_drop_head();
        res->qdrop++;
    }
    return true;
}

bool cgw_queue_append_item(cgw_item_t **qitem, cgw_response_t *res)
{
    cgw_item_t *qi = *qitem;
    qi->timestamp = time_monotonic();
    if (!cgw_queue_make_room(qi, res)) {
        return false;
    }
    pthread_mutex_lock(&g_cgw_queue_mutex);
    ds_dlist_insert_tail(&g_cgw_queue.queue, qi);
    g_cgw_queue.length++;
    g_cgw_queue.size += qi->size;
    pthread_mutex_unlock(&g_cgw_queue_mutex);
    // SECURITY_FIX: Issue #13 - Signal after releasing lock to prevent deadlock
    cgw_mqtt_signal_new_item(); // wake worker
    // take ownership
    *qitem = NULL;
    return true;
}

bool cgw_queue_append_log(cgw_item_t **qitem, cgw_response_t *res)
{
#ifdef CONFIG_LOG_REMOTE
    if (!cgw_log_enabled) {
        g_cgw_log_drop_count++;
        return true;
    }
    cgw_item_t *qi = *qitem;
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
    if (size >= CGW_LOG_QUEUE_SIZE) {
        // too big - drop
        res->qdrop++;
        msg = "--- DROPPED TOO BIG ---";
        size = strlen(msg);
    }
    // SECURITY_FIX: Issue #6 - Add mutex protection for global log buffer
    pthread_mutex_lock(&g_cgw_queue_mutex);
    
    // size +1 for newline
    new_size = g_cgw_log_buf_size + size + 1;
    if (new_size > CGW_LOG_QUEUE_SIZE) {
        // log full - drop and count lines
        char *nl = g_cgw_log_buf;
        g_cgw_log_buf[g_cgw_log_buf_size] = 0;
        while (nl && *nl) {
            g_cgw_log_drop_count++;
            nl = strchr(nl + 1, '\n');
        }
        if (g_cgw_log_drop_count) {
            snprintf(drop_str, sizeof(drop_str), "--- DROPPED %d LINES ---", g_cgw_log_drop_count);
        }
        FREE(g_cgw_log_buf);
        g_cgw_log_buf = NULL;
        g_cgw_log_buf_size = 0;
    }
    new_size = g_cgw_log_buf_size + size;
    if (g_cgw_log_buf_size) new_size++; // for newline
    if (*drop_str) {
        new_size += strlen(drop_str) + 1;
    }
    // SECURITY_FIX: Issue #14 - Check REALLOC return value
    char *new_buf = REALLOC(g_cgw_log_buf, new_size + 1); // +1 for nul term
    if (!new_buf) {
        LOG(ERR, "SECURITY_FIX: Failed to realloc log buffer (size=%d)", new_size + 1);
        pthread_mutex_unlock(&g_cgw_queue_mutex);
        return false;
    }
    g_cgw_log_buf = new_buf;
    
    // copy drop count
    if (*drop_str) {
        strscpy(g_cgw_log_buf, drop_str, new_size);
        g_cgw_log_buf_size = strlen(g_cgw_log_buf);
    }
    // append newline, if any message already in buf
    if (g_cgw_log_buf_size) {
        g_cgw_log_buf[g_cgw_log_buf_size] = '\n';
        g_cgw_log_buf_size++;
        g_cgw_log_buf[g_cgw_log_buf_size] = 0;
    }
    // append log message
    if (g_cgw_log_buf_size + size <= new_size) {
        memcpy(g_cgw_log_buf + g_cgw_log_buf_size, msg, size);
        g_cgw_log_buf_size = new_size;
        g_cgw_log_buf[g_cgw_log_buf_size] = 0;
    }
    
    pthread_mutex_unlock(&g_cgw_queue_mutex);
#else
    (void) *qitem;
    (void) res;
#endif
    return true;
}

bool cgw_queue_put(cgw_item_t **qitem, cgw_response_t *res)
{
    bool result;
    if ((*qitem)->req.data_type == DATA_LOG) {
        result = cgw_queue_append_log(qitem, res);
        cgw_queue_item_free(*qitem);
        *qitem = NULL;
    } else if ((*qitem)->req.data_type == DATA_CONF) {
        result = cgw_send_config_cloud(*qitem);
    } else if ((*qitem)->req.data_type == DATA_EVENT) {
        result = cgw_send_event_cloud(*qitem);
    } else if ((*qitem)->req.data_type == DATA_INFO_EVENT) {
        result = cgw_send_event_cloud(*qitem);
    } else if((*qitem)->req.data_type == DATA_STATS){
        result = cgw_queue_append_item(qitem, res);
        if (!result) {
            res->response = CGW_RESPONSE_ERROR;
            res->error = CGW_ERROR_QUEUE;
        }
    }
    return result;
}

bool cgw_queue_get(cgw_item_t **qitem)
{
    pthread_mutex_lock(&g_cgw_queue_mutex);
    *qitem = ds_dlist_remove_head(&g_cgw_queue.queue);
    if (!*qitem) {
        pthread_mutex_unlock(&g_cgw_queue_mutex);
        return false;
    }
    g_cgw_queue.length--;
    g_cgw_queue.size -= (*qitem)->size;
    pthread_mutex_unlock(&g_cgw_queue_mutex);
    return true;
}
