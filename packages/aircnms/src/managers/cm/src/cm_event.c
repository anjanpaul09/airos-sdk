#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <ev.h>

#include "log.h"
#include "cm.h"
#include "unixcomm.h"
#include "os.h"
#include "memutil.h"


static int g_cm_sock = -1;
static ev_io g_cm_sock_ev;

typedef struct cm_async_ctx
{
    int fd;
    ev_io io;
    void *buf;
    int allocated;
    int size;
    bool used;
} cm_async_ctx_t;

#define CM_MAX_CTX 20
#define CM_BUF_CHUNK (64*1024)

cm_async_ctx_t g_cm_async[CM_MAX_CTX];


void cm_enqueue_and_reply(int fd, cm_item_t *qi)
{
    cm_request_t *req = &qi->req;
    cm_response_t res;

    LOG(TRACE, "%s", __FUNCTION__);
    // Simplified enqueue path (legacy cm_conn removed)
    res.response = 0;
    res.error = 0;
    cm_queue_put(&qi, &res); // sets qi to NULL if successful
    // free queue item if not enqueued
    if (qi) cm_queue_item_free(qi);
    // Legacy cm_conn response path removed
}

cm_async_ctx_t* cm_ctx_new()
{
    int i;
    cm_async_ctx_t *ctx;
    for (i=0; i<CM_MAX_CTX; i++)
    {
        ctx = &g_cm_async[i];
        if (!ctx->used) {
            // found
            return ctx;
        }
    }
    return NULL;
}

int cm_ctx_idx(cm_async_ctx_t *ctx)
{
    return ((void*)ctx - (void*)&g_cm_async) / sizeof(*ctx);
}

void cm_ctx_freebuf(cm_async_ctx_t *ctx)
{
    if (ctx->buf) FREE(ctx->buf);
    ctx->buf = NULL;
    ctx->allocated = 0;
    ctx->size = 0;
}

void cm_ctx_shift_buf(cm_async_ctx_t *ctx, int size)
{
    assert(size <= ctx->size);
    ctx->size -= size;
    if (ctx->size == 0) {
        cm_ctx_freebuf(ctx);
    } else {
        memmove(ctx->buf, ctx->buf + size, ctx->size);
    }
}

void cm_ctx_release(cm_async_ctx_t *ctx)
{
    cm_ctx_freebuf(ctx);
    ev_io_stop(EV_DEFAULT, &ctx->io);
    close(ctx->fd);
    ctx->fd = -1;
    ctx->used = false;
}

// return false on error
bool cm_async_handle_req(cm_async_ctx_t *ctx)
{
    cm_item_t *qi = NULL;
    bool ret = false;
    bool complete;
    int size;

    LOG(TRACE, "%s", __FUNCTION__);

    for (;;) {
        complete = false;
        qi = CALLOC(sizeof(*qi), 1);

        // Legacy parser removed; rely on unixcomm elsewhere for ingress
        // This path is now a no-op
        cm_queue_item_free(qi);
        break;
    }
    return ret;
}

void cm_async_callback(struct ev_loop *ev, struct ev_io *io, int event)
{
    (void)ev;
    (void)io;
    (void)event;
    // Legacy socket callback removed
}

// server

bool cm_event_init()
{
    cm_queue_init();
    // Legacy cm_conn server removed; unixcomm is used instead
    return true;
}

