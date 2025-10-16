#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <ev.h>

#include "log.h"
#include "sm.h"
#include "unixcomm.h"
#include "os.h"
#include "memutil.h"


static int g_sm_sock = -1;
static ev_io g_sm_sock_ev;

typedef struct sm_async_ctx
{
    int fd;
    ev_io io;
    void *buf;
    int allocated;
    int size;
    bool used;
} sm_async_ctx_t;

#define SM_MAX_CTX 20
#define SM_BUF_CHUNK (64*1024)

sm_async_ctx_t g_sm_async[SM_MAX_CTX];


void sm_enqueue_and_reply(int fd, sm_item_t *qi)
{
    // Minimal req-only usage
    sm_response_t res;

    LOG(TRACE, "%s", __FUNCTION__);
    // enqueue
    res.response = 0; res.error = 0; res.qdrop = 0;
    sm_queue_put(&qi, &res); // sets qi to NULL if successful
    // free queue item if not enqueued
    if (qi) sm_queue_item_free(qi);
    // reply
    // Legacy response path removed
}

sm_async_ctx_t* sm_ctx_new()
{
    int i;
    sm_async_ctx_t *ctx;
    for (i=0; i<SM_MAX_CTX; i++)
    {
        ctx = &g_sm_async[i];
        if (!ctx->used) {
            // found
            return ctx;
        }
    }
    return NULL;
}

int sm_ctx_idx(sm_async_ctx_t *ctx)
{
    return ((void*)ctx - (void*)&g_sm_async) / sizeof(*ctx);
}

void sm_ctx_freebuf(sm_async_ctx_t *ctx)
{
    if (ctx->buf) FREE(ctx->buf);
    ctx->buf = NULL;
    ctx->allocated = 0;
    ctx->size = 0;
}

void sm_ctx_shift_buf(sm_async_ctx_t *ctx, int size)
{
    assert(size <= ctx->size);
    ctx->size -= size;
    if (ctx->size == 0) {
        sm_ctx_freebuf(ctx);
    } else {
        memmove(ctx->buf, ctx->buf + size, ctx->size);
    }
}

void sm_ctx_release(sm_async_ctx_t *ctx)
{
    sm_ctx_freebuf(ctx);
    ev_io_stop(EV_DEFAULT, &ctx->io);
    close(ctx->fd);
    ctx->fd = -1;
    ctx->used = false;
}

// return false on error
bool sm_async_handle_req(sm_async_ctx_t *ctx)
{
    sm_item_t *qi = NULL;
    bool ret = false;
    bool complete;
    int size;

    LOG(TRACE, "%s", __FUNCTION__);

    for (;;) {
        complete = false;
        qi = CALLOC(sizeof(*qi), 1);

        // Legacy parser removed; unixcomm used elsewhere
        sm_queue_item_free(qi);
        break;
    }
    return ret;
}

void sm_async_callback(struct ev_loop *ev, struct ev_io *io, int event)
{
    sm_async_ctx_t *ctx = io->data;
    int i = sm_ctx_idx(ctx);
    int free = ctx->allocated - ctx->size;
    int ret;
    int new_size;
    void *new_buf;
    bool result;

    if (!(event & EV_READ)) return;

    if (free < SM_BUF_CHUNK) {
        new_size = ctx->allocated + SM_BUF_CHUNK;
        new_buf = REALLOC(ctx->buf, new_size);
        ctx->buf = new_buf;
        ctx->allocated = new_size;
    }
    free = ctx->allocated - ctx->size;

    ret = read(ctx->fd, ctx->buf + ctx->size, free);
    if (ret < 0) {
        LOG(ERR, "%s read %d %d %d", __FUNCTION__, ctx->size, ret, errno);
        goto release;
    }
    ctx->size += ret;
    LOG(TRACE, "%s ctx:%d fd:%d t:%d r:%d", __FUNCTION__, i, ctx->fd, ctx->size, ret);
    if (ret == 0) {
        // EOF
        goto release;
    }

    result = sm_async_handle_req(ctx);
    if (result) {
        // no error
        return;
    }
    // error: release ctx

release:
    sm_ctx_release(ctx);
}

bool sm_async_new(int fd)
{
    sm_async_ctx_t *ctx;
    ctx = sm_ctx_new();
    if (!ctx) {
        return false;
    }
    MEMZERO(*ctx);
    ctx->fd = fd;
    ev_io_init(&ctx->io, sm_async_callback, fd, EV_READ);
    ctx->io.data = ctx;
    ev_io_start(EV_DEFAULT, &ctx->io);
    LOG(TRACE, "%s ctx:%d fd:%d", __FUNCTION__, sm_ctx_idx(ctx), fd);
    ctx->used = true;
    return true;
}

void sm_sock_callback(struct ev_loop *ev, struct ev_io *io, int event)
{
    //void *data = io->data
    int fd;
    if (event & EV_READ)
    {
        // Legacy sm_conn_accept removed
        (void)fd;
        return;
    }
}

// server

bool sm_rx_event_init()
{
    sm_queue_init();

    // Legacy conn server removed
    return true;
}

