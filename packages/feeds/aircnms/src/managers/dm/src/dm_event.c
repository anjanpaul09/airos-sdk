#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <ev.h>

#include "log.h"
#include "dm.h"
#include "dm_conn.h"
#include "os.h"
#include "memutil.h"


static int g_dm_sock = -1;
static ev_io g_dm_sock_ev;

typedef struct dm_async_ctx
{
    int fd;
    ev_io io;
    void *buf;
    int allocated;
    int size;
    bool used;
} dm_async_ctx_t;

#define DM_MAX_CTX 20
#define DM_BUF_CHUNK (64*1024)

dm_async_ctx_t g_dm_async[DM_MAX_CTX];


void dm_enqueue_and_reply(int fd, dm_item_t *qi)
{
    dm_request_t *req = &qi->req;
    dm_response_t res;

    LOG(TRACE, "%s", __FUNCTION__);
    // enqueue
    dm_res_init(&res, req);
    if (req->cmd == DM_CMD_SEND && req->data_size) {
        if (req->flags & DM_REQ_FLAG_SEND_DIRECT) {
            //dm_mqtt_send_message(qi, &res);
        } else {
            dm_queue_put(&qi, &res); // sets qi to NULL if successful
        }
    }
    // free queue item if not enqueued
    if (qi) dm_queue_item_free(qi);
    // reply
    if (!(req->flags & DM_REQ_FLAG_NO_RESPONSE)) {
        // send response if not disabled by flag
        dm_conn_write_res(fd, &res);
    }
}

dm_async_ctx_t* dm_ctx_new()
{
    int i;
    dm_async_ctx_t *ctx;
    for (i=0; i<DM_MAX_CTX; i++)
    {
        ctx = &g_dm_async[i];
        if (!ctx->used) {
            // found
            return ctx;
        }
    }
    return NULL;
}

int dm_ctx_idx(dm_async_ctx_t *ctx)
{
    return ((void*)ctx - (void*)&g_dm_async) / sizeof(*ctx);
}

void dm_ctx_freebuf(dm_async_ctx_t *ctx)
{
    if (ctx->buf) FREE(ctx->buf);
    ctx->buf = NULL;
    ctx->allocated = 0;
    ctx->size = 0;
}

void dm_ctx_shift_buf(dm_async_ctx_t *ctx, int size)
{
    assert(size <= ctx->size);
    ctx->size -= size;
    if (ctx->size == 0) {
        dm_ctx_freebuf(ctx);
    } else {
        memmove(ctx->buf, ctx->buf + size, ctx->size);
    }
}

void dm_ctx_release(dm_async_ctx_t *ctx)
{
    dm_ctx_freebuf(ctx);
    ev_io_stop(EV_DEFAULT, &ctx->io);
    close(ctx->fd);
    ctx->fd = -1;
    ctx->used = false;
}

// return false on error
bool dm_async_handle_req(dm_async_ctx_t *ctx)
{
    dm_item_t *qi = NULL;
    bool ret = false;
    bool complete;
    int size;

    LOG(TRACE, "%s", __FUNCTION__);

    for (;;) {
        complete = false;
        qi = CALLOC(sizeof(*qi), 1);

        ret = dm_conn_parse_req(ctx->buf, ctx->size, &qi->req, &qi->topic, &qi->buf, &complete);
        if (ret && complete) {
            // shift consumed data in ctx buf
            size = sizeof(qi->req) + qi->req.topic_len + qi->req.data_size;
            dm_ctx_shift_buf(ctx, size);
            // enqueue
            qi->size = qi->req.data_size;
            dm_enqueue_and_reply(ctx->fd, qi);
        } else {
            dm_queue_item_free(qi);
            break;
        }
    }
    return ret;
}

void dm_async_callback(struct ev_loop *ev, struct ev_io *io, int event)
{
    dm_async_ctx_t *ctx = io->data;
    int i = dm_ctx_idx(ctx);
    int free = ctx->allocated - ctx->size;
    int ret;
    int new_size;
    void *new_buf;
    bool result;

    if (!(event & EV_READ)) return;

    if (free < DM_BUF_CHUNK) {
        new_size = ctx->allocated + DM_BUF_CHUNK;
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

    result = dm_async_handle_req(ctx);
    if (result) {
        // no error
        return;
    }
    // error: release ctx

release:
    dm_ctx_release(ctx);
}

bool dm_async_new(int fd)
{
    dm_async_ctx_t *ctx;
    ctx = dm_ctx_new();
    if (!ctx) {
        return false;
    }
    MEMZERO(*ctx);
    ctx->fd = fd;
    ev_io_init(&ctx->io, dm_async_callback, fd, EV_READ);
    ctx->io.data = ctx;
    ev_io_start(EV_DEFAULT, &ctx->io);
    LOG(TRACE, "%s ctx:%d fd:%d", __FUNCTION__, dm_ctx_idx(ctx), fd);
    ctx->used = true;
    return true;
}

void dm_sock_callback(struct ev_loop *ev, struct ev_io *io, int event)
{
    //void *data = io->data
    int fd;
    if (event & EV_READ)
    {
        if (!dm_conn_accept(g_dm_sock, &fd)) return;
        dm_async_new(fd);
    }
}

// server

bool dm_event_init()
{
    dm_queue_init();

    if (!dm_conn_server(&g_dm_sock)) {
        return false;
    }

    ev_io_init(&g_dm_sock_ev, dm_sock_callback, g_dm_sock, EV_READ);
    //g_dm_sock_ev.data = ...;
    ev_io_start(EV_DEFAULT, &g_dm_sock_ev);

    return true;
}

