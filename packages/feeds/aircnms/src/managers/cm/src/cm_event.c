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
#include "cm_conn.h"
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
    // enqueue
    cm_res_init(&res, req);
    if (req->cmd == CM_CMD_SEND && req->data_size) {
        if (req->flags & CM_REQ_FLAG_SEND_DIRECT) {
            //cm_mqtt_send_message(qi, &res);
        } else {
            cm_queue_put(&qi, &res); // sets qi to NULL if successful
        }
    }
    // free queue item if not enqueued
    if (qi) cm_queue_item_free(qi);
    // reply
    if (!(req->flags & CM_REQ_FLAG_NO_RESPONSE)) {
        // send response if not disabled by flag
        cm_conn_write_res(fd, &res);
    }
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

        ret = cm_conn_parse_req(ctx->buf, ctx->size, &qi->req, &qi->topic, &qi->buf, &complete);
        if (ret && complete) {
            // shift consumed data in ctx buf
            size = sizeof(qi->req) + qi->req.topic_len + qi->req.data_size;
            cm_ctx_shift_buf(ctx, size);
            // enqueue
            qi->size = qi->req.data_size;
            cm_enqueue_and_reply(ctx->fd, qi);
        } else {
            cm_queue_item_free(qi);
            break;
        }
    }
    return ret;
}

void cm_async_callback(struct ev_loop *ev, struct ev_io *io, int event)
{
    cm_async_ctx_t *ctx = io->data;
    int i = cm_ctx_idx(ctx);
    int free = ctx->allocated - ctx->size;
    int ret;
    int new_size;
    void *new_buf;
    bool result;

    if (!(event & EV_READ)) return;

    if (free < CM_BUF_CHUNK) {
        new_size = ctx->allocated + CM_BUF_CHUNK;
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

    result = cm_async_handle_req(ctx);
    if (result) {
        // no error
        return;
    }
    // error: release ctx

release:
    cm_ctx_release(ctx);
}

bool cm_async_new(int fd)
{
    cm_async_ctx_t *ctx;
    ctx = cm_ctx_new();
    if (!ctx) {
        return false;
    }
    MEMZERO(*ctx);
    ctx->fd = fd;
    ev_io_init(&ctx->io, cm_async_callback, fd, EV_READ);
    ctx->io.data = ctx;
    ev_io_start(EV_DEFAULT, &ctx->io);
    LOG(TRACE, "%s ctx:%d fd:%d", __FUNCTION__, cm_ctx_idx(ctx), fd);
    ctx->used = true;
    return true;
}

void cm_sock_callback(struct ev_loop *ev, struct ev_io *io, int event)
{
    //void *data = io->data
    int fd;
    if (event & EV_READ)
    {
        if (!cm_conn_accept(g_cm_sock, &fd)) return;
        cm_async_new(fd);
    }
}

// server

bool cm_event_init()
{
    cm_queue_init();

    if (!cm_conn_server(&g_cm_sock)) {
        return false;
    }

    ev_io_init(&g_cm_sock_ev, cm_sock_callback, g_cm_sock, EV_READ);
    //g_cm_sock_ev.data = ...;
    ev_io_start(EV_DEFAULT, &g_cm_sock_ev);

    return true;
}

