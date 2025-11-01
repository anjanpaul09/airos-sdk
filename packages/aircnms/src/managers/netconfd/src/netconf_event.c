#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <ev.h>

#include "log.h"
#include "netconf.h"
#include "unixcomm.h"
#include "os.h"
#include "memutil.h"


__attribute__((unused)) static int g_netconf_sock = -1;
__attribute__((unused)) static ev_io g_netconf_sock_ev;

typedef struct netconf_async_ctx
{
    int fd;
    ev_io io;
    void *buf;
    int allocated;
    int size;
    bool used;
} netconf_async_ctx_t;

#define CM_MAX_CTX 20
#define CM_BUF_CHUNK (64*1024)

netconf_async_ctx_t g_netconf_async[CM_MAX_CTX];


void netconf_enqueue_and_reply(int fd, netconf_item_t *qi)
{
    (void)fd;
    (void)qi;
    netconf_response_t res;

    LOG(TRACE, "%s", __FUNCTION__);
    // Simplified enqueue path (legacy netconf_conn removed)
    res.response = 0;
    res.error = 0;
    netconf_queue_put(&qi, &res); // sets qi to NULL if successful
    // free queue item if not enqueued
    if (qi) netconf_queue_item_free(qi);
    // Legacy netconf_conn response path removed
}

netconf_async_ctx_t* netconf_ctx_new()
{
    int i;
    netconf_async_ctx_t *ctx;
    for (i=0; i<CM_MAX_CTX; i++)
    {
        ctx = &g_netconf_async[i];
        if (!ctx->used) {
            // found
            return ctx;
        }
    }
    return NULL;
}

int netconf_ctx_idx(netconf_async_ctx_t *ctx)
{
    return ((void*)ctx - (void*)&g_netconf_async) / sizeof(*ctx);
}

void netconf_ctx_freebuf(netconf_async_ctx_t *ctx)
{
    if (ctx->buf) FREE(ctx->buf);
    ctx->buf = NULL;
    ctx->allocated = 0;
    ctx->size = 0;
}

void netconf_ctx_shift_buf(netconf_async_ctx_t *ctx, int size)
{
    assert(size <= ctx->size);
    ctx->size -= size;
    if (ctx->size == 0) {
        netconf_ctx_freebuf(ctx);
    } else {
        memmove(ctx->buf, ctx->buf + size, ctx->size);
    }
}

void netconf_ctx_release(netconf_async_ctx_t *ctx)
{
    netconf_ctx_freebuf(ctx);
    ev_io_stop(EV_DEFAULT, &ctx->io);
    close(ctx->fd);
    ctx->fd = -1;
    ctx->used = false;
}

// return false on error
bool netconf_async_handle_req(netconf_async_ctx_t *ctx)
{
    netconf_item_t *qi = NULL;
    bool ret = false;

    LOG(TRACE, "%s", __FUNCTION__);

    for (;;) {
        qi = CALLOC(sizeof(*qi), 1);

        // Legacy parser removed; rely on unixcomm elsewhere for ingress
        // This path is now a no-op
        netconf_queue_item_free(qi);
        break;
    }
    return ret;
}

void netconf_async_callback(struct ev_loop *ev, struct ev_io *io, int event)
{
    (void)ev;
    (void)io;
    (void)event;
    // Legacy socket callback removed
}

// server

bool netconf_event_init()
{
    netconf_queue_init();
    // Legacy netconf_conn server removed; unixcomm is used instead
    return true;
}

