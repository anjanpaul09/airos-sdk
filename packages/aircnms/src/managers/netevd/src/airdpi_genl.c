/*
 * airdpi_genl.c - AIRDPI Generic Netlink event listener (libev-based)
 *
 * Subscribes to the AIRDPI Generic Netlink multicast group and dispatches
 * STA_ADD / STA_DEL events to netev_handle_client_connect() and
 * netev_handle_client_disconnect() respectively.
 *
 * Integration:
 *   Call airdpi_genl_init(loop) after ev_loop creation.
 *   Call airdpi_genl_cleanup(loop) before exiting.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>
#include <ev.h>

#include "log.h"
#include "netev.h"
#include "netev_client_events.h"

/*
 * musl libc's sanitised kernel headers do not always expose NLA_OK /
 * NLA_NEXT from <linux/netlink.h>.  Define them here as fallbacks so
 * the cross-compiler build succeeds without -Wimplicit-function-declaration.
 */
#ifndef NLA_OK
#define NLA_OK(nla, rem) \
    ((rem) >= (int)sizeof(struct nlattr) && \
     (nla)->nla_len >= sizeof(struct nlattr) && \
     (int)(nla)->nla_len <= (rem))
#endif

#ifndef NLA_NEXT
#define NLA_NEXT(nla, attrlen) \
    ((attrlen) -= NLA_ALIGN((nla)->nla_len), \
     (struct nlattr *)(((char *)(nla)) + NLA_ALIGN((nla)->nla_len)))
#endif

/* ------------------------------------------------------------------ */
/* Definitions – must match the kernel module (air_coplane.h)          */
/* ------------------------------------------------------------------ */
#define AIRDPI_GENL_NAME    "AIRDPI"
#define AIRDPI_GENL_VERSION 1

enum {
    AIRDPI_ATTR_UNSPEC,
    AIRDPI_ATTR_MAC,
    AIRDPI_ATTR_IFNAME,
    __AIRDPI_ATTR_MAX,
};
#define AIRDPI_ATTR_MAX (__AIRDPI_ATTR_MAX - 1)

enum {
    AIRDPI_CMD_UNSPEC,
    AIRDPI_CMD_STA_ADD,
    AIRDPI_CMD_STA_DEL,
    __AIRDPI_CMD_MAX,
};

/* ------------------------------------------------------------------ */
/* Internal context                                                    */
/* ------------------------------------------------------------------ */
struct airdpi_genl_ctx {
    int       nl_sock;
    int       family_id;
    ev_io     watcher;
};

static struct airdpi_genl_ctx *g_airdpi_ctx = NULL;

/* ------------------------------------------------------------------ */
/* Resolve family ID and first multicast group ID in one round-trip.   */
/*                                                                     */
/* NLM_F_ACK is intentionally NOT set: it would cause the kernel to   */
/* queue a second NLMSG_ERROR(errno=0) frame after the real reply,    */
/* which would corrupt a subsequent recv() call.                       */
/* ------------------------------------------------------------------ */
static int airdpi_query_family(int nl_sock, int *out_family_id,
                               int *out_mcgroup_id)
{
    char buf[1024];
    struct nlmsghdr   *nlh;
    struct genlmsghdr *gnlh;
    struct nlattr     *nla, *grp_nla, *one_nla;
    int  len, remaining, grp_remaining, one_remaining;
    int  family_id  = -1;
    int  mcgroup_id = -1;

    memset(buf, 0, sizeof(buf));

    nlh  = (struct nlmsghdr *)buf;
    gnlh = (struct genlmsghdr *)(buf + NLMSG_HDRLEN);

    /* NLM_F_REQUEST only – no NLM_F_ACK to avoid stale ACK frames */
    nlh->nlmsg_type  = GENL_ID_CTRL;
    nlh->nlmsg_flags = NLM_F_REQUEST;
    nlh->nlmsg_seq   = 1;

    gnlh->cmd     = CTRL_CMD_GETFAMILY;
    gnlh->version = 1;

    nla = (struct nlattr *)(buf + NLMSG_HDRLEN + GENL_HDRLEN);
    nla->nla_type = CTRL_ATTR_FAMILY_NAME;
    nla->nla_len  = (uint16_t)(NLA_HDRLEN + strlen(AIRDPI_GENL_NAME) + 1);
    strncpy((char *)nla + NLA_HDRLEN, AIRDPI_GENL_NAME,
            strlen(AIRDPI_GENL_NAME) + 1);

    nlh->nlmsg_len = (uint32_t)(NLMSG_HDRLEN + GENL_HDRLEN +
                                 NLA_ALIGN(nla->nla_len));

    if (send(nl_sock, buf, nlh->nlmsg_len, 0) < 0) {
        LOG(ERR, "airdpi_genl: send(CTRL_CMD_GETFAMILY): %s", strerror(errno));
        return -1;
    }

    len = recv(nl_sock, buf, sizeof(buf), 0);
    if (len < 0) {
        LOG(ERR, "airdpi_genl: recv(CTRL_CMD_GETFAMILY): %s", strerror(errno));
        return -1;
    }

    nlh = (struct nlmsghdr *)buf;
    if (!NLMSG_OK(nlh, (unsigned int)len) ||
        nlh->nlmsg_type == NLMSG_ERROR) {
        LOG(ERR, "airdpi_genl: family '%s' not found – is the airdpi module loaded?",
            AIRDPI_GENL_NAME);
        return -1;
    }

    /* Walk top-level attributes once to collect both IDs */
    nla       = (struct nlattr *)(buf + NLMSG_HDRLEN + GENL_HDRLEN);
    remaining = len - NLMSG_HDRLEN - GENL_HDRLEN;

    while (NLA_OK(nla, remaining)) {
        if (nla->nla_type == CTRL_ATTR_FAMILY_ID) {
            family_id = *(uint16_t *)((char *)nla + NLA_HDRLEN);

        } else if (nla->nla_type == CTRL_ATTR_MCAST_GROUPS) {
            grp_nla       = (struct nlattr *)((char *)nla + NLA_HDRLEN);
            grp_remaining = nla->nla_len - NLA_HDRLEN;

            while (NLA_OK(grp_nla, grp_remaining)) {
                one_nla       = (struct nlattr *)((char *)grp_nla + NLA_HDRLEN);
                one_remaining = grp_nla->nla_len - NLA_HDRLEN;

                while (NLA_OK(one_nla, one_remaining)) {
                    if (one_nla->nla_type == CTRL_ATTR_MCAST_GRP_ID) {
                        /* Take the first registered group */
                        mcgroup_id = *(uint32_t *)((char *)one_nla + NLA_HDRLEN);
                    }
                    one_nla = NLA_NEXT(one_nla, one_remaining);
                }
                grp_nla = NLA_NEXT(grp_nla, grp_remaining);
            }
        }
        nla = NLA_NEXT(nla, remaining);
    }

    if (family_id < 0) {
        LOG(ERR, "airdpi_genl: CTRL_ATTR_FAMILY_ID not found in response");
        return -1;
    }
    if (mcgroup_id < 0) {
        LOG(ERR, "airdpi_genl: CTRL_ATTR_MCAST_GROUPS not found – "
            "does the airdpi module register a multicast group?");
        return -1;
    }

    *out_family_id  = family_id;
    *out_mcgroup_id = mcgroup_id;
    return 0;
}


/* ------------------------------------------------------------------ */
/* Step 3: Parse an incoming AIRDPI Generic Netlink message            */
/* ------------------------------------------------------------------ */
static void airdpi_handle_msg(int family_id, char *buf, int len)
{
    struct nlmsghdr  *nlh = (struct nlmsghdr *)buf;

    while (NLMSG_OK(nlh, (unsigned int)len)) {
        struct genlmsghdr *gnlh;
        struct nlattr     *nla;
        int                remaining;
        unsigned char     *mac    = NULL;
        const char        *ifname = NULL;

        if (nlh->nlmsg_type == NLMSG_ERROR ||
            nlh->nlmsg_type == NLMSG_DONE) {
            break;
        }

        /* Filter by our dynamic family ID */
        if ((int)nlh->nlmsg_type != family_id) {
            nlh = NLMSG_NEXT(nlh, len);
            continue;
        }

        gnlh = (struct genlmsghdr *)NLMSG_DATA(nlh);

        nla       = (struct nlattr *)((char *)gnlh + GENL_HDRLEN);
        remaining = (int)(nlh->nlmsg_len - NLMSG_HDRLEN - GENL_HDRLEN);

        while (NLA_OK(nla, remaining)) {
            switch (nla->nla_type) {
            case AIRDPI_ATTR_MAC:
                mac = (unsigned char *)nla + NLA_HDRLEN;
                break;
            case AIRDPI_ATTR_IFNAME:
                ifname = (const char *)nla + NLA_HDRLEN;
                break;
            }
            nla = NLA_NEXT(nla, remaining);
        }

        if (!mac) {
            LOG(WARN, "airdpi_genl: received cmd %d without MAC", gnlh->cmd);
            nlh = NLMSG_NEXT(nlh, len);
            continue;
        }

        switch (gnlh->cmd) {
        case AIRDPI_CMD_STA_ADD:
            LOG(INFO, "airdpi_genl: STA_ADD MAC=%02x:%02x:%02x:%02x:%02x:%02x ifname=%s",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
                ifname ? ifname : "unknown");
            //netev_handle_client_connect(mac, ifname);
            add_event_to_queue(mac, ifname, 1);
            break;

        case AIRDPI_CMD_STA_DEL:
            add_event_to_queue(mac, ifname, 0);
#if 0 
            char mac_str[18];
            snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
                         mac[0], mac[1], mac[2],
                         mac[3], mac[4], mac[5]);
            bool exists_on_other = sta_exists_on_other_iface(mac_str, ifname);
                
            if (exists_on_other) {
                    LOG(INFO, "airdpi_genl: Client %s still connected on another interface, ignoring disconnect from %s (roaming)",
                        mac_str, ifname);
            } else {
                LOG(INFO, "airdpi_genl: STA_DEL MAC=%02x:%02x:%02x:%02x:%02x:%02x ifname=%s",
                    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
                    ifname ? ifname : "unknown");
                // Client not found on other interfaces - this is a real disconnect
                netev_handle_client_disconnect(mac, ifname);
            }
            //netev_handle_client_disconnect(mac, ifname);
#endif
            break;

        default:
            LOG(DEBUG, "airdpi_genl: unknown cmd %d – ignored", gnlh->cmd);
            break;
        }

        nlh = NLMSG_NEXT(nlh, len);
    }
}

/* ------------------------------------------------------------------ */
/* Step 4: libev I/O callback – called when the netlink socket is      */
/*         ready for reading.                                           */
/* ------------------------------------------------------------------ */
static void airdpi_genl_ev_cb(struct ev_loop *loop, ev_io *w, int revents)
{
    struct airdpi_genl_ctx *ctx = (struct airdpi_genl_ctx *)w->data;
    char buf[4096];
    int  len;

    (void)loop;

    if (!(revents & EV_READ))
        return;

    len = recv(ctx->nl_sock, buf, sizeof(buf), MSG_DONTWAIT);
    if (len < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return;  /* no data yet – spurious wakeup */
        LOG(ERR, "airdpi_genl: recv error: %s", strerror(errno));
        return;
    }

    if (len == 0)
        return;

    airdpi_handle_msg(ctx->family_id, buf, len);
}

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

/**
 * airdpi_genl_init() - Set up the AIRDPI netlink listener.
 *
 * Creates a raw Generic Netlink socket, resolves the AIRDPI family ID,
 * subscribes to its multicast group, and registers an ev_io watcher so
 * that events are handled inside the caller's ev_loop without blocking.
 *
 * @loop: The libev event loop to attach the watcher to.
 * @return 0 on success, -1 on error.
 */
int airdpi_genl_init(struct ev_loop *loop)
{
    struct airdpi_genl_ctx *ctx;
    struct sockaddr_nl      sa;
    int                     family_id, mcgroup_id, fd, flags;

    if (g_airdpi_ctx) {
        LOG(WARN, "airdpi_genl: already initialised");
        return 0;
    }

    ctx = calloc(1, sizeof(*ctx));
    if (!ctx) {
        LOG(ERR, "airdpi_genl: calloc failed");
        return -1;
    }
    ctx->nl_sock = -1;

    /* Create Generic Netlink socket */
    ctx->nl_sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
    if (ctx->nl_sock < 0) {
        LOG(ERR, "airdpi_genl: socket: %s", strerror(errno));
        goto err_free;
    }

    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    sa.nl_groups = 0;

    if (bind(ctx->nl_sock, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        LOG(ERR, "airdpi_genl: bind: %s", strerror(errno));
        goto err_sock;
    }

    /* Resolve family ID and multicast group ID in one round-trip */
    if (airdpi_query_family(ctx->nl_sock, &family_id, &mcgroup_id) < 0) {
        LOG(ERR, "airdpi_genl: could not query family '%s' – "
            "is the airdpi kernel module loaded?", AIRDPI_GENL_NAME);
        goto err_sock;
    }
    ctx->family_id = family_id;
    LOG(INFO, "airdpi_genl: family '%s' ID=%d mcgroup=%d",
        AIRDPI_GENL_NAME, family_id, mcgroup_id);

    /* Subscribe to the multicast group */
    if (setsockopt(ctx->nl_sock, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP,
                   &mcgroup_id, sizeof(mcgroup_id)) < 0) {
        LOG(ERR, "airdpi_genl: NETLINK_ADD_MEMBERSHIP: %s", strerror(errno));
        goto err_sock;
    }

    /* Set the socket to non-blocking so libev recv() never blocks */
    fd = ctx->nl_sock;
    flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        LOG(ERR, "airdpi_genl: fcntl(O_NONBLOCK): %s", strerror(errno));
        goto err_sock;
    }

    /* Register with libev */
    ev_io_init(&ctx->watcher, airdpi_genl_ev_cb, fd, EV_READ);
    ctx->watcher.data = ctx;
    ev_io_start(loop, &ctx->watcher);

    g_airdpi_ctx = ctx;
    LOG(INFO, "airdpi_genl: listening for AIRDPI station events");
    return 0;

err_sock:
    close(ctx->nl_sock);
err_free:
    free(ctx);
    return -1;
}

/**
 * airdpi_genl_cleanup() - Stop the watcher and release resources.
 *
 * @loop: The same ev_loop that was passed to airdpi_genl_init().
 */
void airdpi_genl_cleanup(struct ev_loop *loop)
{
    if (!g_airdpi_ctx)
        return;

    ev_io_stop(loop, &g_airdpi_ctx->watcher);
    close(g_airdpi_ctx->nl_sock);
    free(g_airdpi_ctx);
    g_airdpi_ctx = NULL;

    LOG(INFO, "airdpi_genl: cleaned up");
}
