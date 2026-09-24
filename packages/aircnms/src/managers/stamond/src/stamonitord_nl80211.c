#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <net/if.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>
#include <linux/nl80211.h>
#include <ev.h>
#include "log.h"
#include "stamonitord_client_events.h"
#include "stamonitord_history.h"
#include "ds_tree.h"

/* Netlink attribute macros (no libnl dependency) */
#ifndef NLA_HDRLEN
#define NLA_HDRLEN ((int)NLA_ALIGN(sizeof(struct nlattr)))
#endif
#define NLA_DATA(na)        ((void *)((char *)(na) + NLA_HDRLEN))
#define NLA_PAYLOAD(len)    ((int)(len) - NLA_HDRLEN)
#define NLA_OK(na, len) \
    ((len) >= (int)sizeof(struct nlattr) && \
     (na)->nla_len >= sizeof(struct nlattr) && \
     (na)->nla_len <= (len))
#define NLA_NEXT(na, len) \
    ((len) -= NLA_ALIGN((na)->nla_len), \
     (struct nlattr *)((char *)(na) + NLA_ALIGN((na)->nla_len)))

/* MAC address formatting helper */
#define MAC_FMT "%02x:%02x:%02x:%02x:%02x:%02x"
#define MAC_ARG(m) (m)[0],(m)[1],(m)[2],(m)[3],(m)[4],(m)[5]

/* Multicast group tracking */
typedef struct {
    char name[32];
    uint32_t id;
} mcast_grp_t;

static int g_nl_fd = -1;
static struct ev_loop *g_loop = NULL;
static ev_io g_nl_watcher;
static int g_nl80211_family_id = -1;
static mcast_grp_t g_mcast_groups[8];
static int g_mcast_count = 0;

/* Station table */
struct sta_info {
    ds_tree_node_t node;
    uint8_t mac[6];
    char ifname[IFNAMSIZ];
    int ifindex;
    int link_id;
    time_t connect_time;
};

static int mac_cmp(const void *a, const void *b) {
    return memcmp(a, b, 6);
}

static ds_tree_t g_sta_table = DS_TREE_INIT(mac_cmp, struct sta_info, node);

/* Interface name filtering */
static int is_sta_event_ifname(const char *ifname) {
    if (!ifname || !*ifname) return 0;
    if (strncmp(ifname, "wlan", 4) == 0) return 1;
    if (strncmp(ifname, "ap", 2) == 0) return 1;
    if (strstr(ifname, "-ap")) return 1;
    return 0;
}

/* Helper: infer link_id from interface name */
static int infer_link_id_from_ifname(const char *ifname) {
    const char *p = strrchr(ifname, 'p');
    if (!p) return -1;
    p++;
    if (*p >= '0' && *p <= '9') return *p - '0';
    return -1;
}

/* Station table management */
static void stamonitord_sta_handle_add(const char *ifname, int ifindex, int link_id, const uint8_t *mac, int mac_len) {
    if (mac_len != 6) return;

    struct sta_info *sta = ds_tree_find(&g_sta_table, mac);
    if (sta) {
        LOG(DEBUG, "nl80211: STA " MAC_FMT " already connected on %s", MAC_ARG(mac), sta->ifname);
        return;
    }

    sta = calloc(1, sizeof(*sta));
    if (!sta) {
        LOG(ERR, "nl80211: failed to alloc sta_info");
        return;
    }

    memcpy(sta->mac, mac, 6);
    strncpy(sta->ifname, ifname, IFNAMSIZ - 1);
    sta->ifindex = ifindex;
    sta->link_id = link_id;
    sta->connect_time = time(NULL);

    ds_tree_insert(&g_sta_table, sta, sta->mac);
    LOG(INFO, "nl80211: STA " MAC_FMT " connected on %s (link=%d)", MAC_ARG(mac), ifname, link_id);
    stamonitord_handle_client_connect(mac, ifname);
}

static void stamonitord_sta_handle_del(const char *ifname, int ifindex, int link_id, const uint8_t *mac, int mac_len) {
    if (mac_len != 6) return;

    struct sta_info *sta = ds_tree_find(&g_sta_table, mac);
    if (!sta) {
        LOG(DEBUG, "nl80211: STA " MAC_FMT " not found for disconnect", MAC_ARG(mac));
        return;
    }

    ds_tree_remove(&g_sta_table, sta);
    LOG(INFO, "nl80211: STA " MAC_FMT " disconnected from %s (link=%d)", MAC_ARG(mac), ifname, link_id);
    stamonitord_handle_client_disconnect(mac, ifname);
    free(sta);
}

/* Send CTRL_CMD_GETFAMILY request to resolve nl80211 family ID */
static int nl_send_ctrl_getfamily(int fd) {
    struct {
        struct nlmsghdr nlh;
        struct genlmsghdr gnlh;
        char buf[256];
    } req;
    
    memset(&req, 0, sizeof(req));
    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct genlmsghdr));
    req.nlh.nlmsg_type = GENL_ID_CTRL;
    req.nlh.nlmsg_flags = NLM_F_REQUEST;
    req.nlh.nlmsg_seq = 1;
    req.gnlh.cmd = CTRL_CMD_GETFAMILY;
    req.gnlh.version = 1;

    /* Add family name attribute */
    struct nlattr *na = (struct nlattr *)((char *)&req + req.nlh.nlmsg_len);
    na->nla_type = CTRL_ATTR_FAMILY_NAME;
    const char *fam = "nl80211";
    int slen = strlen(fam) + 1;
    na->nla_len = NLA_HDRLEN + slen;
    memcpy(NLA_DATA(na), fam, slen);
    req.nlh.nlmsg_len += NLA_ALIGN(na->nla_len);

    struct sockaddr_nl sa = { .nl_family = AF_NETLINK };
    return sendto(fd, &req, req.nlh.nlmsg_len, 0,
                  (struct sockaddr *)&sa, sizeof(sa));
}

/* Parse CTRL reply to extract family ID and multicast group IDs */
static int nl_parse_ctrl_reply(struct nlmsghdr *hdr) {
    struct genlmsghdr *gnlh = NLMSG_DATA(hdr);
    int rem = hdr->nlmsg_len - NLMSG_HDRLEN - sizeof(*gnlh);
    struct nlattr *na = (struct nlattr *)((char *)gnlh + sizeof(*gnlh));

    for (; NLA_OK(na, rem); na = NLA_NEXT(na, rem)) {
        if (na->nla_type == CTRL_ATTR_FAMILY_ID &&
            NLA_PAYLOAD(na->nla_len) >= 2) {
            g_nl80211_family_id = *(uint16_t *)NLA_DATA(na);
            LOG(INFO, "nl80211: family_id resolved to %d", g_nl80211_family_id);
        } else if (na->nla_type == CTRL_ATTR_MCAST_GROUPS) {
            int grem = NLA_PAYLOAD(na->nla_len);
            struct nlattr *grp = NLA_DATA(na);
            for (; NLA_OK(grp, grem); grp = NLA_NEXT(grp, grem)) {
                int srem = NLA_PAYLOAD(grp->nla_len);
                struct nlattr *sub = NLA_DATA(grp);
                uint32_t gid = 0;
                const char *gname = NULL;
                
                for (; NLA_OK(sub, srem); sub = NLA_NEXT(sub, srem)) {
                    if (sub->nla_type == CTRL_ATTR_MCAST_GRP_ID)
                        gid = *(uint32_t *)NLA_DATA(sub);
                    else if (sub->nla_type == CTRL_ATTR_MCAST_GRP_NAME)
                        gname = NLA_DATA(sub);
                }
                
                if (gname && g_mcast_count < (int)(sizeof(g_mcast_groups)/sizeof(g_mcast_groups[0]))) {
                    strncpy(g_mcast_groups[g_mcast_count].name, gname, 31);
                    g_mcast_groups[g_mcast_count].id = gid;
                    g_mcast_count++;
                }
            }
        }
    }
    return g_nl80211_family_id;
}

/* Lookup multicast group ID by name */
static uint32_t mcast_id(const char *name) {
    for (int i = 0; i < g_mcast_count; i++)
        if (!strcmp(g_mcast_groups[i].name, name))
            return g_mcast_groups[i].id;
    return 0;
}

/* Handle nl80211 station events */
static void sta_nl_handle_msg(struct nlmsghdr *hdr)
{
    struct genlmsghdr *gnlh = (struct genlmsghdr *)NLMSG_DATA(hdr);
    int attr_len = (int)hdr->nlmsg_len - NLMSG_HDRLEN - (int)sizeof(*gnlh);
    struct nlattr *na = (struct nlattr *)((char *)gnlh + sizeof(*gnlh));
    uint8_t *mac = NULL;
    uint8_t *frame = NULL;
    int frame_len = 0;
    int mac_len = 0;
    int ifindex = 0;
    int link_id = -1;
    char ifname[IFNAMSIZ] = {0};

    if (hdr->nlmsg_type != g_nl80211_family_id || !gnlh)
        return;
    if (gnlh->cmd != NL80211_CMD_NEW_STATION &&
        gnlh->cmd != NL80211_CMD_DEL_STATION &&
        gnlh->cmd != NL80211_CMD_FRAME_TX_STATUS)
        return;

    for (; NLA_OK(na, attr_len); na = NLA_NEXT(na, attr_len)) {
        if (na->nla_type == NL80211_ATTR_IFINDEX && NLA_PAYLOAD(na->nla_len) >= 4) {
            ifindex = *(int *)NLA_DATA(na);
        } else if (na->nla_type == NL80211_ATTR_MAC) {
            mac = (uint8_t *)NLA_DATA(na);
            mac_len = NLA_PAYLOAD(na->nla_len);
        } else if (na->nla_type == NL80211_ATTR_FRAME) {
            frame = (uint8_t *)NLA_DATA(na);
            frame_len = NLA_PAYLOAD(na->nla_len);
        } else if (na->nla_type == NL80211_ATTR_MLO_LINK_ID && NLA_PAYLOAD(na->nla_len) >= 1) {
            link_id = (int)(*(uint8_t *)NLA_DATA(na));
        }
    }
    if (ifindex <= 0)
        return;
    if (!if_indextoname((unsigned int)ifindex, ifname))
        return;
    if (!is_sta_event_ifname(ifname))
        return;
    if (link_id < 0)
        link_id = infer_link_id_from_ifname(ifname);

    if (gnlh->cmd == NL80211_CMD_NEW_STATION) {
        if (!mac || mac_len < 6)
            return;
        LOG(INFO, "STA CONNECT event if=%s source=NEW_STATION", ifname);
        stamonitord_sta_handle_add(ifname, ifindex, link_id, mac, 6);
        stamonitord_history_notify_station_connect(mac, ifname);
    } else if (gnlh->cmd == NL80211_CMD_DEL_STATION) {
        if (!mac || mac_len < 6)
            return;
        LOG(INFO, "STA DISCONNECT event if=%s source=DEL_STATION", ifname);
        stamonitord_sta_handle_del(ifname, ifindex, link_id, mac, 6);
        stamonitord_history_notify_station_disconnect(mac, ifname);
    } else if (frame && frame_len >= 30) {
        const uint8_t type = frame[0] & 0xFC;
        const uint16_t status = (uint16_t)frame[26] | ((uint16_t)frame[27] << 8);
        const uint8_t *ra = frame + 4;
        const uint8_t ASSOC_RESP = 0x10;
        const uint8_t REASSOC_RESP = 0x30;
        if ((type == ASSOC_RESP || type == REASSOC_RESP) && status == 0) {
            LOG(INFO, "STA CONNECT event if=%s source=FRAME_TX_STATUS", ifname);
            stamonitord_sta_handle_add(ifname, ifindex, link_id, ra, 6);
            stamonitord_history_notify_station_connect(ra, ifname);
        }
    }
}

/* libev I/O callback for netlink socket */
static void nl_io_cb(EV_P_ ev_io *w, int revents) {
    (void)revents;
    static char buf[16384];
    
    while (1) {
        ssize_t n = recv(w->fd, buf, sizeof(buf), MSG_DONTWAIT);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return;
            if (errno == EINTR) continue;
            if (errno == ENOBUFS) {
                LOG(WARN, "nl80211: ENOBUFS (dropped packets)");
                return;
            }
            LOG(ERR, "nl80211: recv failed: %s", strerror(errno));
            ev_break(EV_A_ EVBREAK_ALL);
            return;
        }
        if (n == 0) return;

        struct nlmsghdr *h = (struct nlmsghdr *)buf;
        for (; NLMSG_OK(h, n); h = NLMSG_NEXT(h, n)) {
            if (h->nlmsg_type == NLMSG_ERROR) {
                struct nlmsgerr *e = NLMSG_DATA(h);
                if (e->error)
                    LOG(WARN, "nl80211: netlink error %d", e->error);
                continue;
            }
            if (h->nlmsg_type == NLMSG_DONE) break;
            if (h->nlmsg_type == GENL_ID_CTRL) {
                nl_parse_ctrl_reply(h);
                continue;
            }
            sta_nl_handle_msg(h);
        }
    }
}

/* Bootstrap nl80211 listener: open socket, resolve family, subscribe to groups */
static int nl_open_and_bootstrap(void) {
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_GENERIC);
    if (fd < 0) {
        LOG(ERR, "nl80211: socket() failed: %s", strerror(errno));
        return -1;
    }

    /* Increase receive buffer */
    int rcvbuf = 1 << 20;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

    /* Bind to netlink */
    struct sockaddr_nl sa = { .nl_family = AF_NETLINK, .nl_pid = 0 };
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        LOG(ERR, "nl80211: bind() failed: %s", strerror(errno));
        close(fd);
        return -1;
    }

    /* Resolve nl80211 family ID (synchronously) */
    LOG(INFO, "nl80211: Resolving family ID...");
    if (nl_send_ctrl_getfamily(fd) < 0) {
        LOG(ERR, "nl80211: getfamily send failed: %s", strerror(errno));
        close(fd);
        return -1;
    }

    /* Read CTRL replies synchronously */
    char buf[8192];
    for (int tries = 0; tries < 4 && g_nl80211_family_id < 0; tries++) {
        ssize_t n = recv(fd, buf, sizeof(buf), 0);
        if (n <= 0) break;
        struct nlmsghdr *h = (struct nlmsghdr *)buf;
        for (; NLMSG_OK(h, n); h = NLMSG_NEXT(h, n)) {
            if (h->nlmsg_type == GENL_ID_CTRL)
                nl_parse_ctrl_reply(h);
        }
    }
    
    if (g_nl80211_family_id < 0) {
        LOG(ERR, "nl80211: family ID not resolved");
        close(fd);
        return -1;
    }
    LOG(INFO, "nl80211: found %d multicast groups", g_mcast_count);

    /* Subscribe to multicast groups */
    const char *groups[] = { "mlme", "config", NULL };
    for (int i = 0; groups[i]; i++) {
        uint32_t gid = mcast_id(groups[i]);
        if (!gid) {
            LOG(WARN, "nl80211: group '%s' not found", groups[i]);
            continue;
        }
        if (setsockopt(fd, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP,
                       &gid, sizeof(gid)) < 0) {
            LOG(WARN, "nl80211: setsockopt NETLINK_ADD_MEMBERSHIP %s: %s",
                groups[i], strerror(errno));
        } else {
            LOG(INFO, "nl80211: subscribed to '%s' (id=%u)", groups[i], gid);
        }
    }

    return fd;
}

int stamonitord_nl80211_start(struct ev_loop *loop) {
    if (!loop) {
        LOG(ERR, "nl80211: loop is NULL");
        return -1;
    }

    g_nl_fd = nl_open_and_bootstrap();
    if (g_nl_fd < 0) {
        LOG(ERR, "nl80211: failed to open and bootstrap");
        return -1;
    }

    g_loop = loop;

    /* Set up libev I/O watcher */
    ev_io_init(&g_nl_watcher, nl_io_cb, g_nl_fd, EV_READ);
    ev_io_start(loop, &g_nl_watcher);

    LOG(INFO, "nl80211: listener started on fd=%d", g_nl_fd);
    return 0;
}

void stamonitord_nl80211_stop(void) {
    if (g_loop && g_nl_fd >= 0) {
        ev_io_stop(g_loop, &g_nl_watcher);
    }
    if (g_nl_fd >= 0) {
        close(g_nl_fd);
        g_nl_fd = -1;
    }
    g_loop = NULL;
    g_nl80211_family_id = -1;
    g_mcast_count = 0;

    /* Clean up station table */
    struct sta_info *sta, *tmp;
    ds_tree_foreach_safe(&g_sta_table, sta, tmp) {
        ds_tree_remove(&g_sta_table, sta);
        free(sta);
    }

    LOG(INFO, "nl80211: listener stopped");
}
