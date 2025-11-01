#define _GNU_SOURCE
#include <string.h>

#include <linux/nl80211.h>
#include <linux/if_ether.h>
#include <netlink/msg.h>
#include <netlink/attr.h>
#include <netlink/socket.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <net/if.h>

#include <netlink/netlink.h>
#include <netlink/genl/family.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include "nl80211.h"
#include "nl80211_scan.h"
#include "nl80211_stats.h"
#include "ext_event.h"

ds_dlist_t g_ext_event_list;

struct nl_global_info nl_sm_global;
static ev_io nl_sm_loop;

struct nl_global_info* get_nl_sm_global(void)
{
    return &nl_sm_global;
}

static int nl_event_parse(struct nl_msg *msg, void *arg)
{

    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    char ifname[IFNAMSIZ] = {'\0'};
    char phyname[IFNAMSIZ] = {'\0'};
    int ifidx = -1, phy = -1;
    unsigned char *mac = NULL;

    memset(tb, 0, sizeof(tb));

    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);

    if (tb[NL80211_ATTR_IFINDEX]) {
        ifidx = nla_get_u32(tb[NL80211_ATTR_IFINDEX]);
        if_indextoname(ifidx, ifname);
    } else if (tb[NL80211_ATTR_IFNAME]) {
        STRSCPY(ifname, nla_get_string(tb[NL80211_ATTR_IFNAME]));
    }

    if (tb[NL80211_ATTR_WIPHY]) {
        phy = nla_get_u32(tb[NL80211_ATTR_WIPHY]);
        if (tb[NL80211_ATTR_WIPHY_NAME])
            STRSCPY(phyname, nla_get_string(tb[NL80211_ATTR_WIPHY_NAME]));
        else
            snprintf(phyname, sizeof(phyname), "phy%d", phy);
    }

    switch (gnlh->cmd) {
        case NL80211_CMD_TRIGGER_SCAN:
            LOGT("%s: scan started\n", ifname);
            break;
        case NL80211_CMD_SCAN_ABORTED:
            LOGT("%s: scan aborted\n", ifname);
            //nl80211_scan_finish(ifname, false);
            break;
        case NL80211_CMD_NEW_SCAN_RESULTS:
            LOGT("%s: scan completed\n", ifname);
            //nl80211_scan_finish(ifname, true);
            break;
	case NL80211_CMD_NEW_STATION:
            mac = nla_data(tb[NL80211_ATTR_MAC]);
            LOGT("%s: station added, MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                       ifname, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	    nl_ext_event_enqueue(NL80211_CMD_NEW_STATION, mac, ifname);
            LOGT("%s: station added\n", ifname);
	    break;
        case NL80211_CMD_DEL_STATION:
            mac = nla_data(tb[NL80211_ATTR_MAC]);
            LOGT("%s: station deleted, MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                       ifname, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	    nl_ext_event_enqueue(NL80211_CMD_DEL_STATION, mac, ifname);
            LOGT("%s: station deleted\n", ifname);
	    break;
        default:
            break;
    }
    return NL_OK;
}

static int finish_handler(struct nl_msg *msg, void *arg)
{
    return NL_SKIP;
}

static int err_handler(struct sockaddr_nl *nla, struct nlmsgerr *err, void *arg)
{
    return NL_SKIP;
}

static int no_seq_check(struct nl_msg *msg, void *arg)
{
    return NL_OK;
}

static void sm_nl_ev_handler(struct ev_loop *ev, struct ev_io *io, int event)
{

    int res = -EINVAL;

    nl_cb_err(nl_sm_global.nl_cb, NL_CB_CUSTOM, err_handler, NULL);
    nl_cb_set(nl_sm_global.nl_cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, NULL);
    nl_cb_set(nl_sm_global.nl_cb, NL_CB_SEQ_CHECK, NL_CB_CUSTOM, no_seq_check, NULL);
    nl_cb_set(nl_sm_global.nl_cb, NL_CB_VALID, NL_CB_CUSTOM, nl_event_parse, NULL);

    res = nl_recvmsgs(nl_sm_global.nl_evt_handle, nl_sm_global.nl_cb);
    if (res < 0)
        LOGE("Failed to receive event message");
}

int nl_sm_init(struct ev_loop *sm_evloop)
{
    if (netlink_init(&nl_sm_global) < 0) {
        LOGE("nl80211: failed to connect\n");
        return -1;
    }

    if (!sm_evloop)
        return -1;

    ds_dlist_init(&g_ext_event_list, netstats_ext_event_t, node);
    add_mcast_subscription(&nl_sm_global, "mlme");
    add_mcast_subscription(&nl_sm_global, "scan");

    ev_io_init(&nl_sm_loop, sm_nl_ev_handler, nl_socket_get_fd(nl_sm_global.nl_evt_handle), EV_READ);
    ev_io_start(sm_evloop, &nl_sm_loop);

    return 0;
}

void nl_sm_deinit()
{
    netlink_deinit(&nl_sm_global);
}
