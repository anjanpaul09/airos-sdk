#define _GNU_SOURCE
#include "nl80211.h"
#include "nl80211_stats.h"
#include "target_nl80211.h"

#include <linux/nl80211.h>
#include <netlink/msg.h>
#include <netlink/attr.h>
#include <netlink/socket.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <net/if.h>

static int nl80211_txchainmask_recv(struct nl_msg *msg, void *arg)
{
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    unsigned int *mask = (unsigned int *)arg;

    memset(tb, 0, sizeof(tb));
    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
            genlmsg_attrlen(gnlh, 0), NULL);

    if (tb[NL80211_ATTR_WIPHY_ANTENNA_TX])
        *mask = nla_get_u32(tb[NL80211_ATTR_WIPHY_ANTENNA_TX]);

    return NL_OK;
}

int nl80211_get_tx_chainmask(char *phyname, unsigned int *mask)
{
    struct nl_msg *msg;
    int phy_idx = -EINVAL;

    if ((phy_idx = util_sys_phyname_to_idx(phyname)) < 0)
        return -EINVAL;

    msg = nlmsg_init(get_nl_sm_global(), NL80211_CMD_GET_WIPHY, false);
    if (!msg)
        return -EINVAL;

    nla_put_u32(msg, NL80211_ATTR_WIPHY, phy_idx);
    return nlmsg_send_and_recv(get_nl_sm_global(), msg, nl80211_txchainmask_recv, mask);
}
