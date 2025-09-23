#define _GNU_SOURCE
#include "nl80211.h"
#include "nl80211_stats.h"
#include "target_nl80211.h"
#include <string.h>

#include <ev.h>
#include <linux/nl80211.h>
#include <netlink/msg.h>
#include <netlink/attr.h>
#include <netlink/socket.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <net/if.h>

struct survey_cb_data {
    struct nl_call_param *param;
    uint32_t channel;
    uint32_t *chan_busy;
    uint32_t *chan_active;
    bool found;
};

static int nl80211_survey_recv(struct nl_msg *msg, void *arg)
{
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    struct survey_cb_data *cb = (struct survey_cb_data *)arg;
    struct nlattr *si[NL80211_SURVEY_INFO_MAX + 1];
    struct nlattr *tb[NL80211_ATTR_MAX + 1];

    static struct nla_policy sp[NL80211_SURVEY_INFO_MAX + 1] = {
        [NL80211_SURVEY_INFO_FREQUENCY]     = { .type = NLA_U32 },
        [NL80211_SURVEY_INFO_TIME]          = { .type = NLA_U64 },
        [NL80211_SURVEY_INFO_TIME_BUSY]     = { .type = NLA_U64 },
    };

    memset(tb, 0, sizeof(tb));
    memset(si, 0, sizeof(si));

    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
              genlmsg_attrlen(gnlh, 0), NULL);

    if (!tb[NL80211_ATTR_SURVEY_INFO])
        return NL_OK;

    if (nla_parse_nested(si, NL80211_SURVEY_INFO_MAX,
                         tb[NL80211_ATTR_SURVEY_INFO], sp))
        return NL_SKIP;

    if (!si[NL80211_SURVEY_INFO_FREQUENCY])
        return NL_SKIP;

    uint32_t freq = nla_get_u32(si[NL80211_SURVEY_INFO_FREQUENCY]);
    uint32_t chan = util_freq_to_chan(freq);

    if (chan != cb->channel)
        return NL_OK;

    if (si[NL80211_SURVEY_INFO_TIME])
        *(cb->chan_active) = (uint32_t)nla_get_u64(si[NL80211_SURVEY_INFO_TIME]);

    if (si[NL80211_SURVEY_INFO_TIME_BUSY])
        *(cb->chan_busy) = (uint32_t)nla_get_u64(si[NL80211_SURVEY_INFO_TIME_BUSY]);

    cb->found = true;
    return NL_STOP;
}

bool nl80211_stats_survey_get(radio_entry_t *radio_cfg,
                              uint32_t channel,
                              uint32_t *chan_busy,
                              uint32_t *chan_active)
{
    struct nl_global_info *nl_sm_global = get_nl_sm_global();
    struct nl_msg *msg;
    int if_index;

    if_index = util_sys_ifname_to_idx(radio_cfg->if_name);
    if (if_index < 0) return false;

    struct nl_call_param param = {
        .ifname = radio_cfg->if_name,
        .list = NULL, // not used in this version
    };

    struct survey_cb_data cb = {
        .param = &param,
        .channel = channel,
        .chan_busy = chan_busy,
        .chan_active = chan_active,
        .found = false
    };

    msg = nlmsg_init(nl_sm_global, NL80211_CMD_GET_SURVEY, true);
    if (!msg) return false;

    nla_put_u32(msg, NL80211_ATTR_IFINDEX, if_index);
    nlmsg_send_and_recv(nl_sm_global, msg, nl80211_survey_recv, &cb);

    return cb.found;
}

