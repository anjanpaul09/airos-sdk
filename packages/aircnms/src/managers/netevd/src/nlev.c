#include <netev.h>
#include <net/if.h>
//#include <netlink/netlink.h>
//#include <netlink/genl/genl.h>
//#include <netlink/genl/ctrl.h>
#include <netlink/attr.h>
#include <linux/nl80211.h>

int iw_debug = 0;
static int (*registered_handler)(struct nl_msg *, void *);
static void *registered_handler_data;

int nl_get_multicast_id(struct nl_sock *sock, const char *family, const char *group);

#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif
void mac_addr_n2a(char *mac_addr, const unsigned char *arg)
{
        int i, l;

        l = 0;
        for (i = 0; i < ETH_ALEN ; i++) {
                if (i == 0) {
                        sprintf(mac_addr+l, "%02x", arg[i]);
                        l += 2;
                } else {
                        sprintf(mac_addr+l, ":%02x", arg[i]);
                        l += 3;
                }
        }
}

void parse_ch_switch_notify(struct nlattr **attrs, int command)
{
        switch (command) {
        case NL80211_CMD_CH_SWITCH_STARTED_NOTIFY:
                printf("channel switch started");
                break;
        case NL80211_CMD_CH_SWITCH_NOTIFY:
                printf("channel switch");
                break;
        default:
                printf("unknown channel switch command (%i) received\n", command);
                return;
        }

	if (attrs[NL80211_ATTR_CH_SWITCH_COUNT])
                printf(" (count=%d)", nla_get_u32(attrs[NL80211_ATTR_CH_SWITCH_COUNT]));

        if (attrs[NL80211_ATTR_WIPHY_FREQ])
                printf(" freq=%d", nla_get_u32(attrs[NL80211_ATTR_WIPHY_FREQ]));

        if (attrs[NL80211_ATTR_CHANNEL_WIDTH]) {
                printf(" width=");
                switch(nla_get_u32(attrs[NL80211_ATTR_CHANNEL_WIDTH])) {
                case NL80211_CHAN_WIDTH_20_NOHT:
                case NL80211_CHAN_WIDTH_20:
                        printf("\"20 MHz\"");
                        break;
                case NL80211_CHAN_WIDTH_40:
                        printf("\"40 MHz\"");
                        break;
                case NL80211_CHAN_WIDTH_80:
                        printf("\"80 MHz\"");
                        break;
                case NL80211_CHAN_WIDTH_80P80:
                        printf("\"80+80 MHz\"");
                        break;
                case NL80211_CHAN_WIDTH_160:
                        printf("\"160 MHz\"");
                        break;
                       break;
                case NL80211_CHAN_WIDTH_5:
                        printf("\"5 MHz\"");
                        break;
                case NL80211_CHAN_WIDTH_10:
                        printf("\"10 MHz\"");
                        break;
                default:
                        printf("\"unknown\"");
                }
        }

	if (attrs[NL80211_ATTR_WIPHY_CHANNEL_TYPE]) {
                printf(" type=");
                switch(nla_get_u32(attrs[NL80211_ATTR_WIPHY_CHANNEL_TYPE])) {
                case NL80211_CHAN_NO_HT:
                        printf("\"No HT\"");
                        break;
                case NL80211_CHAN_HT20:
                        printf("\"HT20\"");
                        break;
                case NL80211_CHAN_HT40MINUS:
                        printf("\"HT40-\"");
                        break;
                case NL80211_CHAN_HT40PLUS:
                        printf("\"HT40+\"");
                        break;
                }
        }

        if (attrs[NL80211_ATTR_CENTER_FREQ1])
                printf(" freq1=%d", nla_get_u32(attrs[NL80211_ATTR_CENTER_FREQ1]));

        if (attrs[NL80211_ATTR_CENTER_FREQ2])
                printf(" freq2=%d", nla_get_u32(attrs[NL80211_ATTR_CENTER_FREQ2]));

        printf("\n");
}

void parse_sta_opmode_changed(struct nlattr **attrs)
{
        char macbuf[ETH_ALEN*3];

        printf("sta opmode changed");

        if (attrs[NL80211_ATTR_MAC]) {
                mac_addr_n2a(macbuf, nla_data(attrs[NL80211_ATTR_MAC]));
                printf(" %s", macbuf);
        }

        if (attrs[NL80211_ATTR_SMPS_MODE])
                printf(" smps mode %d", nla_get_u8(attrs[NL80211_ATTR_SMPS_MODE]));

        if (attrs[NL80211_ATTR_CHANNEL_WIDTH])
                printf(" chan width %d", nla_get_u8(attrs[NL80211_ATTR_CHANNEL_WIDTH]));

        if (attrs[NL80211_ATTR_NSS])
                printf(" nss %d", nla_get_u8(attrs[NL80211_ATTR_NSS]));

        printf("\n");
}

void parse_assoc_comeback(struct nlattr **attrs, int command)
{
        __u32 timeout = 0;
        char macbuf[6 * 3] = "<unset>";

        if (attrs[NL80211_ATTR_MAC])
                mac_addr_n2a(macbuf, nla_data(attrs[NL80211_ATTR_MAC]));

        if (attrs[NL80211_ATTR_TIMEOUT])
                timeout = nla_get_u32(attrs[NL80211_ATTR_TIMEOUT]);

        printf("assoc comeback bssid %s timeout %d\n",
               macbuf, timeout);
}



int nl_rx_event(struct nl_msg *msg, void *arg)
{
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    char ifname[100];

    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);

    if (tb[NL80211_ATTR_IFINDEX] && tb[NL80211_ATTR_WIPHY]) {
        /* if_indextoname may fails on delete interface/wiphy event */
        if_indextoname(nla_get_u32(tb[NL80211_ATTR_IFINDEX]), ifname);
        if (if_indextoname(nla_get_u32(tb[NL80211_ATTR_IFINDEX]), ifname))
            printf("%s (phy #%d): \n", ifname, nla_get_u32(tb[NL80211_ATTR_WIPHY]));
        else
            printf("phy #%d: \n", nla_get_u32(tb[NL80211_ATTR_WIPHY]));
    } else if (tb[NL80211_ATTR_WDEV] && tb[NL80211_ATTR_WIPHY]) {
        printf("wdev 0x%llx (phy #%d): \n", (unsigned long long)nla_get_u64(tb[NL80211_ATTR_WDEV]),
                                                              nla_get_u32(tb[NL80211_ATTR_WIPHY]));
    } else if (tb[NL80211_ATTR_IFINDEX]) {
        if_indextoname(nla_get_u32(tb[NL80211_ATTR_IFINDEX]), ifname);
        printf("%s: \n", ifname);
    } else if (tb[NL80211_ATTR_WDEV]) {
        printf("wdev 0x%llx: \n", (unsigned long long)nla_get_u64(tb[NL80211_ATTR_WDEV]));
    } else if (tb[NL80211_ATTR_WIPHY]) {
        printf("phy #%d: \n", nla_get_u32(tb[NL80211_ATTR_WIPHY]));
    }

    switch (gnlh->cmd) {
        case NL80211_CMD_NEW_WIPHY: {
            printf("EVENT: NL80211_CMD_NEW_WIPHY\n");
            break;
	}
        case NL80211_CMD_TRIGGER_SCAN: {
                printf("EVENT: NL80211_CMD_TRIGGER_SCAN\n");
                break;
	}
        case NL80211_CMD_NEW_SCAN_RESULTS:
                printf("EVENT: NL80211_CMD_NEW_SCAN_RESULTS\n");
                break;
        case NL80211_CMD_SCAN_ABORTED:
                printf("EVENT: NL80211_CMD_SCAN_ABORTED\n");
                break;
        case NL80211_CMD_START_SCHED_SCAN:
                printf("EVENT: NL80211_CMD_START_SCHED_SCAN\n");
                break;
        case NL80211_CMD_SCHED_SCAN_STOPPED:
                printf("EVENT: NL80211_CMD_SCHED_SCAN_STOPPED\n");
                break;
        case NL80211_CMD_SCHED_SCAN_RESULTS:
                printf("EVENT: NL80211_CMD_SCHED_SCAN_RESULTS\n");
                break;
        case NL80211_CMD_WIPHY_REG_CHANGE:
                printf("EVENT: NL80211_CMD_WIPHY_REG_CHANGE\n");
                break;
        case NL80211_CMD_REG_CHANGE:
                printf("EVENT: NL80211_CMD_REG_CHANGE\n");
                break;
	case NL80211_CMD_NEW_STATION:
                printf("EVENT: NL80211_CMD_NEW_STATION\n");
                break;
        case NL80211_CMD_DEL_STATION:
                printf("EVENT: NL80211_CMD_DEL_STATION\n");
                break;
        case NL80211_CMD_JOIN_IBSS:
                printf("EVENT: NL80211_CMD_JOIN_IBSS\n");
                break;
        case NL80211_CMD_AUTHENTICATE:
                printf("EVENT: NL80211_CMD_AUTHENTICATE\n");
                break;
        case NL80211_CMD_ASSOCIATE:
                printf("EVENT: NL80211_CMD_ASSOCIATE\n");
                break;
        case NL80211_CMD_DEAUTHENTICATE:
                printf("EVENT: NL80211_CMD_DEAUTHENTICATE\n");
                break;
        case NL80211_CMD_DISASSOCIATE:
                printf("EVENT: NL80211_CMD_DISASSOCIATE\n");
                break;
        case NL80211_CMD_UNPROT_DEAUTHENTICATE:
                printf("EVENT: NL80211_CMD_UNPROT_DEAUTHENTICATE\n");
                break;
        case NL80211_CMD_UNPROT_DISASSOCIATE:
                printf("EVENT: NL80211_CMD_UNPROT_DISASSOCIATE\n");
                break;
        case NL80211_CMD_CONNECT:
                printf("EVENT: NL80211_CMD_CONNECT\n");
                break;
        case NL80211_CMD_ROAM:
                printf("EVENT: NL80211_CMD_ROAM\n");
                break;
        case NL80211_CMD_DISCONNECT:
                printf("EVENT: NL80211_CMD_DISCONNECT\n");

	case NL80211_CMD_REMAIN_ON_CHANNEL:
                printf("EVENT: NL80211_CMD_REMAIN_ON_CHANNEL\n");
                break;
        case NL80211_CMD_CANCEL_REMAIN_ON_CHANNEL:
                printf("EVENT: NL80211_CMD_CANCEL_REMAIN_ON_CHANNEL\n");
                break;
        case NL80211_CMD_FRAME_WAIT_CANCEL:
                printf("EVENT: NL80211_CMD_FRAME_WAIT_CANCEL\n");
                break;
	case NL80211_CMD_NEW_INTERFACE:
                printf("EVENT: NL80211_CMD_NEW_INTERFACE\n");
                break;
        case NL80211_CMD_SET_INTERFACE:
                printf("EVENT: NL80211_CMD_SET_INTERFACE\n");
                break;
        case NL80211_CMD_DEL_INTERFACE:
                printf("EVENT: NL80211_CMD_DEL_INTERFACE\n");
                break;
        case NL80211_CMD_STOP_AP:
                printf("EVENT: NL80211_CMD_STOP_AP\n");
                break;
        case NL80211_CMD_STA_OPMODE_CHANGED:
                printf("EVENT: NL80211_CMD_STA_OPMODE_CHANGED\n");
                parse_sta_opmode_changed(tb);
                break;
        case NL80211_CMD_CH_SWITCH_STARTED_NOTIFY:
                printf("EVENT: NL80211_CMD_CH_SWITCH_STARTED_NOTIFY\n");
                parse_ch_switch_notify(tb, gnlh->cmd);
                break;
        case NL80211_CMD_CH_SWITCH_NOTIFY:
                printf("EVENT: NL80211_CMD_CH_SWITCH_NOTIFY\n");
                parse_ch_switch_notify(tb, gnlh->cmd);
                break;
        case NL80211_CMD_ASSOC_COMEBACK: /* 147 */
                printf("EVENT: NL80211_CMD_ASSOC_COMEBACK\n");
                parse_assoc_comeback(tb, gnlh->cmd);
                break;
        default: {
                printf("EVENT: UNKNOWN EVENT (cmd=%d)\n", gnlh->cmd);
                break;
	}
    }

    return NL_SKIP;
}

void register_handler(int (*handler)(struct nl_msg *, void *), void *data)
{
    registered_handler = handler;
    registered_handler_data = data;
}

static int no_seq_check(struct nl_msg *msg, void *arg)
{
        return NL_OK;
}

int valid_handler(struct nl_msg *msg, void *arg)
{
    if (registered_handler)
        return registered_handler(msg, registered_handler_data);

    return NL_OK;
}

int do_listen_events(struct nl80211_state *state, const int n_waits, const __u32 *waits,
                      const int n_prints, const __u32 *prints, struct print_event_args *args)
{
    struct nl_cb *cb = nl_cb_alloc(iw_debug ? NL_CB_DEBUG : NL_CB_DEFAULT);
    
    if (!cb) {
        fprintf(stderr, "failed to allocate netlink callbacks\n");
        return -ENOMEM;
    }

    /* no sequence checking for multicast messages */
    nl_cb_set(cb, NL_CB_SEQ_CHECK, NL_CB_CUSTOM, no_seq_check, NULL);
    nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, valid_handler, NULL);
    register_handler(nl_rx_event, args);

    while (1) {
        nl_recvmsgs(state->nl_sock, cb);
    }

    nl_cb_put(cb);

    return 0;
}

int prepare_listen_events(struct nl80211_state *state)
{
    int mcid, ret;
    /* Configuration multicast group */

    mcid = genl_ctrl_resolve(state->nl_sock, "nl80211");
    if (mcid < 0)
        return mcid;

    ret = nl_socket_add_membership(state->nl_sock, mcid);
    if (ret)
        return ret;
         
    mcid = genl_ctrl_resolve(state->nl_sock, "nlctrl");
    if (mcid < 0)
        return mcid;

    ret = nl_socket_add_membership(state->nl_sock, mcid);
    if (ret)
        return ret;

    mcid = nl_get_multicast_id(state->nl_sock, "nl80211", "config");
    if (mcid < 0)
        return mcid;

    ret = nl_socket_add_membership(state->nl_sock, mcid);
    if (ret)
        return ret;

    /* Scan multicast group */
    mcid = nl_get_multicast_id(state->nl_sock, "nl80211", "scan");
    if (mcid >= 0) {
        ret = nl_socket_add_membership(state->nl_sock, mcid);
        if (ret)
            return ret;
    }
    mcid = nl_get_multicast_id(state->nl_sock, "nl80211", "mlme");
    if (mcid >= 0) {
        ret = nl_socket_add_membership(state->nl_sock, mcid);
        if (ret)
            return ret;
    }

    /* Regulatory multicast group */
    mcid = nl_get_multicast_id(state->nl_sock, "nl80211", "regulatory");
    if (mcid >= 0) {
        ret = nl_socket_add_membership(state->nl_sock, mcid);
        if (ret)
            return ret;
    }

    /* MLME multicast group */
    mcid = nl_get_multicast_id(state->nl_sock, "nl80211", "mlme");
    if (mcid >= 0) {
        ret = nl_socket_add_membership(state->nl_sock, mcid);
        if (ret)
            return ret;
    }

    mcid = nl_get_multicast_id(state->nl_sock, "nl80211", "vendor");
    if (mcid >= 0) {
        ret = nl_socket_add_membership(state->nl_sock, mcid);
        if (ret)
            return ret;
    }

    mcid = nl_get_multicast_id(state->nl_sock, "nl80211", "nan");
    if (mcid >= 0) {
        ret = nl_socket_add_membership(state->nl_sock, mcid);
        if (ret)
            return ret;
    }

    return 0;
}

int listen_events(struct nl80211_state *state, const int n_waits, const __u32 *waits)
{
    int ret;

    ret = prepare_listen_events(state);
    if (ret) {
        return ret;
    }

    return do_listen_events(state, n_waits, waits, 0, NULL, NULL);
}

int nl80211_init(struct nl80211_state *state)
{
    int err;

    state->nl_sock = nl_socket_alloc();
    if (!state->nl_sock) {
        return -ENOMEM;
    }

    if (genl_connect(state->nl_sock)) {
        err = -ENOLINK;
    }

    nl_socket_set_buffer_size(state->nl_sock, 8192, 8192);

    /* try to set NETLINK_EXT_ACK to 1, ignoring errors */
    err = 1;
    setsockopt(nl_socket_get_fd(state->nl_sock), SOL_NETLINK, NETLINK_EXT_ACK, &err, sizeof(err));

    state->nl80211_id = genl_ctrl_resolve(state->nl_sock, "nl80211");
    if (state->nl80211_id < 0) {
        err = -ENOENT;
    }

    return 0;
}

