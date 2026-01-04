#include <linux/nl80211.h>
#include <stdio.h>
#include <stdbool.h>
#include <net/if.h>
#include <netev.h>

struct nl_sock *nl_sock_global = NULL;
int nl80211_id = -1;

// Convert MAC string → 6 bytes
static bool mac_str_to_bytes(const char *mac_str, unsigned char *mac)
{
    return sscanf(mac_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                  &mac[0], &mac[1], &mac[2],
                  &mac[3], &mac[4], &mac[5]) == 6;
}


// Callback to detect GET_STATION success
static int get_station_cb(struct nl_msg *msg, void *arg)
{
    bool *found = arg;
    *found = true;
    return NL_OK;
}


// Check GET_STATION on one interface
static bool check_station_on_iface(int ifindex, const unsigned char *mac)
{
    struct nl_msg *msg = nlmsg_alloc();
    if (!msg)
        return false;

    bool sta_found = false;

    // Build message
    genlmsg_put(msg, 0, 0, nl80211_id, 0, NLM_F_ECHO,
                NL80211_CMD_GET_STATION, 0);

    nla_put_u32(msg, NL80211_ATTR_IFINDEX, ifindex);
    nla_put(msg, NL80211_ATTR_MAC, 6, mac);

    // Send and wait for response
    int err = nl_send_auto(nl_sock_global, msg);
    if (err < 0) {
        nlmsg_free(msg);
        return false;
    }

    nl_socket_modify_cb(nl_sock_global, NL_CB_VALID, NL_CB_CUSTOM, get_station_cb, &sta_found);

    // Process until done (1 message)
    nl_recvmsgs_default(nl_sock_global);

    nlmsg_free(msg);
    return sta_found;
}



// Enumerate all wireless AP-mode interfaces
static int iface_list_cb(struct nl_msg *msg, void *arg)
{
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    int iftype, ifindex;

    struct {
        const unsigned char *mac;
        bool result;
    } *ctx = arg;

    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
              genlmsg_attrlen(gnlh, 0), NULL);

    if (!tb[NL80211_ATTR_IFINDEX] || !tb[NL80211_ATTR_IFTYPE])
        return NL_OK;

    ifindex = nla_get_u32(tb[NL80211_ATTR_IFINDEX]);
    iftype  = nla_get_u32(tb[NL80211_ATTR_IFTYPE]);

    // We only care about AP-mode interfaces
    if (iftype != NL80211_IFTYPE_AP)
        return NL_OK;

    // Check if STA exists on this interface
    if (check_station_on_iface(ifindex, ctx->mac)) {
        ctx->result = true;  // STA found
    }

    return NL_OK;
}

// Context for checking if STA exists on other interfaces (excluding exclude_ifname)
struct iface_list_other_ctx {
    const unsigned char *mac;
    const char *exclude_ifname;
    bool result;
};

// Enumerate all wireless AP-mode interfaces, checking for STA on OTHER interfaces
static int iface_list_other_cb(struct nl_msg *msg, void *arg)
{
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    int iftype, ifindex;
    char ifname[IF_NAMESIZE];

    struct iface_list_other_ctx *ctx = (struct iface_list_other_ctx *)arg;

    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
              genlmsg_attrlen(gnlh, 0), NULL);

    if (!tb[NL80211_ATTR_IFINDEX] || !tb[NL80211_ATTR_IFTYPE])
        return NL_OK;

    ifindex = nla_get_u32(tb[NL80211_ATTR_IFINDEX]);
    iftype  = nla_get_u32(tb[NL80211_ATTR_IFTYPE]);

    // We only care about AP-mode interfaces
    if (iftype != NL80211_IFTYPE_AP)
        return NL_OK;

    // Get interface name
    if (!if_indextoname(ifindex, ifname))
        return NL_OK;

    // Skip the interface that reported the disconnect
    if (ctx->exclude_ifname && strcmp(ifname, ctx->exclude_ifname) == 0)
        return NL_OK;

    // Check if STA exists on this OTHER interface
    if (check_station_on_iface(ifindex, ctx->mac)) {
        ctx->result = true;  // STA found on another interface
    }

    return NL_OK;
}



// PUBLIC FUNCTION
// -------------------------------
// Returns true  → STA is connected (on any AP interface)
// Returns false → STA not connected anywhere
// -------------------------------
bool sta_exists_on_any_iface(const char *mac_str)
{
    unsigned char mac[6];
    if (!mac_str_to_bytes(mac_str, mac)) {
        fprintf(stderr, "Invalid MAC string: %s\n", mac_str);
        return false;
    }

    struct nl_msg *msg = nlmsg_alloc();
    if (!msg)
        return false;

    struct {
        const unsigned char *mac;
        bool result;
    } ctx = {
        .mac = mac,
        .result = false
    };

    // Build dump command: GET_INTERFACE dump
    genlmsg_put(msg, 0, 0, nl80211_id, 0,
                NLM_F_DUMP,
                NL80211_CMD_GET_INTERFACE, 0);

    nl_socket_modify_cb(nl_sock_global, NL_CB_VALID, NL_CB_CUSTOM,
                        iface_list_cb, &ctx);

    nl_send_auto(nl_sock_global, msg);
    nl_recvmsgs_default(nl_sock_global);

    nlmsg_free(msg);

    return ctx.result;
}

// PUBLIC FUNCTION
// -------------------------------
// Returns true  → STA is connected on OTHER interfaces (excluding exclude_ifname)
// Returns false → STA not connected on other interfaces (or error)
// -------------------------------
bool sta_exists_on_other_iface(const char *mac_str, const char *exclude_ifname)
{
    unsigned char mac[6];
    if (!mac_str_to_bytes(mac_str, mac)) {
        fprintf(stderr, "Invalid MAC string: %s\n", mac_str);
        return false;
    }

    struct nl_msg *msg = nlmsg_alloc();
    if (!msg)
        return false;

    struct iface_list_other_ctx ctx = {
        .mac = mac,
        .exclude_ifname = exclude_ifname,
        .result = false
    };

    // Build dump command: GET_INTERFACE dump
    genlmsg_put(msg, 0, 0, nl80211_id, 0,
                NLM_F_DUMP,
                NL80211_CMD_GET_INTERFACE, 0);

    nl_socket_modify_cb(nl_sock_global, NL_CB_VALID, NL_CB_CUSTOM,
                        iface_list_other_cb, &ctx);

    nl_send_auto(nl_sock_global, msg);
    nl_recvmsgs_default(nl_sock_global);

    nlmsg_free(msg);

    return ctx.result;
}

/**
 * Initialize NL80211 socket.
 *
 * Returns:
 *   0  → success
 *  -1  → failure
 */
int nl80211_init(void)
{
    int err;

    nl_sock_global = nl_socket_alloc();
    if (!nl_sock_global) {
        fprintf(stderr, "nl80211_init: failed to allocate nl socket\n");
        return -1;
    }

    // Disable sequence checking (we do async dump + multi msg)
    nl_socket_disable_seq_check(nl_sock_global);

    // Set buffer sizes for reliability (optional)
    nl_socket_set_buffer_size(nl_sock_global, 8192, 8192);

    // Connect to generic netlink
    err = genl_connect(nl_sock_global);
    if (err < 0) {
        fprintf(stderr, "nl80211_init: genl_connect() failed: %s\n",
                nl_geterror(err));
        nl_socket_free(nl_sock_global);
        nl_sock_global = NULL;
        return -1;
    }

    // Resolve nl80211 family ID
    nl80211_id = genl_ctrl_resolve(nl_sock_global, "nl80211");
    if (nl80211_id < 0) {
        fprintf(stderr, "nl80211_init: cannot resolve nl80211 family\n");
        nl_socket_free(nl_sock_global);
        nl_sock_global = NULL;
        return -1;
    }

    printf("nl80211_init: success, nl80211_id=%d\n", nl80211_id);
    return 0;
}

void nl80211_cleanup(void)
{
    if (nl_sock_global) {
        nl_socket_free(nl_sock_global);
        nl_sock_global = NULL;
    }
}

