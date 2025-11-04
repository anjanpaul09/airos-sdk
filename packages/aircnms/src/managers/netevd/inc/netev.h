#ifndef NETEV_H
#define NETEV_H

#include <linux/rtnetlink.h>
#include <netlink/types.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <stdbool.h>
#include <errno.h>

struct print_event_args {
    struct timeval ts; /* internal */
    bool have_ts; /* must be set false */
    bool frame, time, reltime, ctime;
};

struct wait_event {
    int n_cmds, n_prints;
    const __u32 *cmds;
    const __u32 *prints;
    __u32 cmd;
    struct print_event_args *pargs;
};

struct nl80211_state {
    struct nl_sock *nl_sock;
    int nl80211_id;
};


#endif // NETEV_H

