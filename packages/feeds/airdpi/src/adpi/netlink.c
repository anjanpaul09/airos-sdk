#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <linux/init.h>
#include <linux/version.h>
#include <net/sock.h>

#include "air_vif.h"

static struct sock *nl_sk = NULL;
int pid = 0;

static int send_netlink_msg(int pid, char *msg) 
{
    struct sk_buff *skb;
    struct nlmsghdr *nlh;
    int msg_size = strlen(msg) + 1;
    int res;

    if (!pid) {
        pr_err("Netlink: Invalid PID\n");
        return -1;
    }

    skb = nlmsg_new(msg_size, GFP_KERNEL);
    if (!skb) {
        pr_err("Netlink: Failed to allocate skb\n");
        return -1;
    }

    nlh = nlmsg_put(skb, 0, 0, NLMSG_DONE, msg_size, 0);
    strncpy(nlmsg_data(nlh), msg, msg_size);

    res = netlink_unicast(nl_sk, skb, pid, MSG_DONTWAIT);
    
    if (res < 0)
        pr_err("Netlink: Failed to send message to user-space\n");

    return res;
}

int send_nl_event(char *msg)
{
    return send_netlink_msg(pid, msg);
}

static void netlink_recv_msg(struct sk_buff *skb) 
{
    struct nlmsghdr *nlh;

    nlh = (struct nlmsghdr *)skb->data;
    pid = nlh->nlmsg_pid;  // User-space process ID

    pr_info("Netlink: Received message from user-space: %s\n", (char *)nlmsg_data(nlh));

    // **Send an event back to user-space**
    send_netlink_msg(pid, "Event: Kernel message received!");
}

int netlink_init(void) 
{
    struct netlink_kernel_cfg cfg = {
        .input = netlink_recv_msg,
    };

    nl_sk = netlink_kernel_create(&init_net, NETLINK_USER, &cfg);
    if (!nl_sk) {
        pr_err("Netlink: Failed to create socket\n");
        return -ENOMEM;
    }

    printk("Netlink: Kernel module loaded\n");
    return 0;
}

void netlink_exit(void) 
{
    netlink_kernel_release(nl_sk);
    printk("Netlink: Kernel module unloaded\n");
}
