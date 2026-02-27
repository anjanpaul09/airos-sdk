#include <linux/module.h>
#include <linux/kernel.h>
#include <net/genetlink.h>
#include <linux/skbuff.h>
#include <linux/netlink.h>
#include "air_coplane.h"

static const struct nla_policy airdpi_genl_policy[AIRDPI_ATTR_MAX + 1] = {
	[AIRDPI_ATTR_MAC]    = { .type = NLA_BINARY, .len = ETH_ALEN },
	[AIRDPI_ATTR_IFNAME] = { .type = NLA_NUL_STRING, .len = IFNAMSIZ },
};

static const struct genl_multicast_group airdpi_mcgrps[] = {
	{ .name = "events" },
};

static struct genl_family airdpi_gnl_family = {
	.name    = AIRDPI_GENL_NAME,
	.version = AIRDPI_GENL_VERSION,
	.maxattr = AIRDPI_ATTR_MAX,
	.policy  = airdpi_genl_policy,
	.module  = THIS_MODULE,
	.mcgrps  = airdpi_mcgrps,
	.n_mcgrps = ARRAY_SIZE(airdpi_mcgrps),
};

int airdpi_genl_notify_sta(const u8 *mac, const char *ifname, int cmd)
{
	struct sk_buff *skb;
	void *msg_head;
	int res;

	if (!mac || !ifname)
		return -EINVAL;

	skb = genlmsg_new(NLMSG_GOODSIZE, GFP_ATOMIC);
	if (!skb)
		return -ENOMEM;

	msg_head = genlmsg_put(skb, 0, 0, &airdpi_gnl_family, 0, cmd);
	if (!msg_head) {
		nlmsg_free(skb);
		return -ENOMEM;
	}

	if (nla_put(skb, AIRDPI_ATTR_MAC, ETH_ALEN, mac) ||
	    nla_put_string(skb, AIRDPI_ATTR_IFNAME, ifname)) {
		genlmsg_cancel(skb, msg_head);
		nlmsg_free(skb);
		return -EMSGSIZE;
	}

	genlmsg_end(skb, msg_head);

	/* Broadcast to all listeners on the "events" multicast group (index 0) */
	res = genlmsg_multicast(&airdpi_gnl_family, skb, 0, 0, GFP_ATOMIC);
	if (res == -ESRCH) {
		/* No listeners — not an error */
		return 0;
	}

	return res;
}
EXPORT_SYMBOL_GPL(airdpi_genl_notify_sta);

int netlink_init(void)
{
	int res;

	res = genl_register_family(&airdpi_gnl_family);
	if (res != 0) {
		pr_err("AIRDPI: Failed to register Generic Netlink family: %d\n", res);
		return res;
	}

	pr_info("AIRDPI: Generic Netlink family '%s' registered (id=%d)\n",
		AIRDPI_GENL_NAME, airdpi_gnl_family.id);
	return 0;
}

void netlink_exit(void)
{
	genl_unregister_family(&airdpi_gnl_family);
	pr_info("AIRDPI: Generic Netlink family '%s' unregistered\n", AIRDPI_GENL_NAME);
}
