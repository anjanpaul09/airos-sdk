#include <stdlib.h>
#include <string.h>

#include <libubox/blobmsg_json.h>
#include <libubus.h>
#include "airioctl.h"

#include "airhdlr.h"

enum {
	AIR_ARG_MAC,
	AIR_ARG_IFACE,
	AIR_ARG_RATE,
	AIR_ARG_DIRECTION,
	AIR_ARG_DOMAIN,
	__AIR_ARG_MAX
};

static const struct blobmsg_policy air_get_user_rate_policy[] = {
	[AIR_ARG_MAC] = { .name = "mac", .type = BLOBMSG_TYPE_STRING },
};

static const struct blobmsg_policy air_get_wlan_rate_policy[] = {
	[AIR_ARG_IFACE] = { .name = "interface", .type = BLOBMSG_TYPE_STRING },
};

static const struct blobmsg_policy air_set_user_rate_policy[] = {
	[AIR_ARG_MAC] = { .name = "mac", .type = BLOBMSG_TYPE_STRING },
	[AIR_ARG_RATE] = { .name = "rate", .type = BLOBMSG_TYPE_INT32 },
	[AIR_ARG_DIRECTION] = { .name = "direction", .type = BLOBMSG_TYPE_STRING },
};

static const struct blobmsg_policy air_set_wlan_rate_policy[] = {
        [AIR_ARG_MAC] = { .name = NULL, .type = 0 },
	[AIR_ARG_IFACE] = { .name = "interface", .type = BLOBMSG_TYPE_STRING },
	[AIR_ARG_RATE] = { .name = "rate", .type = BLOBMSG_TYPE_INT32 },
	[AIR_ARG_DIRECTION] = { .name = "direction", .type = BLOBMSG_TYPE_STRING },
        [AIR_ARG_DOMAIN] = { .name = NULL, .type = 0 },
};

static const struct blobmsg_policy air_block_domain_policy[] = {
	[AIR_ARG_DOMAIN] = { .name = "domain", .type = BLOBMSG_TYPE_STRING },
};

static const struct blobmsg_policy air_unblock_domain_policy[] = {
	[AIR_ARG_DOMAIN] = { .name = "domain", .type = BLOBMSG_TYPE_STRING },
};

static int ubus_call_air(const char *method, struct blob_attr *msg, struct blob_buf *out)
{
	/* Replace previous proxy with direct ioctl calls and simple result response */
	int rc = 0;
	blob_buf_init(out, 0);
	if (strcmp(method, "get_all_clients") == 0) {
		rc = air_ioctl_get_all_clients(out);
		//blobmsg_add_u8(out, "result", rc == 0);
	} else if (strcmp(method, "get_all_top_domains") == 0) {
		rc = air_ioctl_get_all_top_domains(out);
		blobmsg_add_u8(out, "result", rc == 0);
	} else if (strcmp(method, "get_user_rate_limit") == 0) {
		struct blob_attr *tb[__AIR_ARG_MAX];
		const char *mac = NULL;
		//blobmsg_parse(air_get_user_rate_policy, __AIR_ARG_MAX, tb, blob_data(msg), blob_len(msg));
		blobmsg_parse(air_set_user_rate_policy, __AIR_ARG_MAX, tb, blob_data(msg), blob_len(msg));
                if (tb[AIR_ARG_MAC]) mac = blobmsg_get_string(tb[AIR_ARG_MAC]);
                printf("Ankit: mac = %s\n", mac);
		rc = air_ioctl_get_user_rate_limit(out, mac);
		blobmsg_add_u8(out, "result", rc == 0);
	} else if (strcmp(method, "get_wlan_rate_limit") == 0) {
		struct blob_attr *tb[__AIR_ARG_MAX];
		const char *iface = NULL;
		//blobmsg_parse(air_get_wlan_rate_policy, __AIR_ARG_MAX, tb, blob_data(msg), blob_len(msg));
		blobmsg_parse(air_set_wlan_rate_policy, __AIR_ARG_MAX, tb, blob_data(msg), blob_len(msg));
		if (tb[AIR_ARG_IFACE]) iface = blobmsg_get_string(tb[AIR_ARG_IFACE]);
		rc = air_ioctl_get_wlan_rate_limit(out, iface);
		blobmsg_add_u8(out, "result", rc == 0);
	} else if (strcmp(method, "set_user_rate_limit") == 0) {
		struct blob_attr *tb[__AIR_ARG_MAX];
		const char *mac = NULL, *dir = NULL; uint32_t rate = 0;
		blobmsg_parse(air_set_user_rate_policy, __AIR_ARG_MAX, tb, blob_data(msg), blob_len(msg));
		if (tb[AIR_ARG_MAC]) mac = blobmsg_get_string(tb[AIR_ARG_MAC]);
		if (tb[AIR_ARG_DIRECTION]) dir = blobmsg_get_string(tb[AIR_ARG_DIRECTION]);
		if (tb[AIR_ARG_RATE]) rate = blobmsg_get_u32(tb[AIR_ARG_RATE]);
		rc = air_ioctl_set_user_rate_limit(out, mac, rate, dir);
		blobmsg_add_u8(out, "result", rc == 0);
	} else if (strcmp(method, "set_wlan_rate_limit") == 0) {
		struct blob_attr *tb[__AIR_ARG_MAX];
		const char *iface = NULL, *dir = NULL; uint32_t rate = 0;
		blobmsg_parse(air_set_wlan_rate_policy, __AIR_ARG_MAX, tb, blob_data(msg), blob_len(msg));

                if (!tb[AIR_ARG_IFACE] || !tb[AIR_ARG_DIRECTION] || !tb[AIR_ARG_RATE]) {
                    blobmsg_add_string(out, "error", "Missing required arguments");
                    blobmsg_add_u8(out, "result", 0);
                    return;
                }
		if (tb[AIR_ARG_IFACE]) iface = blobmsg_get_string(tb[AIR_ARG_IFACE]);
		if (tb[AIR_ARG_DIRECTION]) dir = blobmsg_get_string(tb[AIR_ARG_DIRECTION]);
		if (tb[AIR_ARG_RATE]) rate = blobmsg_get_u32(tb[AIR_ARG_RATE]);
		rc = air_ioctl_set_wlan_rate_limit(out, iface, rate, dir);
		blobmsg_add_u8(out, "result", rc == 0);
	} else if (strcmp(method, "block_domain") == 0) {
		struct blob_attr *tb[__AIR_ARG_MAX];
		const char *domain = NULL;
		blobmsg_parse(air_block_domain_policy, __AIR_ARG_MAX, tb, blob_data(msg), blob_len(msg));
		if (tb[AIR_ARG_DOMAIN]) domain = blobmsg_get_string(tb[AIR_ARG_DOMAIN]);
		rc = air_ioctl_block_domain(out, domain);
		blobmsg_add_u8(out, "result", rc == 0);
	} else if (strcmp(method, "unblock_domain") == 0) {
		struct blob_attr *tb[__AIR_ARG_MAX];
		const char *domain = NULL;
		blobmsg_parse(air_unblock_domain_policy, __AIR_ARG_MAX, tb, blob_data(msg), blob_len(msg));
		if (tb[AIR_ARG_DOMAIN]) domain = blobmsg_get_string(tb[AIR_ARG_DOMAIN]);
		rc = air_ioctl_unblock_domain(out, domain);
		blobmsg_add_u8(out, "result", rc == 0);
	} else {
		rc = UBUS_STATUS_METHOD_NOT_FOUND;
	}
	return rc;
}

static int air_get_all_clients(struct blob_attr *msg, struct blob_buf *out)
{
	(void)msg;
	return ubus_call_air("get_all_clients", NULL, out);
}

static int air_get_all_top_domains(struct blob_attr *msg, struct blob_buf *out)
{
	(void)msg;
	return ubus_call_air("get_all_top_domains", NULL, out);
}

static int air_get_user_rate_limit(struct blob_attr *msg, struct blob_buf *out)
{
	return ubus_call_air("get_user_rate_limit", msg, out);
}

static int air_get_wlan_rate_limit(struct blob_attr *msg, struct blob_buf *out)
{
	return ubus_call_air("get_wlan_rate_limit", msg, out);
}

static int air_set_user_rate_limit(struct blob_attr *msg, struct blob_buf *out)
{
	return ubus_call_air("set_user_rate_limit", msg, out);
}

static int air_set_wlan_rate_limit(struct blob_attr *msg, struct blob_buf *out)
{
	return ubus_call_air("set_wlan_rate_limit", msg, out);
}

static int air_block_domain(struct blob_attr *msg, struct blob_buf *out)
{
	return ubus_call_air("block_domain", msg, out);
}

static int air_unblock_domain(struct blob_attr *msg, struct blob_buf *out)
{
	return ubus_call_air("unblock_domain", msg, out);
}

static const struct blobmsg_policy nopolicy[] = {};

static const ray_airdpi_method_t g_air_methods[] = {
	{ .name = "get_all_clients", .handler = air_get_all_clients, .policy = nopolicy, .n_policy = 0 },
	{ .name = "get_all_top_domains", .handler = air_get_all_top_domains, .policy = nopolicy, .n_policy = 0 },
	{ .name = "get_user_rate_limit", .handler = air_get_user_rate_limit, .policy = air_get_user_rate_policy, .n_policy = 1 },
	{ .name = "get_wlan_rate_limit", .handler = air_get_wlan_rate_limit, .policy = air_get_wlan_rate_policy, .n_policy = 1 },
	{ .name = "set_user_rate_limit", .handler = air_set_user_rate_limit, .policy = air_set_user_rate_policy, .n_policy = 3 },
	{ .name = "set_wlan_rate_limit", .handler = air_set_wlan_rate_limit, .policy = air_set_wlan_rate_policy, .n_policy = 3 },
	{ .name = "block_domain", .handler = air_block_domain, .policy = air_block_domain_policy, .n_policy = 1 },
	{ .name = "unblock_domain", .handler = air_unblock_domain, .policy = air_unblock_domain_policy, .n_policy = 1 },
};

const ray_airdpi_method_t *rayairdpi_methods(void)
{
	return g_air_methods;
}

size_t rayairdpi_methods_nr(void)
{
	return sizeof(g_air_methods)/sizeof(g_air_methods[0]);
}


