#include <unistd.h>
#include <sys/utsname.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <libubox/uloop.h>
#include <libubox/blobmsg_json.h>

#include "systemhdlr.h"

static int system_show_systeminfo(struct blob_attr *msg, struct blob_buf *out)
{
	(void)msg;
	struct utsname u;
	uname(&u);
	blob_buf_init(out, 0);
	void *t = blobmsg_open_table(out, "systeminfo");
	blobmsg_add_string(out, "hostname", u.nodename);
	blobmsg_add_string(out, "kernel", u.release);
	blobmsg_add_string(out, "machine", u.machine);
	blobmsg_close_table(out, t);
	return 0;
}

static const struct blobmsg_policy nopolicy[] = {};

static const ray_system_method_t g_system_methods[] = {
	{
		.name = "system_show_systeminfo",
		.handler = system_show_systeminfo,
		.policy = nopolicy,
		.n_policy = 0,
	},
};

const ray_system_method_t *raysystem_methods(void)
{
	return g_system_methods;
}

size_t raysystem_methods_nr(void)
{
	return sizeof(g_system_methods)/sizeof(g_system_methods[0]);
}


