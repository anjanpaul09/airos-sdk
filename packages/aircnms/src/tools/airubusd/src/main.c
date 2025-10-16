#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

#include <libubox/uloop.h>
#include <libubox/blobmsg_json.h>
#include <libubus.h>

#include "systemhdlr.h"
#include "airhdlr.h"

static struct ubus_auto_conn g_conn;
static struct ubus_object g_obj;
static struct ubus_object_type g_obj_type;
static struct ubus_method *g_methods = NULL;
static size_t g_methods_nr = 0;

static struct blob_buf g_buf;

static int dispatcher(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method, struct blob_attr *msg)
{
	(void)obj;
	/* System table */
	const ray_system_method_t *st = raysystem_methods();
	size_t stn = raysystem_methods_nr();
	for (size_t i = 0; i < stn; i++) {
		if (strcmp(method, st[i].name) == 0) {
			blob_buf_init(&g_buf, 0);
			int rc = st[i].handler(msg, &g_buf);
			//int rc = g_methods[i].handler(msg, &g_buf); // real handler
                        return ubus_send_reply(ctx, req, g_buf.head) ?: rc;
		}
	}
	return UBUS_STATUS_METHOD_NOT_FOUND;
}

static int dispatcher_airdpi(struct ubus_context *ctx, struct ubus_object *obj,
                             struct ubus_request_data *req, const char *method,
                             struct blob_attr *msg)
{
    const ray_airdpi_method_t *at = rayairdpi_methods();
    size_t atn = rayairdpi_methods_nr();

    blob_buf_init(&g_buf, 0);

    for (size_t i = 0; i < atn; i++) {
        if (strcmp(method, at[i].name) == 0) {
            int rc = at[i].handler(msg, &g_buf);  // msg + out signature
            return ubus_send_reply(ctx, req, g_buf.head) ?: rc;
        }
    }

    return UBUS_STATUS_METHOD_NOT_FOUND;
}


static void build_methods_array(void)
{
	const ray_system_method_t *st = raysystem_methods();
	size_t stn = raysystem_methods_nr();
	const ray_airdpi_method_t *at = rayairdpi_methods();
	size_t atn = rayairdpi_methods_nr();

	g_methods_nr = stn + atn;
	g_methods = calloc(g_methods_nr, sizeof(*g_methods));
	if (!g_methods)
		return;
	/* System */
	for (size_t i = 0; i < stn; i++) {
		size_t j = i;
		g_methods[j].name = st[i].name;
		g_methods[j].handler = dispatcher;
		g_methods[j].policy = st[i].policy;
		g_methods[j].n_policy = st[i].n_policy;
	}
	/* Air */
	for (size_t i = 0; i < atn; i++) {
		size_t j = stn + i;
		g_methods[j].name = at[i].name;
		g_methods[j].handler = dispatcher_airdpi;
		g_methods[j].policy = at[i].policy;
		g_methods[j].n_policy = at[i].n_policy;
	}
}

static void ubus_connect_cb(struct ubus_context *ctx)
{
	build_methods_array();
	g_obj_type.id = 0;
	g_obj_type.name = "raynetd";
	g_obj_type.methods = g_methods;
	g_obj_type.n_methods = g_methods_nr;

	g_obj.name = "raynetd";
	g_obj.type = &g_obj_type;
	g_obj.methods = g_methods;
	g_obj.n_methods = g_methods_nr;

	ubus_add_object(ctx, &g_obj);
}

static void sig_handler(int signo)
{
	(void)signo;
	uloop_end();
}

int main(int argc, char **argv)
{
	(void)argc; (void)argv;
	uloop_init();
	blob_buf_init(&g_buf, 0);
	g_conn.cb = ubus_connect_cb;
	ubus_auto_connect(&g_conn);
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);
	uloop_run();
	//ubus_auto_shutdown(&g_conn);
	uloop_done();
	free(g_methods);
	return 0;
}

/* Provide access to the ubus context for other modules */
struct ubus_context *ray_get_ubus_ctx(void)
{
	//return g_conn->ctx;
}


