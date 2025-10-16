#ifndef RAYNETD_AIRDPIHDLR_H
#define RAYNETD_AIRDPIHDLR_H

#include <stddef.h>
#include <libubox/blobmsg.h>

typedef int (*ray_airdpi_handler_fn)(struct blob_attr *msg, struct blob_buf *out);

typedef struct ray_airdpi_method {
	const char *name;
	ray_airdpi_handler_fn handler;
	const struct blobmsg_policy *policy;
	int n_policy;
} ray_airdpi_method_t;

const ray_airdpi_method_t *rayairdpi_methods(void);
size_t rayairdpi_methods_nr(void);

/* Exposed by main.c */
struct ubus_context *ray_get_ubus_ctx(void);

#endif /* RAYNETD_AIRDPIHDLR_H */


