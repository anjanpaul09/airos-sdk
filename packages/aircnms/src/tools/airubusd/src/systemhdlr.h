#ifndef RAYNETD_SYSTEMHDLR_H
#define RAYNETD_SYSTEMHDLR_H

#include <stddef.h>
#include <libubox/blobmsg.h>

typedef int (*ray_system_handler_fn)(struct blob_attr *msg, struct blob_buf *out);

typedef struct ray_system_method {
	const char *name;
	ray_system_handler_fn handler;
	const struct blobmsg_policy *policy;
	int n_policy;
} ray_system_method_t;

const ray_system_method_t *raysystem_methods(void);
size_t raysystem_methods_nr(void);

#endif /* RAYNETD_SYSTEMHDLR_H */


