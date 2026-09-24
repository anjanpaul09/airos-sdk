#ifndef PORTAL_UTILS_H_INCLUDED
#define PORTAL_UTILS_H_INCLUDED

#include <stdbool.h>
#include <stddef.h>

#define PORTAL_BASE_DIR      "/etc/airpro/captive_portals"
#define PORTAL_TEMPLATE_DIR  PORTAL_BASE_DIR "/templates"
#define PORTAL_INSTANCE_DIR  PORTAL_BASE_DIR "/instances"
#ifndef PORTAL_PATH_LEN
#define PORTAL_PATH_LEN      512
#endif

bool portal_id_valid(const char *portal_id);
void portal_make_network_name(const char *portal_id, char *buf, size_t len);
void portal_make_bridge_name(const char *network, char *buf, size_t len);
void portal_make_tun_name(const char *network, char *buf, size_t len);
int portal_mkdir_p(const char *path);
int portal_remove_tree(const char *path);
int portal_write_file(const char *path, const char *data);
int portal_cmd(const char *cmd);

#endif /* PORTAL_UTILS_H_INCLUDED */
