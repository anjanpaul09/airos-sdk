#include <dirent.h>
#include <errno.h>
#include <jansson.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "log.h"
#include "os.h"
#include "portal_template.h"
#include "portal_utils.h"

typedef struct portal_kv {
    const char *key;
    const char *value;
} portal_kv_t;

static const char *specific_template =
    "radiusserver1 '${RADIUS_SERVER}'\n"
    "radiusserver2 'localhost'\n"
    "radiusauthport ${RADIUS_AUTH_PORT}\n"
    "radiusacctport ${RADIUS_ACCT_PORT}\n"
    "radiussecret '${RADIUS_SECRET}'\n"
    "uamserver '${UAM_SERVER}'\n"
    "radiusnasid '${NAS_ID}'\n"
    "dhcpif '${BRIDGE}'\n"
    "uamallowed '${UAM_IP}'\n"
    "uamallowed '${AUTH_HOST}'\n"
    "uamallowed 'api-freeradius.cloud.netstream.net.in'\n"
    "cmdsocket '${CMDSOCKET}'\n"
    "unixipc '${UNIXIPC}'\n"
    "pidfile '${PIDFILE}'\n"
    "uamsecret '${UAM_SECRET}'\n"
    "dns1 '${DNS1}'\n"
    "dns2 '${DNS2}'\n"
    "ssid '${SSID}'\n";

static const char *unique_template =
    "net ${NETWORK_CIDR}\n"
    "dynip ${DYNIP_CIDR}\n"
    "tundev ${TUNDEV}\n"
    "uamlisten ${UAM_IP}\n"
    "uamhomepage http://${UAM_IP}:3990/www/radiusdesk.html\n"
    "radiuslocationname \"${NAS_ID}\"\n"
    "radiuslocationid \"isocc=,cc=,ac=,network=${NAS_ID},\"\n";

static const char *chilli_template =
    "include ${INSTANCE_DIR}/common.conf\n"
    "include ${INSTANCE_DIR}/unique.conf\n"
    "include ${INSTANCE_DIR}/specific.conf\n"
    "ipup=/etc/chilli/up.sh\n"
    "ipdown=/etc/chilli/down.sh\n";

static const char *common_template =
    "swapoctets\n"
    "uamport 3990\n"
    "domain \"mesh-manager.com\"\n"
    "wwwdir /etc/chilli/www\n"
    "wwwbin /etc/chilli/wwwsh\n"
    "uamuiport 4990\n"
    "locationname \"MESHdesk\"\n"
    "papalwaysok\n"
    "lease 3600\n"
    "uamanydns\n"
    "uamaliasname \"login\"\n"
    "adminupdatefile \"/etc/chilli/local.conf\"\n"
    "mtu 1468\n";

static const char *privoxy_template =
    "listen-address ${UAM_IP}:8118\n"
    "actionsfile ${INSTANCE_DIR}/auth.action\n";

static const char *auth_action_template =
    "{ +redirect{s@.*@${UAM_SERVER}@} }\n"
    "/\n";

static int portal_write_default_template(const char *name, const char *data)
{
    char path[PORTAL_PATH_LEN];

    snprintf(path, sizeof(path), "%s/%s", PORTAL_TEMPLATE_DIR, name);
    return portal_write_file(path, data);
}

int portal_template_init_defaults(void)
{
    if (portal_mkdir_p(PORTAL_TEMPLATE_DIR) != 0)
        return -1;
    if (portal_mkdir_p(PORTAL_INSTANCE_DIR) != 0)
        return -1;

    if (portal_write_default_template("specific.conf.template",
                                      specific_template) != 0)
        return -1;
    if (portal_write_default_template("unique.conf.template",
                                      unique_template) != 0)
        return -1;
    if (portal_write_default_template("chilli.conf.template",
                                      chilli_template) != 0)
        return -1;
    if (portal_write_default_template("common.conf.template",
                                      common_template) != 0)
        return -1;
    if (portal_write_default_template("privoxy.conf.template",
                                      privoxy_template) != 0)
        return -1;
    if (portal_write_default_template("auth.action.template",
                                      auth_action_template) != 0)
        return -1;

    return 0;
}

static void portal_replace_all(char *dst, size_t dst_len, const char *src,
                               const char *from, const char *to)
{
    const char *p = src;
    size_t used = 0;
    size_t from_len = strlen(from);
    size_t to_len = strlen(to ? to : "");

    if (dst_len == 0)
        return;

    dst[0] = '\0';
    while (*p && used < dst_len - 1) {
        if (!strncmp(p, from, from_len)) {
            size_t n = to_len;
            if (n > dst_len - used - 1)
                n = dst_len - used - 1;
            memcpy(dst + used, to ? to : "", n);
            used += n;
            p += from_len;
        } else {
            dst[used++] = *p++;
        }
    }
    dst[used] = '\0';
}

static char *portal_render(const char *tmpl, const portal_kv_t *vars, int n_vars)
{
    char *cur;
    int i;

    cur = strdup(tmpl ? tmpl : "");
    if (!cur)
        return NULL;

    for (i = 0; i < n_vars; i++) {
        char pattern[64];
        char *next;

        snprintf(pattern, sizeof(pattern), "${%s}", vars[i].key);
        next = calloc(1, strlen(cur) + strlen(vars[i].value ? vars[i].value : "") + 4096);
        if (!next) {
            free(cur);
            return NULL;
        }
        portal_replace_all(next, strlen(cur) + strlen(vars[i].value ? vars[i].value : "") + 4096,
                           cur, pattern, vars[i].value);
        free(cur);
        cur = next;
    }

    return cur;
}

static const char *portal_builtin_template(const char *template_name)
{
    if (!strcmp(template_name, "specific.conf"))
        return specific_template;
    if (!strcmp(template_name, "unique.conf"))
        return unique_template;
    if (!strcmp(template_name, "chilli.conf"))
        return chilli_template;
    if (!strcmp(template_name, "common.conf"))
        return common_template;
    if (!strcmp(template_name, "privoxy.conf"))
        return privoxy_template;
    if (!strcmp(template_name, "auth.action"))
        return auth_action_template;

    return NULL;
}

static int portal_render_file(const char *template_name, const char *output_name,
                              const portal_kv_t *vars, int n_vars,
                              const char *instance_dir)
{
    char out_path[PORTAL_PATH_LEN];
    const char *tmpl;
    char *rendered;
    int rc;

    snprintf(out_path, sizeof(out_path), "%s/%s", instance_dir, output_name);

    tmpl = portal_builtin_template(template_name);
    if (!tmpl)
        return -1;

    rendered = portal_render(tmpl, vars, n_vars);
    if (!rendered)
        return -1;

    rc = portal_write_file(out_path, rendered);
    free(rendered);
    return rc;
}

static int portal_mask_to_prefix(const char *netmask)
{
    struct in_addr addr;
    uint32_t mask;
    int prefix = 0;

    if (!netmask || inet_pton(AF_INET, netmask, &addr) != 1)
        return 24;

    mask = ntohl(addr.s_addr);
    while (mask & 0x80000000U) {
        prefix++;
        mask <<= 1;
    }

    return prefix;
}

static void portal_make_cidr(const char *ipaddr, const char *netmask,
                             char *buf, size_t len)
{
    struct in_addr ip;
    struct in_addr mask;
    struct in_addr net;
    char net_addr[32];
    int prefix;

    if (!buf || len == 0)
        return;

    if (!ipaddr || !netmask ||
        inet_pton(AF_INET, ipaddr, &ip) != 1 ||
        inet_pton(AF_INET, netmask, &mask) != 1) {
        snprintf(buf, len, "%s/%s", ipaddr ? ipaddr : "", netmask ? netmask : "");
        return;
    }

    net.s_addr = ip.s_addr & mask.s_addr;
    if (!inet_ntop(AF_INET, &net, net_addr, sizeof(net_addr))) {
        snprintf(buf, len, "%s/%s", ipaddr, netmask);
        return;
    }

    prefix = portal_mask_to_prefix(netmask);
    snprintf(buf, len, "%s/%d", net_addr, prefix);
}

static void portal_make_dynip_cidr(const char *ipaddr, const char *netmask,
                                   char *buf, size_t len)
{
    struct in_addr ip;
    struct in_addr mask;
    struct in_addr dyn;
    char dyn_addr[32];
    int prefix;

    if (!buf || len == 0)
        return;

    if (!ipaddr || !netmask ||
        inet_pton(AF_INET, ipaddr, &ip) != 1 ||
        inet_pton(AF_INET, netmask, &mask) != 1) {
        snprintf(buf, len, "%s/%s", ipaddr ? ipaddr : "", netmask ? netmask : "");
        return;
    }

    prefix = portal_mask_to_prefix(netmask);
    if (prefix > 16) {
        portal_make_cidr(ipaddr, netmask, buf, len);
        return;
    }

    dyn.s_addr = (ip.s_addr & mask.s_addr) | htonl(0x00000100U);
    if (!inet_ntop(AF_INET, &dyn, dyn_addr, sizeof(dyn_addr))) {
        snprintf(buf, len, "%s/%s", ipaddr, netmask);
        return;
    }

    snprintf(buf, len, "%s/%d", dyn_addr, prefix);
}

static void portal_auth_host(const char *url, char *buf, size_t len)
{
    const char *host;
    const char *end;
    size_t n;

    if (!buf || len == 0)
        return;

    buf[0] = '\0';
    if (!url || url[0] == '\0')
        return;

    host = strstr(url, "://");
    host = host ? host + 3 : url;
    end = host;
    while (*end && *end != '/' && *end != ':' && *end != '?' && *end != '#')
        end++;

    n = (size_t)(end - host);
    if (n >= len)
        n = len - 1;
    memcpy(buf, host, n);
    buf[n] = '\0';
}

static void portal_make_uam_server(const char *auth_url, const char *portal_id,
                                   char *buf, size_t len)
{
    const char *sep;

    if (!buf || len == 0)
        return;

    if (!auth_url || auth_url[0] == '\0') {
        buf[0] = '\0';
        return;
    }

    if (strstr(auth_url, "realm=") || !portal_id || portal_id[0] == '\0') {
        strlcpy(buf, auth_url, len);
        return;
    }

    sep = strchr(auth_url, '?') ? "&" : "?";
    snprintf(buf, len, "%s%srealm=%s", auth_url, sep, portal_id);
}

int portal_template_write_metadata(portal_entry_t *entry,
        const struct airpro_mgr_wlan_vap_params *vif)
{
    json_t *root;
    char instance_dir[PORTAL_PATH_LEN];
    char uam_ip[32];
    char nas_id[64];
    char subnet[32];
    char cmdsocket[128];
    char status_url[128];
    char uam_server[640];
    int rc;

    if (!entry || !vif)
        return -1;

    snprintf(instance_dir, sizeof(instance_dir), "%s/%s",
             PORTAL_INSTANCE_DIR, entry->portal_id);
    if (portal_mkdir_p(instance_dir) != 0)
        return -1;
    strlcpy(uam_ip, vif->uam_ip[0] ? vif->uam_ip : entry->ipaddr,
            sizeof(uam_ip));
    strlcpy(nas_id, vif->nas_id[0] ? vif->nas_id : entry->network,
            sizeof(nas_id));
    portal_make_cidr(entry->ipaddr, entry->netmask, subnet, sizeof(subnet));
    snprintf(cmdsocket, sizeof(cmdsocket), "/var/run/chilli_%s.sock",
             entry->network);
    snprintf(status_url, sizeof(status_url), "http://%s:3990/status", uam_ip);
    portal_make_uam_server(vif->auth_url, entry->portal_id, uam_server,
                           sizeof(uam_server));

    root = json_object();
    if (!root)
        return -1;

    json_object_set_new(root, "portalId", json_string(entry->portal_id));
    json_object_set_new(root, "network", json_string(entry->network));
    json_object_set_new(root, "bridge", json_string(entry->bridge));
    json_object_set_new(root, "interface", json_string(entry->interface));
    json_object_set_new(root, "tun", json_string(entry->tun));
    json_object_set_new(root, "ipaddr", json_string(entry->ipaddr));
    json_object_set_new(root, "netmask", json_string(entry->netmask));
    json_object_set_new(root, "subnet", json_string(subnet));
    json_object_set_new(root, "cmdsocket", json_string(cmdsocket));
    json_object_set_new(root, "refCount", json_integer(entry->ref_count));
    json_object_set_new(root, "uamServer", json_string(uam_server));
    json_object_set_new(root, "radiusServer", json_string(vif->server_ip));
    json_object_set_new(root, "nasId", json_string(nas_id));
    json_object_set_new(root, "statusUrl", json_string(status_url));

    rc = json_dump_file(root, entry->metadata_path, JSON_INDENT(2));
    json_decref(root);
    return rc;
}

int portal_template_render_instance(portal_entry_t *entry,
        const struct airpro_mgr_wlan_vap_params *vif)
{
    char instance_dir[PORTAL_PATH_LEN];
    char uam_ip[32];
    char nas_id[64];
    char auth_port[16];
    char acct_port[16];
    char network_cidr[32];
    char dynip_cidr[32];
    char auth_host[128];
    char uam_server[640];
    char uam_secret[64];
    char cmdsocket[128];
    char unixipc[128];
    char pidfile[128];
    portal_kv_t vars[22];
    int n = 0;
    int rc = 0;

    if (!entry || !vif)
        return -1;

    snprintf(instance_dir, sizeof(instance_dir), "%s/%s",
             PORTAL_INSTANCE_DIR, entry->portal_id);
    if (portal_mkdir_p(instance_dir) != 0)
        return -1;

    strlcpy(uam_ip, vif->uam_ip[0] ? vif->uam_ip : entry->ipaddr,
            sizeof(uam_ip));
    strlcpy(nas_id, vif->nas_id[0] ? vif->nas_id : entry->network,
            sizeof(nas_id));
    strlcpy(auth_port, vif->auth_port[0] ? vif->auth_port : "1812",
            sizeof(auth_port));
    strlcpy(acct_port, vif->acct_port[0] ? vif->acct_port : "1813",
            sizeof(acct_port));
    portal_make_cidr(entry->ipaddr, entry->netmask, network_cidr,
                     sizeof(network_cidr));
    portal_make_dynip_cidr(entry->ipaddr, entry->netmask, dynip_cidr,
                           sizeof(dynip_cidr));
    portal_make_uam_server(vif->auth_url, entry->portal_id, uam_server,
                           sizeof(uam_server));
    portal_auth_host(uam_server, auth_host, sizeof(auth_host));
    strlcpy(uam_secret, vif->uam_secret[0] ? vif->uam_secret : "greatsecret",
            sizeof(uam_secret));
    snprintf(cmdsocket, sizeof(cmdsocket), "/var/run/chilli_%s.sock",
             entry->network);
    snprintf(unixipc, sizeof(unixipc), "/var/run/chilli_%s.ipc",
             entry->network);
    snprintf(pidfile, sizeof(pidfile), "/var/run/chilli_%s.pid",
             entry->network);

    vars[n++] = (portal_kv_t){ "RADIUS_SERVER", vif->server_ip };
    vars[n++] = (portal_kv_t){ "RADIUS_AUTH_PORT", auth_port };
    vars[n++] = (portal_kv_t){ "RADIUS_ACCT_PORT", acct_port };
    vars[n++] = (portal_kv_t){ "RADIUS_SECRET", vif->secret_key };
    vars[n++] = (portal_kv_t){ "UAM_SERVER", uam_server };
    vars[n++] = (portal_kv_t){ "UAM_SECRET", uam_secret };
    vars[n++] = (portal_kv_t){ "NAS_ID", nas_id };
    vars[n++] = (portal_kv_t){ "BRIDGE", entry->bridge };
    vars[n++] = (portal_kv_t){ "TUNDEV", entry->tun };
    vars[n++] = (portal_kv_t){ "NETWORK", entry->network };
    vars[n++] = (portal_kv_t){ "NETWORK_CIDR", network_cidr };
    vars[n++] = (portal_kv_t){ "DYNIP_CIDR", dynip_cidr };
    vars[n++] = (portal_kv_t){ "UAM_IP", uam_ip };
    vars[n++] = (portal_kv_t){ "AUTH_HOST", auth_host };
    vars[n++] = (portal_kv_t){ "DNS1", "8.8.8.8" };
    vars[n++] = (portal_kv_t){ "DNS2", "4.2.2.2" };
    vars[n++] = (portal_kv_t){ "CMDSOCKET", cmdsocket };
    vars[n++] = (portal_kv_t){ "UNIXIPC", unixipc };
    vars[n++] = (portal_kv_t){ "PIDFILE", pidfile };
    vars[n++] = (portal_kv_t){ "SSID", vif->ssid };
    vars[n++] = (portal_kv_t){ "INSTANCE_DIR", instance_dir };
    vars[n++] = (portal_kv_t){ "PORTAL_ID", entry->portal_id };

    rc |= portal_render_file("common.conf", "common.conf", vars, n,
                             instance_dir);
    rc |= portal_render_file("specific.conf", "specific.conf", vars, n,
                             instance_dir);
    rc |= portal_render_file("unique.conf", "unique.conf", vars, n,
                             instance_dir);
    rc |= portal_render_file("chilli.conf", "chilli.conf", vars, n,
                             instance_dir);
    rc |= portal_render_file("privoxy.conf", "privoxy.conf", vars, n,
                             instance_dir);
    rc |= portal_render_file("auth.action", "auth.action", vars, n,
                             instance_dir);
    rc |= portal_template_write_metadata(entry, vif);

    if (rc != 0)
        LOG(ERR, "portal_template: render failed for portal=%s", entry->portal_id);

    return rc;
}

int portal_template_load_metadata(const char *portal_id, portal_entry_t *entry)
{
    char path[PORTAL_PATH_LEN];
    json_error_t error;
    json_t *root;
    json_t *v;

    if (!portal_id || !entry)
        return -1;

    snprintf(path, sizeof(path), "%s/%s/metadata.json", PORTAL_INSTANCE_DIR,
             portal_id);
    root = json_load_file(path, 0, &error);
    if (!root)
        return -1;

    v = json_object_get(root, "network");
    if (json_is_string(v))
        strlcpy(entry->network, json_string_value(v), sizeof(entry->network));
    v = json_object_get(root, "bridge");
    if (json_is_string(v))
        strlcpy(entry->bridge, json_string_value(v), sizeof(entry->bridge));
    v = json_object_get(root, "interface");
    if (json_is_string(v))
        strlcpy(entry->interface, json_string_value(v), sizeof(entry->interface));
    v = json_object_get(root, "tun");
    if (json_is_string(v))
        strlcpy(entry->tun, json_string_value(v), sizeof(entry->tun));
    portal_make_tun_name(entry->network, entry->tun, sizeof(entry->tun));
    v = json_object_get(root, "ipaddr");
    if (json_is_string(v))
        strlcpy(entry->ipaddr, json_string_value(v), sizeof(entry->ipaddr));
    v = json_object_get(root, "netmask");
    if (json_is_string(v))
        strlcpy(entry->netmask, json_string_value(v), sizeof(entry->netmask));
    v = json_object_get(root, "refCount");
    if (json_is_integer(v))
        entry->ref_count = (int)json_integer_value(v);
    strlcpy(entry->metadata_path, path, sizeof(entry->metadata_path));

    json_decref(root);
    return 0;
}
