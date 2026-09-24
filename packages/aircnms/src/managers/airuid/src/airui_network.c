#include "airui_network.h"
#include "airui_apply_status.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>
#include <json-c/json.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>

#include "airui_response.h"
#include "airui_ubus_client.h"

enum {
    WIRELESS_SECTION,
    WIRELESS_DISABLED,
    WIRELESS_SSID,
    WIRELESS_ENCRYPTION,
    WIRELESS_KEY,
    WIRELESS_NETWORK,
    WIRELESS_CHANNEL,
    WIRELESS_HTMODE,
    WIRELESS_COUNTRY,
    WIRELESS_DEVICE,
    WIRELESS_MODE,
    WIRELESS_TYPE,
    WIRELESS_HIDDEN,
    WIRELESS_ISOLATE,
    WIRELESS_MAXASSOC,
    WIRELESS_BAND_STEERING,
    WIRELESS_AIRTIME_FAIRNESS,
    WIRELESS_DOWNLOAD,
    WIRELESS_UPLOAD,
    WIRELESS_AIR_VIF_ID,
    WIRELESS_AIR_LINK_ID,
    WIRELESS_AIR_MLD_ID,
    WIRELESS_MLD_ID,
    WIRELESS_SECURITY_REF,
    WIRELESS_NETWORK_REF,
    WIRELESS_QOS_REF,
    WIRELESS_PORTAL_REF,
    WIRELESS_DRY_RUN,
    __WIRELESS_MAX
};

static const struct blobmsg_policy wireless_set_policy[__WIRELESS_MAX] = {
    [WIRELESS_SECTION] = { .name = "section", .type = BLOBMSG_TYPE_STRING },
    [WIRELESS_DISABLED] = { .name = "disabled", .type = BLOBMSG_TYPE_BOOL },
    [WIRELESS_SSID] = { .name = "ssid", .type = BLOBMSG_TYPE_STRING },
    [WIRELESS_ENCRYPTION] = { .name = "encryption", .type = BLOBMSG_TYPE_STRING },
    [WIRELESS_KEY] = { .name = "key", .type = BLOBMSG_TYPE_STRING },
    [WIRELESS_NETWORK] = { .name = "network", .type = BLOBMSG_TYPE_STRING },
    [WIRELESS_CHANNEL] = { .name = "channel", .type = BLOBMSG_TYPE_STRING },
    [WIRELESS_HTMODE] = { .name = "htmode", .type = BLOBMSG_TYPE_STRING },
    [WIRELESS_COUNTRY] = { .name = "country", .type = BLOBMSG_TYPE_STRING },
    [WIRELESS_DEVICE] = { .name = "device", .type = BLOBMSG_TYPE_STRING },
    [WIRELESS_MODE] = { .name = "mode", .type = BLOBMSG_TYPE_STRING },
    [WIRELESS_TYPE] = { .name = "type", .type = BLOBMSG_TYPE_STRING },
    [WIRELESS_HIDDEN] = { .name = "hidden", .type = BLOBMSG_TYPE_BOOL },
    [WIRELESS_ISOLATE] = { .name = "isolate", .type = BLOBMSG_TYPE_BOOL },
    [WIRELESS_MAXASSOC] = { .name = "maxassoc", .type = BLOBMSG_TYPE_STRING },
    [WIRELESS_BAND_STEERING] = { .name = "band_steering", .type = BLOBMSG_TYPE_BOOL },
    [WIRELESS_AIRTIME_FAIRNESS] = { .name = "airtime_fairness", .type = BLOBMSG_TYPE_BOOL },
    [WIRELESS_DOWNLOAD] = { .name = "download", .type = BLOBMSG_TYPE_STRING },
    [WIRELESS_UPLOAD] = { .name = "upload", .type = BLOBMSG_TYPE_STRING },
    [WIRELESS_AIR_VIF_ID] = { .name = "air_vif_id", .type = BLOBMSG_TYPE_STRING },
    [WIRELESS_AIR_LINK_ID] = { .name = "air_link_id", .type = BLOBMSG_TYPE_STRING },
    [WIRELESS_AIR_MLD_ID] = { .name = "air_mld_id", .type = BLOBMSG_TYPE_STRING },
    [WIRELESS_MLD_ID] = { .name = "mld_id", .type = BLOBMSG_TYPE_STRING },
    [WIRELESS_SECURITY_REF] = { .name = "security_ref", .type = BLOBMSG_TYPE_STRING },
    [WIRELESS_NETWORK_REF] = { .name = "network_ref", .type = BLOBMSG_TYPE_STRING },
    [WIRELESS_QOS_REF] = { .name = "qos_ref", .type = BLOBMSG_TYPE_STRING },
    [WIRELESS_PORTAL_REF] = { .name = "portal_ref", .type = BLOBMSG_TYPE_STRING },
    [WIRELESS_DRY_RUN] = { .name = "dry_run", .type = BLOBMSG_TYPE_BOOL },
};

struct wireless_config_data {
    const char *uci_json;
    const char *runtime_json;
    const char *enterprise_json;
};

struct wireless_set_data {
    const char *operation;
    const char *section;
    bool dry_run;
    bool changed;
    const char *uci_action_json;
    const char *uci_commit_json;
    const char *reload_json;
};

static void add_json_or_null(struct blob_buf *b, const char *name, const char *json)
{
    struct json_object *obj;
    void *empty;

    if (!json) {
        empty = blobmsg_open_table(b, name);
        blobmsg_close_table(b, empty);
        return;
    }

    obj = json_tokener_parse(json);
    if (!obj || !blobmsg_add_json_element(b, name, obj)) {
        if (obj) {
            json_object_put(obj);
        }
        empty = blobmsg_open_table(b, name);
        blobmsg_close_table(b, empty);
        return;
    }

    json_object_put(obj);
}

static void wireless_config_builder(struct blob_buf *b, void *user)
{
    struct wireless_config_data *data = user;

    add_json_or_null(b, "uci", data ? data->uci_json : NULL);
    add_json_or_null(b, "runtime", data ? data->runtime_json : NULL);
    add_json_or_null(b, "enterprise", data ? data->enterprise_json : NULL);
}

static const char *json_string_value(struct json_object *obj, const char *key)
{
    struct json_object *value;

    if (!obj || !json_object_object_get_ex(obj, key, &value)) {
        return NULL;
    }

    return json_object_get_string(value);
}

static bool json_has_key(struct json_object *obj, const char *key)
{
    struct json_object *value;

    return obj && key && json_object_object_get_ex(obj, key, &value);
}

static bool json_bool_value(struct json_object *obj, const char *key, bool fallback)
{
    struct json_object *value;
    const char *str;

    if (!obj || !json_object_object_get_ex(obj, key, &value)) {
        return fallback;
    }

    if (json_object_is_type(value, json_type_boolean)) {
        return json_object_get_boolean(value);
    }

    str = json_object_get_string(value);
    if (!str) {
        return fallback;
    }

    return strcmp(str, "1") == 0 || strcasecmp(str, "true") == 0 ||
           strcasecmp(str, "yes") == 0 || strcasecmp(str, "on") == 0;
}

static const char *device_band_key(const char *device)
{
    if (!device) {
        return "unknown";
    }

    if (strcmp(device, "wifi1") == 0 || strcmp(device, "radio0") == 0) {
        return "2g";
    }

    if (strcmp(device, "wifi0") == 0 || strcmp(device, "radio1") == 0) {
        return "5g";
    }

    if (strcmp(device, "wifi2") == 0 || strcmp(device, "radio2") == 0) {
        return "6g";
    }

    return device;
}

static const char *radio_id_for_device(const char *device)
{
    if (!device) {
        return "radio_unknown";
    }

    if (strcmp(device, "wifi1") == 0 || strcmp(device, "radio0") == 0) {
        return "radio_0";
    }

    if (strcmp(device, "wifi0") == 0 || strcmp(device, "radio1") == 0) {
        return "radio_1";
    }

    if (strcmp(device, "wifi2") == 0 || strcmp(device, "radio2") == 0) {
        return "radio_2";
    }

    return device;
}

static void sanitize_identifier(const char *input, char *out, size_t out_len)
{
    size_t i;
    size_t used = 0;

    if (!out || out_len == 0) {
        return;
    }

    out[0] = '\0';
    if (!input || !input[0]) {
        snprintf(out, out_len, "unnamed");
        return;
    }

    for (i = 0; input[i] && used + 1 < out_len; i++) {
        char c = input[i];

        if ((c >= 'a' && c <= 'z') ||
            (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9')) {
            out[used++] = c;
        } else if (used > 0 && out[used - 1] != '_') {
            out[used++] = '_';
        }
    }

    while (used > 0 && out[used - 1] == '_') {
        used--;
    }

    out[used] = '\0';
    if (!out[0]) {
        snprintf(out, out_len, "unnamed");
    }
}

static const char *security_profile_id(struct json_object *iface,
                                       char *buf,
                                       size_t buf_len)
{
    const char *configured = json_string_value(iface, "security_ref");
    const char *encryption;
    char safe[64];

    if (configured && configured[0]) {
        return configured;
    }

    encryption = json_string_value(iface, "encryption");
    sanitize_identifier(encryption ? encryption : "open", safe, sizeof(safe));
    snprintf(buf, buf_len, "sec_%s", safe);
    return buf;
}

static const char *network_profile_id(struct json_object *iface,
                                      char *buf,
                                      size_t buf_len)
{
    const char *configured = json_string_value(iface, "network_ref");
    const char *network;
    char safe[64];

    if (configured && configured[0]) {
        return configured;
    }

    network = json_string_value(iface, "network");
    sanitize_identifier(network ? network : "lan", safe, sizeof(safe));
    snprintf(buf, buf_len, "net_%s", safe);
    return buf;
}

static const char *vif_id_for_iface(const char *section,
                                    struct json_object *iface,
                                    char *buf,
                                    size_t buf_len)
{
    const char *configured = json_string_value(iface, "air_vif_id");
    const char *ssid;
    const char *network;
    uint32_t hash = 2166136261u;
    const char *parts[3];
    size_t i;

    if (configured && configured[0]) {
        return configured;
    }

    ssid = json_string_value(iface, "ssid");
    network = json_string_value(iface, "network");
    parts[0] = ssid && ssid[0] ? ssid : section;
    parts[1] = "|";
    parts[2] = network && network[0] ? network : "lan";

    for (i = 0; i < sizeof(parts) / sizeof(parts[0]); i++) {
        const unsigned char *p = (const unsigned char *)parts[i];

        while (p && *p) {
            hash ^= *p++;
            hash *= 16777619u;
        }
    }

    snprintf(buf, buf_len, "vif_%04x", hash & 0xffffu);
    return buf;
}

static struct json_object *find_or_add_by_id(struct json_object *array,
                                             const char *id_key,
                                             const char *id)
{
    size_t i;

    if (!array || !id) {
        return NULL;
    }

    for (i = 0; i < json_object_array_length(array); i++) {
        struct json_object *item = json_object_array_get_idx(array, i);
        const char *current = json_string_value(item, id_key);

        if (current && strcmp(current, id) == 0) {
            return item;
        }
    }

    {
        struct json_object *item = json_object_new_object();
        json_object_object_add(item, id_key, json_object_new_string(id));
        json_object_array_add(array, item);
        return item;
    }
}

static void add_unique_string(struct json_object *array, const char *value)
{
    size_t i;

    if (!array || !value || !value[0]) {
        return;
    }

    for (i = 0; i < json_object_array_length(array); i++) {
        struct json_object *item = json_object_array_get_idx(array, i);
        const char *current = json_object_get_string(item);

        if (current && strcmp(current, value) == 0) {
            return;
        }
    }

    json_object_array_add(array, json_object_new_string(value));
}

static struct json_object *runtime_for_device(struct json_object *runtime_values,
                                              const char *device,
                                              const char *band)
{
    struct json_object *runtime = NULL;

    if (runtime_values && device &&
        json_object_object_get_ex(runtime_values, device, &runtime)) {
        return runtime;
    }

    if (runtime_values && band &&
        json_object_object_get_ex(runtime_values, band, &runtime)) {
        return runtime;
    }

    return NULL;
}

static struct json_object *runtime_for_iface(struct json_object *runtime_values,
                                             const char *section,
                                             const char *device,
                                             const char *band)
{
    struct json_object *radio;
    struct json_object *interfaces;
    size_t i;

    if (runtime_values && section &&
        json_object_object_get_ex(runtime_values, section, &radio)) {
        return radio;
    }

    radio = runtime_for_device(runtime_values, device, band);
    if (!radio || !json_object_object_get_ex(radio, "interfaces", &interfaces) ||
        !json_object_is_type(interfaces, json_type_array)) {
        return NULL;
    }

    for (i = 0; i < json_object_array_length(interfaces); i++) {
        struct json_object *iface = json_object_array_get_idx(interfaces, i);
        const char *runtime_section = json_string_value(iface, "section");

        if (runtime_section && section && strcmp(runtime_section, section) == 0) {
            return iface;
        }
    }

    return NULL;
}

static int next_link_id(struct json_object *links)
{
    if (!links || !json_object_is_type(links, json_type_array)) {
        return 0;
    }

    return (int)json_object_array_length(links);
}

static void add_radio_if_missing(struct json_object *radios,
                                 struct json_object *values,
                                 struct json_object *runtime_values,
                                 const char *section,
                                 struct json_object *cfg)
{
    const char *device = section;
    const char *band;
    const char *radio_id;
    struct json_object *radio;
    struct json_object *capabilities;
    struct json_object *runtime;
    struct json_object *runtime_copy = NULL;
    int max_width = 80;

    if (!cfg || strcmp(json_string_value(cfg, ".type") ? json_string_value(cfg, ".type") : "",
                       "wifi-device") != 0) {
        return;
    }

    (void)values;
    band = device_band_key(device);
    radio_id = radio_id_for_device(device);
    if (find_or_add_by_id(radios, "radio_id", radio_id) !=
        json_object_array_get_idx(radios, json_object_array_length(radios) - 1)) {
        return;
    }

    radio = json_object_array_get_idx(radios, json_object_array_length(radios) - 1);
    json_object_object_add(radio, "band", json_object_new_string(band));
    json_object_object_add(radio, "phy",
                           json_object_new_string(json_string_value(cfg, "phy") ?:
                                                  device));

    capabilities = json_object_new_object();
    json_object_object_add(capabilities, "wifi6", json_object_new_boolean(true));
    json_object_object_add(capabilities, "wifi7", json_object_new_boolean(strcmp(band, "2g") != 0));
    json_object_object_add(capabilities, "mlo", json_object_new_boolean(strcmp(band, "2g") != 0));
    if (strcmp(band, "2g") == 0) {
        max_width = 40;
    } else if (strcmp(band, "6g") == 0) {
        max_width = 320;
    } else {
        max_width = 160;
    }
    json_object_object_add(capabilities, "max_channel_width_mhz", json_object_new_int(max_width));
    json_object_object_add(radio, "capabilities", capabilities);

    runtime = runtime_for_device(runtime_values, device, band);
    if (runtime) {
        runtime_copy = json_object_get(runtime);
    } else {
        runtime_copy = json_object_new_object();
    }
    json_object_object_add(radio, "runtime", runtime_copy);
}

static void add_profiles(struct json_object *enterprise,
                         struct json_object *iface,
                         const char *security_ref,
                         const char *network_ref)
{
    struct json_object *security_profiles;
    struct json_object *network_profiles;

    if (!json_object_object_get_ex(enterprise, "security_profiles", &security_profiles)) {
        security_profiles = json_object_new_object();
        json_object_object_add(enterprise, "security_profiles", security_profiles);
    }

    if (!json_object_object_get_ex(enterprise, "network_profiles", &network_profiles)) {
        network_profiles = json_object_new_object();
        json_object_object_add(enterprise, "network_profiles", network_profiles);
    }

    if (security_ref && !json_has_key(security_profiles, security_ref)) {
        struct json_object *profile = json_object_new_object();
        const char *encryption = json_string_value(iface, "encryption");

        json_object_object_add(profile, "type",
                               json_object_new_string(encryption && encryption[0] ? encryption : "none"));
        json_object_object_add(profile, "pmf",
                               json_object_new_string(json_string_value(iface, "ieee80211w") ?: "optional"));
        json_object_object_add(security_profiles, security_ref, profile);
    }

    if (network_ref && !json_has_key(network_profiles, network_ref)) {
        struct json_object *profile = json_object_new_object();
        const char *network = json_string_value(iface, "network");

        json_object_object_add(profile, "network",
                               json_object_new_string(network && network[0] ? network : "lan"));
        json_object_object_add(profile, "client_isolation",
                               json_object_new_boolean(json_bool_value(iface, "isolate", false)));
        json_object_object_add(network_profiles, network_ref, profile);
    }
}

static char *build_enterprise_wireless_json(const char *uci_json, const char *runtime_json)
{
    struct json_object *uci = NULL;
    struct json_object *runtime = NULL;
    struct json_object *values = NULL;
    struct json_object *runtime_values = NULL;
    struct json_object *enterprise = NULL;
    struct json_object *radios;
    struct json_object *vifs;
    const char *json;
    char *copy = NULL;

    if (uci_json) {
        uci = json_tokener_parse(uci_json);
    }
    if (runtime_json) {
        runtime = json_tokener_parse(runtime_json);
    }

    enterprise = json_object_new_object();
    radios = json_object_new_array();
    vifs = json_object_new_array();
    json_object_object_add(enterprise, "schema", json_object_new_string("airui.enterprise.wireless.v1"));
    json_object_object_add(enterprise, "radios", radios);
    json_object_object_add(enterprise, "vifs", vifs);
    json_object_object_add(enterprise, "security_profiles", json_object_new_object());
    json_object_object_add(enterprise, "network_profiles", json_object_new_object());
    json_object_object_add(enterprise, "qos_profiles", json_object_new_object());
    json_object_object_add(enterprise, "portal_profiles", json_object_new_object());

    if (uci) {
        json_object_object_get_ex(uci, "values", &values);
    }
    runtime_values = runtime;

    if (values && json_object_is_type(values, json_type_object)) {
        {
            json_object_object_foreach(values, section, cfg) {
                add_radio_if_missing(radios, values, runtime_values, section, cfg);
            }
        }

        {
            json_object_object_foreach(values, section, cfg) {
                const char *type = json_string_value(cfg, ".type");
                const char *device;
                const char *band;
                const char *radio_id;
                const char *vif_id;
                const char *mld_id;
                const char *security_ref;
                const char *network_ref;
                char generated_vif_id[160];
                char generated_security_ref[96];
                char generated_network_ref[96];
                struct json_object *vif;
                struct json_object *identity;
                struct json_object *configuration;
                struct json_object *deployment;
                struct json_object *bands;
                struct json_object *mlo;
                struct json_object *links;
                struct json_object *link;
                struct json_object *sync;
                struct json_object *runtime_iface;
                int link_id;

                if (!type || strcmp(type, "wifi-iface") != 0) {
                    continue;
                }

                device = json_string_value(cfg, "device");
                band = device_band_key(device);
                radio_id = radio_id_for_device(device);
                vif_id = vif_id_for_iface(section, cfg, generated_vif_id, sizeof(generated_vif_id));
                security_ref = security_profile_id(cfg, generated_security_ref, sizeof(generated_security_ref));
                network_ref = network_profile_id(cfg, generated_network_ref, sizeof(generated_network_ref));

                vif = find_or_add_by_id(vifs, "vif_id", vif_id);
                if (!json_object_object_get_ex(vif, "identity", &identity)) {
                    const char *ssid = json_string_value(cfg, "ssid");

                    identity = json_object_new_object();
                    json_object_object_add(identity, "name",
                                           json_object_new_string(ssid && ssid[0] ? ssid : vif_id));
                    json_object_object_add(identity, "ssid",
                                           json_object_new_string(ssid && ssid[0] ? ssid : ""));
                    json_object_object_add(vif, "identity", identity);

                    configuration = json_object_new_object();
                    json_object_object_add(configuration, "enabled",
                                           json_object_new_boolean(!json_bool_value(cfg, "disabled", false)));
                    json_object_object_add(configuration, "mode",
                                           json_object_new_string(json_string_value(cfg, "mode") ?: "ap"));
                    json_object_object_add(configuration, "security_ref", json_object_new_string(security_ref));
                    json_object_object_add(configuration, "network_ref", json_object_new_string(network_ref));
                    json_object_object_add(configuration, "qos_ref",
                                           json_object_new_string(json_string_value(cfg, "qos_ref") ?: "qos_default"));
                    if (json_string_value(cfg, "portal_ref")) {
                        json_object_object_add(configuration, "portal_ref",
                                               json_object_new_string(json_string_value(cfg, "portal_ref")));
                    } else {
                        json_object_object_add(configuration, "portal_ref", json_object_new_null());
                    }
                    json_object_object_add(vif, "configuration", configuration);

                    deployment = json_object_new_object();
                    bands = json_object_new_array();
                    mlo = json_object_new_object();
                    json_object_object_add(deployment, "bands", bands);
                    json_object_object_add(deployment, "mlo", mlo);
                    json_object_object_add(vif, "deployment", deployment);

                    links = json_object_new_array();
                    json_object_object_add(vif, "links", links);

                    sync = json_object_new_object();
                    json_object_object_add(sync, "desired_revision",
                                           json_object_new_int(json_string_value(cfg, "revision")
                                                               ? atoi(json_string_value(cfg, "revision")) : 0));
                    json_object_object_add(sync, "applied_revision",
                                           json_object_new_int(json_string_value(cfg, "applied_revision")
                                                               ? atoi(json_string_value(cfg, "applied_revision")) : 0));
                    json_object_object_add(sync, "state",
                                           json_object_new_string(json_string_value(cfg, "sync_state") ?: "synced"));
                    json_object_object_add(vif, "synchronization", sync);

                    add_profiles(enterprise, cfg, security_ref, network_ref);
                } else {
                    json_object_object_get_ex(vif, "deployment", &deployment);
                    json_object_object_get_ex(deployment, "bands", &bands);
                    json_object_object_get_ex(vif, "links", &links);
                }

                add_unique_string(bands, band);

                json_object_object_get_ex(deployment, "mlo", &mlo);
                mld_id = json_string_value(cfg, "air_mld_id");
                if (!mld_id) {
                    mld_id = json_string_value(cfg, "mld_id");
                }
                if (mld_id && mld_id[0]) {
                    json_object_object_add(mlo, "enabled", json_object_new_boolean(true));
                    json_object_object_add(mlo, "mld_id", json_object_new_string(mld_id));
                    if (json_string_value(cfg, "mld_mac")) {
                        json_object_object_add(mlo, "mld_mac",
                                               json_object_new_string(json_string_value(cfg, "mld_mac")));
                    }
                } else if (!json_has_key(mlo, "enabled")) {
                    json_object_object_add(mlo, "enabled", json_object_new_boolean(false));
                }

                link_id = json_string_value(cfg, "air_link_id")
                    ? atoi(json_string_value(cfg, "air_link_id"))
                    : next_link_id(links);
                runtime_iface = runtime_for_iface(runtime_values, section, device, band);

                link = json_object_new_object();
                json_object_object_add(link, "link_id", json_object_new_int(link_id));
                json_object_object_add(link, "radio_id", json_object_new_string(radio_id));
                json_object_object_add(link, "band", json_object_new_string(band));
                json_object_object_add(link, "uci_section", json_object_new_string(section));
                json_object_object_add(link, "phy",
                                       json_object_new_string(json_string_value(cfg, "phy") ?: device ?: ""));
                json_object_object_add(link, "ifname",
                                       json_object_new_string(json_string_value(cfg, "ifname") ?:
                                                              json_string_value(runtime_iface, "ifname") ?:
                                                              section));
                json_object_object_add(link, "bssid",
                                       json_object_new_string(json_string_value(cfg, "bssid") ?:
                                                              json_string_value(runtime_iface, "bssid") ?:
                                                              ""));
                json_object_object_add(link, "state",
                                       json_object_new_string(json_bool_value(cfg, "disabled", false)
                                                              ? "down" : "up"));
                json_object_array_add(links, link);
            }
        }
    }

    json = json_object_to_json_string_ext(enterprise, JSON_C_TO_STRING_PLAIN);
    if (json) {
        copy = strdup(json);
    }

    if (uci) {
        json_object_put(uci);
    }
    if (runtime) {
        json_object_put(runtime);
    }
    json_object_put(enterprise);

    return copy;
}

static void wireless_set_builder(struct blob_buf *b, void *user)
{
    struct wireless_set_data *data = user;

    if (!data) {
        return;
    }

    blobmsg_add_string(b, "operation", data->operation);
    blobmsg_add_string(b, "section", data->section);
    blobmsg_add_u8(b, "dry_run", data->dry_run);
    blobmsg_add_u8(b, "changed", data->changed);
    add_json_or_null(b, "uci_action", data->uci_action_json);
    add_json_or_null(b, "uci_commit", data->uci_commit_json);
    add_json_or_null(b, "wireless_reload", data->reload_json);
}

static bool valid_section_name(const char *section)
{
    const char *p;

    if (!section || !section[0]) {
        return false;
    }

    for (p = section; *p; p++) {
        if ((*p >= 'a' && *p <= 'z') ||
            (*p >= 'A' && *p <= 'Z') ||
            (*p >= '0' && *p <= '9') ||
            *p == '_' || *p == '-') {
            continue;
        }
        return false;
    }

    return true;
}

static void generate_vif_section(char *buf,
                                 size_t buf_len,
                                 const char *ssid,
                                 const char *device)
{
    uint32_t hash = 2166136261u;
    const char *parts[6];
    static unsigned int seq;
    size_t i;

    if (!buf || buf_len == 0) {
        return;
    }

    parts[0] = ssid && ssid[0] ? ssid : "ssid";
    parts[1] = "|";
    parts[2] = device && device[0] ? device : "radio";
    parts[3] = "|";
    parts[4] = NULL;
    parts[5] = NULL;

    {
        char salt[64];
        snprintf(salt, sizeof(salt), "%ld:%ld:%u",
                 (long)time(NULL), (long)getpid(), ++seq);
        parts[4] = salt;

        for (i = 0; i < sizeof(parts) / sizeof(parts[0]); i++) {
            const unsigned char *p = (const unsigned char *)parts[i];

            while (p && *p) {
                hash ^= *p++;
                hash *= 16777619u;
            }
        }
    }

    snprintf(buf, buf_len, "vif_%06x", hash & 0xffffffu);
}

static bool valid_string_len(struct blob_attr *attr, size_t max_len)
{
    const char *value;

    if (!attr) {
        return true;
    }

    value = blobmsg_get_string(attr);
    return value && strlen(value) <= max_len;
}

static bool has_wireless_changes(struct blob_attr **tb)
{
    return tb[WIRELESS_DISABLED] || tb[WIRELESS_SSID] ||
           tb[WIRELESS_ENCRYPTION] || tb[WIRELESS_KEY] ||
           tb[WIRELESS_NETWORK] || tb[WIRELESS_CHANNEL] ||
           tb[WIRELESS_HTMODE] || tb[WIRELESS_COUNTRY] ||
           tb[WIRELESS_DEVICE] || tb[WIRELESS_MODE] ||
           tb[WIRELESS_TYPE] || tb[WIRELESS_HIDDEN] ||
           tb[WIRELESS_ISOLATE] || tb[WIRELESS_MAXASSOC] ||
           tb[WIRELESS_BAND_STEERING] || tb[WIRELESS_AIRTIME_FAIRNESS] ||
           tb[WIRELESS_DOWNLOAD] || tb[WIRELESS_UPLOAD] ||
           tb[WIRELESS_AIR_VIF_ID] || tb[WIRELESS_AIR_LINK_ID] ||
           tb[WIRELESS_AIR_MLD_ID] || tb[WIRELESS_MLD_ID] ||
           tb[WIRELESS_SECURITY_REF] || tb[WIRELESS_NETWORK_REF] ||
           tb[WIRELESS_QOS_REF] || tb[WIRELESS_PORTAL_REF];
}

static void add_string_value(struct blob_buf *b,
                             struct blob_attr **tb,
                             int field,
                             const char *name)
{
    if (tb[field]) {
        blobmsg_add_string(b, name, blobmsg_get_string(tb[field]));
    }
}

static void add_wireless_values(struct blob_buf *b,
                                struct blob_attr **tb,
                                const char *type,
                                const char *generated_vif_id)
{
    void *values = blobmsg_open_table(b, "values");
    bool is_radio = type && strcmp(type, "wifi-device") == 0;

    if (tb[WIRELESS_DISABLED]) {
        blobmsg_add_string(b, "disabled",
                           blobmsg_get_bool(tb[WIRELESS_DISABLED]) ? "1" : "0");
    }
    if (tb[WIRELESS_HIDDEN]) {
        blobmsg_add_string(b, "hidden",
                           blobmsg_get_bool(tb[WIRELESS_HIDDEN]) ? "1" : "0");
    }
    if (tb[WIRELESS_ISOLATE]) {
        blobmsg_add_string(b, "isolate",
                           blobmsg_get_bool(tb[WIRELESS_ISOLATE]) ? "1" : "0");
    }
    if (tb[WIRELESS_BAND_STEERING]) {
        blobmsg_add_string(b, "band_steering",
                           blobmsg_get_bool(tb[WIRELESS_BAND_STEERING]) ? "1" : "0");
    }
    if (tb[WIRELESS_AIRTIME_FAIRNESS]) {
        blobmsg_add_string(b, "airtime_fairness",
                           blobmsg_get_bool(tb[WIRELESS_AIRTIME_FAIRNESS]) ? "1" : "0");
    }
    add_string_value(b, tb, WIRELESS_SSID, "ssid");
    add_string_value(b, tb, WIRELESS_ENCRYPTION, "encryption");
    add_string_value(b, tb, WIRELESS_KEY, "key");
    add_string_value(b, tb, WIRELESS_NETWORK, "network");
    add_string_value(b, tb, WIRELESS_CHANNEL, "channel");
    add_string_value(b, tb, WIRELESS_HTMODE, "htmode");
    add_string_value(b, tb, WIRELESS_COUNTRY, "country");
    add_string_value(b, tb, WIRELESS_DEVICE, "device");
    if (!is_radio) {
        add_string_value(b, tb, WIRELESS_MODE, "mode");
    }
    add_string_value(b, tb, WIRELESS_MAXASSOC, "maxassoc");
    add_string_value(b, tb, WIRELESS_DOWNLOAD, "downrate");
    add_string_value(b, tb, WIRELESS_UPLOAD, "uprate");
    if (tb[WIRELESS_AIR_VIF_ID]) {
        add_string_value(b, tb, WIRELESS_AIR_VIF_ID, "air_vif_id");
    } else if (generated_vif_id && generated_vif_id[0]) {
        blobmsg_add_string(b, "air_vif_id", generated_vif_id);
    }
    add_string_value(b, tb, WIRELESS_AIR_LINK_ID, "air_link_id");
    add_string_value(b, tb, WIRELESS_AIR_MLD_ID, "air_mld_id");
    add_string_value(b, tb, WIRELESS_MLD_ID, "mld_id");
    add_string_value(b, tb, WIRELESS_SECURITY_REF, "security_ref");
    add_string_value(b, tb, WIRELESS_NETWORK_REF, "network_ref");
    add_string_value(b, tb, WIRELESS_QOS_REF, "qos_ref");
    add_string_value(b, tb, WIRELESS_PORTAL_REF, "portal_ref");

    blobmsg_close_table(b, values);
}

static int delete_wireless_option(struct ubus_context *ctx,
                                  const char *section,
                                  const char *option)
{
    struct airui_ubus_result result = {};
    struct blob_buf b = {};
    int ret;

    if (!section || !section[0] || !option || !option[0]) {
        return 0;
    }

    blob_buf_init(&b, 0);
    blobmsg_add_string(&b, "config", "wireless");
    blobmsg_add_string(&b, "section", section);
    blobmsg_add_string(&b, "option", option);
    ret = airui_ubus_call_json(ctx, "uci", "delete", &b, &result);
    blob_buf_free(&b);
    airui_ubus_result_free(&result);

    return ret;
}

static int commit_and_reload(struct ubus_context *ctx,
                             struct airui_ubus_result *commit,
                             struct airui_ubus_result *reload)
{
    struct blob_buf uci_commit = {};
    int ret;

    blob_buf_init(&uci_commit, 0);
    blobmsg_add_string(&uci_commit, "config", "wireless");
    ret = airui_ubus_call_json(ctx, "uci", "commit", &uci_commit, commit);
    blob_buf_free(&uci_commit);
    if (ret) {
        return ret;
    }

    {
        bool recovered = false;
        return airui_network_reload_with_recovery(ctx, reload, 15, &recovered);
    }
}

static bool validate_common_wireless_fields(struct ubus_context *ctx,
                                            struct ubus_request_data *req,
                                            struct blob_attr **tb)
{
    if (!valid_string_len(tb[WIRELESS_SSID], 32)) {
        airui_reply_error(ctx, req, "invalid_argument", "ssid",
                          "SSID must be 32 characters or fewer");
        return false;
    }

    if (!valid_string_len(tb[WIRELESS_KEY], 63)) {
        airui_reply_error(ctx, req, "invalid_argument", "key",
                          "Wireless key must be 63 characters or fewer");
        return false;
    }

    return true;
}

int airui_network_wireless_config(struct ubus_context *ctx,
                                  struct ubus_object *obj,
                                  struct ubus_request_data *req,
                                  const char *method,
                                  struct blob_attr *msg)
{
    struct airui_ubus_result uci = {};
    struct airui_ubus_result runtime = {};
    struct wireless_config_data data;
    struct blob_buf query = {};

    (void)obj;
    (void)method;
    (void)msg;

    blob_buf_init(&query, 0);
    blobmsg_add_string(&query, "config", "wireless");
    airui_ubus_call_json(ctx, "uci", "get", &query, &uci);
    blob_buf_free(&query);

    airui_ubus_call_json(ctx, "network.wireless", "status", NULL, &runtime);

    data.uci_json = uci.json;
    data.runtime_json = runtime.json;
    data.enterprise_json = build_enterprise_wireless_json(uci.json, runtime.json);
    airui_reply_ok(ctx, req, wireless_config_builder, &data);

    free((void *)data.enterprise_json);
    airui_ubus_result_free(&uci);
    airui_ubus_result_free(&runtime);
    return 0;
}

int airui_network_wireless_set(struct ubus_context *ctx,
                               struct ubus_object *obj,
                               struct ubus_request_data *req,
                               const char *method,
                               struct blob_attr *msg)
{
    struct blob_attr *tb[__WIRELESS_MAX];
    struct airui_ubus_result set = {};
    struct airui_ubus_result commit = {};
    struct airui_ubus_result reload = {};
    struct wireless_set_data data = {};
    struct blob_buf uci_set = {};
    const char *section;
    const char *type = NULL;
    bool dry_run;
    int ret;

    (void)obj;
    (void)method;

    blobmsg_parse(wireless_set_policy,
                  __WIRELESS_MAX,
                  tb,
                  msg ? blob_data(msg) : NULL,
                  msg ? blob_len(msg) : 0);

    if (!tb[WIRELESS_SECTION]) {
        airui_reply_error(ctx, req, "invalid_argument", "section",
                          "Wireless section is required");
        return 0;
    }

    section = blobmsg_get_string(tb[WIRELESS_SECTION]);
    if (!valid_section_name(section)) {
        airui_reply_error(ctx, req, "invalid_argument", "section",
                          "Wireless section contains unsupported characters");
        return 0;
    }

    if (!has_wireless_changes(tb)) {
        airui_reply_error(ctx, req, "invalid_argument", NULL,
                          "At least one wireless field must be provided");
        return 0;
    }

    if (!validate_common_wireless_fields(ctx, req, tb)) {
        return 0;
    }

    dry_run = tb[WIRELESS_DRY_RUN] && blobmsg_get_bool(tb[WIRELESS_DRY_RUN]);
    if (tb[WIRELESS_TYPE]) {
        type = blobmsg_get_string(tb[WIRELESS_TYPE]);
    }

    data.operation = "set";
    data.section = section;
    data.dry_run = dry_run;
    data.changed = !dry_run;

    if (!dry_run) {
        airui_apply_begin("wireless");
        blob_buf_init(&uci_set, 0);
        blobmsg_add_string(&uci_set, "config", "wireless");
        blobmsg_add_string(&uci_set, "section", section);
        add_wireless_values(&uci_set, tb, type, NULL);

        ret = airui_ubus_call_json(ctx, "uci", "set", &uci_set, &set);
        blob_buf_free(&uci_set);
        if (ret) {
            airui_apply_failed("Unable to update wireless configuration");
            airui_reply_error(ctx, req, "backend_unavailable", "uci",
                              ubus_strerror(ret));
            return 0;
        }

        if (type && strcmp(type, "wifi-device") == 0) {
            delete_wireless_option(ctx, section, "mode");
        }

        ret = commit_and_reload(ctx, &commit, &reload);
        if (ret) {
            airui_apply_failed("Unable to commit or reload wireless configuration");
            airui_ubus_result_free(&set);
            airui_reply_error(ctx, req, "backend_unavailable", NULL,
                              ubus_strerror(ret));
            return 0;
        }
    }

    data.uci_action_json = set.json;
    data.uci_commit_json = commit.json;
    data.reload_json = reload.json;
    airui_reply_ok(ctx, req, wireless_set_builder, &data);

    if (!dry_run)
        airui_apply_success("Wireless configuration applied");

    airui_ubus_result_free(&set);
    airui_ubus_result_free(&commit);
    airui_ubus_result_free(&reload);
    return 0;
}

int airui_network_wireless_add(struct ubus_context *ctx,
                               struct ubus_object *obj,
                               struct ubus_request_data *req,
                               const char *method,
                               struct blob_attr *msg)
{
    struct blob_attr *tb[__WIRELESS_MAX];
    struct airui_ubus_result add = {};
    struct airui_ubus_result commit = {};
    struct airui_ubus_result reload = {};
    struct wireless_set_data data = {};
    struct blob_buf uci_add = {};
    const char *section = NULL;
    const char *type = "wifi-iface";
    char generated_section[32] = {};
    bool dry_run;
    int ret;

    (void)obj;
    (void)method;

    blobmsg_parse(wireless_set_policy,
                  __WIRELESS_MAX,
                  tb,
                  msg ? blob_data(msg) : NULL,
                  msg ? blob_len(msg) : 0);

    if (tb[WIRELESS_SECTION]) {
        section = blobmsg_get_string(tb[WIRELESS_SECTION]);
        if (section && !section[0]) {
            section = NULL;
        }
        if (section && !valid_section_name(section)) {
            airui_reply_error(ctx, req, "invalid_argument", "section",
                              "Wireless section contains unsupported characters");
            return 0;
        }
    }

    if (tb[WIRELESS_TYPE]) {
        type = blobmsg_get_string(tb[WIRELESS_TYPE]);
    }

    if (strcmp(type, "wifi-iface") != 0 && strcmp(type, "wifi-device") != 0) {
        airui_reply_error(ctx, req, "invalid_argument", "type",
                          "Wireless type must be wifi-iface or wifi-device");
        return 0;
    }

    if (strcmp(type, "wifi-iface") == 0 && !tb[WIRELESS_DEVICE]) {
        airui_reply_error(ctx, req, "invalid_argument", "device",
                          "Wireless interface add requires a device");
        return 0;
    }

    if (strcmp(type, "wifi-iface") == 0 && !section) {
        generate_vif_section(generated_section, sizeof(generated_section),
                             tb[WIRELESS_SSID] ? blobmsg_get_string(tb[WIRELESS_SSID]) : NULL,
                             tb[WIRELESS_DEVICE] ? blobmsg_get_string(tb[WIRELESS_DEVICE]) : NULL);
        section = generated_section;
    }

    if (!validate_common_wireless_fields(ctx, req, tb)) {
        return 0;
    }

    dry_run = tb[WIRELESS_DRY_RUN] && blobmsg_get_bool(tb[WIRELESS_DRY_RUN]);
    data.operation = "add";
    data.section = section ? section : "";
    data.dry_run = dry_run;
    data.changed = !dry_run;

    if (!dry_run) {
        blob_buf_init(&uci_add, 0);
        blobmsg_add_string(&uci_add, "config", "wireless");
        blobmsg_add_string(&uci_add, "type", type);
        if (section) {
            blobmsg_add_string(&uci_add, "name", section);
        }
        add_wireless_values(&uci_add, tb, type,
                            strcmp(type, "wifi-iface") == 0 ? section : NULL);

        ret = airui_ubus_call_json(ctx, "uci", "add", &uci_add, &add);
        blob_buf_free(&uci_add);
        if (ret) {
            airui_reply_error(ctx, req, "backend_unavailable", "uci",
                              ubus_strerror(ret));
            return 0;
        }

        ret = commit_and_reload(ctx, &commit, &reload);
        if (ret) {
            airui_ubus_result_free(&add);
            airui_reply_error(ctx, req, "backend_unavailable", NULL,
                              ubus_strerror(ret));
            return 0;
        }
    }

    data.uci_action_json = add.json;
    data.uci_commit_json = commit.json;
    data.reload_json = reload.json;
    airui_reply_ok(ctx, req, wireless_set_builder, &data);

    airui_ubus_result_free(&add);
    airui_ubus_result_free(&commit);
    airui_ubus_result_free(&reload);
    return 0;
}

int airui_network_wireless_delete(struct ubus_context *ctx,
                                  struct ubus_object *obj,
                                  struct ubus_request_data *req,
                                  const char *method,
                                  struct blob_attr *msg)
{
    struct blob_attr *tb[__WIRELESS_MAX];
    struct airui_ubus_result del = {};
    struct airui_ubus_result commit = {};
    struct airui_ubus_result reload = {};
    struct wireless_set_data data = {};
    struct blob_buf uci_delete = {};
    const char *section;
    bool dry_run;
    int ret;

    (void)obj;
    (void)method;

    blobmsg_parse(wireless_set_policy,
                  __WIRELESS_MAX,
                  tb,
                  msg ? blob_data(msg) : NULL,
                  msg ? blob_len(msg) : 0);

    if (!tb[WIRELESS_SECTION]) {
        airui_reply_error(ctx, req, "invalid_argument", "section",
                          "Wireless section is required");
        return 0;
    }

    section = blobmsg_get_string(tb[WIRELESS_SECTION]);
    if (!valid_section_name(section)) {
        airui_reply_error(ctx, req, "invalid_argument", "section",
                          "Wireless section contains unsupported characters");
        return 0;
    }

    dry_run = tb[WIRELESS_DRY_RUN] && blobmsg_get_bool(tb[WIRELESS_DRY_RUN]);
    data.operation = "delete";
    data.section = section;
    data.dry_run = dry_run;
    data.changed = !dry_run;

    if (!dry_run) {
        blob_buf_init(&uci_delete, 0);
        blobmsg_add_string(&uci_delete, "config", "wireless");
        blobmsg_add_string(&uci_delete, "section", section);

        ret = airui_ubus_call_json(ctx, "uci", "delete", &uci_delete, &del);
        blob_buf_free(&uci_delete);
        if (ret) {
            airui_reply_error(ctx, req, "backend_unavailable", "uci",
                              ubus_strerror(ret));
            return 0;
        }

        ret = commit_and_reload(ctx, &commit, &reload);
        if (ret) {
            airui_ubus_result_free(&del);
            airui_reply_error(ctx, req, "backend_unavailable", NULL,
                              ubus_strerror(ret));
            return 0;
        }
    }

    data.uci_action_json = del.json;
    data.uci_commit_json = commit.json;
    data.reload_json = reload.json;
    airui_reply_ok(ctx, req, wireless_set_builder, &data);

    airui_ubus_result_free(&del);
    airui_ubus_result_free(&commit);
    airui_ubus_result_free(&reload);
    return 0;
}
