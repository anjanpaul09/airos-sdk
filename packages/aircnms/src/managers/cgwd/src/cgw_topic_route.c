#include <json-c/json.h>
#include <limits.h>
#include <string.h>
#include "cgw_topic_route.h"

static bool subscribed(const char topics[][CGW_ROUTE_TOPIC_LEN], int topic_count,
                       const char *topic)
{
    int i;

    if (!topics || !topic || !topic[0] || topic_count < 0 || topic_count > 16)
        return false;
    for (i = 0; i < topic_count; i++)
        if (strcmp(topics[i], topic) == 0)
            return true;
    return false;
}

cgw_topic_route_t cgw_topic_route(const char topics[][CGW_ROUTE_TOPIC_LEN],
                                  int topic_count, const char *topic)
{
    const char *leaf;

    if (!subscribed(topics, topic_count, topic))
        return CGW_ROUTE_REJECT;
    leaf = strrchr(topic, '/');
    leaf = leaf ? leaf + 1 : topic;
    if (strcmp(leaf, "config") == 0)
        return CGW_ROUTE_CONFIG;
    if (strcmp(leaf, "cmd") == 0)
        return CGW_ROUTE_COMMAND;
    if (strcmp(leaf, "bw_list") == 0)
        return CGW_ROUTE_ACL;
    if (strcmp(leaf, "rate_limit") == 0)
        return CGW_ROUTE_RATE_LIMIT;
    return CGW_ROUTE_REJECT;
}

static unsigned count_cmd_keys(const char *payload, size_t payload_len)
{
    static const char key[] = "\"cmd\"";
    unsigned count = 0;
    size_t i;

    for (i = 0; i + sizeof(key) - 1 <= payload_len; i++)
        if (memcmp(payload + i, key, sizeof(key) - 1) == 0)
            count++;
    return count;
}

bool cgw_payload_is_rf_scan(const void *payload, size_t payload_len)
{
    struct json_tokener *tok = NULL;
    struct json_object *root = NULL;
    struct json_object *cmd = NULL;
    enum json_tokener_error error;
    bool result = false;

    if (!payload || payload_len == 0 || payload_len > 1024 * 1024 ||
        payload_len > (size_t)INT_MAX ||
        count_cmd_keys(payload, payload_len) != 1)
        return false;
    tok = json_tokener_new();
    if (!tok)
        return false;
    json_tokener_set_flags(tok, JSON_TOKENER_STRICT);
    root = json_tokener_parse_ex(tok, payload, (int)payload_len);
    error = json_tokener_get_error(tok);
    if (error != json_tokener_success || !root ||
        json_object_get_type(root) != json_type_object ||
        json_tokener_get_parse_end(tok) != payload_len)
        goto out;
    if (!json_object_object_get_ex(root, "cmd", &cmd) ||
        json_object_get_type(cmd) != json_type_string)
        goto out;
    result = strcmp(json_object_get_string(cmd), "rf_scan") == 0;
out:
    if (root)
        json_object_put(root);
    json_tokener_free(tok);
    return result;
}

const char *cgw_topic_route_string(cgw_topic_route_t route)
{
    switch (route) {
    case CGW_ROUTE_CONFIG: return "CONFIG";
    case CGW_ROUTE_COMMAND: return "COMMAND";
    case CGW_ROUTE_ACL: return "ACL";
    case CGW_ROUTE_RATE_LIMIT: return "RATE_LIMIT";
    default: return "REJECT";
    }
}
