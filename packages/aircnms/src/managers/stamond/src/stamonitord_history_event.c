/*
 * stamonitord_history_event.c
 */

#include "stamonitord_info_events.h"
#include "stamonitord_history_event.h"
#include "stamonitord_ubus_tx.h"

#include "info_events.h"
#include "log.h"

#include <jansson.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <inttypes.h>
#include <dirent.h>
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>

#define HISTORY_SPOOL_DIR             "/tmp/ap-history"
#define HISTORY_SPOOL_PREFIX          "history-"
#define HISTORY_SPOOL_SUFFIX          ".json"
#define HISTORY_BATCH_PREFIX          "batch-"
#define HISTORY_FILE_MAX_BYTES        (1024U * 1024U)
#define HISTORY_FILE_MAX_COUNT        5
#define HISTORY_BATCH_FILE_COUNT      4
#define HISTORY_JSON_FOOTER_RESERVE   128
#define HISTORY_INTERVAL_MS           (3ULL * 60ULL * 1000ULL)
#define HISTORY_BATCH_WINDOW_MS \
    (HISTORY_INTERVAL_MS * HISTORY_BATCH_FILE_COUNT)

typedef struct {
    char name[NAME_MAX + 1];
    char path[PATH_MAX];
} history_spool_file_t;

typedef struct history_agg_entry {
    char domain[256];
    char service[64];
    char type[16];
    char mac[18];
    uint64_t uploaded;
    uint64_t downloaded;
    uint64_t time_spent_ms;
    uint64_t visits;
    uint64_t connections;
    uint64_t type_bytes;
    bool active;
    struct history_agg_entry *next;
} history_agg_entry_t;

/* ------------------------------------------------------------------------- */
/* JSON BUFFER                                                               */
/* ------------------------------------------------------------------------- */

typedef struct {
    char *data;
    size_t len;
} json_buf_t;

/* ------------------------------------------------------------------------- */
/* HELPERS                                                                   */
/* ------------------------------------------------------------------------- */

static const char *history_type_str(history_entry_t *d)
{
    switch (d->type) {

        case TRAFFIC_QUIC:
            return "QUIC";

        case TRAFFIC_HTTPS:
            return "HTTPS";

        case TRAFFIC_HTTP:
            return "HTTP";

        case TRAFFIC_DNS:
            return "DNS";

        default:
            return "other";
    }
}

static void free_json_buf(json_buf_t *buf)
{
    if (!buf)
        return;

    free(buf->data);

    buf->data = NULL;
    buf->len = 0;
}

static void get_uci_value(const char *cmd,
                          char *buf,
                          size_t len)
{
    FILE *fp;
    char tmp[128] = {0};

    if (!buf || len == 0)
        return;

    fp = popen(cmd, "r");
    if (!fp) {
        buf[0] = '\0';
        return;
    }

    if (fgets(tmp, sizeof(tmp), fp)) {

        tmp[strcspn(tmp, "\r\n")] = '\0';

        snprintf(buf, len, "%s", tmp);

    } else {

        buf[0] = '\0';
    }

    pclose(fp);
}

static void history_read_ids(char *network_id,
                             size_t network_len,
                             char *device_id,
                             size_t device_len,
                             char *org_id,
                             size_t org_len)
{
    get_uci_value(
        "uci get aircnms.@aircnms[0].network_id 2>/dev/null",
        network_id,
        network_len);

    get_uci_value(
        "uci get aircnms.@aircnms[0].device_id 2>/dev/null",
        device_id,
        device_len);

    get_uci_value(
        "uci get aircnms.@aircnms[0].org_id 2>/dev/null",
        org_id,
        org_len);
}

static void history_write_event_header(FILE *f,
                                       const char *network_id,
                                       const char *device_id,
                                       const char *org_id,
                                       uint64_t report_time)
{
    fprintf(f, "{\n");

    fprintf(f, "   \"type\":\"web_usages\",\n");
    fprintf(f, "   \"cmd\":\"\",\n");

    fprintf(f, "   \"networkId\":");
    json_escape(f, network_id);
    fprintf(f, ",\n");

    fprintf(f, "   \"deviceId\":");
    json_escape(f, device_id);
    fprintf(f, ",\n");

    fprintf(f, "   \"orgId\":");
    json_escape(f, org_id);
    fprintf(f, ",\n");

    fprintf(f, "   \"tms\":%" PRIu64 ",\n", report_time);

    fprintf(f, "   \"result\":{\n");
    fprintf(f, "      \"browsing_history\":[\n");
}

static void history_write_event_footer(FILE *f)
{
    fprintf(f, "\n");
    fprintf(f, "      ]\n");
    fprintf(f, "   }\n");
    fprintf(f, "}\n");
}

static void history_write_compact_header(FILE *f,
                                         const char *network_id,
                                         const char *device_id,
                                         const char *org_id,
                                         uint64_t report_time)
{
    fprintf(f, "{\"type\":\"web_usages\",\"cmd\":\"\",\"networkId\":");
    json_escape(f, network_id);
    fprintf(f, ",\"deviceId\":");
    json_escape(f, device_id);
    fprintf(f, ",\"orgId\":");
    json_escape(f, org_id);
    fprintf(f, ",\"tms\":%" PRIu64 ",\"result\":{\"browsing_history\":[",
            report_time);
}

static void history_write_compact_footer(FILE *f)
{
    fprintf(f, "]}}\n");
}

static void history_write_entry(FILE *f,
                                history_entry_t *d,
                                const char *mac)
{
    uint64_t spent_ms = 0;

    if (d->last_seen_ms > d->first_seen_ms)
        spent_ms = d->last_seen_ms - d->first_seen_ms;

    if (spent_ms > HISTORY_INTERVAL_MS)
        spent_ms = HISTORY_INTERVAL_MS;

    fprintf(f, "         {\n");

    fprintf(f, "            \"domain\":");
    json_escape(f, d->domain);
    fprintf(f, ",\n");

    fprintf(f, "            \"service\":");
    json_escape(f, d->service[0] ? d->service : "Unknown");
    fprintf(f, ",\n");

    fprintf(f, "            \"uploaded\":%" PRIu64 ",\n",
            d->uploaded);

    fprintf(f, "            \"downloaded\":%" PRIu64 ",\n",
            d->downloaded);

    fprintf(f, "            \"time_spent_ms\":%" PRIu64 ",\n",
            spent_ms);

    fprintf(f, "            \"visits\":%" PRIu64 ",\n",
            d->visits);

    fprintf(f, "            \"connections\":%" PRIu64 ",\n",
            d->connections);

    fprintf(f, "            \"type\":");
    json_escape(f, history_type_str(d));
    fprintf(f, ",\n");

    fprintf(f, "            \"active\":%s,\n",
            d->active ? "true" : "false");

    fprintf(f, "            \"mac\":");
    json_escape(f, mac);
    fprintf(f, "\n");

    fprintf(f, "         }");
}

static bool history_entry_to_buf(history_entry_t *d,
                                 const char *mac,
                                 char **data,
                                 size_t *len)
{
    FILE *f;

    if (!data || !len)
        return false;

    *data = NULL;
    *len = 0;

    f = open_memstream(data, len);
    if (!f)
        return false;

    history_write_entry(f, d, mac);
    fclose(f);

    return *data != NULL;
}

static bool history_spool_ensure_dir(void)
{
    if (mkdir(HISTORY_SPOOL_DIR, 0755) == 0)
        return true;

    return errno == EEXIST;
}

static bool history_name_is_interval_file(const char *name)
{
    size_t name_len;
    size_t prefix_len = strlen(HISTORY_SPOOL_PREFIX);
    size_t suffix_len = strlen(HISTORY_SPOOL_SUFFIX);

    if (!name)
        return false;

    name_len = strlen(name);

    if (name_len <= prefix_len + suffix_len)
        return false;

    if (strncmp(name, HISTORY_SPOOL_PREFIX, prefix_len) != 0)
        return false;

    return strcmp(name + name_len - suffix_len, HISTORY_SPOOL_SUFFIX) == 0;
}

static int history_spool_file_cmp(const void *a, const void *b)
{
    const history_spool_file_t *fa = a;
    const history_spool_file_t *fb = b;

    return strcmp(fa->name, fb->name);
}

static size_t history_spool_list(history_spool_file_t *files, size_t max_files)
{
    DIR *dir;
    struct dirent *de;
    size_t count = 0;

    dir = opendir(HISTORY_SPOOL_DIR);
    if (!dir)
        return 0;

    while ((de = readdir(dir)) != NULL) {
        if (!history_name_is_interval_file(de->d_name))
            continue;

        if (count >= max_files)
            break;

        snprintf(files[count].name,
                 sizeof(files[count].name),
                 "%s",
                 de->d_name);

        snprintf(files[count].path,
                 sizeof(files[count].path),
                 "%s/%s",
                 HISTORY_SPOOL_DIR,
                 de->d_name);

        count++;
    }

    closedir(dir);

    qsort(files, count, sizeof(files[0]), history_spool_file_cmp);

    return count;
}

static const char *json_string_or_default(json_t *obj,
                                          const char *key,
                                          const char *def)
{
    json_t *v = json_object_get(obj, key);

    if (!json_is_string(v))
        return def;

    return json_string_value(v);
}

static uint64_t json_uint64_or_zero(json_t *obj, const char *key)
{
    json_t *v = json_object_get(obj, key);

    if (!json_is_integer(v))
        return 0;

    return (uint64_t)json_integer_value(v);
}

static void history_normalize_domain_service(const char *in_domain,
                                             const char *in_service,
                                             char *out_domain,
                                             size_t out_domain_len,
                                             char *out_service,
                                             size_t out_service_len)
{
    const char *domain = in_domain && in_domain[0] ? in_domain : "unknown";
    const char *service = in_service && in_service[0] ? in_service : "Unknown";
    const char *mapped_service;
    const char *mapped_domain;

    if (!strcmp(domain, "dns") || !strcmp(service, "DNS")) {
        snprintf(out_domain, out_domain_len, "%s", "dns");
        snprintf(out_service, out_service_len, "%s", "DNS");
        return;
    }

    if (strstr(domain, "devices.a2z.com") ||
        strstr(domain, "bdtelemetry.amazon") ||
        strstr(domain, "mshop") ||
        strstr(domain, "amazon.com") ||
        strstr(domain, "amazon.in"))
    {
        snprintf(out_domain, out_domain_len, "%s", "amazon.com");
        snprintf(out_service, out_service_len, "%s", "Amazon");
        return;
    }

    mapped_service = service_from_domain(domain);
    if (mapped_service && strcmp(mapped_service, "Unknown"))
        service = mapped_service;

    mapped_domain = history_domain_for_service(service, domain);

    snprintf(out_domain,
             out_domain_len,
             "%s",
             mapped_domain && mapped_domain[0] ? mapped_domain : domain);

    snprintf(out_service,
             out_service_len,
             "%s",
             service && service[0] ? service : "Unknown");
}

static history_agg_entry_t *history_agg_find(history_agg_entry_t *head,
                                             const char *domain,
                                             const char *service,
                                             const char *mac)
{
    for (history_agg_entry_t *e = head; e; e = e->next) {
        if (!strcmp(e->domain, domain) &&
            !strcmp(e->service, service) &&
            !strcmp(e->mac, mac))
        {
            return e;
        }
    }

    return NULL;
}

static bool history_agg_add(history_agg_entry_t **head, json_t *entry)
{
    const char *domain;
    const char *service;
    const char *type;
    const char *mac;
    char norm_domain[256];
    char norm_service[64];
    uint64_t uploaded;
    uint64_t downloaded;
    uint64_t bytes;
    history_agg_entry_t *e;

    if (!head || !json_is_object(entry))
        return true;

    domain = json_string_or_default(entry, "domain", "unknown");
    service = json_string_or_default(entry, "service", "Unknown");
    type = json_string_or_default(entry, "type", "other");
    mac = json_string_or_default(entry, "mac", "");

    history_normalize_domain_service(domain,
                                     service,
                                     norm_domain,
                                     sizeof(norm_domain),
                                     norm_service,
                                     sizeof(norm_service));

    uploaded = json_uint64_or_zero(entry, "uploaded");
    downloaded = json_uint64_or_zero(entry, "downloaded");
    bytes = uploaded + downloaded;

    e = history_agg_find(*head, norm_domain, norm_service, mac);
    if (!e) {
        e = calloc(1, sizeof(*e));
        if (!e)
            return false;

        snprintf(e->domain, sizeof(e->domain), "%s", norm_domain);
        snprintf(e->service, sizeof(e->service), "%s", norm_service);
        snprintf(e->type, sizeof(e->type), "%s", type);
        snprintf(e->mac, sizeof(e->mac), "%s", mac);
        e->type_bytes = bytes;

        e->next = *head;
        *head = e;
    } else if (bytes >= e->type_bytes) {
        snprintf(e->type, sizeof(e->type), "%s", type);
        e->type_bytes = bytes;
    }

    e->uploaded += uploaded;
    e->downloaded += downloaded;
    e->time_spent_ms += json_uint64_or_zero(entry, "time_spent_ms");
    if (e->time_spent_ms > HISTORY_BATCH_WINDOW_MS)
        e->time_spent_ms = HISTORY_BATCH_WINDOW_MS;
    e->visits += json_uint64_or_zero(entry, "visits");
    e->connections += json_uint64_or_zero(entry, "connections");

    /*
     * Files are merged oldest -> newest, so the latest interval wins.
     */
    e->active = json_is_true(json_object_get(entry, "active"));

    return true;
}

static void history_agg_free(history_agg_entry_t *head)
{
    while (head) {
        history_agg_entry_t *next = head->next;
        free(head);
        head = next;
    }
}

static size_t history_agg_count(history_agg_entry_t *head)
{
    size_t count = 0;

    for (; head; head = head->next)
        count++;

    return count;
}

static bool history_agg_load_file(history_agg_entry_t **head, const char *path)
{
    json_error_t error;
    json_t *root;
    json_t *result;
    json_t *history;
    size_t i;
    json_t *entry;
    bool ok = true;

    root = json_load_file(path, 0, &error);
    if (!root) {
        LOG(WARN,
            "history spool: cannot parse %s: %s",
            path,
            error.text);
        return false;
    }

    result = json_object_get(root, "result");
    history = json_object_get(result, "browsing_history");

    if (!json_is_array(history)) {
        json_decref(root);
        return false;
    }

    json_array_foreach(history, i, entry) {
        if (!history_agg_add(head, entry)) {
            ok = false;
            break;
        }
    }

    json_decref(root);

    return ok;
}

static void history_write_compact_agg_entry(FILE *f, history_agg_entry_t *e)
{
    fprintf(f, "{\"domain\":");
    json_escape(f, e->domain);
    fprintf(f, ",\"service\":");
    json_escape(f, e->service);
    fprintf(f, ",\"uploaded\":%" PRIu64, e->uploaded);
    fprintf(f, ",\"downloaded\":%" PRIu64, e->downloaded);
    fprintf(f, ",\"time_spent_ms\":%" PRIu64, e->time_spent_ms);
    fprintf(f, ",\"visits\":%" PRIu64, e->visits);
    fprintf(f, ",\"connections\":%" PRIu64, e->connections);
    fprintf(f, ",\"type\":");
    json_escape(f, e->type);
    fprintf(f, ",\"active\":%s", e->active ? "true" : "false");
    fprintf(f, ",\"mac\":");
    json_escape(f, e->mac);
    fprintf(f, "}");
}

/* ------------------------------------------------------------------------- */
/* BUILD HISTORY JSON                                                        */
/* ------------------------------------------------------------------------- */

static json_buf_t history_event_build_json(app_t *app,
                                           uint64_t report_time)
{
    json_buf_t out = {0};

    char network_id[128] = {0};
    char device_id[128] = {0};
    char org_id[128] = {0};

    history_read_ids(network_id,
                     sizeof(network_id),
                     device_id,
                     sizeof(device_id),
                     org_id,
                     sizeof(org_id));

    if (!app)
        return out;

    FILE *f = open_memstream(&out.data, &out.len);
    if (!f)
        return out;

    history_write_event_header(f,
                               network_id,
                               device_id,
                               org_id,
                               report_time);

    bool first_entry = true;
    int history_entries = 0;

    client_state_t *client;

    ds_tree_foreach(&g_client_tree, client) {
            history_entry_t *history;

            history = build_delta_history_entries(client, report_time);
            if (!history)
                continue;

            char mac[18];
            mac_addr_t client_mac;

            memcpy(client_mac.b, client->mac, sizeof(client_mac.b));
            mac_to_str(client_mac, mac);

            for (history_entry_t *d = history; d; d = d->next) {

                if (!first_entry)
                    fprintf(f, ",\n");

                first_entry = false;
                history_entries++;
                
                history_write_entry(f,
                                    d,
                                    mac);
            }

            mark_client_history_reported(client, report_time);

            free_history_entries(history);
    }

    if (history_entries == 0) {
        fclose(f);

        free(out.data);
        out.data = NULL;
        out.len = 0;

        return out;
    }

    history_write_event_footer(f);

    fclose(f);

    return out;
}

static bool history_read_file(const char *path, char **data, size_t *len)
{
    FILE *f;
    long sz;

    if (!data || !len)
        return false;

    *data = NULL;
    *len = 0;

    f = fopen(path, "r");
    if (!f)
        return false;

    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return false;
    }

    sz = ftell(f);
    if (sz <= 0) {
        fclose(f);
        return false;
    }

    rewind(f);

    *data = malloc((size_t)sz + 1);
    if (!*data) {
        fclose(f);
        return false;
    }

    if (fread(*data, 1, (size_t)sz, f) != (size_t)sz) {
        free(*data);
        *data = NULL;
        fclose(f);
        return false;
    }

    fclose(f);

    (*data)[sz] = '\0';
    *len = (size_t)sz;

    return true;
}

bool history_event_spool_interval(app_t *app)
{
    uint64_t report_time;
    char network_id[128] = {0};
    char device_id[128] = {0};
    char org_id[128] = {0};
    char path[PATH_MAX];
    char tmp_path[PATH_MAX];
    FILE *f;
    bool first_entry = true;
    bool truncated = false;
    int history_entries = 0;
    client_state_t *client;

    if (!app)
        return false;

    if (!history_spool_ensure_dir()) {
        LOG(ERR, "history spool: cannot create %s: %s",
            HISTORY_SPOOL_DIR, strerror(errno));
        return false;
    }

    {
        history_spool_file_t files[HISTORY_FILE_MAX_COUNT + 8];
        size_t count = history_spool_list(files,
                                          sizeof(files) / sizeof(files[0]));

        if (count >= HISTORY_FILE_MAX_COUNT &&
            !history_event_spool_send(app, true))
        {
            LOG(WARN,
                "history spool: max file count reached, skipping new interval file");
            return false;
        }
    }

    report_time = get_timestamp_ms();

    history_read_ids(network_id,
                     sizeof(network_id),
                     device_id,
                     sizeof(device_id),
                     org_id,
                     sizeof(org_id));

    snprintf(path,
             sizeof(path),
             "%s/%s%" PRIu64 "%s",
             HISTORY_SPOOL_DIR,
             HISTORY_SPOOL_PREFIX,
             report_time,
             HISTORY_SPOOL_SUFFIX);

    snprintf(tmp_path,
             sizeof(tmp_path),
             "%s/%s%" PRIu64 "%s.tmp",
             HISTORY_SPOOL_DIR,
             HISTORY_SPOOL_PREFIX,
             report_time,
             HISTORY_SPOOL_SUFFIX);

    f = fopen(tmp_path, "w");
    if (!f) {
        LOG(ERR, "history spool: cannot open %s: %s",
            tmp_path, strerror(errno));
        return false;
    }

    history_write_event_header(f,
                               network_id,
                               device_id,
                               org_id,
                               report_time);

    ds_tree_foreach(&g_client_tree, client) {
        history_entry_t *history;
        char mac[18];
        mac_addr_t client_mac;

        history = build_delta_history_entries(client, report_time);
        if (!history)
            continue;

        memcpy(client_mac.b, client->mac, sizeof(client_mac.b));
        mac_to_str(client_mac, mac);

        for (history_entry_t *d = history; d; d = d->next) {
            char *entry = NULL;
            size_t entry_len = 0;
            long pos;
            size_t comma_len;

            if (!history_entry_to_buf(d,
                                      mac,
                                      &entry,
                                      &entry_len))
            {
                truncated = true;
                break;
            }

            pos = ftell(f);
            comma_len = first_entry ? 0 : 2;

            if (pos < 0 ||
                (size_t)pos + comma_len + entry_len +
                HISTORY_JSON_FOOTER_RESERVE > HISTORY_FILE_MAX_BYTES)
            {
                free(entry);
                truncated = true;
                break;
            }

            if (!first_entry)
                fprintf(f, ",\n");

            fwrite(entry, 1, entry_len, f);
            first_entry = false;
            history_entries++;

            free(entry);
        }

        free_history_entries(history);

        if (truncated)
            break;
    }

    if (history_entries == 0) {
        fclose(f);
        unlink(tmp_path);
        return false;
    }

    history_write_event_footer(f);

    fflush(f);
    fsync(fileno(f));
    fclose(f);

    if (rename(tmp_path, path) < 0) {
        LOG(ERR, "history spool: rename %s -> %s failed: %s",
            tmp_path, path, strerror(errno));
        unlink(tmp_path);
        return false;
    }

    if (!truncated) {
        ds_tree_foreach(&g_client_tree, client)
            mark_client_history_reported(client, report_time);
    } else {
        LOG(WARN,
            "history spool: %s reached 1MB cap; unreported data will retry later",
            path);
    }

    LOG(INFO,
        "history spool: wrote %s entries=%d%s",
        path,
        history_entries,
        truncated ? " truncated" : "");

    history_event_spool_send(app, false);
    history_event_spool_send(app, true);

    return true;
}

bool history_event_spool_send(app_t *app, bool force)
{
    history_spool_file_t files[HISTORY_FILE_MAX_COUNT + 8];
    size_t count;
    size_t batch_count = HISTORY_BATCH_FILE_COUNT;
    uint64_t timestamp_ms;
    char network_id[128] = {0};
    char device_id[128] = {0};
    char org_id[128] = {0};
    char path[PATH_MAX];
    char tmp_path[PATH_MAX];
    FILE *f;
    bool first_entry = true;
    char *json = NULL;
    size_t json_len = 0;
    bool sent;
    history_agg_entry_t *agg = NULL;
    size_t agg_count;

    (void)app;

    if (!history_spool_ensure_dir())
        return false;

    count = history_spool_list(files, sizeof(files) / sizeof(files[0]));

    if (force) {
        if (count < HISTORY_FILE_MAX_COUNT)
            return false;
    } else {
        if (count < HISTORY_BATCH_FILE_COUNT)
            return false;
    }

    if (count < batch_count)
        return false;

    timestamp_ms = get_timestamp_ms();

    history_read_ids(network_id,
                     sizeof(network_id),
                     device_id,
                     sizeof(device_id),
                     org_id,
                     sizeof(org_id));

    snprintf(path,
             sizeof(path),
             "%s/%s%" PRIu64 "%s",
             HISTORY_SPOOL_DIR,
             HISTORY_BATCH_PREFIX,
             timestamp_ms,
             HISTORY_SPOOL_SUFFIX);

    snprintf(tmp_path,
             sizeof(tmp_path),
             "%s/%s%" PRIu64 "%s.tmp",
             HISTORY_SPOOL_DIR,
             HISTORY_BATCH_PREFIX,
             timestamp_ms,
             HISTORY_SPOOL_SUFFIX);

    for (size_t i = 0; i < batch_count; i++) {
        if (!history_agg_load_file(&agg, files[i].path)) {
            LOG(WARN,
                "history spool: skipping unreadable interval file %s",
                files[i].path);
        }
    }

    agg_count = history_agg_count(agg);
    if (agg_count == 0) {
        history_agg_free(agg);
        return false;
    }

    f = fopen(tmp_path, "w");
    if (!f) {
        LOG(ERR, "history spool: cannot open batch %s: %s",
            tmp_path, strerror(errno));
        history_agg_free(agg);
        return false;
    }

    history_write_compact_header(f,
                                 network_id,
                                 device_id,
                                 org_id,
                                 timestamp_ms);

    for (history_agg_entry_t *e = agg; e; e = e->next) {
        if (!first_entry)
            fprintf(f, ",");

        history_write_compact_agg_entry(f, e);
        first_entry = false;
    }

    history_write_compact_footer(f);

    fflush(f);
    fsync(fileno(f));
    fclose(f);
    history_agg_free(agg);

    if (rename(tmp_path, path) < 0) {
        LOG(ERR, "history spool: rename %s -> %s failed: %s",
            tmp_path, path, strerror(errno));
        unlink(tmp_path);
        return false;
    }

    if (!history_read_file(path, &json, &json_len)) {
        unlink(path);
        return false;
    }

    sent = stamonitord_send_client_history_event(json,
                                                 json_len,
                                                 timestamp_ms);
    free(json);

    if (!sent) {
        LOG(WARN,
            "history spool: batch send failed, keeping interval files");
        unlink(path);
        return false;
    }

    for (size_t i = 0; i < batch_count; i++)
        unlink(files[i].path);

    unlink(path);

    LOG(INFO,
        "history spool: sent and removed %zu interval files aggregated_entries=%zu",
        batch_count,
        agg_count);

    return true;
}



/* ------------------------------------------------------------------------- */
/* PUBLIC API                                                                */
/* ------------------------------------------------------------------------- */

bool history_event_publish(app_t *app)
{
    if (!app)
        return false;

    uint64_t timestamp_ms = get_timestamp_ms();

    json_buf_t json =
        history_event_build_json(app, timestamp_ms);

    if (!json.data || json.len == 0) {
        LOG(DEBUG,
            "history_event_publish: no history changes to publish");
        free_json_buf(&json);

        return false;
    }

    bool ret =
        stamonitord_send_client_history_event(
            json.data,
            json.len,
            timestamp_ms);

    free_json_buf(&json);

    return ret;
}
