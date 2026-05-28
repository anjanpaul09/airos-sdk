#include "stamonitord_history_internal.h"
#include "info_events.h"
#include "stamonitord_ubus_tx.h"
#include "stamonitord_history_event.h"
#include "log.h"

/* ------------------------------------------------------------------------- */
/* JSON                                                                      */
/* ------------------------------------------------------------------------- */

history_entry_t *history_entry_get_or_create(history_entry_t **head,
                                             const char *service,
                                             const char *domain)
{
    for (history_entry_t *e = *head; e; e = e->next) {
        if (!strcmp(e->service, service))
            return e;
    }

    history_entry_t *e = calloc(1, sizeof(*e));
    if (!e)
        return NULL;

    strncpy(e->service, service, sizeof(e->service) - 1);
    strncpy(e->domain, domain, sizeof(e->domain) - 1);

    e->next = *head;
    *head = e;

    return e;
}

void free_history_entries(history_entry_t *head)
{
    while (head) {
        history_entry_t *next = head->next;
        free(head);
        head = next;
    }
}

static bool delta_domain_needs_report(history_domain_t *d)
{
    return d->last_seen_ms > d->last_reported_ms ||
           d->uploaded != d->uploaded_reported ||
           d->downloaded != d->downloaded_reported ||
           d->visits != d->visits_reported ||
           d->connections != d->connections_reported;
}

static bool add_history_domain(history_entry_t **head,
                               history_domain_t *d,
                               bool delta,
                               uint64_t report_time)
{
    const char *service = normalized_history_service(d->service,
                                                     d->ndpi_protocol,
                                                     d->domain);
    const char *domain = history_domain_for_service(service, d->domain);
    history_entry_t *e = history_entry_get_or_create(head, service, domain);
    uint64_t uploaded;
    uint64_t downloaded;
    uint64_t visits;
    uint64_t connections;
    uint64_t bytes;
    bool current_specific;
    bool new_specific;

    if (!e)
        return false;

    if (delta) {
        uploaded = d->uploaded - d->uploaded_reported;
        downloaded = d->downloaded - d->downloaded_reported;
        visits = d->visits - d->visits_reported;
        connections = d->connections - d->connections_reported;
    } else {
        uploaded = d->uploaded;
        downloaded = d->downloaded;
        visits = d->visits;
        connections = d->connections;
    }

    bytes = uploaded + downloaded;
    current_specific = !ndpi_label_is_generic(e->ndpi_protocol);
    new_specific = !ndpi_label_is_generic(d->ndpi_protocol);

    e->uploaded += uploaded;
    e->downloaded += downloaded;
    e->visits += visits;
    e->connections += connections;
    e->active = e->active || d->active;

    if (delta) {
        uint64_t first_seen = d->first_seen_ms;
        uint64_t last_seen = d->last_seen_ms;

        if (d->last_reported_ms > first_seen)
            first_seen = d->last_reported_ms;

        if (report_time > 0 && last_seen > report_time)
            last_seen = report_time;

        if (last_seen < first_seen)
            first_seen = last_seen;

        if (e->first_seen_ms == 0 || first_seen < e->first_seen_ms)
            e->first_seen_ms = first_seen;

        if (last_seen > e->last_seen_ms)
            e->last_seen_ms = last_seen;
    } else {
        if (e->first_seen_ms == 0 || d->first_seen_ms < e->first_seen_ms)
            e->first_seen_ms = d->first_seen_ms;

        if (d->last_seen_ms > e->last_seen_ms)
            e->last_seen_ms = d->last_seen_ms;
    }

    if ((!current_specific && new_specific) ||
        (current_specific == new_specific && bytes >= e->representative_bytes)) {
        if (d->ndpi_protocol[0]) {
            snprintf(e->ndpi_protocol,
                     sizeof(e->ndpi_protocol),
                     "%s",
                     d->ndpi_protocol);
        }

        e->type = d->type;
        e->representative_bytes = bytes;
    } else if (!e->ndpi_protocol[0] && d->ndpi_protocol[0]) {
        snprintf(e->ndpi_protocol,
                 sizeof(e->ndpi_protocol),
                 "%s",
                 d->ndpi_protocol);
    }

    if (e->type == TRAFFIC_OTHER && d->type != TRAFFIC_OTHER)
        e->type = d->type;

    return true;
}

history_entry_t *build_delta_history_entries(client_state_t *client,
                                             uint64_t report_time)
{
    history_entry_t *head = NULL;
    history_domain_t *d;

    (void)report_time;

    if (!client)
        return NULL;

    ds_tree_foreach(&client->history.domains, d) {
        if (!delta_domain_needs_report(d))
            continue;

        if (!add_history_domain(&head, d, true, report_time)) {
            free_history_entries(head);
            return NULL;
        }
    }

    return head;
}

void mark_client_history_reported(client_state_t *client, uint64_t report_time)
{
    history_domain_t *d;

    if (!client)
        return;

    client->history.last_reported_ms = report_time;

    ds_tree_foreach(&client->history.domains, d) {
        d->last_reported_ms = report_time;
        d->uploaded_reported = d->uploaded;
        d->downloaded_reported = d->downloaded;
        d->visits_reported = d->visits;
        d->connections_reported = d->connections;
    }
}

history_entry_t *build_history_entries(client_state_t *client)
{
    history_entry_t *head = NULL;
    history_domain_t *d;

    if (!client)
        return NULL;

    ds_tree_foreach(&client->history.domains, d) {
        if (!add_history_domain(&head, d, false, 0)) {
            free_history_entries(head);
            return NULL;
        }
    }

    return head;
}

int count_history_entries(history_entry_t *head, bool active_only)
{
    int count = 0;
    uint64_t t = now_ms();

    for (history_entry_t *e = head; e; e = e->next) {
        if (!active_only) {
            count++;
        } else if (e->active &&
                   t >= e->last_seen_ms &&
                   t - e->last_seen_ms <= DOMAIN_ACTIVE_TIMEOUT_SEC * 1000ULL) {
            count++;
        }
    }

    return count;
}

static void client_mac_to_str(client_state_t *client, char out[18])
{
    mac_addr_t mac;

    memset(&mac, 0, sizeof(mac));

    if (client)
        memcpy(mac.b, client->mac, sizeof(mac.b));

    mac_to_str(mac, out);
}

static const char *client_ip_str(client_state_t *client)
{
    if (!client || !client->info.ipaddr[0])
        return "0.0.0.0";

    return client->info.ipaddr;
}

void write_client_json(FILE *f, client_state_t *client)
{
    char mac[18], ts[64];
    char total_s[64], upload_s[64], download_s[64];
    history_entry_t *history = build_history_entries(client);
    uint64_t total;
    bool first_domain = true;

    if (!client)
        return;

    total = client->history.uploaded + client->history.downloaded;

    client_mac_to_str(client, mac);
    format_timestamp(now_ms(), ts, sizeof(ts));

    format_bytes(total, total_s, sizeof(total_s));
    format_bytes(client->history.uploaded, upload_s, sizeof(upload_s));
    format_bytes(client->history.downloaded, download_s, sizeof(download_s));

    fprintf(f, "{\n");
    fprintf(f, "      \"mac\": "); json_escape(f, mac); fprintf(f, ",\n");
    fprintf(f, "      \"ip\": "); json_escape(f, client_ip_str(client)); fprintf(f, ",\n");
    fprintf(f, "      \"zone\": "); json_escape(f, "unknown"); fprintf(f, ",\n");
    fprintf(f, "      \"timestamp\": "); json_escape(f, ts); fprintf(f, ",\n");
    fprintf(f, "      \"total_data\": "); json_escape(f, total_s); fprintf(f, ",\n");
    fprintf(f, "      \"total_uploaded\": "); json_escape(f, upload_s); fprintf(f, ",\n");
    fprintf(f, "      \"total_downloaded\": "); json_escape(f, download_s); fprintf(f, ",\n");
    fprintf(f, "      \"uploaded_bytes\": %" PRIu64 ",\n", client->history.uploaded);
    fprintf(f, "      \"downloaded_bytes\": %" PRIu64 ",\n", client->history.downloaded);
    fprintf(f, "      \"domains_visited\": %d,\n", count_history_entries(history, false));
    fprintf(f, "      \"active_domains\": %d,\n", count_history_entries(history, true));
    fprintf(f, "      \"browsing_history\": [\n");

    for (history_entry_t *d = history; d; d = d->next) {
        char data_s[64], dur_s[64];
        uint64_t d_total = d->uploaded + d->downloaded;
        uint64_t spent_ms = 0;

        if (!first_domain)
            fprintf(f, ",\n");

        first_domain = false;

        if (d->last_seen_ms > d->first_seen_ms)
            spent_ms = d->last_seen_ms - d->first_seen_ms;

        format_bytes(d_total, data_s, sizeof(data_s));
        format_duration(spent_ms, dur_s, sizeof(dur_s));

        fprintf(f, "        {\n");
        fprintf(f, "          \"service\": ");
        json_escape(f, d->service[0] ? d->service : "Unknown");
        fprintf(f, ",\n");
        fprintf(f, "          \"ndpi_protocol\": ");
        json_escape(f, d->ndpi_protocol[0] ? d->ndpi_protocol : "unknown");
        fprintf(f, ",\n");
        fprintf(f, "          \"domain\": "); json_escape(f, d->domain); fprintf(f, ",\n");
        fprintf(f, "          \"data\": "); json_escape(f, data_s); fprintf(f, ",\n");
        fprintf(f, "          \"uploaded\": %" PRIu64 ",\n", d->uploaded);
        fprintf(f, "          \"downloaded\": %" PRIu64 ",\n", d->downloaded);
        fprintf(f, "          \"time_spent\": "); json_escape(f, dur_s); fprintf(f, ",\n");
        fprintf(f, "          \"time_spent_ms\": %" PRIu64 ",\n", spent_ms);
        fprintf(f, "          \"visits\": %" PRIu64 ",\n", d->visits);
        fprintf(f, "          \"connections\": %" PRIu64 ",\n", d->connections);
        fprintf(f, "          \"type\": "); json_escape(f, traffic_type_str(d->type)); fprintf(f, ",\n");
        fprintf(f, "          \"active\": %s\n", d->active ? "true" : "false");
        fprintf(f, "        }");
    }

    fprintf(f, "\n      ]\n");
    fprintf(f, "    }");

    free_history_entries(history);
}

void write_client_report_json(FILE *f, client_state_t *client, history_entry_t *history)
{
    char mac[18], ts[64];
    uint64_t total_upload = 0;
    uint64_t total_download = 0;
    bool first_domain = true;

    if (!client || !history)
        return;

    for (history_entry_t *d = history; d; d = d->next) {
        total_upload += d->uploaded;
        total_download += d->downloaded;
    }

    client_mac_to_str(client, mac);
    format_timestamp(now_ms(), ts, sizeof(ts));

    fprintf(f, "{\n");
    fprintf(f, "      \"mac\": "); json_escape(f, mac); fprintf(f, ",\n");
    fprintf(f, "      \"ip\": "); json_escape(f, client_ip_str(client)); fprintf(f, ",\n");
    fprintf(f, "      \"zone\": "); json_escape(f, "unknown"); fprintf(f, ",\n");
    fprintf(f, "      \"timestamp\": "); json_escape(f, ts); fprintf(f, ",\n");
    fprintf(f, "      \"delta_uploaded_bytes\": %" PRIu64 ",\n", total_upload);
    fprintf(f, "      \"delta_downloaded_bytes\": %" PRIu64 ",\n", total_download);
    fprintf(f, "      \"domains_visited\": %d,\n", count_history_entries(history, false));
    fprintf(f, "      \"active_domains\": %d,\n", count_history_entries(history, true));
    fprintf(f, "      \"browsing_history\": [\n");

    for (history_entry_t *d = history; d; d = d->next) {
        char data_s[64], dur_s[64];
        uint64_t d_total = d->uploaded + d->downloaded;
        uint64_t spent_ms = 0;

        if (!first_domain)
            fprintf(f, ",\n");

        first_domain = false;

        if (d->last_seen_ms > d->first_seen_ms)
            spent_ms = d->last_seen_ms - d->first_seen_ms;

        format_bytes(d_total, data_s, sizeof(data_s));
        format_duration(spent_ms, dur_s, sizeof(dur_s));

        fprintf(f, "        {\n");
        fprintf(f, "          \"service\": ");
        json_escape(f, d->service[0] ? d->service : "Unknown");
        fprintf(f, ",\n");
        fprintf(f, "          \"ndpi_protocol\": ");
        json_escape(f, d->ndpi_protocol[0] ? d->ndpi_protocol : "unknown");
        fprintf(f, ",\n");
        fprintf(f, "          \"domain\": "); json_escape(f, d->domain); fprintf(f, ",\n");
        fprintf(f, "          \"data\": "); json_escape(f, data_s); fprintf(f, ",\n");
        fprintf(f, "          \"uploaded_delta\": %" PRIu64 ",\n", d->uploaded);
        fprintf(f, "          \"downloaded_delta\": %" PRIu64 ",\n", d->downloaded);
        fprintf(f, "          \"time_spent\": "); json_escape(f, dur_s); fprintf(f, ",\n");
        fprintf(f, "          \"time_spent_ms\": %" PRIu64 ",\n", spent_ms);
        fprintf(f, "          \"visits_delta\": %" PRIu64 ",\n", d->visits);
        fprintf(f, "          \"connections_delta\": %" PRIu64 ",\n", d->connections);
        fprintf(f, "          \"type\": "); json_escape(f, traffic_type_str(d->type)); fprintf(f, ",\n");
        fprintf(f, "          \"active\": %s\n", d->active ? "true" : "false");
        fprintf(f, "        }");
    }

    fprintf(f, "\n      ]\n");
    fprintf(f, "    }");
}

void report_json(app_t *app)
{
    uint64_t report_time;
    char ts[64];
    char tmp[512];
    FILE *f;
    bool first_station = true;
    int stations_reported = 0;
    client_state_t *client;

    if (!app)
        return;

    LOG(INFO, "STAMONITORD history report_json starting seq=%" PRIu64, app->report_seq + 1);

    report_time = now_ms();
    format_timestamp(report_time, ts, sizeof(ts));

    snprintf(tmp, sizeof(tmp), "%s.tmp", app->output_path);

    f = fopen(tmp, "w");
    if (!f) {
        LOG(ERR, "report_json: cannot open %s: %s", tmp, strerror(errno));
        return;
    }

    fprintf(f, "{\n");
    fprintf(f, "  \"daemon\": "); json_escape(f, APP_NAME); fprintf(f, ",\n");
    fprintf(f, "  \"timestamp\": "); json_escape(f, ts); fprintf(f, ",\n");
    fprintf(f, "  \"report_sequence\": %" PRIu64 ",\n", ++app->report_seq);
    fprintf(f, "  \"report_window_ms\": %" PRIu64 ",\n", (uint64_t)(app->flush_interval_sec * 1000.0));
    fprintf(f, "  \"stations\": [\n");

    ds_tree_foreach(&g_client_tree, client) {
        history_entry_t *history = build_delta_history_entries(client, report_time);
        if (!history)
            continue;

        if (!first_station)
            fprintf(f, ",\n");

        first_station = false;
        stations_reported++;
        write_client_report_json(f, client, history);
        free_history_entries(history);
    }

    fprintf(f, "\n  ]\n");
    fprintf(f, "}\n");

    fflush(f);
    if (fsync(fileno(f)) < 0)
        LOG(ERR, "report_json: fsync %s failed: %s", tmp, strerror(errno));

    fclose(f);

    if (rename(tmp, app->output_path) < 0) {
        LOG(ERR, "report_json: rename %s -> %s failed: %s", tmp, app->output_path, strerror(errno));
    } else {
        LOG(INFO, "STAMONITORD history wrote report file %s (stations_reported=%d)", app->output_path, stations_reported);
    }

    if (stations_reported > 0) {
        ds_tree_foreach(&g_client_tree, client)
            mark_client_history_reported(client, report_time);
    }
}

void flush_json(app_t *app)
{
    char tmp[512];
    FILE *f;
    char ts[64];
    size_t flows_active = 0;
    size_t ndpi_flows_active = 0;
    bool first_cap = true;
    bool first_station = true;
    client_state_t *client;

    if (!app)
        return;

    snprintf(tmp, sizeof(tmp), "%s.tmp", app->output_path);

    f = fopen(tmp, "w");
    if (!f) {
        LOG(ERR, "cannot open %s: %s", tmp, strerror(errno));
        return;
    }

    format_timestamp(now_ms(), ts, sizeof(ts));

    fprintf(f, "{\n");
    fprintf(f, "  \"daemon\": "); json_escape(f, APP_NAME); fprintf(f, ",\n");
    fprintf(f, "  \"timestamp\": "); json_escape(f, ts); fprintf(f, ",\n");

    for (size_t i = 0; i < FLOW_BUCKETS; i++) {
        for (flow_t *flow = app->flows[i]; flow; flow = flow->next) {
            flows_active++;
            if (flow->ndpi_flow)
                ndpi_flows_active++;
        }
    }

    fprintf(f, "  \"stats\": {\n");
    fprintf(f, "    \"packets_seen\": %" PRIu64 ",\n", app->packets_seen);
    fprintf(f, "    \"packets_parsed\": %" PRIu64 ",\n", app->packets_parsed);
    fprintf(f, "    \"packets_parse_failed\": %" PRIu64 ",\n", app->packets_parse_failed);
    fprintf(f, "    \"packets_accounted\": %" PRIu64 ",\n", app->packets_accounted);
    fprintf(f, "    \"flows_active\": %zu,\n", flows_active);
    fprintf(f, "    \"ndpi_flows_active\": %zu\n", ndpi_flows_active);
    fprintf(f, "  },\n");

    fprintf(f, "  \"capture_interfaces\": [\n");

    for (cap_if_t *c = app->caps; c; c = c->next) {
        if (!first_cap)
            fprintf(f, ",\n");

        first_cap = false;

        fprintf(f, "    {\"ifname\": ");
        json_escape(f, c->ifname);
        fprintf(f, ", \"bridge\": ");
        json_escape(f, c->bridge);
        fprintf(f, ", \"zone\": ");
        json_escape(f, zone_str(c->zone));
        fprintf(f, ", \"ifindex\": %d}", c->ifindex);
    }

    fprintf(f, "\n  ],\n");
    fprintf(f, "  \"stations\": [\n");

    ds_tree_foreach(&g_client_tree, client) {
        if (!first_station)
            fprintf(f, ",\n");

        first_station = false;
        write_client_json(f, client);
    }

    fprintf(f, "\n  ]\n");
    fprintf(f, "}\n");

    fflush(f);
    fsync(fileno(f));
    fclose(f);

    if (rename(tmp, app->output_path) < 0) {
        LOG(ERR, "rename %s -> %s failed: %s",
                tmp, app->output_path, strerror(errno));
    }
}

void flush_cb(EV_P_ ev_timer *w, int revents)
{
    app_t *app = w->data;

    (void)loop;
    (void)revents;

    if (!app)
        return;

    history_event_spool_interval(app);
}

void send_cb(EV_P_ ev_timer *w, int revents)
{
    app_t *app = w->data;

    (void)loop;
    (void)revents;

    if (!app)
        return;

    history_event_spool_send(app, false);
}
