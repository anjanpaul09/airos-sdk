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
                                                    const char *domain) {
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

void free_history_entries(history_entry_t *head) {
    while (head) {
        history_entry_t *next = head->next;
        free(head);
        head = next;
    }
}

static bool delta_domain_needs_report(domain_stat_t *d) {
    return d->last_seen_ms > d->last_reported_ms ||
           d->uploaded != d->uploaded_reported ||
           d->downloaded != d->downloaded_reported ||
           d->visits != d->visits_reported ||
           d->connections != d->connections_reported;
}

history_entry_t *build_delta_history_entries(station_t *s, uint64_t report_time) {
    history_entry_t *head = NULL;

    for (size_t i = 0; i < DOMAIN_BUCKETS; i++) {
        for (domain_stat_t *d = s->domains[i]; d; d = d->next) {
            if (!delta_domain_needs_report(d))
                continue;

            const char *service = normalized_history_service(d->service,
                                                             d->ndpi_protocol,
                                                             d->domain);
            const char *domain = history_domain_for_service(service, d->domain);

            history_entry_t *e = history_entry_get_or_create(&head, service, domain);
            if (!e) {
                free_history_entries(head);
                return NULL;
            }

            uint64_t uploaded = d->uploaded - d->uploaded_reported;
            uint64_t downloaded = d->downloaded - d->downloaded_reported;
            uint64_t visits = d->visits - d->visits_reported;
            uint64_t connections = d->connections - d->connections_reported;
            uint64_t bytes = uploaded + downloaded;
            bool current_specific = !ndpi_label_is_generic(e->ndpi_protocol);
            bool new_specific = !ndpi_label_is_generic(d->ndpi_protocol);

            e->uploaded += uploaded;
            e->downloaded += downloaded;
            e->visits += visits;
            e->connections += connections;
            e->active = e->active || d->active;

            if (e->first_seen_ms == 0 || d->first_seen_ms < e->first_seen_ms)
                e->first_seen_ms = d->first_seen_ms;

            if (d->last_seen_ms > e->last_seen_ms)
                e->last_seen_ms = d->last_seen_ms;

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
        }
    }

    return head;
}

void mark_station_history_reported(station_t *s, uint64_t report_time) {
    if (!s)
        return;

    s->last_reported_ms = report_time;

    for (size_t j = 0; j < DOMAIN_BUCKETS; j++) {
        for (domain_stat_t *d = s->domains[j]; d; d = d->next) {
            d->last_reported_ms = report_time;
            d->uploaded_reported = d->uploaded;
            d->downloaded_reported = d->downloaded;
            d->visits_reported = d->visits;
            d->connections_reported = d->connections;
        }
    }
}

history_entry_t *build_history_entries(station_t *s) {
    history_entry_t *head = NULL;

    for (size_t i = 0; i < DOMAIN_BUCKETS; i++) {
        for (domain_stat_t *d = s->domains[i]; d; d = d->next) {
            const char *service = normalized_history_service(d->service,
                                                             d->ndpi_protocol,
                                                             d->domain);
            const char *domain = history_domain_for_service(service, d->domain);

            history_entry_t *e = history_entry_get_or_create(&head, service, domain);
            if (!e) {
                free_history_entries(head);
                return NULL;
            }

            uint64_t bytes = d->uploaded + d->downloaded;
            bool current_specific = !ndpi_label_is_generic(e->ndpi_protocol);
            bool new_specific = !ndpi_label_is_generic(d->ndpi_protocol);

            e->uploaded += d->uploaded;
            e->downloaded += d->downloaded;
            e->visits += d->visits;
            e->connections += d->connections;
            e->active = e->active || d->active;

            if (e->first_seen_ms == 0 || d->first_seen_ms < e->first_seen_ms)
                e->first_seen_ms = d->first_seen_ms;

            if (d->last_seen_ms > e->last_seen_ms)
                e->last_seen_ms = d->last_seen_ms;

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
        }
    }

    return head;
}

int count_history_entries(history_entry_t *head, bool active_only) {
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

void write_station_json(FILE *f, station_t *s) {
    char mac[18], ip[INET_ADDRSTRLEN], ts[64];
    char total_s[64], upload_s[64], download_s[64];
    history_entry_t *history = build_history_entries(s);

    uint64_t total = s->uploaded + s->downloaded;

    mac_to_str(s->mac, mac);
    ip4_to_str(s->ip, ip);
    format_timestamp(now_ms(), ts, sizeof(ts));

    format_bytes(total, total_s, sizeof(total_s));
    format_bytes(s->uploaded, upload_s, sizeof(upload_s));
    format_bytes(s->downloaded, download_s, sizeof(download_s));

    fprintf(f, "{\n");

    fprintf(f, "      \"mac\": "); json_escape(f, mac); fprintf(f, ",\n");
    fprintf(f, "      \"ip\": "); json_escape(f, ip); fprintf(f, ",\n");
    fprintf(f, "      \"zone\": "); json_escape(f, zone_str(s->zone)); fprintf(f, ",\n");
    fprintf(f, "      \"timestamp\": "); json_escape(f, ts); fprintf(f, ",\n");
    fprintf(f, "      \"total_data\": "); json_escape(f, total_s); fprintf(f, ",\n");
    fprintf(f, "      \"total_uploaded\": "); json_escape(f, upload_s); fprintf(f, ",\n");
    fprintf(f, "      \"total_downloaded\": "); json_escape(f, download_s); fprintf(f, ",\n");
    fprintf(f, "      \"uploaded_bytes\": %" PRIu64 ",\n", s->uploaded);
    fprintf(f, "      \"downloaded_bytes\": %" PRIu64 ",\n", s->downloaded);
    fprintf(f, "      \"domains_visited\": %d,\n", count_history_entries(history, false));
    fprintf(f, "      \"active_domains\": %d,\n", count_history_entries(history, true));
    fprintf(f, "      \"browsing_history\": [\n");

    bool first_domain = true;

    for (history_entry_t *d = history; d; d = d->next) {
            if (!first_domain)
                fprintf(f, ",\n");

            first_domain = false;

            char data_s[64], dur_s[64];
            uint64_t d_total = d->uploaded + d->downloaded;
            uint64_t spent_ms = 0;

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

            fprintf(f, "          \"domain\": ");
            json_escape(f, d->domain);
            fprintf(f, ",\n");

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

#if 0
static void send_stamonitord_history_report(const char *json, size_t len, uint64_t timestamp_ms) {
    if (!json || len == 0)
        return;

    size_t header_size = sizeof(info_event_type_t) + sizeof(uint64_t) + sizeof(uint32_t);
    size_t buf_size = header_size + len;
    uint8_t *buf = calloc(1, buf_size);
    if (!buf)
        return;

    //info_event_type_t type = INFO_EVENT_AP_HISTORY;
    memcpy(buf, &type, sizeof(type));
    memcpy(buf + sizeof(type), &timestamp_ms, sizeof(timestamp_ms));

    uint32_t json_len = (uint32_t)len;
    memcpy(buf + sizeof(type) + sizeof(timestamp_ms), &json_len, sizeof(json_len));
    memcpy(buf + header_size, json, len);

    stamonitord_publish_info_event(buf, buf_size);
    free(buf);
}

static void dump_report_to_file(app_t *app, const char *json, size_t len) {
    if (!app || !json || len == 0)
        return;

    char tmp[512];
    snprintf(tmp, sizeof(tmp), "%s.tmp", app->output_path);

    FILE *f = fopen(tmp, "w");
    if (!f) {
        LOG(ERR, "cannot open %s: %s", tmp, strerror(errno));
        return;
    }

    if (fwrite(json, 1, len, f) != len) {
        LOG(ERR, "failed to write report to %s: %s", tmp, strerror(errno));
    }

    fflush(f);
    fsync(fileno(f));
    fclose(f);

    if (rename(tmp, app->output_path) < 0) {
        LOG(ERR, "rename %s -> %s failed: %s", tmp, app->output_path, strerror(errno));
    }
}
#endif


void write_station_report_json(FILE *f, station_t *s, history_entry_t *history) {
    char mac[18], ip[INET_ADDRSTRLEN], ts[64];
    char upload_s[64], download_s[64];
    uint64_t total_upload = 0;
    uint64_t total_download = 0;

    if (!history)
        return;

    for (history_entry_t *d = history; d; d = d->next) {
        total_upload += d->uploaded;
        total_download += d->downloaded;
    }

    mac_to_str(s->mac, mac);
    ip4_to_str(s->ip, ip);
    format_timestamp(now_ms(), ts, sizeof(ts));

    format_bytes(total_upload + total_download, upload_s, sizeof(upload_s));
    format_bytes(total_upload, download_s, sizeof(download_s));

    fprintf(f, "{\n");
    fprintf(f, "      \"mac\": "); json_escape(f, mac); fprintf(f, ",\n");
    fprintf(f, "      \"ip\": "); json_escape(f, ip); fprintf(f, ",\n");
    fprintf(f, "      \"zone\": "); json_escape(f, zone_str(s->zone)); fprintf(f, ",\n");
    fprintf(f, "      \"timestamp\": "); json_escape(f, ts); fprintf(f, ",\n");
    fprintf(f, "      \"delta_uploaded_bytes\": %" PRIu64 ",\n", total_upload);
    fprintf(f, "      \"delta_downloaded_bytes\": %" PRIu64 ",\n", total_download);
    fprintf(f, "      \"domains_visited\": %d,\n", count_history_entries(history, false));
    fprintf(f, "      \"active_domains\": %d,\n", count_history_entries(history, true));
    fprintf(f, "      \"browsing_history\": [\n");

    bool first_domain = true;

    for (history_entry_t *d = history; d; d = d->next) {
        if (!first_domain)
            fprintf(f, ",\n");

        first_domain = false;

        char data_s[64], dur_s[64];
        uint64_t d_total = d->uploaded + d->downloaded;
        uint64_t spent_ms = 0;

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

void report_json(app_t *app) {
    if (!app)
        return;

    LOG(INFO, "STAMONITORD history report_json starting seq=%" PRIu64, app->report_seq + 1);

    uint64_t report_time = now_ms();
    char ts[64];
    format_timestamp(report_time, ts, sizeof(ts));

    char tmp[512];
    snprintf(tmp, sizeof(tmp), "%s.tmp", app->output_path);

    FILE *f = fopen(tmp, "w");
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

    bool first_station = true;
    int stations_reported = 0;

    for (size_t i = 0; i < STATION_BUCKETS; i++) {
        for (station_t *s = app->stations[i]; s; s = s->next) {
            history_entry_t *history = build_delta_history_entries(s, report_time);
            if (!history)
                continue;

            if (!first_station)
                fprintf(f, ",\n");

            first_station = false;
            stations_reported++;
            write_station_report_json(f, s, history);
            free_history_entries(history);
        }
    }

    fprintf(f, "\n  ]\n");
    fprintf(f, "}\n");

    fflush(f);
    if (fsync(fileno(f)) < 0) {
        LOG(ERR, "report_json: fsync %s failed: %s", tmp, strerror(errno));
    }
    fclose(f);

    if (rename(tmp, app->output_path) < 0) {
        LOG(ERR, "report_json: rename %s -> %s failed: %s", tmp, app->output_path, strerror(errno));
    } else {
        LOG(INFO, "STAMONITORD history wrote report file %s (stations_reported=%d)", app->output_path, stations_reported);
    }

    if (stations_reported > 0) {
        for (size_t i = 0; i < STATION_BUCKETS; i++) {
            for (station_t *s = app->stations[i]; s; s = s->next) {
                mark_station_history_reported(s, report_time);
            }
        }
    }
}

void flush_json(app_t *app) {
    char tmp[512];
    snprintf(tmp, sizeof(tmp), "%s.tmp", app->output_path);

    FILE *f = fopen(tmp, "w");
    if (!f) {
        LOG(ERR, "cannot open %s: %s", tmp, strerror(errno));
        return;
    }

    char ts[64];
    format_timestamp(now_ms(), ts, sizeof(ts));

    fprintf(f, "{\n");
    fprintf(f, "  \"daemon\": "); json_escape(f, APP_NAME); fprintf(f, ",\n");
    fprintf(f, "  \"timestamp\": "); json_escape(f, ts); fprintf(f, ",\n");

    size_t flows_active = 0;
    size_t ndpi_flows_active = 0;

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

    bool first_cap = true;

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

    bool first_station = true;

    for (size_t i = 0; i < STATION_BUCKETS; i++) {
        for (station_t *s = app->stations[i]; s; s = s->next) {
            if (!first_station)
                fprintf(f, ",\n");

            first_station = false;
            write_station_json(f, s);
        }
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

void flush_cb(EV_P_ ev_timer *w, int revents) {
    (void)loop;
    (void)revents;

    app_t *app = w->data;

    if (!app)
        return;

    history_event_publish(app);


    // if (app) {
    //     LOG(DEBUG, "STAMONITORD history flush timer fired");
    //     report_json(app);
    // }
}
