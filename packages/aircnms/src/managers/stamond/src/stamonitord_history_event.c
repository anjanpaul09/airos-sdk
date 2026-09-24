/*
 * stamonitord_history_event.c
 */

#include "stamonitord_info_events.h"
#include "stamonitord_history_event.h"
#include "stamonitord_ubus_tx.h"

#include "info_events.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <inttypes.h>

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

    get_uci_value(
        "uci get aircnms.@aircnms[0].network_id 2>/dev/null",
        network_id,
        sizeof(network_id));

    get_uci_value(
        "uci get aircnms.@aircnms[0].device_id 2>/dev/null",
        device_id,
        sizeof(device_id));

    get_uci_value(
        "uci get aircnms.@aircnms[0].org_id 2>/dev/null",
        org_id,
        sizeof(org_id));

    if (!app)
        return out;

    FILE *f = open_memstream(&out.data, &out.len);
    if (!f)
        return out;

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

    bool first_entry = true;
    int history_entries = 0;

    for (size_t i = 0; i < STATION_BUCKETS; i++) {

        for (station_t *s = app->stations[i]; s; s = s->next) {

            history_entry_t *history;

            history = build_delta_history_entries(s, report_time);
            if (!history)
                continue;

            char mac[18];
            char ip[INET_ADDRSTRLEN];

            mac_to_str(s->mac, mac);
            ip4_to_str(s->ip, ip);

            for (history_entry_t *d = history; d; d = d->next) {

                if (!first_entry)
                    fprintf(f, ",\n");

                first_entry = false;
                history_entries++;
                
                uint64_t spent_ms = 0;

                if (d->last_seen_ms > d->first_seen_ms)
                    spent_ms = d->last_seen_ms - d->first_seen_ms;

                fprintf(f, "         {\n");

                fprintf(f, "            \"domain\":");
                json_escape(f, d->domain);
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
                fprintf(f, ",\n");

                fprintf(f, "            \"ip\":");
                json_escape(f, ip);
                fprintf(f, "\n");

                fprintf(f, "         }");
            }

            mark_station_history_reported(s, report_time);

            free_history_entries(history);
        }
    }

    if (history_entries == 0) {
        fclose(f);

        free(out.data);
        out.data = NULL;
        out.len = 0;

        return out;
    }

    fprintf(f, "\n");
    fprintf(f, "      ]\n");
    fprintf(f, "   }\n");
    fprintf(f, "}\n");

    fclose(f);

    return out;
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
