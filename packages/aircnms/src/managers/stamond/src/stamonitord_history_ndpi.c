#include "stamonitord_history_internal.h"
#include "log.h"

#if STAMONITORD_HISTORY_ENABLE_NDPI
static size_t get_ndpi_flow_size(void) {
#ifdef SIZEOF_FLOW_STRUCT
    return SIZEOF_FLOW_STRUCT;
#else
    return ndpi_detection_get_sizeof_ndpi_flow_struct();
#endif
}
#endif

/* ------------------------------------------------------------------------- */
/* nDPI + service helpers                                                    */
/* ------------------------------------------------------------------------- */

bool ndpi_label_is_generic(const char *s);

int init_ndpi(app_t *app) {
#if !STAMONITORD_HISTORY_ENABLE_NDPI
    app->ndpi = NULL;
    app->ndpi_flow_size = 0;
    LOG(INFO, "nDPI disabled for STAMONITORD history");
    return 0;
#else
    app->ndpi = ndpi_init_detection_module(NULL);
    if (!app->ndpi) {
        LOG(ERR, "ndpi_init_detection_module failed");
        return -1;
    }

    if (ndpi_finalize_initialization(app->ndpi) != 0) {
        LOG(ERR, "ndpi_finalize_initialization failed");
        ndpi_exit_detection_module(app->ndpi);
        app->ndpi = NULL;
        return -1;
    }

    app->ndpi_flow_size = get_ndpi_flow_size();

    LOG(INFO, "nDPI initialized, flow_size=%zu",
            app->ndpi_flow_size);

    return 0;
#endif
}

void ndpi_process_flow_packet(app_t *app,
                                     flow_t *flow,
                                     const parsed_pkt_t *pp) {
#if !STAMONITORD_HISTORY_ENABLE_NDPI
    (void)app;
    (void)flow;
    (void)pp;
    return;
#else
    if (!app->ndpi || !flow || !flow->ndpi_flow)
        return;

    if (!pp->l3_packet || pp->l3_packet_len == 0)
        return;

    if (flow->ndpi_packets >= NDPI_MAX_PACKETS_PER_FLOW) {
        free(flow->ndpi_flow);
        flow->ndpi_flow = NULL;
        return;
    }

    if (pp->l3_packet_len > 65535)
        return;

    /*
     * Your nDPI header expects:
     *
     * ndpi_detection_process_packet(ndpi_struct,
     *                               flow,
     *                               packet,
     *                               packetlen,
     *                               current_time_ms,
     *                               input_info);
     *
     * input_info can be NULL for basic detection.
     */
    ndpi_protocol proto = ndpi_detection_process_packet(
        app->ndpi,
        flow->ndpi_flow,
        pp->l3_packet,
        (unsigned short)pp->l3_packet_len,
        now_ms(),
        NULL
    );

    flow->ndpi_packets++;

    /*
     * Avoid accessing proto.master_protocol / proto.app_protocol directly,
     * because your nDPI version uses different struct field names.
     * ndpi_protocol2name() is the portable way.
     * ndpi_protocol has a .proto field of type ndpi_master_app_protocol
     */
    char proto_name[64] = {0};

    ndpi_protocol2name(app->ndpi,
                       proto.proto,
                       proto_name,
                       sizeof(proto_name));

    if (proto_name[0] &&
        strcmp(proto_name, "Unknown") &&
        strcmp(proto_name, "UNKNOWN")) {
        snprintf(flow->ndpi_proto_name,
                 sizeof(flow->ndpi_proto_name),
                 "%s",
                 proto_name);

        if (!ndpi_label_is_generic(proto_name)) {
            flow->ndpi_detected = true;
            free(flow->ndpi_flow);
            flow->ndpi_flow = NULL;
        }
    }

    if (flow->ndpi_packets >= NDPI_MAX_PACKETS_PER_FLOW &&
        flow->ndpi_flow) {
        free(flow->ndpi_flow);
        flow->ndpi_flow = NULL;
    }
#endif
}

const char *service_from_domain(const char *d) {
    if (!d || !d[0] || !strcmp(d, "unknown"))
        return "Unknown";

    if (strstr(d, "youtube.com") ||
        strstr(d, "googlevideo.com") ||
        strstr(d, "ytimg.com") ||
        strstr(d, "youtubei.googleapis.com") ||
        strstr(d, "yt3.googleusercontent.com")) {
        return "YouTube";
    }

    if (strstr(d, "nflxvideo.net") ||
        strstr(d, "netflix.com")) {
        return "Netflix";
    }

    if (strstr(d, "facebook.com") ||
        strstr(d, "fbcdn.net") ||
        strstr(d, "messenger.com")) {
        return "Facebook";
    }

    if (strstr(d, "instagram.com") ||
        strstr(d, "cdninstagram.com")) {
        return "Instagram";
    }

    if (strstr(d, "tiktok.com") ||
        strstr(d, "tiktokcdn.com")) {
        return "TikTok";
    }

    if (strstr(d, "google.com") ||
        strstr(d, "googleapis.com") ||
        strstr(d, "gstatic.com") ||
        strstr(d, "googleusercontent.com")) {
        return "Google";
    }

    return d;
}

const char *service_from_flow_and_domain(flow_t *flow, const char *domain) {
    if (flow && flow->ndpi_detected && flow->ndpi_proto_name[0]) {
        if (strstr(flow->ndpi_proto_name, "YouTube")) return "YouTube";
        if (strstr(flow->ndpi_proto_name, "Netflix")) return "Netflix";
        if (strstr(flow->ndpi_proto_name, "Facebook")) return "Facebook";
        if (strstr(flow->ndpi_proto_name, "Instagram")) return "Instagram";
        if (strstr(flow->ndpi_proto_name, "TikTok")) return "TikTok";
        if (strstr(flow->ndpi_proto_name, "Google")) return "Google";

        if (strcmp(flow->ndpi_proto_name, "QUIC") &&
            strcmp(flow->ndpi_proto_name, "TLS") &&
            strcmp(flow->ndpi_proto_name, "HTTP") &&
            strcmp(flow->ndpi_proto_name, "HTTPS")) {
            return flow->ndpi_proto_name;
        }
    }

    return service_from_domain(domain);
}

const char *domain_from_service_if_unknown(const char *domain,
                                                  const char *service) {
    if (domain && strcmp(domain, "unknown"))
        return domain;

    if (!service || !service[0] || !strcmp(service, "Unknown"))
        return domain ? domain : "unknown";

    if (!strcmp(service, "YouTube")) return "youtube.com";
    if (!strcmp(service, "Netflix")) return "netflix.com";
    if (!strcmp(service, "Facebook")) return "facebook.com";
    if (!strcmp(service, "Instagram")) return "instagram.com";
    if (!strcmp(service, "TikTok")) return "tiktok.com";
    if (!strcmp(service, "Google")) return "google.com";

    return domain ? domain : "unknown";
}

bool str_contains_ci(const char *haystack, const char *needle) {
    return haystack && needle && strcasestr(haystack, needle);
}

const char *strip_service_prefix(const char *s) {
    static const char *prefixes[] = {"TLS.", "QUIC.", "HTTP.", "HTTPS."};

    if (!s)
        return NULL;

    for (size_t i = 0; i < sizeof(prefixes) / sizeof(prefixes[0]); i++) {
        size_t len = strlen(prefixes[i]);
        if (!strncasecmp(s, prefixes[i], len))
            return s + len;
    }

    return s;
}

bool ndpi_label_is_generic(const char *s) {
    if (!s || !s[0])
        return true;

    return !strcasecmp(s, "unknown") ||
           !strcasecmp(s, "http") ||
           !strcasecmp(s, "https") ||
           !strcasecmp(s, "tls") ||
           !strcasecmp(s, "quic") ||
           !strcasecmp(s, "dns");
}

const char *normalized_history_service(const char *service,
                                              const char *ndpi_protocol,
                                              const char *domain) {
    if (str_contains_ci(service, "dns") ||
        str_contains_ci(ndpi_protocol, "dns") ||
        (domain && !strcmp(domain, "dns"))) {
        return "DNS";
    }

    if (str_contains_ci(service, "youtube") ||
        str_contains_ci(ndpi_protocol, "youtube") ||
        str_contains_ci(domain, "youtube.com") ||
        str_contains_ci(domain, "googlevideo.com") ||
        str_contains_ci(domain, "ytimg.com") ||
        str_contains_ci(domain, "youtubei.googleapis.com") ||
        str_contains_ci(domain, "yt3.googleusercontent.com")) {
        return "YouTube";
    }

    if (str_contains_ci(service, "netflix") ||
        str_contains_ci(ndpi_protocol, "netflix") ||
        str_contains_ci(domain, "netflix.com") ||
        str_contains_ci(domain, "nflxvideo.net") ||
        str_contains_ci(domain, "fast.com")) {
        return "Netflix";
    }

    if (str_contains_ci(service, "facebook") ||
        str_contains_ci(service, "fbook") ||
        str_contains_ci(ndpi_protocol, "facebook") ||
        str_contains_ci(ndpi_protocol, "fbook") ||
        str_contains_ci(domain, "facebook.com") ||
        str_contains_ci(domain, "fbcdn.net") ||
        str_contains_ci(domain, "messenger.com")) {
        return "Facebook";
    }

    if (str_contains_ci(service, "instagram") ||
        str_contains_ci(ndpi_protocol, "instagram") ||
        str_contains_ci(domain, "instagram.com") ||
        str_contains_ci(domain, "cdninstagram.com")) {
        return "Instagram";
    }

    if (str_contains_ci(service, "tiktok") ||
        str_contains_ci(ndpi_protocol, "tiktok") ||
        str_contains_ci(domain, "tiktok.com") ||
        str_contains_ci(domain, "tiktokcdn.com")) {
        return "TikTok";
    }

    if (str_contains_ci(service, "reddit") ||
        str_contains_ci(ndpi_protocol, "reddit") ||
        str_contains_ci(domain, "reddit.com") ||
        str_contains_ci(domain, "redditspace.com")) {
        return "Reddit";
    }

    if (str_contains_ci(service, "wechat") ||
        str_contains_ci(ndpi_protocol, "wechat") ||
        str_contains_ci(domain, "wechat.com")) {
        return "WeChat";
    }

    if (str_contains_ci(service, "playstore") ||
        str_contains_ci(ndpi_protocol, "playstore") ||
        str_contains_ci(domain, "play.google.com") ||
        str_contains_ci(domain, "play-fe.googleapis.com")) {
        return "Play Store";
    }

    if (str_contains_ci(service, "google") ||
        str_contains_ci(ndpi_protocol, "google") ||
        str_contains_ci(domain, "google.com") ||
        str_contains_ci(domain, "googleapis.com") ||
        str_contains_ci(domain, "gstatic.com") ||
        str_contains_ci(domain, "googleusercontent.com") ||
        str_contains_ci(domain, "ampproject.org")) {
        return "Google";
    }

    if (service && service[0] &&
        strcasecmp(service, "unknown") &&
        strcasecmp(service, "Unknown")) {
        return strip_service_prefix(service);
    }

    if (domain && domain[0] &&
        strcmp(domain, "unknown") &&
        strcmp(domain, "dns")) {
        return domain;
    }

    if (ndpi_protocol && ndpi_protocol[0] &&
        !ndpi_label_is_generic(ndpi_protocol)) {
        return strip_service_prefix(ndpi_protocol);
    }

    return "Unknown";
}

const char *history_domain_for_service(const char *service,
                                              const char *fallback_domain) {
    if (!service || !service[0])
        return fallback_domain ? fallback_domain : "unknown";

    if (!strcmp(service, "DNS")) return "dns";
    if (!strcmp(service, "YouTube")) return "youtube.com";
    if (!strcmp(service, "Netflix")) return "netflix.com";
    if (!strcmp(service, "Facebook")) return "facebook.com";
    if (!strcmp(service, "Instagram")) return "instagram.com";
    if (!strcmp(service, "TikTok")) return "tiktok.com";
    if (!strcmp(service, "Reddit")) return "reddit.com";
    if (!strcmp(service, "WeChat")) return "wechat.com";
    if (!strcmp(service, "Play Store")) return "play.google.com";
    if (!strcmp(service, "Google")) return "google.com";

    if (fallback_domain && fallback_domain[0] && strcmp(fallback_domain, "unknown"))
        return fallback_domain;

    if (!strcmp(service, "Unknown"))
        return "unknown";

    return service;
}
