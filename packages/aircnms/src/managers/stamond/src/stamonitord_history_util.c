#include "stamonitord_history_internal.h"

/* paste Utility section here, but remove static from function definitions */

uint64_t now_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return ((uint64_t)tv.tv_sec * 1000ULL) + ((uint64_t)tv.tv_usec / 1000ULL);
}

/* continue with rd16, rd32, hash_bytes, ip helpers, mac helpers,
 * domain helpers, zone_str, classify_traffic, format_bytes,
 * format_duration, format_timestamp.
 *
 * Also put json_escape() here or in stamonitord_history_json.c.
 */

uint16_t rd16(const uint8_t *p) {
    return ((uint16_t)p[0] << 8) | p[1];
}

uint32_t rd32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) |
           ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) |
           p[3];
}

uint32_t hash_bytes(const void *data, size_t len) {
    const uint8_t *p = data;
    uint32_t h = 2166136261u;

    for (size_t i = 0; i < len; i++) {
        h ^= p[i];
        h *= 16777619u;
    }

    return h;
}

void ip16_from_ip4(uint8_t out[16], uint32_t ip) {
    memset(out, 0, 16);
    memcpy(out + 12, &ip, 4);
}

void ip16_from_ip6(uint8_t out[16], const uint8_t ip6[16]) {
    memcpy(out, ip6, 16);
}

uint32_t hash_ip_key(uint8_t ip_version, const uint8_t ip[16]) {
    uint8_t key[17];
    key[0] = ip_version;
    memcpy(key + 1, ip, 16);
    return hash_bytes(key, sizeof(key));
}

bool mac_equal(mac_addr_t a, mac_addr_t b) {
    return memcmp(a.b, b.b, 6) == 0;
}

bool mac_is_zero(mac_addr_t m) {
    static const uint8_t z[6] = {0};
    return memcmp(m.b, z, 6) == 0;
}

bool mac_is_broadcast(mac_addr_t m) {
    static const uint8_t b[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
    return memcmp(m.b, b, 6) == 0;
}

bool mac_is_multicast(mac_addr_t m) {
    return !!(m.b[0] & 0x01);
}

void mac_to_str(mac_addr_t mac, char out[18]) {
    snprintf(out, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac.b[0], mac.b[1], mac.b[2],
             mac.b[3], mac.b[4], mac.b[5]);
}

int parse_mac_str(const char *s, mac_addr_t *mac) {
    unsigned int b[6];

    if (sscanf(s, "%02x:%02x:%02x:%02x:%02x:%02x",
               &b[0], &b[1], &b[2],
               &b[3], &b[4], &b[5]) != 6)
        return -1;

    for (int i = 0; i < 6; i++)
        mac->b[i] = (uint8_t)b[i];

    return 0;
}

const char *ip4_to_str(uint32_t ip_net, char out[INET_ADDRSTRLEN]) {
    struct in_addr a;
    a.s_addr = ip_net;
    if (!inet_ntop(AF_INET, &a, out, INET_ADDRSTRLEN))
        snprintf(out, INET_ADDRSTRLEN, "0.0.0.0");
    return out;
}

bool is_private_or_local_ipv4(uint32_t ip_net) {
    uint32_t ip = ntohl(ip_net);

    if ((ip & 0xff000000U) == 0x0a000000U) return true;
    if ((ip & 0xfff00000U) == 0xac100000U) return true;
    if ((ip & 0xffff0000U) == 0xc0a80000U) return true;
    if ((ip & 0xffff0000U) == 0xa9fe0000U) return true;
    if (ip == 0) return true;

    return false;
}

bool is_common_gateway_ip(uint32_t ip_net) {
    uint32_t ip = ntohl(ip_net);
    uint8_t last = ip & 0xff;
    return last == 1 || last == 254;
}

bool is_ap_own_oui(mac_addr_t mac) {
    return mac.b[0] == 0x58 &&
           mac.b[1] == 0x7b &&
           mac.b[2] == 0xe9;
}

bool domain_is_tld_artifact(const char *d) {
    if (!d || !d[0]) return true;
    if (!strcmp(d, "com")) return true;
    if (!strcmp(d, "net")) return true;
    if (!strcmp(d, "org")) return true;
    if (!strcmp(d, "in"))  return true;
    if (!strcmp(d, "io"))  return true;
    if (!strcmp(d, "co"))  return true;
    return false;
}

bool valid_domain_for_history(const char *d) {
    if (!d || !d[0]) return false;

    size_t len = strlen(d);

    if (len < 4 || len > 253) return false;
    if (domain_is_tld_artifact(d)) return false;
    //if (!strchr(d, '.')) return false;

    /*
 * Allow local/internal domains too.
 */
if (!strchr(d, '.') &&
    strcmp(d, "localhost") != 0 &&
    strcmp(d, "dns") != 0 &&
    strcmp(d, "unknown") != 0)
{
    return false;
}

    return true;
}

const char *zone_str(zone_t z) {
    switch (z) {
    case ZONE_BR_LAN: return "br-lan";
    case ZONE_BR_NAT: return "br-nat";
    default: return "unknown";
    }
}

traffic_type_t classify_traffic(uint8_t proto, uint16_t sport, uint16_t dport) {
    sport = ntohs(sport);
    dport = ntohs(dport);

    if (proto == IPPROTO_UDP && (sport == 53 || dport == 53)) return TRAFFIC_DNS;
    if (proto == IPPROTO_TCP && (sport == 80 || dport == 80)) return TRAFFIC_HTTP;
    if (proto == IPPROTO_TCP && (sport == 443 || dport == 443)) return TRAFFIC_HTTPS;
    if (proto == IPPROTO_UDP && (sport == 443 || dport == 443)) return TRAFFIC_QUIC;

    return TRAFFIC_OTHER;
}

const char *traffic_type_str(traffic_type_t t) {
    switch (t) {
    case TRAFFIC_DNS: return "DNS";
    case TRAFFIC_HTTP: return "HTTP";
    case TRAFFIC_HTTPS: return "HTTPS";
    case TRAFFIC_QUIC: return "QUIC";
    default: return "OTHER";
    }
}

void format_bytes(uint64_t b, char *out, size_t n) {
    const char *units[] = {"B", "KB", "MB", "GB", "TB"};
    double v = (double)b;
    int u = 0;

    while (v >= 1024.0 && u < 4) {
        v /= 1024.0;
        u++;
    }

    snprintf(out, n, "%.2f %s", v, units[u]);
}

void format_duration(uint64_t ms, char *out, size_t n) {
    uint64_t sec = ms / 1000;
    uint64_t h = sec / 3600;
    uint64_t m = (sec % 3600) / 60;
    uint64_t s = sec % 60;

    if (h)
        snprintf(out, n, "%" PRIu64 "h %" PRIu64 "m %" PRIu64 "s", h, m, s);
    else if (m)
        snprintf(out, n, "%" PRIu64 "m %" PRIu64 "s", m, s);
    else
        snprintf(out, n, "%" PRIu64 "s", s);
}

void format_timestamp(uint64_t ms, char *out, size_t n) {
    time_t sec = (time_t)(ms / 1000);
    struct tm tmv;
    char base[64];

    localtime_r(&sec, &tmv);
    strftime(base, sizeof(base), "%Y-%m-%d %H:%M:%S", &tmv);
    snprintf(out, n, "%s.%03u", base, (unsigned)(ms % 1000));
}

void json_escape(FILE *f, const char *s) {
    fputc('"', f);

    if (!s)
        s = "";

    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;

        switch (c) {
        case '"': fputs("\\\"", f); break;
        case '\\': fputs("\\\\", f); break;
        case '\b': fputs("\\b", f); break;
        case '\f': fputs("\\f", f); break;
        case '\n': fputs("\\n", f); break;
        case '\r': fputs("\\r", f); break;
        case '\t': fputs("\\t", f); break;
        default:
            if (c < 0x20) fprintf(f, "\\u%04x", c);
            else fputc(c, f);
        }
    }

    fputc('"', f);
}
