#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "netconf_payload_validate.h"

#define MAX_VIFS 16
#define MAX_RADIOS 2
#define MAX_RATE_MBPS 10000L

static bool fail(char *out, size_t n, const char *fmt, ...)
{
    va_list ap;
    if (out && n) {
        va_start(ap, fmt);
        vsnprintf(out, n, fmt, ap);
        va_end(ap);
    }
    return false;
}

static const char *str_field(json_t *o, const char *key)
{
    json_t *v = json_object_get(o, key);
    return json_is_string(v) ? json_string_value(v) : NULL;
}

static bool integer_string(const char *s, long min, long max, long *value)
{
    char *end = NULL;
    long v;
    if (!s || !*s) return false;
    errno = 0;
    v = strtol(s, &end, 10);
    if (errno || !end || *end || v < min || v > max) return false;
    if (value) *value = v;
    return true;
}

static bool ipv4(const char *s)
{
    struct in_addr a;
    return s && inet_pton(AF_INET, s, &a) == 1;
}

static bool mac(const char *s)
{
    unsigned int b[6]; char tail;
    return s && sscanf(s, "%2x:%2x:%2x:%2x:%2x:%2x%c",
        &b[0], &b[1], &b[2], &b[3], &b[4], &b[5], &tail) == 6;
}

static bool one_of(const char *s, const char *const *values)
{
    if (!s) return false;
    for (; *values; values++) if (!strcmp(s, *values)) return true;
    return false;
}

static bool valid_psk(const char *s)
{
    size_t n;
    if (!s) return false;
    n = strlen(s);
    if (n >= 8 && n <= 63) return true;
    if (n != 64) return false;
    for (size_t i = 0; i < n; i++) if (!isxdigit((unsigned char)s[i])) return false;
    return true;
}

static bool valid_time(const char *s)
{
    int h, m; char tail;
    return s && sscanf(s, "%2d:%2d%c", &h, &m, &tail) == 2 &&
           h >= 0 && h <= 23 && m >= 0 && m <= 59 && strlen(s) == 5;
}

static bool valid_day(const char *s)
{
    static const char *const days[] = {
        "mon", "monday", "tue", "tuesday", "wed", "wednesday",
        "thu", "thursday", "fri", "friday", "sat", "saturday",
        "sun", "sunday", NULL
    };
    if (!s) return false;
    for (const char *const *day = days; *day; day++)
        if (!strcasecmp(s, *day)) return true;
    return false;
}

static bool valid_country(const char *s)
{
    return s && strlen(s) == 2 &&
           isalpha((unsigned char)s[0]) && isalpha((unsigned char)s[1]);
}

static bool validate_vif(json_t *v, size_t i, char *err, size_t n)
{
    /* SAE Personal modes are runtime-tested on the target image. WPA3
     * Enterprise remains available for the separate RADIUS validation pass. */
    static const char *const encs[] = {"open", "wpa-psk", "wpa2-psk",
        "wpa/wpa2-psk", "wpa3-psk", "wpa2/wpa3-psk",
        "wpa2-enterprise", "wpa3-enterprise", NULL};
    static const char *const forwards[] = {"Bridge", "NAT", NULL};
    static const char *const radios[] = {"2.4GHz", "5GHz", NULL};
    const char *id, *ssid, *enc, *key, *forward, *radio;
    json_t *j;
    long status, vlan;

    if (!json_is_object(v)) return fail(err, n, "vif[%zu] must be an object", i);
    id = str_field(v, "recordId");
    if (!id || !*id || strlen(id) >= 12 || strncmp(id, "wlan", 4))
        return fail(err, n, "vif[%zu].recordId is invalid", i);
    j = json_object_get(v, "status");
    if (!json_is_integer(j) || (status = json_integer_value(j)) < 0 || status > 3)
        return fail(err, n, "vif[%zu].status must be 0..3", i);
    j = json_object_get(v, "enable");
    if (!json_is_boolean(j)) return fail(err, n, "vif[%zu].enable must be boolean", i);
    if (status == 2 || !json_boolean_value(j)) return true;

    ssid = str_field(v, "ssid");
    if (!ssid || !*ssid || strlen(ssid) > 32)
        return fail(err, n, "vif[%zu].ssid must contain 1..32 bytes", i);
    enc = str_field(v, "encryption");
    if (!one_of(enc, encs)) return fail(err, n, "vif[%zu].encryption is unsupported", i);
    key = str_field(v, "key");
    if (!strcmp(enc, "open")) {
        if (key && *key) return fail(err, n, "vif[%zu] open network must not contain a key", i);
    } else if (!strstr(enc, "enterprise") && !valid_psk(key)) {
        return fail(err, n, "vif[%zu].key must be 8..63 bytes or 64 hex digits", i);
    }
    if (strstr(enc, "enterprise")) {
        const char *server = str_field(v, "serverIp");
        const char *secret = str_field(v, "communicateKey");
        json_t *auth = json_object_get(v, "authPort");
        json_t *acct = json_object_get(v, "accountPort");
        if (!ipv4(server) || !secret || !*secret || strlen(secret) >= 64 ||
            !json_is_integer(auth) || json_integer_value(auth) < 1 || json_integer_value(auth) > 65535 ||
            !json_is_integer(acct) || json_integer_value(acct) < 1 || json_integer_value(acct) > 65535)
            return fail(err, n, "vif[%zu] has invalid RADIUS settings", i);
    }
    forward = str_field(v, "forwardType");
    if (!one_of(forward, forwards)) return fail(err, n, "vif[%zu].forwardType is invalid", i);
    radio = str_field(v, "radioType");
    if (!one_of(radio, radios)) return fail(err, n, "vif[%zu].radioType is invalid", i);
    j = json_object_get(v, "vlanId");
    if (!json_is_integer(j) || (vlan = json_integer_value(j)) < 0 || vlan > 4094)
        return fail(err, n, "vif[%zu].vlanId must be 0..4094", i);

    const char *rate_keys[] = {"uprate", "downrate", "wlanUprate", "wlanDownrate"};
    for (size_t k = 0; k < sizeof(rate_keys)/sizeof(rate_keys[0]); k++) {
        const char *rate = str_field(v, rate_keys[k]);
        if (rate && *rate && !integer_string(rate, 0, MAX_RATE_MBPS, NULL))
            return fail(err, n, "vif[%zu].%s is invalid", i, rate_keys[k]);
    }
    j = json_object_get(v, "schedule");
    if (j && !json_is_null(j)) {
        if (!json_is_array(j) || json_array_size(j) > 7)
            return fail(err, n, "vif[%zu].schedule must contain at most 7 entries", i);
        size_t si; json_t *entry;
        json_array_foreach(j, si, entry) {
            const char *day = str_field(entry, "day");
            const char *start = str_field(entry, "start");
            const char *end = str_field(entry, "end");
            if (!json_is_object(entry) || !valid_day(day) ||
                !valid_time(start) || !valid_time(end) || strcmp(start, end) == 0)
                return fail(err, n, "vif[%zu].schedule[%zu] is invalid", i, si);
        }
    }
    return true;
}

static bool valid_channel(const char *band, const char *s)
{
    long ch;
    if (!s || !strcmp(s, "auto")) return s != NULL;
    if (!integer_string(s, 1, 196, &ch)) return false;
    if (!strcmp(band, "2.4GHz")) return ch >= 1 && ch <= 14;
    /* Valid 20 MHz center channels accepted by this MT7621 target. */
    return (ch >= 36 && ch <= 64 && ch % 4 == 0) ||
           (ch >= 100 && ch <= 144 && ch % 4 == 0) ||
           (ch >= 149 && ch <= 165 && (ch - 149) % 4 == 0);
}

static bool validate_radio(json_t *r, size_t i, char *err, size_t n)
{
    static const char *const bands[] = {"2.4GHz", "5GHz", NULL};
    static const char *const modes24[] = {"11B", "11G", "11BGN", "11AX", "11BGN_11AX", NULL};
    static const char *const modes5[] = {"11NA", "11AC", "11AX", "11NA_11AC_11AX", NULL};
    const char *band, *channel, *tx, *ul, *country, *hwmode;
    json_t *j; long width;
    if (!json_is_object(r)) return fail(err, n, "radio[%zu] must be an object", i);
    band = str_field(r, "radioType");
    if (!one_of(band, bands)) return fail(err, n, "radio[%zu].radioType is invalid", i);
    j = json_object_get(r, "status");
    if (!json_is_integer(j) || json_integer_value(j) < 0 || json_integer_value(j) > 2)
        return fail(err, n, "radio[%zu].status must be 0, 1, or 2", i);
    channel = str_field(r, "channel");
    if (channel && !valid_channel(band, channel)) return fail(err, n, "radio[%zu].channel is invalid", i);
    tx = str_field(r, "txpower");
    if (tx && *tx && !integer_string(tx, 0, 30, NULL)) return fail(err, n, "radio[%zu].txpower is invalid", i);
    j = json_object_get(r, "channelWidth");
    if (j) {
        if (!json_is_integer(j)) return fail(err, n, "radio[%zu].channelWidth must be integer", i);
        width = json_integer_value(j);
        if ((!strcmp(band, "2.4GHz") && width != 20 && width != 40) ||
            (!strcmp(band, "5GHz") && width != 20 && width != 40 && width != 80))
            return fail(err, n, "radio[%zu].channelWidth is unsupported", i);
    }
    ul = str_field(r, "userlimit");
    if (ul && *ul && !integer_string(ul, 1, 128, NULL)) return fail(err, n, "radio[%zu].userlimit is invalid", i);
    j = json_object_get(r, "disabled");
    if (j && !json_is_boolean(j) && !json_is_integer(j) && !json_is_string(j))
        return fail(err, n, "radio[%zu].disabled has invalid type", i);
    country = str_field(r, "country");
    if (country && *country && !valid_country(country))
        return fail(err, n, "radio[%zu].country must be a two-letter code", i);
    hwmode = str_field(r, "hwmode");
    if (hwmode && *hwmode && !one_of(hwmode, !strcmp(band, "2.4GHz") ? modes24 : modes5))
        return fail(err, n, "radio[%zu].hwmode is unsupported for %s", i, band);
    return true;
}

bool netconf_validate_config_payload(json_t *root, char *err, size_t n)
{
    json_t *vif_root, *vifs, *radio_root, *radios, *nat;
    if (!json_is_object(root)) return fail(err, n, "root must be an object");
    vif_root = json_object_get(root, "vif");
    vifs = vif_root ? json_object_get(vif_root, "vifList") : NULL;
    if (vifs) {
        if (!json_is_array(vifs) || json_array_size(vifs) > MAX_VIFS)
            return fail(err, n, "vifList must be an array with at most %d entries", MAX_VIFS);
        size_t i; json_t *v;
        json_array_foreach(vifs, i, v) {
            if (!validate_vif(v, i, err, n)) return false;
            for (size_t j = 0; j < i; j++)
                if (!strcmp(str_field(v, "recordId"), str_field(json_array_get(vifs, j), "recordId")))
                    return fail(err, n, "duplicate vif recordId at index %zu", i);
        }
    }
    radio_root = json_object_get(root, "radio");
    radios = radio_root ? json_object_get(radio_root, "radioList") : NULL;
    if (radios) {
        if (!json_is_array(radios) || json_array_size(radios) > MAX_RADIOS)
            return fail(err, n, "radioList must be an array with at most %d entries", MAX_RADIOS);
        size_t i; json_t *r;
        json_array_foreach(radios, i, r) {
            if (!validate_radio(r, i, err, n)) return false;
            for (size_t j = 0; j < i; j++)
                if (!strcmp(str_field(r, "radioType"), str_field(json_array_get(radios, j), "radioType")))
                    return fail(err, n, "duplicate radioType at index %zu", i);
        }
    }
    nat = json_object_get(root, "natConfig");
    if (nat) {
        const char *ip, *mask;
        if (!json_is_object(nat)) return fail(err, n, "natConfig must be an object");
        ip = str_field(nat, "netSegmentIp"); mask = str_field(nat, "netMaskIp");
        if ((ip && *ip) || (mask && *mask))
            if (!ipv4(ip) || !ipv4(mask)) return fail(err, n, "natConfig requires valid IPv4 address and mask");
    }
    if (!vifs && !radios && !nat) return fail(err, n, "payload contains no supported configuration");
    return true;
}

bool netconf_validate_acl_payload(json_t *root, char *err, size_t n)
{
    if (!json_is_object(root)) return fail(err, n, "root must be an object");
    const char *names[] = {"blackList", "whiteList"}; bool found = false;
    for (size_t x = 0; x < 2; x++) {
        json_t *list = json_object_get(root, names[x]);
        if (!list)
            continue;
        found = true;
        if (!json_is_object(list)) return fail(err, n, "%s must be an object", names[x]);
        const char *type = str_field(list, "type");
        if (!type || (strcmp(type, "ssid") && strcmp(type, "network") && strcmp(type, "device")))
            return fail(err, n, "%s.type must be device, network, or ssid", names[x]);
        if (!strcmp(type, "ssid")) {
            const char *ssid = str_field(list, "ssid");
            if (!ssid || !*ssid || strlen(ssid) > 32)
                return fail(err, n, "%s.ssid must contain 1..32 bytes", names[x]);
        }
        const char *keys[] = {"add", "remove"};
        for (size_t k = 0; k < 2; k++) {
            json_t *a = json_object_get(list, keys[k]);
            if (!a) continue;
            if (!json_is_array(a) || json_array_size(a) > 1024) return fail(err, n, "%s.%s is invalid", names[x], keys[k]);
            size_t i; json_t *m; json_array_foreach(a, i, m)
                if (!json_is_string(m) || !mac(json_string_value(m))) return fail(err, n, "%s.%s[%zu] is not a MAC", names[x], keys[k], i);
        }
    }
    return found ? true : fail(err, n, "missing blackList/whiteList");
}

bool netconf_validate_rate_limit_payload(json_t *root, char *err, size_t n)
{
    json_t *r; const char *m, *up, *down;
    if (!json_is_object(root) || !json_is_object(r = json_object_get(root, "rateLimit")))
        return fail(err, n, "missing rateLimit object");
    m = str_field(r, "mac"); up = str_field(r, "uplink"); down = str_field(r, "downlink");
    if (!mac(m)) return fail(err, n, "rateLimit.mac is invalid");
    if (!integer_string(up, 0, MAX_RATE_MBPS, NULL) || !integer_string(down, 0, MAX_RATE_MBPS, NULL))
        return fail(err, n, "rateLimit values must be integers between 0 and %ld", MAX_RATE_MBPS);
    return true;
}
