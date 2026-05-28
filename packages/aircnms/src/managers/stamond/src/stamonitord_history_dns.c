#include "stamonitord_history_internal.h"

/* paste DNS cache section */
/* paste DNS parser section */
/* paste TLS SNI parser section */

/* ------------------------------------------------------------------------- */
/* DNS cache                                                                 */
/* ------------------------------------------------------------------------- */

void dns_put_addr(app_t *app,
                         uint8_t ip_version,
                         const uint8_t ip[16],
                         const char *domain,
                         uint32_t ttl) {
    if (!ip || !domain || !domain[0])
        return;

    if (!valid_domain_for_history(domain))
        return;

    uint32_t h = hash_ip_key(ip_version, ip) % DNS_BUCKETS;
    uint64_t t = now_ms();

    uint32_t effective_ttl = ttl ? ttl : DNS_DEFAULT_TTL_SEC;

    if (effective_ttl < DNS_MIN_TTL_SEC)
        effective_ttl = DNS_MIN_TTL_SEC;

    if (effective_ttl > DNS_MAX_TTL_SEC)
        effective_ttl = DNS_MAX_TTL_SEC;

    uint64_t expires = t + ((uint64_t)effective_ttl * 1000ULL);

    for (dns_entry_t *e = app->dns[h]; e; e = e->next) {
        if (e->ip_version == ip_version && !memcmp(e->ip, ip, 16)) {
            snprintf(e->domain, sizeof(e->domain), "%s", domain);
            e->expires_ms = expires;
            e->last_seen_ms = t;
            return;
        }
    }

    dns_entry_t *e = calloc(1, sizeof(*e));
    if (!e)
        return;

    e->ip_version = ip_version;
    memcpy(e->ip, ip, 16);
    snprintf(e->domain, sizeof(e->domain), "%s", domain);
    e->expires_ms = expires;
    e->last_seen_ms = t;

    e->next = app->dns[h];
    app->dns[h] = e;
}

void dns_put4(app_t *app, uint32_t ip, const char *domain, uint32_t ttl) {
    uint8_t key[16];

    if (!ip)
        return;

    ip16_from_ip4(key, ip);
    dns_put_addr(app, 4, key, domain, ttl);
}

void dns_put6(app_t *app, const uint8_t ip[16], const char *domain, uint32_t ttl) {
    dns_put_addr(app, 6, ip, domain, ttl);
}

const char *dns_lookup_addr(app_t *app, uint8_t ip_version, const uint8_t ip[16]) {
    uint32_t h = hash_ip_key(ip_version, ip) % DNS_BUCKETS;
    uint64_t t = now_ms();

    for (dns_entry_t *e = app->dns[h]; e; e = e->next) {
        if (e->ip_version == ip_version &&
            !memcmp(e->ip, ip, 16) &&
            e->expires_ms > t) {
            return e->domain;
        }
    }

    return NULL;
}

const char *dns_lookup4(app_t *app, uint32_t ip) {
    uint8_t key[16];

    if (!ip)
        return NULL;

    ip16_from_ip4(key, ip);
    return dns_lookup_addr(app, 4, key);
}

const char *dns_lookup6(app_t *app, const uint8_t ip[16]) {
    return dns_lookup_addr(app, 6, ip);
}

/* ------------------------------------------------------------------------- */
/* DNS parser                                                                */
/* ------------------------------------------------------------------------- */

int dns_read_name(const uint8_t *pkt,
                         size_t len,
                         size_t *off,
                         char *out,
                         size_t out_len,
                         int depth) {
    if (depth > 10)
        return -1;

    size_t p = *off;
    size_t o = 0;
    bool jumped = false;

    if (out_len == 0)
        return -1;

    out[0] = '\0';

    while (p < len) {
        uint8_t c = pkt[p];

        if (c == 0) {
            p++;
            if (!jumped)
                *off = p;

            if (o > 0 && out[o - 1] == '.')
                out[o - 1] = '\0';
            else
                out[o] = '\0';

            return 0;
        }

        if ((c & 0xc0) == 0xc0) {
            if (p + 1 >= len)
                return -1;

            uint16_t ptr = ((uint16_t)(c & 0x3f) << 8) | pkt[p + 1];

            p += 2;
            if (!jumped)
                *off = p;

            jumped = true;

            char suffix[256];
            size_t noff = ptr;

            if (dns_read_name(pkt, len, &noff, suffix, sizeof(suffix), depth + 1) < 0)
                return -1;

            if (suffix[0]) {
                size_t sl = strlen(suffix);

                if (o && out[o - 1] != '.') {
                    if (o + 1 >= out_len)
                        return -1;
                    out[o++] = '.';
                }

                if (o + sl >= out_len)
                    return -1;

                memcpy(out + o, suffix, sl);
                o += sl;
                out[o] = '\0';
            }

            return 0;
        }

        if (c & 0xc0)
            return -1;

        p++;

        if (p + c > len)
            return -1;

        if (o + c + 2 >= out_len)
            return -1;

        memcpy(out + o, pkt + p, c);
        o += c;
        out[o++] = '.';
        out[o] = '\0';

        p += c;
    }

    return -1;
}

void parse_dns_response(app_t *app, const uint8_t *dns, size_t len) {
    if (len < 12)
        return;

    uint16_t flags = rd16(dns + 2);
    bool is_response = !!(flags & 0x8000);

    if (!is_response)
        return;

    uint16_t qdcount = rd16(dns + 4);
    uint16_t ancount = rd16(dns + 6);

    size_t off = 12;
    char qname[256] = {0};

    for (uint16_t i = 0; i < qdcount; i++) {
        char tmp[256] = {0};

        if (dns_read_name(dns, len, &off, tmp, sizeof(tmp), 0) < 0)
            return;

        if (i == 0)
            snprintf(qname, sizeof(qname), "%s", tmp);

        if (off + 4 > len)
            return;

        off += 4;
    }

    for (uint16_t i = 0; i < ancount; i++) {
        char name[256] = {0};

        if (dns_read_name(dns, len, &off, name, sizeof(name), 0) < 0)
            return;

        if (off + 10 > len)
            return;

        uint16_t type = rd16(dns + off);
        uint16_t class_ = rd16(dns + off + 2);
        uint32_t ttl = rd32(dns + off + 4);
        uint16_t rdlen = rd16(dns + off + 8);

        off += 10;

        if (off + rdlen > len)
            return;

        if (class_ == 1 && type == 1 && rdlen == 4) {
            uint32_t ip;
            memcpy(&ip, dns + off, 4);

            const char *domain = valid_domain_for_history(qname) ? qname : name;
            dns_put4(app, ip, domain, ttl);
        } else if (class_ == 1 && type == 28 && rdlen == 16) {
            const char *domain = valid_domain_for_history(qname) ? qname : name;
            dns_put6(app, dns + off, domain, ttl);
        }

        off += rdlen;
    }
}

/* ------------------------------------------------------------------------- */
/* TLS SNI parser for TCP/443                                                */
/* ------------------------------------------------------------------------- */

bool parse_tls_sni(const uint8_t *p, size_t len, char *out, size_t out_len) {
    if (!p || len < 5 || out_len == 0)
        return false;

    out[0] = '\0';

    if (p[0] != 0x16)
        return false;

    uint16_t rec_len = rd16(p + 3);

    if (rec_len + 5 > len)
        return false;

    size_t pos = 5;

    if (pos + 4 > len)
        return false;

    if (p[pos] != 0x01)
        return false;

    uint32_t hs_len = ((uint32_t)p[pos + 1] << 16) |
                      ((uint32_t)p[pos + 2] << 8) |
                      p[pos + 3];

    pos += 4;

    if (pos + hs_len > len)
        return false;

    if (pos + 34 > len)
        return false;

    pos += 34;

    if (pos + 1 > len)
        return false;

    uint8_t sid_len = p[pos++];
    if (pos + sid_len > len)
        return false;

    pos += sid_len;

    if (pos + 2 > len)
        return false;

    uint16_t cs_len = rd16(p + pos);
    pos += 2;

    if (pos + cs_len > len)
        return false;

    pos += cs_len;

    if (pos + 1 > len)
        return false;

    uint8_t comp_len = p[pos++];

    if (pos + comp_len > len)
        return false;

    pos += comp_len;

    if (pos + 2 > len)
        return false;

    uint16_t ext_total_len = rd16(p + pos);
    pos += 2;

    if (pos + ext_total_len > len)
        return false;

    size_t ext_end = pos + ext_total_len;

    while (pos + 4 <= ext_end) {
        uint16_t ext_type = rd16(p + pos);
        uint16_t ext_len = rd16(p + pos + 2);

        pos += 4;

        if (pos + ext_len > ext_end)
            return false;

        if (ext_type == 0) {
            size_t ep = pos;

            if (ep + 2 > pos + ext_len)
                return false;

            uint16_t list_len = rd16(p + ep);
            ep += 2;

            if (ep + list_len > pos + ext_len)
                return false;

            while (ep + 3 <= pos + ext_len) {
                uint8_t name_type = p[ep++];
                uint16_t name_len = rd16(p + ep);
                ep += 2;

                if (ep + name_len > pos + ext_len)
                    return false;

                if (name_type == 0 && name_len > 0 && name_len < out_len) {
                    memcpy(out, p + ep, name_len);
                    out[name_len] = '\0';

                    if (valid_domain_for_history(out))
                        return true;

                    return false;
                }

                ep += name_len;
            }
        }

        pos += ext_len;
    }

    return false;
}
