#include "stamonitord_history_internal.h"
#include "stamonitord_client_events.h"

/* paste Packet parsing section */
/* paste Accounting section */

/* ------------------------------------------------------------------------- */
/* Packet parsing                                                            */
/* ------------------------------------------------------------------------- */

int parse_ether_ip(const uint8_t *pkt, size_t len, parsed_pkt_t *pp) {
    memset(pp, 0, sizeof(*pp));

    if (len < sizeof(struct ethhdr))
        return -1;

    const struct ethhdr *eth = (const struct ethhdr *)pkt;

    memcpy(pp->eth_src.b, eth->h_source, 6);
    memcpy(pp->eth_dst.b, eth->h_dest, 6);

    uint16_t ethertype = ntohs(eth->h_proto);
    size_t off = sizeof(struct ethhdr);

    for (int i = 0; i < 2; i++) {
        if (ethertype == 0x8100 || ethertype == 0x88a8) {
            if (len < off + 4)
                return -1;

            ethertype = rd16(pkt + off + 2);
            off += 4;
        }
    }

    if (ethertype == ETH_P_IP) {
        if (len < off + sizeof(struct iphdr))
            return -1;

        const struct iphdr *ip = (const struct iphdr *)(pkt + off);

        if (ip->version != 4)
            return -1;

        size_t ihl = ip->ihl * 4;

        if (ihl < sizeof(struct iphdr))
            return -1;

        if (len < off + ihl)
            return -1;

        size_t ip_len = ntohs(ip->tot_len);
        if (ip_len == 0 || off + ip_len > len)
            ip_len = len - off;

        pp->ip_version = 4;
        pp->l3_packet = pkt + off;
        pp->l3_packet_len = ip_len;

        pp->ip_src = ip->saddr;
        pp->ip_dst = ip->daddr;
        pp->proto = ip->protocol;
        pp->ip_total_len = ntohs(ip->tot_len);

        size_t l4off = off + ihl;

        if (pp->proto == IPPROTO_TCP) {
            if (len < l4off + sizeof(struct tcphdr))
                return -1;

            const struct tcphdr *tcp = (const struct tcphdr *)(pkt + l4off);
            size_t thl = tcp->doff * 4;

            if (thl < sizeof(struct tcphdr))
                return -1;

            if (len < l4off + thl)
                return -1;

            pp->sport = tcp->source;
            pp->dport = tcp->dest;

            pp->l4_payload = pkt + l4off + thl;
            pp->l4_payload_len = len - (l4off + thl);

            return 0;
        }

        if (pp->proto == IPPROTO_UDP) {
            if (len < l4off + sizeof(struct udphdr))
                return -1;

            const struct udphdr *udp = (const struct udphdr *)(pkt + l4off);

            pp->sport = udp->source;
            pp->dport = udp->dest;

            pp->l4_payload = pkt + l4off + sizeof(struct udphdr);
            pp->l4_payload_len = len - (l4off + sizeof(struct udphdr));

            return 0;
        }

        /*
         * Still allow nDPI to see IP packet, but no accounting for unknown L4.
         */
        return 0;
    }

    if (ethertype == ETH_P_IPV6) {
        if (len < off + sizeof(struct ip6_hdr))
            return -1;

        const struct ip6_hdr *ip6 = (const struct ip6_hdr *)(pkt + off);

        pp->ip_version = 6;

        memcpy(pp->ip6_src, &ip6->ip6_src, 16);
        memcpy(pp->ip6_dst, &ip6->ip6_dst, 16);

        size_t ip6_len = 40 + ntohs(ip6->ip6_plen);
        if (ip6_len == 40 || off + ip6_len > len)
            ip6_len = len - off;

        pp->l3_packet = pkt + off;
        pp->l3_packet_len = ip6_len;

        uint8_t nxt = ip6->ip6_nxt;
        size_t l4off = off + sizeof(struct ip6_hdr);

        /*
         * Minimal IPv6 extension-header walker.
         * This catches common TCP/UDP/QUIC traffic.
         */
        for (int i = 0; i < 4; i++) {
            if (nxt == IPPROTO_HOPOPTS ||
                nxt == IPPROTO_ROUTING ||
                nxt == IPPROTO_DSTOPTS) {
                if (len < l4off + 2)
                    return -1;

                uint8_t next_nxt = pkt[l4off];
                uint8_t hdr_ext_len = pkt[l4off + 1];

                size_t ext_len = ((size_t)hdr_ext_len + 1) * 8;

                if (len < l4off + ext_len)
                    return -1;

                l4off += ext_len;
                nxt = next_nxt;
                continue;
            }

            if (nxt == IPPROTO_FRAGMENT) {
                return -1;
            }

            break;
        }

        pp->proto = nxt;
        pp->ip_total_len = (uint16_t)ip6_len;

        if (pp->proto == IPPROTO_TCP) {
            if (len < l4off + sizeof(struct tcphdr))
                return -1;

            const struct tcphdr *tcp = (const struct tcphdr *)(pkt + l4off);
            size_t thl = tcp->doff * 4;

            if (thl < sizeof(struct tcphdr))
                return -1;

            if (len < l4off + thl)
                return -1;

            pp->sport = tcp->source;
            pp->dport = tcp->dest;

            pp->l4_payload = pkt + l4off + thl;
            pp->l4_payload_len = len - (l4off + thl);

            return 0;
        }

        if (pp->proto == IPPROTO_UDP) {
            if (len < l4off + sizeof(struct udphdr))
                return -1;

            const struct udphdr *udp = (const struct udphdr *)(pkt + l4off);

            pp->sport = udp->source;
            pp->dport = udp->dest;

            pp->l4_payload = pkt + l4off + sizeof(struct udphdr);
            pp->l4_payload_len = len - (l4off + sizeof(struct udphdr));

            return 0;
        }

        return 0;
    }

    return -1;
}

/* ------------------------------------------------------------------------- */
/* Accounting                                                                */
/* ------------------------------------------------------------------------- */

static void copy_option_string(char *dst, size_t dst_len, const uint8_t *src, size_t src_len) {
    if (!dst || dst_len == 0)
        return;

    size_t out = 0;
    for (size_t i = 0; i < src_len && out + 1 < dst_len; i++) {
        uint8_t c = src[i];

        if (c < 32 || c > 126)
            continue;

        dst[out++] = (char)c;
    }

    dst[out] = '\0';
}

static void append_dhcp_option_code(char *dst, size_t dst_len, uint8_t code) {
    if (!dst || dst_len == 0)
        return;

    size_t used = strlen(dst);
    if (used >= dst_len - 1)
        return;

    int ret = snprintf(dst + used,
                       dst_len - used,
                       "%s%u",
                       used ? "," : "",
                       code);

    if (ret < 0 || (size_t)ret >= dst_len - used)
        dst[dst_len - 1] = '\0';
}

static bool is_dhcp_udp(const parsed_pkt_t *pp) {
    if (!pp || pp->ip_version != 4 || pp->proto != IPPROTO_UDP)
        return false;

    uint16_t sport = ntohs(pp->sport);
    uint16_t dport = ntohs(pp->dport);

    return (sport == 67 || sport == 68) && (dport == 67 || dport == 68);
}

bool process_dhcp_packet(app_t *app, cap_if_t *cap, const parsed_pkt_t *pp) {
    if (!app || !cap || !pp || !is_dhcp_udp(pp))
        return false;

    const uint8_t *dhcp = pp->l4_payload;
    size_t len = pp->l4_payload_len;

    if (!dhcp || len < 240)
        return false;

    uint8_t htype = dhcp[1];
    uint8_t hlen = dhcp[2];

    if (htype != 1 || hlen < 6)
        return false;

    if (memcmp(dhcp + 236, "\x63\x82\x53\x63", 4) != 0)
        return false;

    mac_addr_t station_mac;
    memcpy(station_mac.b, dhcp + 28, sizeof(station_mac.b));

    if (mac_is_zero(station_mac) ||
        mac_is_broadcast(station_mac) ||
        mac_is_multicast(station_mac) ||
        is_ap_own_oui(station_mac) ||
        local_mac_contains(app, station_mac)) {
        return false;
    }

    uint32_t ciaddr;
    uint32_t yiaddr;
    uint32_t requested_ip = 0;
    uint32_t station_ip = 0;
    uint8_t msg_type = 0;
    char hostname[DHCP_HOSTNAME_STR_LEN] = {0};
    char vendor[DHCP_VENDOR_STR_LEN] = {0};
    char options[DHCP_OPTIONS_STR_LEN] = {0};

    memcpy(&ciaddr, dhcp + 12, sizeof(ciaddr));
    memcpy(&yiaddr, dhcp + 16, sizeof(yiaddr));

    size_t off = 240;
    while (off < len) {
        uint8_t code = dhcp[off++];

        if (code == 0)
            continue;

        if (code == 255)
            break;

        if (off >= len)
            break;

        uint8_t opt_len = dhcp[off++];

        if (off + opt_len > len)
            break;

        const uint8_t *val = dhcp + off;

        switch (code) {
            case 12:
                copy_option_string(hostname, sizeof(hostname), val, opt_len);
                break;
            case 50:
                if (opt_len == 4)
                    memcpy(&requested_ip, val, sizeof(requested_ip));
                break;
            case 53:
                if (opt_len >= 1)
                    msg_type = val[0];
                break;
            case 55:
                for (uint8_t i = 0; i < opt_len; i++)
                    append_dhcp_option_code(options, sizeof(options), val[i]);
                break;
            case 60:
                copy_option_string(vendor, sizeof(vendor), val, opt_len);
                break;
            default:
                break;
        }

        off += opt_len;
    }

    if (yiaddr)
        station_ip = yiaddr;
    else if (requested_ip)
        station_ip = requested_ip;
    else if (ciaddr)
        station_ip = ciaddr;

    station_t *s = station_get_or_create(app,
                                         station_mac,
                                         station_ip,
                                         cap->zone,
                                         station_ip ? 4 : 0);
    if (!s)
        return false;

    if (station_ip)
        s->ip = station_ip;

    if (cap->zone != ZONE_UNKNOWN)
        s->zone = cap->zone;

    if (hostname[0])
        snprintf(s->hostname, sizeof(s->hostname), "%s", hostname);

    if (options[0])
        snprintf(s->dhcp_options, sizeof(s->dhcp_options), "%s", options);

    if (vendor[0])
        snprintf(s->dhcp_vendor, sizeof(s->dhcp_vendor), "%s", vendor);

    if (msg_type)
        s->dhcp_msg_type = msg_type;

    s->identity_last_seen_ms = now_ms();

    if (s->ip != 0) {
        stamonitord_client_events_on_dhcp_resolved(station_mac.b);
    }

    return true;
}

bool determine_station_and_direction(app_t *app,
                                            const parsed_pkt_t *pp,
                                            mac_addr_t *station_mac,
                                            uint32_t *station_ip,
                                            direction_t *dir) {
    /*
     * A packet socket bound to an AP netdev reports AP-transmitted frames as
     * PACKET_OUTGOING. For those frames the Ethernet source can be the AP/BSSID,
     * so the associated station is the destination.
     */
    if (pp->packet_type == PACKET_OUTGOING) {
        if (!mac_is_station_candidate(app, pp->eth_dst))
            return false;

        *station_mac = pp->eth_dst;
        *station_ip = (pp->ip_version == 4) ? pp->ip_dst : 0;
        *dir = DIR_DOWNLOAD;
        return true;
    }

    /*
     * IPv6 clients usually have globally routable addresses.
     * Use WiFi/AP Ethernet MAC direction instead of private/public IP logic.
     */
    if (pp->ip_version == 6) {
        if (mac_is_station_candidate(app, pp->eth_src)) {
            *station_mac = pp->eth_src;
            *station_ip = 0;
            *dir = DIR_UPLOAD;
            return true;
        }

        if (mac_is_station_candidate(app, pp->eth_dst)) {
            *station_mac = pp->eth_dst;
            *station_ip = 0;
            *dir = DIR_DOWNLOAD;
            return true;
        }

        return false;
    }

    bool src_local = is_private_or_local_ipv4(pp->ip_src);
    bool dst_local = is_private_or_local_ipv4(pp->ip_dst);

    uint16_t sport = ntohs(pp->sport);
    uint16_t dport = ntohs(pp->dport);

    if (src_local && !dst_local) {
        *station_mac = pp->eth_src;
        *station_ip = pp->ip_src;
        *dir = DIR_UPLOAD;
        return true;
    }

    if (!src_local && dst_local) {
        *station_mac = pp->eth_dst;
        *station_ip = pp->ip_dst;
        *dir = DIR_DOWNLOAD;
        return true;
    }

    if (src_local && dst_local && dport == 53) {
        *station_mac = pp->eth_src;
        *station_ip = pp->ip_src;
        *dir = DIR_UPLOAD;
        return true;
    }

    if (src_local && dst_local && sport == 53) {
        *station_mac = pp->eth_dst;
        *station_ip = pp->ip_dst;
        *dir = DIR_DOWNLOAD;
        return true;
    }

    if (pp->proto == IPPROTO_UDP && sport == 68 && dport == 67) {
        *station_mac = pp->eth_src;
        *station_ip = pp->ip_src;
        *dir = DIR_UPLOAD;
        return true;
    }

    /*
     * Fallback for AP interface captures.
     */
    if (mac_is_station_candidate(app, pp->eth_src)) {
        *station_mac = pp->eth_src;
        *station_ip = pp->ip_src;
        *dir = DIR_UPLOAD;
        return true;
    }

    if (mac_is_station_candidate(app, pp->eth_dst)) {
        *station_mac = pp->eth_dst;
        *station_ip = pp->ip_dst;
        *dir = DIR_DOWNLOAD;
        return true;
    }

    return false;
}

void account_packet(app_t *app, cap_if_t *cap, const parsed_pkt_t *pp) {
    mac_addr_t station_mac;
    uint32_t station_ip = 0;
    direction_t dir = DIR_UNKNOWN;

    process_dhcp_packet(app, cap, pp);

    if (!determine_station_and_direction(app, pp, &station_mac, &station_ip, &dir))
        return;

    if (pp->ip_version == 4 && station_ip == 0)
        return;

    if (pp->ip_version == 4 && is_common_gateway_ip(station_ip))
        return;

    if (mac_is_zero(station_mac) ||
        mac_is_broadcast(station_mac) ||
        mac_is_multicast(station_mac))
        return;

    if (is_ap_own_oui(station_mac))
        return;

    if (local_mac_contains(app, station_mac))
        return;

    traffic_type_t type = classify_traffic(pp->proto, pp->sport, pp->dport);

    /*
     * Browsing/service history only.
     */
    if (type == TRAFFIC_OTHER)
        return;

    station_t *s = station_get_or_create(app,
                                         station_mac,
                                         station_ip,
                                         cap->zone,
                                         pp->ip_version);
    if (!s)
        return;

    /*
     * Learn DNS A/AAAA answers for IPv4 and IPv6 DNS.
     */
    if (type == TRAFFIC_DNS &&
        pp->proto == IPPROTO_UDP &&
        pp->l4_payload &&
        pp->l4_payload_len >= 12) {
        parse_dns_response(app, pp->l4_payload, pp->l4_payload_len);
    }

    uint32_t remote_ip = 0;
    uint8_t remote_ip6[16] = {0};

    if (pp->ip_version == 4) {
        remote_ip = (dir == DIR_UPLOAD) ? pp->ip_dst : pp->ip_src;
    } else if (pp->ip_version == 6) {
        if (dir == DIR_UPLOAD)
            ip16_from_ip6(remote_ip6, pp->ip6_dst);
        else
            ip16_from_ip6(remote_ip6, pp->ip6_src);
    }

    /*
     * Learn TLS SNI for TCP/443 uploads on both IPv4 and IPv6.
     */
    char sni[256];

    if (type == TRAFFIC_HTTPS &&
        pp->proto == IPPROTO_TCP &&
        ntohs(pp->dport) == 443 &&
        dir == DIR_UPLOAD &&
        pp->l4_payload &&
        pp->l4_payload_len > 0) {
        if (parse_tls_sni(pp->l4_payload, pp->l4_payload_len, sni, sizeof(sni))) {
            if (pp->ip_version == 4)
                dns_put4(app, remote_ip, sni, 3600);
            else if (pp->ip_version == 6)
                dns_put6(app, remote_ip6, sni, 3600);
        }
    }

    const char *domain = NULL;

    if (pp->ip_version == 4)
        domain = dns_lookup4(app, remote_ip);
    else if (pp->ip_version == 6)
        domain = dns_lookup6(app, remote_ip6);

    if (domain && !valid_domain_for_history(domain))
        domain = NULL;

    if (!domain || !domain[0]) {
        if (type == TRAFFIC_DNS)
            domain = "dns";
        else
            domain = "unknown";
    }

    bool flow_new = false;

    flow_t *flow = flow_get_or_create(app,
                                      pp,
                                      station_mac,
                                      station_ip,
                                      domain,
                                      type,
                                      &flow_new);
    if (!flow)
        return;

    ndpi_process_flow_packet(app, flow, pp);

    const char *final_domain = flow->domain[0] ? flow->domain : domain;
    const char *service = service_from_flow_and_domain(flow, final_domain);

    final_domain = domain_from_service_if_unknown(final_domain, service);

    if (final_domain && !valid_domain_for_history(final_domain) &&
        strcmp(final_domain, "dns") &&
        strcmp(final_domain, "unknown")) {
        final_domain = "unknown";
    }

    domain_stat_t *ds = domain_get_or_create(s, final_domain, type);
    if (!ds)
        return;

    if (service && service[0])
        snprintf(ds->service, sizeof(ds->service), "%s", service);

    if (flow->ndpi_proto_name[0]) {
        snprintf(ds->ndpi_protocol,
                 sizeof(ds->ndpi_protocol),
                 "%s",
                 flow->ndpi_proto_name);
    }

    uint64_t bytes = pp->ip_total_len ? pp->ip_total_len : 1;

    if (dir == DIR_UPLOAD) {
        s->uploaded += bytes;
        ds->uploaded += bytes;
    } else if (dir == DIR_DOWNLOAD) {
        s->downloaded += bytes;
        ds->downloaded += bytes;
    }

    uint64_t t = now_ms();

    s->last_seen_ms = t;
    ds->last_seen_ms = t;
    ds->active = true;

    if (flow_new) {
        ds->connections++;
        ds->visits++;
    }

    app->packets_accounted++;
}
