#include "stamonitord_history_internal.h"
#include "stamonitord_client_events.h"
#include "log.h"

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

/*
 * AP-mode WLAN: PACKET_HOST is airside Rx (typically STA -> AP);
 * PACKET_OUTGOING is airside Tx (typically AP -> STA).  This is more
 * reliable than Ethernet MAC order on some drivers and fixes IPv6-heavy
 * flows when client metadata only carries an IPv4 string.
 */
static bool cap_if_is_wifi_pkttype_iface(const cap_if_t *cap)
{
    const char *n;

    if (!cap || !cap->ifname[0])
        return false;

    n = cap->ifname;

    if (strncmp(n, "br-", 3) == 0)
        return false;

    if (strncmp(n, "wlan", 4) == 0)
        return true;

    if (strncmp(n, "phy", 3) == 0 && strstr(n, "-ap"))
        return true;

    if (strncmp(n, "rax", 3) == 0)
        return true;

    if (strncmp(n, "rai", 3) == 0)
        return true;

    if (n[0] == 'r' && n[1] == 'a' &&
        n[2] >= '0' && n[2] <= '9')
        return true;

    return false;
}

static bool mac_is_known_client(const uint8_t *mac)
{
    return mac && stamonitord_client_lookup(mac) != NULL;
}

/*
 * Resolve upload vs download. Order matters: L3/port work on br-lan and
 * IPv6; WLAN pkttype only on VAPs; L2 is last (often wrong on MTK WiFi).
 */
static direction_t history_resolve_traffic_direction(const parsed_pkt_t *pp,
                                                     const cap_if_t *cap,
                                                     const client_state_t *client,
                                                     direction_t dir_l2)
{
    uint16_t src_port = ntohs(pp->sport);
    uint16_t dst_port = ntohs(pp->dport);
    uint32_t cip = 0;
    bool have_v4 = false;
    struct in_addr ia;

    if (client && client->info.ipaddr[0] &&
        inet_aton(client->info.ipaddr, &ia))
    {
        cip = ia.s_addr;
        have_v4 = true;
    }

    if (pp->ip_version == 4 && have_v4) {
        if (pp->ip_src == cip && pp->ip_dst != cip)
            return DIR_UPLOAD;
        if (pp->ip_dst == cip && pp->ip_src != cip)
            return DIR_DOWNLOAD;
    }

    if (pp->proto == IPPROTO_TCP || pp->proto == IPPROTO_UDP) {
        if (src_port == 53 && dst_port > 1024)
            return DIR_DOWNLOAD;
        if (dst_port == 53 && src_port > 1024)
            return DIR_UPLOAD;

        if ((src_port == 443 || src_port == 80) && dst_port > 1024)
            return DIR_DOWNLOAD;
        if ((dst_port == 443 || dst_port == 80) && src_port > 1024)
            return DIR_UPLOAD;
    }

    if (cap && cap_if_is_wifi_pkttype_iface(cap)) {
        if (pp->packet_type == PACKET_OUTGOING) {
            if (pp->ip_version == 4 && have_v4) {
                if (pp->ip_dst == cip && pp->ip_src != cip)
                    return DIR_DOWNLOAD;
            } else if (pp->ip_version == 6) {
                return DIR_DOWNLOAD;
            }
        } else if (pp->packet_type == PACKET_HOST) {
            if (pp->ip_version == 4 && have_v4) {
                if (pp->ip_src == cip && pp->ip_dst != cip)
                    return DIR_UPLOAD;
            } else if (pp->ip_version == 6) {
                return DIR_UPLOAD;
            }
        }
    }

    if (dir_l2 == DIR_DOWNLOAD || dir_l2 == DIR_UPLOAD)
        return dir_l2;

    return DIR_UPLOAD;
}

bool determine_station_and_direction(app_t *app,
                                     const parsed_pkt_t *pp,
                                     mac_addr_t *station_mac,
                                     uint32_t *station_ip,
                                     direction_t *dir)
{
    direction_t dir_l2 = DIR_UNKNOWN;

    /*
     * Prefer MACs of clients we already track (DHCP / hostapd metadata).
     */
    if (mac_is_known_client(pp->eth_src.b)) {

        *station_mac = pp->eth_src;
        *station_ip =
            (pp->ip_version == 4) ? pp->ip_src : 0;
        dir_l2 = DIR_UPLOAD;

    } else if (mac_is_known_client(pp->eth_dst.b)) {

        *station_mac = pp->eth_dst;
        *station_ip =
            (pp->ip_version == 4) ? pp->ip_dst : 0;
        dir_l2 = DIR_DOWNLOAD;

    } else if (mac_is_station_candidate(app, pp->eth_src)) {

        *station_mac = pp->eth_src;
        *station_ip =
            (pp->ip_version == 4) ? pp->ip_src : 0;
        dir_l2 = DIR_UPLOAD;

    } else if (mac_is_station_candidate(app, pp->eth_dst)) {

        *station_mac = pp->eth_dst;
        *station_ip =
            (pp->ip_version == 4) ? pp->ip_dst : 0;
        dir_l2 = DIR_DOWNLOAD;

    } else {
        return false;
    }

    *dir = dir_l2;
    return true;
}

void account_packet(app_t *app,
                    cap_if_t *cap,
                    const parsed_pkt_t *pp)
{
    mac_addr_t station_mac;
    uint32_t station_ip = 0;
    direction_t dir = DIR_UNKNOWN;

    if (!determine_station_and_direction(app,
                                         pp,
                                         &station_mac,
                                         &station_ip,
                                         &dir))
    {
        return;
    }

    /*
     * Ignore invalid/broadcast traffic.
     */
    if (mac_is_zero(station_mac) ||
        mac_is_broadcast(station_mac) ||
        mac_is_multicast(station_mac))
    {
        return;
    }

    /*
     * Ignore AP/local interfaces.
     */
    if (is_ap_own_oui(station_mac))
        return;

    if (local_mac_contains(app, station_mac))
        return;

    uint16_t dst_port = ntohs(pp->dport);
    uint16_t src_port = ntohs(pp->sport);

    traffic_type_t type;

    /*
     * Match BOTH directions.
     */
    if (pp->proto == IPPROTO_TCP &&
        (dst_port == 443 || src_port == 443))
    {
        type = TRAFFIC_HTTPS;
    }
    else if (pp->proto == IPPROTO_UDP &&
             (dst_port == 443 || src_port == 443))
    {
        type = TRAFFIC_QUIC;
    }
    else if (dst_port == 53 ||
             src_port == 53)
    {
        type = TRAFFIC_DNS;
    }
    else if (dst_port == 80 ||
             src_port == 80)
    {
        type = TRAFFIC_HTTP;
    }
    else {
        type = TRAFFIC_OTHER;
    }

    /*
     * Browsing/service history only.
     */
    if (type == TRAFFIC_OTHER)
        return;


    /*
     * Learn DNS responses.
     */
    if (type == TRAFFIC_DNS &&
        pp->proto == IPPROTO_UDP &&
        pp->l4_payload &&
        pp->l4_payload_len >= 12)
    {
        parse_dns_response(app,
                           pp->l4_payload,
                           pp->l4_payload_len);
    }

    uint32_t remote_ip = 0;
    uint8_t remote_ip6[16] = {0};

    /*
     * Determine remote/server IP.
     */
    if (pp->ip_version == 4) {

        /*
         * Server side is always the well-known port side.
         */
        if (dst_port == 443 ||
            dst_port == 80 ||
            dst_port == 53)
        {
            remote_ip = pp->ip_dst;
        }
        else {
            remote_ip = pp->ip_src;
        }

    } else if (pp->ip_version == 6) {

        if (dst_port == 443 ||
            dst_port == 80 ||
            dst_port == 53)
        {
            ip16_from_ip6(remote_ip6,
                          pp->ip6_dst);
        }
        else {
            ip16_from_ip6(remote_ip6,
                          pp->ip6_src);
        }
    }

    /*
     * Learn TLS SNI only from client requests.
     */
    char sni[256];

    if (type == TRAFFIC_HTTPS &&
        pp->proto == IPPROTO_TCP &&
        dst_port == 443 &&
        src_port > 1024 &&
        pp->l4_payload &&
        pp->l4_payload_len > 0)
    {
        if (parse_tls_sni(pp->l4_payload,
                          pp->l4_payload_len,
                          sni,
                          sizeof(sni)))
        {
            if (pp->ip_version == 4)
                dns_put4(app, remote_ip, sni, 3600);
            else if (pp->ip_version == 6)
                dns_put6(app, remote_ip6, sni, 3600);
        }
    }

    /*
     * Resolve domain.
     */
    const char *domain = NULL;

    if (pp->ip_version == 4)
        domain = dns_lookup4(app, remote_ip);
    else if (pp->ip_version == 6)
        domain = dns_lookup6(app, remote_ip6);

    if (domain &&
        !valid_domain_for_history(domain))
    {
        domain = NULL;
    }

    if (!domain || !domain[0]) {

        if (type == TRAFFIC_DNS)
            domain = "dns";
        else
            domain = "unknown";
    }

    bool flow_new = false;

    flow_t *flow =
        flow_get_or_create(app,
                           pp,
                           station_mac,
                           station_ip,
                           domain,
                           type,
                           &flow_new);

    if (!flow)
        return;

    client_state_t *client =
    stamonitord_client_lookup(station_mac.b);

/*
 * Bridge download packets may lose STA MAC.
 * Recover ownership from flow.
 */
    if (!client &&
        flow &&
        !mac_is_zero(flow->station_mac))
    {
        client =
            stamonitord_client_lookup(flow->station_mac.b);
    }

    if (!client)
        return;

    if (client->history.first_seen_ms == 0)
        client->history.first_seen_ms = now_ms();

    /*
     * Reuse learned flow domain.
     */
    if ((!domain || !domain[0] ||
         !strcmp(domain, "unknown")) &&
        flow->domain[0])
    {
        domain = flow->domain;
    }

    /*
     * Final domain selection.
     */
    const char *final_domain = "unknown";

    if (flow->domain[0])
        final_domain = flow->domain;
    else if (domain && domain[0])
        final_domain = domain;

    /*
     * Service classification.
     */
    const char *service =
        service_from_domain(final_domain);

    if (!service ||
        !strcmp(service, "Unknown"))
    {
        service =
            service_from_flow_and_domain(flow,
                                         final_domain);
    }

    final_domain =
        domain_from_service_if_unknown(final_domain,
                                       service);

    if (final_domain &&
        !valid_domain_for_history(final_domain) &&
        strcmp(final_domain, "dns") &&
        strcmp(final_domain, "unknown"))
    {
        final_domain = "unknown";
    }

    history_domain_t *ds =
        history_domain_get_or_create(&client->history,
                                     final_domain,
                                     type);

    if (!ds)
        return;

    if (service && service[0]) {
        snprintf(ds->service,
                 sizeof(ds->service),
                 "%s",
                 service);
    }

    snprintf(ds->ndpi_protocol,
             sizeof(ds->ndpi_protocol),
             "disabled");

    dir = history_resolve_traffic_direction(pp, cap, client, dir);

    uint64_t bytes =
        pp->ip_total_len ? pp->ip_total_len : 1;

    /*
     * Final accounting.
     */
    if (dir == DIR_DOWNLOAD) {

        client->history.downloaded += bytes;
        ds->downloaded += bytes;

    } else {

        client->history.uploaded += bytes;
        ds->uploaded += bytes;
    }

    uint64_t t = now_ms();

    client->history.last_seen_ms = t;

    ds->last_seen_ms = t;
    ds->active = true;

    if (flow_new) {
        ds->connections++;
        ds->visits++;
    }

    app->packets_accounted++;
}
