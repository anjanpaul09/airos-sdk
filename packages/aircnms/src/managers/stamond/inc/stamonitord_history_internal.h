#ifndef STAMONITORD_HISTORY_INTERNAL_H
#define STAMONITORD_HISTORY_INTERNAL_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "stamonitord_history.h"
#include "stamonitord_history_service.h"
#include "stamonitord_client_events.h"

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <limits.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
//#include <ndpi/ndpi_api.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define APP_NAME                    "ap-histd"

#define MAX_PACKET_SIZE             4096
#define SOCKET_RCVBUF               (256 * 1024)

#define DNS_BUCKETS                 512
#define FLOW_BUCKETS                1024
#define LOCAL_MAC_MAX               128

#define DNS_DEFAULT_TTL_SEC         3600
#define FLOW_IDLE_TIMEOUT_SEC       30
#define DOMAIN_ACTIVE_TIMEOUT_SEC   120

#define MAX_DOMAINS_PER_STATION   256
#define MAX_ACTIVE_FLOWS          2048

#define DOMAIN_RETENTION_MS \
    (6ULL * 3600ULL * 1000ULL)

#define FLOW_RETENTION_MS \
    (5ULL * 60ULL * 1000ULL)

#define DNS_MIN_TTL_SEC 60
#define DNS_MAX_TTL_SEC 3600

#define NDPI_MAX_PACKETS_PER_FLOW 8

#ifndef container_of
#define container_of(ptr, type, member) \
    ((type *)((char *)(ptr) - offsetof(type, member)))
#endif

typedef enum {
    ZONE_UNKNOWN = 0,
    ZONE_BR_LAN,
    ZONE_BR_NAT
} zone_t;

typedef enum {
    DIR_UNKNOWN = 0,
    DIR_UPLOAD,
    DIR_DOWNLOAD
} direction_t;

typedef struct mac_addr {
    uint8_t b[6];
} mac_addr_t;

typedef struct parsed_pkt {
    mac_addr_t eth_src;
    mac_addr_t eth_dst;
    uint8_t packet_type;

    uint8_t ip_version;

    uint32_t ip_src;
    uint32_t ip_dst;

    uint8_t ip6_src[16];
    uint8_t ip6_dst[16];

    uint8_t proto;
    uint16_t sport;
    uint16_t dport;

    uint16_t ip_total_len;

    const uint8_t *l3_packet;
    size_t l3_packet_len;

    const uint8_t *l4_payload;
    size_t l4_payload_len;
} parsed_pkt_t;

typedef struct dns_entry {
    uint8_t ip_version;
    uint8_t ip[16];
    char domain[256];
    uint64_t expires_ms;
    uint64_t last_seen_ms;
    struct dns_entry *next;
} dns_entry_t;

typedef struct flow_key {
    uint8_t ip_version;
    uint8_t proto;

    uint8_t a_ip[16];
    uint8_t b_ip[16];

    uint16_t a_port;
    uint16_t b_port;
} flow_key_t;

typedef struct flow {
    flow_key_t key;
    mac_addr_t station_mac;
    uint32_t station_ip;

    char domain[256];

    char ndpi_proto_name[64];
    bool ndpi_detected;
    uint16_t ndpi_packets;

    struct ndpi_flow_struct *ndpi_flow;

    traffic_type_t type;
    uint64_t first_seen_ms;
    uint64_t last_seen_ms;
    struct flow *next;
} flow_t;

typedef struct history_entry {
    char domain[256];
    char service[64];
    char ndpi_protocol[64];
    uint64_t uploaded;
    uint64_t downloaded;
    uint64_t visits;
    uint64_t connections;
    uint64_t first_seen_ms;
    uint64_t last_seen_ms;
    uint64_t representative_bytes;
    traffic_type_t type;
    bool active;
    struct history_entry *next;
} history_entry_t;

typedef struct local_macs {
    mac_addr_t macs[LOCAL_MAC_MAX];
    size_t count;
} local_macs_t;

struct app;

typedef struct cap_if {
    char ifname[IFNAMSIZ];
    char bridge[IFNAMSIZ];
    int ifindex;
    int fd;
    zone_t zone;
    bool seen;
    ev_io io;
    struct app *app;
    struct cap_if *next;
} cap_if_t;

typedef struct app {
    struct ev_loop *loop;

    cap_if_t *caps;

    dns_entry_t *dns[DNS_BUCKETS];
    flow_t *flows[FLOW_BUCKETS];

    struct ndpi_detection_module_struct *ndpi;
    size_t ndpi_flow_size;

    local_macs_t local_macs;

    int rtnl_fd;
    ev_io rtnl_io;

    ev_timer flush_timer;
    ev_timer send_timer;
    ev_timer expire_timer;
    ev_timer resync_timer;
    ev_timer resync_debounce_timer;

    ev_signal sigint_watcher;
    ev_signal sigterm_watcher;

    char *output_path;

    double flush_interval_sec;
    double send_interval_sec;
    double expire_interval_sec;
    double resync_interval_sec;
    double resync_debounce_sec;
    uint64_t report_seq;

    bool install_signal_handlers;

    uint64_t packets_seen;
    uint64_t packets_parsed;
    uint64_t packets_parse_failed;
    uint64_t packets_accounted;

    size_t active_flows;
    bool shutting_down;
} app_t;

typedef struct ap_history {
    app_t app;
} stamonitord_history_t;

/* util */
uint64_t now_ms(void);

uint16_t rd16(const uint8_t *p);
uint32_t rd32(const uint8_t *p);
uint32_t hash_bytes(const void *data, size_t len);
uint32_t hash_ip_key(uint8_t ip_version, const uint8_t ip[16]);

void ip16_from_ip4(uint8_t out[16], uint32_t ip);
void ip16_from_ip6(uint8_t out[16], const uint8_t ip6[16]);

bool mac_equal(mac_addr_t a, mac_addr_t b);
bool mac_is_zero(mac_addr_t m);
bool mac_is_broadcast(mac_addr_t m);
bool mac_is_multicast(mac_addr_t m);
void mac_to_str(mac_addr_t mac, char out[18]);
int parse_mac_str(const char *s, mac_addr_t *mac);

const char *ip4_to_str(uint32_t ip_net, char out[INET_ADDRSTRLEN]);
bool is_private_or_local_ipv4(uint32_t ip_net);
bool is_common_gateway_ip(uint32_t ip_net);
bool is_ap_own_oui(mac_addr_t mac);

bool domain_is_tld_artifact(const char *d);
bool valid_domain_for_history(const char *d);

const char *zone_str(zone_t z);
traffic_type_t classify_traffic(uint8_t proto, uint16_t sport, uint16_t dport);
const char *traffic_type_str(traffic_type_t t);

void format_bytes(uint64_t b, char *out, size_t n);
void format_duration(uint64_t ms, char *out, size_t n);
void format_timestamp(uint64_t ms, char *out, size_t n);
void json_escape(FILE *f, const char *s);

/* ndpi/service */
bool init_ndpi(app_t *app);
void cleanup_ndpi(app_t *app);
void ndpi_process_flow_packet(flow_t *flow,
                              const uint8_t *payload,
                              size_t payload_len,
                              uint64_t ts_ms);
const char *service_from_domain(const char *d);
const char *service_from_flow_and_domain(flow_t *flow, const char *domain);
const char *domain_from_service_if_unknown(const char *domain, const char *service);
bool str_contains_ci(const char *haystack, const char *needle);
const char *strip_service_prefix(const char *s);
bool ndpi_label_is_generic(const char *s);
const char *normalized_history_service(const char *service,
                                       const char *ndpi_protocol,
                                       const char *domain);
const char *history_domain_for_service(const char *service,
                                       const char *fallback_domain);

/* local MACs */
bool local_mac_contains(app_t *app, mac_addr_t mac);
void local_mac_add(app_t *app, mac_addr_t mac);
void load_local_macs(app_t *app);
bool mac_is_station_candidate(app_t *app, mac_addr_t mac);

/* DNS */
void dns_put_addr(app_t *app,
                  uint8_t ip_version,
                  const uint8_t ip[16],
                  const char *domain,
                  uint32_t ttl);
void dns_put4(app_t *app, uint32_t ip, const char *domain, uint32_t ttl);
void dns_put6(app_t *app, const uint8_t ip[16], const char *domain, uint32_t ttl);
const char *dns_lookup_addr(app_t *app, uint8_t ip_version, const uint8_t ip[16]);
const char *dns_lookup4(app_t *app, uint32_t ip);
const char *dns_lookup6(app_t *app, const uint8_t ip[16]);
int dns_read_name(const uint8_t *pkt,
                  size_t len,
                  size_t *off,
                  char *out,
                  size_t out_len,
                  int depth);
void parse_dns_response(app_t *app, const uint8_t *dns, size_t len);
bool parse_tls_sni(const uint8_t *p, size_t len, char *out, size_t out_len);

/* client history/domain */
history_domain_t *history_domain_get_or_create(history_state_t *history,
                                               const char *domain,
                                               traffic_type_t type);

/* flow */
void flow_key_set_ip4(uint8_t out[16], uint32_t ip);
void flow_key_set_ip6(uint8_t out[16], const uint8_t ip6[16]);
int ip16_cmp(const uint8_t a[16], const uint8_t b[16]);
void normalize_flow_key(flow_key_t *k);
void flow_free(flow_t *f);
bool traffic_type_needs_ndpi(traffic_type_t type);
flow_t *flow_get_or_create(app_t *app,
                           const parsed_pkt_t *pp,
                           mac_addr_t station_mac,
                           uint32_t station_ip,
                           const char *domain,
                           traffic_type_t type,
                           bool *is_new);

/* packet/accounting */
int parse_ether_ip(const uint8_t *pkt, size_t len, parsed_pkt_t *pp);
bool determine_station_and_direction(app_t *app,
                                     const parsed_pkt_t *pp,
                                     mac_addr_t *station_mac,
                                     uint32_t *station_ip,
                                     direction_t *dir);
void account_packet(app_t *app, cap_if_t *cap, const parsed_pkt_t *pp);

/* capture/rtnetlink */
int set_nonblock_cloexec(int fd);
int open_packet_socket(const char *ifname);
cap_if_t *find_cap(app_t *app, const char *ifname);
int ensure_capture(app_t *app, const char *ifname, const char *bridge);
void remove_capture(app_t *app, cap_if_t *c, cap_if_t *prev);
void mark_all_caps_unseen(app_t *app);
void remove_unseen_caps(app_t *app);
void scan_bridge(app_t *app, const char *bridge);
void resync_interfaces(app_t *app);
int open_rtnetlink_socket(void);

/* callbacks */
void packet_read_cb(EV_P_ ev_io *w, int revents);
void rtnl_read_cb(EV_P_ ev_io *w, int revents);
void flush_cb(EV_P_ ev_timer *w, int revents);
void send_cb(EV_P_ ev_timer *w, int revents);
void expire_cb(EV_P_ ev_timer *w, int revents);
void resync_timer_cb(EV_P_ ev_timer *w, int revents);
void resync_debounce_cb(EV_P_ ev_timer *w, int revents);
void signal_cb(EV_P_ ev_signal *w, int revents);

/* json */
history_entry_t *history_entry_get_or_create(history_entry_t **head,
                                             const char *service,
                                             const char *domain);
void free_history_entries(history_entry_t *head);
history_entry_t *build_history_entries(client_state_t *client);
history_entry_t *build_delta_history_entries(client_state_t *client, uint64_t report_time);
void mark_client_history_reported(client_state_t *client, uint64_t report_time);
int count_history_entries(history_entry_t *head, bool active_only);
void write_client_json(FILE *f, client_state_t *client);
void write_client_report_json(FILE *f, client_state_t *client, history_entry_t *history);
void flush_json(app_t *app);
void report_json(app_t *app);

/* cleanup */
void cleanup_app(app_t *app);

#endif
