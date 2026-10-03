#include "onbd.h"
#include "log.h"

#include <arpa/inet.h>
#include <curl/curl.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include <uci.h>

static bool read_one(const char *path, char expected)
{
    char value = 0;
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    bool ok = fd >= 0 && read(fd, &value, 1) == 1 && value == expected;
    if (fd >= 0) close(fd);
    return ok;
}

static bool carrier_present(void)
{
    static const char *paths[] = {
        "/sys/class/net/eth0/carrier", "/sys/class/net/eth1/carrier",
        "/sys/class/net/wan/carrier", "/sys/class/net/lan/carrier",
        "/sys/class/net/br-lan/carrier"
    };
    size_t i;
    for (i = 0; i < sizeof(paths) / sizeof(paths[0]); i++)
        if (read_one(paths[i], '1')) return true;
    return false;
}

static bool is_management_ifname(const char *name)
{
    if (!name) return false;
    /* Skip loopback, internal management bridge, NAT bridge, physical LAN port, and wireless interfaces */
    if (!strcmp(name, "lo") || !strcmp(name, "br-mgmt") || !strcmp(name, "br-nat") || !strcmp(name, "lan"))
        return false;
    if (!strncmp(name, "phy", 3) || !strncmp(name, "ra", 2) || !strncmp(name, "wlan", 4))
        return false;
    /* Accept WAN bridge or main uplink interfaces */
    if (!strcmp(name, "br-lan") || !strcmp(name, "eth0") || !strcmp(name, "eth1") ||
        !strcmp(name, "wan"))
        return true;
    return false;
}

static bool management_ipv4_present(void)
{
    struct ifaddrs *list = NULL, *it;
    bool found = false;
    if (getifaddrs(&list) != 0) return false;
    for (it = list; it; it = it->ifa_next) {
        struct sockaddr_in *address;
        uint32_t host;
        if (!it->ifa_name || !it->ifa_addr || it->ifa_addr->sa_family != AF_INET ||
            !(it->ifa_flags & IFF_UP) || (it->ifa_flags & IFF_LOOPBACK)) continue;
        if (!is_management_ifname(it->ifa_name)) continue;
        address = (struct sockaddr_in *)it->ifa_addr;
        host = ntohl(address->sin_addr.s_addr);
        /* Filter out:
         * - 0.0.0.0
         * - 127.0.0.0/8 (loopback)
         * - 169.254.0.0/16 (link-local)
         * - 192.168.188.253 (0xC0A8BCFD - recovery fallback IP)
         */
        if (host != 0 && (host >> 24) != 127 && (host >> 16) != 0xA9FE && host != 0xC0A8BCFD) {
            found = true;
            break;
        }
    }
    freeifaddrs(list);
    return found;
}

static bool default_route_present(char *gateway, size_t gateway_len)
{
    FILE *fp = fopen("/proc/net/route", "r");
    char line[256], iface[IFNAMSIZ];
    unsigned long destination, gw, flags;
    bool found = false;
    if (gateway && gateway_len) gateway[0] = '\0';
    if (!fp) return false;
    (void)fgets(line, sizeof(line), fp);
    while (fgets(line, sizeof(line), fp)) {
        if (sscanf(line, "%15s %lx %lx %lx", iface, &destination, &gw, &flags) == 4 &&
            destination == 0 && gw != 0 && (flags & 0x1)) {
            struct in_addr a;
            a.s_addr = (in_addr_t)gw;
            if (gateway && gateway_len) snprintf(gateway, gateway_len, "%s", inet_ntoa(a));
            found = true;
            break;
        }
    }
    fclose(fp);
    return found;
}

static bool dns_configured(void)
{
    FILE *fp = fopen("/tmp/resolv.conf.d/resolv.conf.auto", "r");
    char line[256];
    bool found = false;
    if (!fp) fp = fopen("/etc/resolv.conf", "r");
    if (!fp) return false;
    while (fgets(line, sizeof(line), fp))
        if (!strncmp(line, "nameserver ", 11)) { found = true; break; }
    fclose(fp);
    return found;
}

static bool dns_resolves(const char *host)
{
    struct addrinfo hints = {0}, *result = NULL;
    int rc;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    rc = getaddrinfo(host && host[0] ? host : "api.new.cloud.netstream.net.in", NULL, &hints, &result);
    if (result) freeaddrinfo(result);
    return rc == 0;
}

static bool run_ping(const char *target)
{
    char command[192];
    int rc;
    if (!target || !target[0] || strspn(target, "0123456789.") != strlen(target)) return false;
    snprintf(command, sizeof(command), "ping -c 1 -W 1 %s >/dev/null 2>&1", target);
    rc = system(command);
    return rc != -1 && WIFEXITED(rc) && WEXITSTATUS(rc) == 0;
}

static bool tcp_probe(const char *ip, uint16_t port)
{
    struct sockaddr_in target = {0};
    struct pollfd pfd;
    int fd, flags, error = 0;
    socklen_t length = sizeof(error);
    fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return false;
    flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) { close(fd); return false; }
    target.sin_family = AF_INET;
    target.sin_port = htons(port);
    inet_pton(AF_INET, ip, &target.sin_addr);
    if (connect(fd, (struct sockaddr *)&target, sizeof(target)) == 0) { close(fd); return true; }
    if (errno != EINPROGRESS) { close(fd); return false; }
    pfd.fd = fd; pfd.events = POLLOUT; pfd.revents = 0;
    if (poll(&pfd, 1, 750) <= 0 || getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length) < 0)
        error = EIO;
    close(fd);
    return error == 0;
}

static void read_cloud_host(char *host, size_t host_len)
{
    struct uci_context *ctx = uci_alloc_context();
    struct uci_package *pkg = NULL;
    struct uci_element *element;
    snprintf(host, host_len, "%s", "api.new.cloud.netstream.net.in");
    if (!ctx || uci_load(ctx, "aircnms", &pkg) != UCI_OK) goto out;
    uci_foreach_element(&pkg->sections, element) {
        struct uci_section *section = uci_to_section(element);
        const char *url, *start;
        size_t n;
        if (strcmp(section->type, "aircnms")) continue;
        url = uci_lookup_option_string(ctx, section, "cloud_url");
        if (!url || strncmp(url, "https://", 8)) break;
        start = url + 8;
        n = strcspn(start, "/:");
        if (n > 0 && n < host_len) {
            memcpy(host, start, n);
            host[n] = '\0';
        }
        break;
    }
out:
    if (pkg) uci_unload(ctx, pkg);
    if (ctx) uci_free_context(ctx);
}

static bool cloud_https_probe(const char *host)
{
    CURL *curl;
    CURLcode rc;
    char url[256];
    long code = 0;
    curl = curl_easy_init();
    if (!curl) return false;
    snprintf(url, sizeof(url), "https://%s/health", host && host[0] ? host : "api.new.cloud.netstream.net.in");
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 1500L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, 1000L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "air-onbd/1");
    rc = curl_easy_perform(curl);
    if (rc == CURLE_OK) curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    curl_easy_cleanup(curl);
    return rc == CURLE_OK && code >= 200 && code < 500;
}

void onbd_probe_network(onbd_state_t *state)
{
    bool has_ip;
    if (!state) return;
    read_cloud_host(state->cloud_host, sizeof(state->cloud_host));
    state->carrier_available = carrier_present();
    has_ip = management_ipv4_present();
    state->management_ip_available = has_ip;
    if (has_ip) {
        state->dhcp_wait_ticks = 0;
        state->dhcp_retry_count = 0;
    } else if (state->carrier_available && state->dhcp_wait_ticks < UINT32_MAX) {
        state->dhcp_wait_ticks++;
        if (state->dhcp_wait_ticks >= ONBD_DHCP_WAIT_LIMIT) {
            state->dhcp_wait_ticks = 0;
            if (state->dhcp_retry_count < ONBD_DHCP_RETRY_LIMIT) {
                state->dhcp_retry_count++;
                LOG(NOTICE, "DHCP_PROBE: waiting for lease (attempt %u/%d)...",
                    state->dhcp_retry_count, ONBD_DHCP_RETRY_LIMIT);
            }
        }
    }
    state->default_route_available = default_route_present(state->default_gateway, sizeof(state->default_gateway));
    state->gateway_reachable = state->default_route_available && run_ping(state->default_gateway);
    state->dns_available = dns_configured();
    state->dns_resolved = state->dns_available && dns_resolves(state->cloud_host);
    state->internet_available = state->gateway_reachable && tcp_probe("1.1.1.1", 443);
    state->cloud_available = state->internet_available && state->dns_resolved && cloud_https_probe(state->cloud_host);

    static bool s_last_cloud_avail = false;
    static bool s_last_gw_avail = false;
    static bool s_last_dns_avail = false;
    static bool s_first_probe = true;

    if (s_first_probe ||
        state->cloud_available != s_last_cloud_avail ||
        state->gateway_reachable != s_last_gw_avail ||
        state->dns_resolved != s_last_dns_avail) {
        LOG(INFO, "PROBE_NETWORK: carrier=%d ip=%d gw=%s(ping=%d) dns_cfg=%d dns_res=%d inet=%d cloud=%d host='%s'",
            state->carrier_available,
            state->management_ip_available,
            state->default_gateway[0] ? state->default_gateway : "none",
            state->gateway_reachable,
            state->dns_available,
            state->dns_resolved,
            state->internet_available,
            state->cloud_available,
            state->cloud_host);
        s_last_cloud_avail = state->cloud_available;
        s_last_gw_avail = state->gateway_reachable;
        s_last_dns_avail = state->dns_resolved;
        s_first_probe = false;
    }
}
