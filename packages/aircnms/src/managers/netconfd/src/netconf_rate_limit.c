#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/wait.h>

#define MAX_OUTPUT_LEN 1024
#define TC_RATE_BURST "64kb"
#define TC_RATE_LATENCY "50ms"
#define TC_WLAN_UP_PREF 10

const char* get_ifname_from_secname(const char *section) {
    static char ifname[MAX_OUTPUT_LEN];
    char command[MAX_OUTPUT_LEN];

    ifname[0] = 0;

    // Construct the ubus command with the section name argument
    snprintf(command, sizeof(command),
             "ubus call network.wireless status | grep -A 5 '\"section\": \"%s\"' | grep '\"ifname\"' | awk -F'\"' '{print $4}'",
             section);

    // Open a process to run the command
    FILE *fp = popen(command, "r");
    if (fp == NULL) {
        perror("Failed to run command");
        return NULL;
    }

    // Read the output from the command
    if (fgets(ifname, sizeof(ifname), fp) != NULL) {
        // Remove trailing newline if present
        size_t len = strlen(ifname);
        if (len > 0 && ifname[len - 1] == '\n') {
            ifname[len - 1] = '\0';
        }
    }

    // Close the file pointer
    fclose(fp);

    // Return the interface name
    return ifname[0] != '\0' ? ifname : NULL;
}

static bool is_safe_ifname(const char *ifname)
{
    if (!ifname || !ifname[0])
        return false;

    for (const unsigned char *p = (const unsigned char *)ifname; *p; p++) {
        if (!isalnum(*p) && *p != '_' && *p != '-' && *p != '.')
            return false;
    }

    return true;
}

static void mac_to_str(const uint8_t *mac, char out[18])
{
    snprintf(out, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static int run_tc_cmd(const char *cmd)
{
    int rc;

    printf("netconfd rate-limit: %s\n", cmd);
    rc = system(cmd);
    if (rc == -1)
        return -1;

    if (WIFEXITED(rc))
        return WEXITSTATUS(rc);

    return -1;
}

static void tc_delete_qdisc(const char *ifname, const char *qdisc)
{
    char cmd[MAX_OUTPUT_LEN];

    snprintf(cmd, sizeof(cmd), "tc qdisc del dev %s %s 2>/dev/null",
             ifname, qdisc);
    run_tc_cmd(cmd);
}

static bool tc_apply_interface_limit(const char *ifname, int uprate, int downrate)
{
    char cmd[MAX_OUTPUT_LEN];
    bool ok = true;

    if (!is_safe_ifname(ifname)) {
        fprintf(stderr, "Invalid interface name for rate limit\n");
        return false;
    }

    if (downrate > 0) {
        snprintf(cmd, sizeof(cmd),
                 "tc qdisc replace dev %s root tbf rate %dmbit burst %s latency %s",
                 ifname, downrate, TC_RATE_BURST, TC_RATE_LATENCY);
        ok &= (run_tc_cmd(cmd) == 0);
    } else {
        tc_delete_qdisc(ifname, "root");
    }

    if (uprate > 0) {
        snprintf(cmd, sizeof(cmd), "tc qdisc replace dev %s clsact", ifname);
        ok &= (run_tc_cmd(cmd) == 0);

        snprintf(cmd, sizeof(cmd),
                 "tc filter replace dev %s ingress protocol all pref %d flower "
                 "action police rate %dmbit burst %s conform-exceed drop",
                 ifname, TC_WLAN_UP_PREF, uprate, TC_RATE_BURST);
        ok &= (run_tc_cmd(cmd) == 0);
    } else {
        snprintf(cmd, sizeof(cmd),
                 "tc filter del dev %s ingress pref %d 2>/dev/null",
                 ifname, TC_WLAN_UP_PREF);
        run_tc_cmd(cmd);

        if (downrate <= 0)
            tc_delete_qdisc(ifname, "clsact");
    }

    return ok;
}

bool air_ifname_rate_limit(char *ifname, int uprate, int downrate)
{
    if (!ifname)
        return false;

    if (!tc_apply_interface_limit(ifname, uprate, downrate)) {
        fprintf(stderr, "Failed to apply tc rate limit on %s uplink=%d downlink=%d\n",
                ifname, uprate, downrate);
        return false;
    }

    printf("Rate limit set successfully: ifname=%s uplink=%d Mbps downlink=%d Mbps\n",
           ifname, uprate, downrate);
    return true;
}

bool air_interface_rate_limit(char *vif_name, int uprate, int downrate, char *type)
{
    const char *ifname;

    if (!vif_name || !type)
        return false;

    if (strcmp(type, "wlan_per_user") == 0) {
        printf("netconfd rate-limit: wlan_per_user requires per-client rules; skipping interface section %s\n",
               vif_name);
        return true;
    }

    if (strcmp(type, "wlan") != 0) {
        fprintf(stderr, "Unknown rate limit type: %s\n", type);
        return false;
    }

#ifdef CONFIG_PLATFORM_MTK_JEDI
    ifname = vif_name;
#else
    ifname = get_ifname_from_secname(vif_name);
#endif

    if (!ifname) {
        fprintf(stderr, "Failed to resolve ifname for section %s\n", vif_name);
        return false;
    }

    return air_ifname_rate_limit((char *)ifname, uprate, downrate);
}

static unsigned int mac_filter_pref(const uint8_t *mac, unsigned int salt)
{
    unsigned int hash = 2166136261u;

    for (int i = 0; i < 6; i++) {
        hash ^= mac[i];
        hash *= 16777619u;
    }

    return 1000 + ((hash + salt) % 30000);
}

static bool find_station_ifname(const char *macaddr, char *ifname, size_t ifname_len)
{
    FILE *fp;
    char candidate[64];

    if (!macaddr || !ifname || ifname_len == 0)
        return false;

    fp = popen("iw dev 2>/dev/null | awk '/Interface/{print $2}'", "r");
    if (!fp)
        return false;

    while (fgets(candidate, sizeof(candidate), fp)) {
        char cmd[MAX_OUTPUT_LEN];
        int rc;
        size_t len = strlen(candidate);

        if (len > 0 && candidate[len - 1] == '\n')
            candidate[len - 1] = '\0';

        if (!is_safe_ifname(candidate))
            continue;

        snprintf(cmd, sizeof(cmd),
                 "iw dev %s station get %s >/dev/null 2>&1",
                 candidate, macaddr);
        rc = system(cmd);
        if (rc != -1 && WIFEXITED(rc) && WEXITSTATUS(rc) == 0) {
            snprintf(ifname, ifname_len, "%s", candidate);
            pclose(fp);
            return true;
        }
    }

    pclose(fp);
    return false;
}

bool air_user_rate_limit(uint8_t *mac, int uprate, int downrate)
{
    char macaddr[18];
    char ifname[64] = {0};
    char cmd[MAX_OUTPUT_LEN];
    unsigned int up_pref;
    unsigned int down_pref;
    bool ok = true;

    if (!mac)
        return false;

    mac_to_str(mac, macaddr);

    if (!find_station_ifname(macaddr, ifname, sizeof(ifname))) {
        fprintf(stderr, "Failed to find associated interface for client %s\n", macaddr);
        return false;
    }

    if (!is_safe_ifname(ifname)) {
        fprintf(stderr, "Invalid interface name for client %s\n", macaddr);
        return false;
    }

    up_pref = mac_filter_pref(mac, 0);
    down_pref = mac_filter_pref(mac, 1);

    if (uprate > 0 || downrate > 0) {
        snprintf(cmd, sizeof(cmd), "tc qdisc replace dev %s clsact", ifname);
        ok &= (run_tc_cmd(cmd) == 0);
    }

    if (uprate > 0) {
        snprintf(cmd, sizeof(cmd),
                 "tc filter replace dev %s ingress protocol all pref %u flower src_mac %s "
                 "action police rate %dmbit burst %s conform-exceed drop",
                 ifname, up_pref, macaddr, uprate, TC_RATE_BURST);
        ok &= (run_tc_cmd(cmd) == 0);
    } else {
        snprintf(cmd, sizeof(cmd),
                 "tc filter del dev %s ingress pref %u 2>/dev/null",
                 ifname, up_pref);
        run_tc_cmd(cmd);
    }

    if (downrate > 0) {
        snprintf(cmd, sizeof(cmd),
                 "tc filter replace dev %s egress protocol all pref %u flower dst_mac %s "
                 "action police rate %dmbit burst %s conform-exceed drop",
                 ifname, down_pref, macaddr, downrate, TC_RATE_BURST);
        ok &= (run_tc_cmd(cmd) == 0);
    } else {
        snprintf(cmd, sizeof(cmd),
                 "tc filter del dev %s egress pref %u 2>/dev/null",
                 ifname, down_pref);
        run_tc_cmd(cmd);
    }

    if (!ok) {
        fprintf(stderr, "Failed to apply tc user rate limit for %s on %s\n",
                macaddr, ifname);
        return false;
    }

    printf("User rate limit set successfully: mac=%s ifname=%s uplink=%d Mbps downlink=%d Mbps\n",
           macaddr, ifname, uprate, downrate);
    return true;
}
