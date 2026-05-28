#include "stamonitord_history_internal.h"

/* paste Local MAC ignore table section here
 * remove static from exported internal functions
 */

/* ------------------------------------------------------------------------- */
/* Local MAC ignore table                                                    */
/* ------------------------------------------------------------------------- */

bool local_mac_contains(app_t *app, mac_addr_t mac) {
    for (size_t i = 0; i < app->local_macs.count; i++) {
        if (mac_equal(app->local_macs.macs[i], mac))
            return true;
    }
    return false;
}

void local_mac_add(app_t *app, mac_addr_t mac) {
    if (mac_is_zero(mac) || mac_is_broadcast(mac) || mac_is_multicast(mac))
        return;

    if (local_mac_contains(app, mac))
        return;

    if (app->local_macs.count >= LOCAL_MAC_MAX)
        return;

    app->local_macs.macs[app->local_macs.count++] = mac;
}

void load_local_macs(app_t *app) {
    DIR *d = opendir("/sys/class/net");
    if (!d)
        return;

    struct dirent *de;

    while ((de = readdir(d))) {
        if (de->d_name[0] == '.')
            continue;

        char path[512];

        int ret = snprintf(path,
                        sizeof(path),
                        "/sys/class/net/%s/address",
                        de->d_name);

        if (ret < 0 || (size_t)ret >= sizeof(path))
            continue;

        FILE *f = fopen(path, "r");
        if (!f)
            continue;

        char buf[64];

        if (fgets(buf, sizeof(buf), f)) {
            mac_addr_t mac;
            if (parse_mac_str(buf, &mac) == 0)
                local_mac_add(app, mac);
        }

        fclose(f);
    }

    closedir(d);
}

bool mac_is_station_candidate(app_t *app, mac_addr_t mac) {
    if (mac_is_zero(mac) || mac_is_broadcast(mac) || mac_is_multicast(mac))
        return false;

    if (is_ap_own_oui(mac))
        return false;

    if (local_mac_contains(app, mac))
        return false;

    return true;
}
