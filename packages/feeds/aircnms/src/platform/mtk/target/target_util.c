#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>

#include "log.h"
#include "target_util.h"
#include "util.h"

int util_wifi_get_parent(const char *vif, char *buf, int len)
{
    char p_buf[32] = {0};

    if (util_get_vif_radio(vif, p_buf, sizeof(p_buf))) {
        LOGW("%s: failed to get vif radio", vif);
        return -EINVAL;
    }
    strscpy(buf, p_buf, len);

    return 0;
}

bool util_wifi_is_phy_vif_match(const char *phy, const char *vif)
{
    char buf[32];
    util_wifi_get_parent(vif, buf, sizeof(buf));
    return !strcmp(phy, buf);
}
