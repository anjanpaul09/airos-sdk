#include "netconf_snapshot.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"

#define SNAPSHOT_ROOT "/etc/airpro/netconfd/snapshots"

static bool safe_job_id(const char *job_id)
{
    size_t i;
    if (!job_id || !job_id[0]) return false;
    for (i = 0; job_id[i]; i++) {
        unsigned char c = (unsigned char)job_id[i];
        if (!isalnum(c) && c != '-' && c != '_')
            return false;
    }
    return i < 80;
}

static int run_command(const char *cmd)
{
    int rc = system(cmd);
    return rc == 0;
}

bool netconf_snapshot_create(const char *job_id)
{
    char cmd[512];
    if (!safe_job_id(job_id)) {
        LOG(ERR, "SNAPSHOT_CREATE_REJECTED job_id=%s", job_id ? job_id : "");
        return false;
    }
    snprintf(cmd, sizeof(cmd),
             "mkdir -p '%s/%s' && "
             "for f in network wireless dhcp firewall aircnms wifi-schedule; do "
             "[ -f /etc/config/$f ] && cp -p /etc/config/$f '%s/%s/' || true; "
             "done && sync",
             SNAPSHOT_ROOT, job_id, SNAPSHOT_ROOT, job_id);
    if (!run_command(cmd)) {
        LOG(ERR, "SNAPSHOT_CREATE_FAILED job_id=%s", job_id);
        return false;
    }
    LOG(INFO, "SNAPSHOT_CREATED job_id=%s", job_id);
    return true;
}

bool netconf_snapshot_restore(const char *job_id)
{
    char cmd[768];
    if (!safe_job_id(job_id)) {
        LOG(ERR, "SNAPSHOT_RESTORE_REJECTED job_id=%s", job_id ? job_id : "");
        return false;
    }
    snprintf(cmd, sizeof(cmd),
             "[ -d '%s/%s' ] && "
             "for f in network wireless dhcp firewall aircnms wifi-schedule; do "
             "[ -f '%s/%s/'$f ] && cp -p '%s/%s/'$f /etc/config/$f || true; "
             "done && sync && "
             "/etc/init.d/network reload >/dev/null 2>&1 || true; "
             "wifi reload >/dev/null 2>&1 || true; "
             "/etc/init.d/dnsmasq restart >/dev/null 2>&1 || true; "
             "/etc/init.d/firewall reload >/dev/null 2>&1 || true",
             SNAPSHOT_ROOT, job_id, SNAPSHOT_ROOT, job_id, SNAPSHOT_ROOT, job_id);
    if (!run_command(cmd)) {
        LOG(ERR, "SNAPSHOT_RESTORE_FAILED job_id=%s", job_id);
        return false;
    }
    LOG(INFO, "SNAPSHOT_RESTORED job_id=%s", job_id);
    return true;
}
