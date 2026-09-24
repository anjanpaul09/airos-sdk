#include <signal.h>
#include <dirent.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "log.h"
#include "portal_chilli.h"
#include "portal_utils.h"

static void portal_chilli_kill_by_conf(const char *conf)
{
    DIR *dir;
    struct dirent *de;

    if (!conf || conf[0] == '\0')
        return;

    dir = opendir("/proc");
    if (!dir)
        return;

    while ((de = readdir(dir)) != NULL) {
        char path[320];
        char cmdline[1024];
        FILE *fp;
        size_t n;
        pid_t pid;

        if (!isdigit((unsigned char)de->d_name[0]))
            continue;

        snprintf(path, sizeof(path), "/proc/%s/cmdline", de->d_name);
        fp = fopen(path, "r");
        if (!fp)
            continue;

        n = fread(cmdline, 1, sizeof(cmdline) - 1, fp);
        fclose(fp);
        if (n == 0)
            continue;

        cmdline[n] = '\0';
        for (size_t i = 0; i < n; i++) {
            if (cmdline[i] == '\0')
                cmdline[i] = ' ';
        }

        if (!strstr(cmdline, "chilli") || !strstr(cmdline, conf))
            continue;

        pid = (pid_t)atoi(de->d_name);
        if (pid > 1) {
            kill(pid, SIGTERM);
            usleep(200000);
            kill(pid, SIGKILL);
            LOG(INFO, "portal_chilli: killed stale pid=%d conf=%s", pid, conf);
        }
    }

    closedir(dir);
}

int portal_chilli_start(portal_entry_t *entry)
{
    char cmd[1536];
    char pidfile[128];
    char cmdsocket[128];
    char unixipc[128];

    if (!entry)
        return -1;

    snprintf(pidfile, sizeof(pidfile), "/var/run/chilli_%s.pid", entry->network);
    snprintf(cmdsocket, sizeof(cmdsocket), "/var/run/chilli_%s.sock", entry->network);
    snprintf(unixipc, sizeof(unixipc), "/var/run/chilli_%s.ipc", entry->network);

    portal_chilli_stop(entry);

    snprintf(cmd, sizeof(cmd),
             "echo 'starting chilli portal=%s conf=%s/%s/chilli.conf pidfile=%s cmdsocket=%s unixipc=%s tundev=%s' >/tmp/chilli_%s.log; "
             "chilli --conf %s/%s/chilli.conf --pidfile %s --cmdsocket %s --unixipc %s --tundev %s >>/tmp/chilli_%s.log 2>&1 & "
             "sleep 2; test -S %s",
             entry->portal_id, PORTAL_INSTANCE_DIR, entry->portal_id, pidfile,
             cmdsocket, unixipc, entry->tun,
             entry->network, PORTAL_INSTANCE_DIR, entry->portal_id, pidfile,
             cmdsocket, unixipc, entry->tun, entry->network, cmdsocket);

    if (portal_cmd(cmd) != 0) {
        entry->running = false;
        return -1;
    }

    entry->running = true;
    entry->pid = 0;
    portal_cmd("/etc/init.d/firewall reload");
    LOG(INFO, "portal_chilli: started portal=%s config=%s/%s/chilli.conf",
        entry->portal_id, PORTAL_INSTANCE_DIR, entry->portal_id);
    return 0;
}

int portal_chilli_stop(portal_entry_t *entry)
{
    char cmd[512];
    char conf[PORTAL_PATH_LEN];
    char pidfile[128];
    char cmdsocket[128];
    char unixipc[128];

    if (!entry)
        return -1;

    snprintf(conf, sizeof(conf), "%s/%s/chilli.conf", PORTAL_INSTANCE_DIR,
             entry->portal_id);
    snprintf(pidfile, sizeof(pidfile), "/var/run/chilli_%s.pid", entry->network);
    snprintf(cmdsocket, sizeof(cmdsocket), "/var/run/chilli_%s.sock", entry->network);
    snprintf(unixipc, sizeof(unixipc), "/var/run/chilli_%s.ipc", entry->network);

    snprintf(cmd, sizeof(cmd),
             "test ! -f %s || kill $(cat %s) 2>/dev/null",
             pidfile, pidfile);
    portal_cmd(cmd);

    portal_chilli_kill_by_conf(conf);

    snprintf(cmd, sizeof(cmd), "rm -f %s %s %s /var/run/chilli.ipc",
             pidfile, cmdsocket, unixipc);
    portal_cmd(cmd);

    entry->running = false;
    entry->pid = 0;
    LOG(INFO, "portal_chilli: stopped portal=%s", entry->portal_id);
    return 0;
}
