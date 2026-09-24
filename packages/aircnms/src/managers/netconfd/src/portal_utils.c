#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "log.h"
#include "os.h"
#include "portal_utils.h"

bool portal_id_valid(const char *portal_id)
{
    size_t i;
    size_t len;

    if (!portal_id)
        return false;

    len = strlen(portal_id);
    if (len < 6 || len >= 64)
        return false;

    for (i = 0; i < len; i++) {
        if (!isalnum((unsigned char)portal_id[i]) &&
            portal_id[i] != '-' && portal_id[i] != '_') {
            return false;
        }
    }

    return true;
}

void portal_make_network_name(const char *portal_id, char *buf, size_t len)
{
    char hash[9] = {0};
    size_t i;
    size_t j = 0;

    if (!buf || len == 0)
        return;

    for (i = 0; portal_id && portal_id[i] != '\0' && j < sizeof(hash) - 1; i++) {
        if (isalnum((unsigned char)portal_id[i]))
            hash[j++] = (char)tolower((unsigned char)portal_id[i]);
    }

    if (j < 6)
        strlcpy(hash, "portal0", sizeof(hash));

    snprintf(buf, len, "cp_%s", hash);
}

void portal_make_bridge_name(const char *network, char *buf, size_t len)
{
    snprintf(buf, len, "br-%s", network ? network : "cp");
}

void portal_make_tun_name(const char *network, char *buf, size_t len)
{
    if (network && !strncmp(network, "cp_", 3))
        snprintf(buf, len, "tc_%s", network + 3);
    else
        snprintf(buf, len, "tc_cp");
}

int portal_mkdir_p(const char *path)
{
    char tmp[PORTAL_PATH_LEN];
    char *p;

    if (!path || path[0] == '\0')
        return -1;

    strlcpy(tmp, path, sizeof(tmp));
    for (p = tmp + 1; *p; p++) {
        if (*p != '/')
            continue;
        *p = '\0';
        if (mkdir(tmp, 0755) != 0 && errno != EEXIST)
            return -1;
        *p = '/';
    }

    if (mkdir(tmp, 0755) != 0 && errno != EEXIST)
        return -1;

    return 0;
}

int portal_write_file(const char *path, const char *data)
{
    FILE *fp;

    fp = fopen(path, "w");
    if (!fp)
        return -1;

    if (fputs(data ? data : "", fp) == EOF) {
        fclose(fp);
        return -1;
    }

    return fclose(fp);
}

int portal_remove_tree(const char *path)
{
    DIR *dir;
    struct dirent *de;

    dir = opendir(path);
    if (!dir) {
        if (errno == ENOENT)
            return 0;
        return -1;
    }

    while ((de = readdir(dir)) != NULL) {
        char child[PORTAL_PATH_LEN];
        struct stat st;

        if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
            continue;

        if (snprintf(child, sizeof(child), "%s/%s", path, de->d_name) >=
            (int)sizeof(child)) {
            LOG(ERR, "portal_remove_tree: path too long under %s", path);
            continue;
        }
        if (lstat(child, &st) != 0)
            continue;

        if (S_ISDIR(st.st_mode))
            portal_remove_tree(child);
        else
            unlink(child);
    }

    closedir(dir);
    return rmdir(path);
}

int portal_cmd(const char *cmd)
{
    int rc;

    if (!cmd || cmd[0] == '\0')
        return -1;

    rc = system(cmd);
    if (rc != 0)
        LOG(ERR, "portal command failed rc=%d cmd=%s", rc, cmd);

    return rc;
}
