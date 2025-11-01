#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "os.h"
#include "log.h"

int target_process_network_id(char *network_id)
{
#define UCI_BUF_LEN 256
    char buf[UCI_BUF_LEN];
    char aircnms_netwrkid[128];
    size_t len;
    int rc;

    memset(buf, 0, sizeof(buf));
    rc = cmd_buf("uci get aircnms.@aircnms[0].network_id", buf, (size_t)UCI_BUF_LEN);
    len = strlen(buf);
    if (len == 0) {
        LOGI("%s: No uci found", __func__);
        return -1;
    }
    sscanf(buf, "%s", aircnms_netwrkid);

    if (strcmp(network_id, aircnms_netwrkid) != 0) {
        system("/etc/init.d/qminit restart");
    }

    return rc;
}
