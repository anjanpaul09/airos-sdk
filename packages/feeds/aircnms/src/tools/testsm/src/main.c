#include <stdarg.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <netinet/in.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <jansson.h>
#include <ev.h>
#include <syslog.h>
#include <getopt.h>

#include "ds_tree.h"
#include "log.h"
#include "os.h"
#include "target.h"

bool sm_mqtt_init(void);
bool gemmsg_qm_init(void);

int main(int argc, char **argv)
{
    struct ev_loop *loop = EV_DEFAULT;
    bool rc;

    rc = target_init(TARGET_INIT_MGR_SM, loop);
    if (true != rc) {
        LOG(ERR, "Initializing SM ""(Failed to init target library)");
        return -1;
    }

    if (!dpp_init()) {
        return -1;
    }

    //if (!sm_mqtt_init()) {
      //  return -1;
    //}

    if (!gemmsg_qm_init()) {
        return -1;
    }

    put_client_to_dpp();

    target_close(TARGET_INIT_MGR_SM, loop);

    ev_run(EV_DEFAULT, 0);
    ev_default_destroy();

    return 0;
}
