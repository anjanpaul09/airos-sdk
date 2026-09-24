#include <ev.h>
#include <signal.h>

#include "airuid.h"
#include "log.h"

static ev_signal sigterm_watcher;
static ev_signal sigint_watcher;

static void signal_cb(struct ev_loop *loop, ev_signal *w, int revents)
{
    (void)w;
    (void)revents;

    LOG(INFO, "AIRUID: shutdown requested");
    ev_break(loop, EVBREAK_ALL);
}

int main(int argc, char *argv[])
{
    struct ev_loop *loop = EV_DEFAULT;
    int ret = 0;

    (void)argc;
    (void)argv;

    log_open("AIRUID", 0);

    ev_signal_init(&sigterm_watcher, signal_cb, SIGTERM);
    ev_signal_start(loop, &sigterm_watcher);
    ev_signal_init(&sigint_watcher, signal_cb, SIGINT);
    ev_signal_start(loop, &sigint_watcher);

    if (!airui_ubus_service_init()) {
        LOG(ERR, "AIRUID: failed to initialize ubus service");
        ret = -1;
        goto cleanup;
    }

    LOG(INFO, "AIRUID: running");
    ev_run(loop, 0);

    airui_ubus_service_cleanup();

cleanup:
    ev_signal_stop(loop, &sigterm_watcher);
    ev_signal_stop(loop, &sigint_watcher);
    ev_default_destroy();
    LOG(INFO, "AIRUID: stopped");
    return ret;
}
