#include "logd.h"
#include "logd_config.h"
#include "logd_filter.h"
#include "logd_rotate.h"
#include "logd_stream.h"
#include "logd_ubus.h"

#include <signal.h>

logd_ctx_t g_logd;

static ev_signal s_sigint_watcher;
static ev_signal s_sigterm_watcher;
static ev_signal s_sighup_watcher;

static void sigterm_cb(EV_P_ ev_signal *w, int revents)
{
    (void)w; (void)revents;
    ev_break(EV_A_ EVBREAK_ALL);
}

static void sighup_cb(EV_P_ ev_signal *w, int revents)
{
    (void)loop; (void)w; (void)revents;
    logd_config_t new_cfg;
    if (logd_config_load(&new_cfg)) {
        g_logd.config = new_cfg;
    }
}

int main(int argc, char **argv)
{
    (void)argc; (void)argv;
    struct ev_loop *loop = EV_DEFAULT;

    memset(&g_logd, 0, sizeof(g_logd));
    g_logd.loop = loop;
    g_logd.stats.start_time = time(NULL);

    if (!logd_config_load(&g_logd.config)) {
        fprintf(stderr, "Failed to load logd config, using defaults\n");
    }

    if (!g_logd.config.enabled) {
        return 0;
    }

    logd_filter_init();

    if (!logd_rotate_init()) {
        fprintf(stderr, "Failed to initialize logd rotation engine\n");
        return 1;
    }

    if (!logd_ubus_init(loop)) {
        fprintf(stderr, "Failed to initialize logd UBUS\n");
        logd_rotate_close();
        return 1;
    }

    if (!logd_stream_init()) {
        fprintf(stderr, "Failed to initialize logd stream\n");
        logd_ubus_cleanup();
        logd_rotate_close();
        return 1;
    }

    logd_stream_start();

    ev_signal_init(&s_sigint_watcher, sigterm_cb, SIGINT);
    ev_signal_start(loop, &s_sigint_watcher);

    ev_signal_init(&s_sigterm_watcher, sigterm_cb, SIGTERM);
    ev_signal_start(loop, &s_sigterm_watcher);

    ev_signal_init(&s_sighup_watcher, sighup_cb, SIGHUP);
    ev_signal_start(loop, &s_sighup_watcher);

    /* Run event loop */
    ev_run(loop, 0);

    /* Cleanup */
    ev_signal_stop(loop, &s_sighup_watcher);
    ev_signal_stop(loop, &s_sigterm_watcher);
    ev_signal_stop(loop, &s_sigint_watcher);

    logd_stream_cleanup();
    logd_ubus_cleanup();
    logd_rotate_close();

    return 0;
}
