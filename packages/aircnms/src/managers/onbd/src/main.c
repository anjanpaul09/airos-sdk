#include "onbd.h"

#include <ev.h>
#include <signal.h>
#include <string.h>
#include "log.h"

onbd_state_t g_onbd_state;
static ev_signal sigterm_watcher, sigint_watcher;
static ev_timer observe_timer;
static onbd_lifecycle_t persisted_lifecycle;
static bool persisted_operational_once;
static uint64_t persisted_desired_revision;
static uint64_t persisted_applied_revision;
static char persisted_attempt_id[ONBD_ID_LEN];
static char persisted_config_job_id[ONBD_ID_LEN];

static void signal_cb(EV_P_ ev_signal *watcher, int revents)
{
    (void)watcher; (void)revents;
    ev_break(loop, EVBREAK_ALL);
}

static void maybe_persist_checkpoint(void)
{
    if (g_onbd_state.lifecycle == persisted_lifecycle &&
        g_onbd_state.operational_once == persisted_operational_once &&
        g_onbd_state.desired_revision == persisted_desired_revision &&
        g_onbd_state.applied_revision == persisted_applied_revision &&
        !strcmp(g_onbd_state.attempt_id, persisted_attempt_id) &&
        !strcmp(g_onbd_state.config_job_id, persisted_config_job_id))
        return;
    if (!onbd_persist_checkpoint(&g_onbd_state)) {
        LOG(WARNING, "ONBD_CHECKPOINT_WRITE_FAILED");
        return;
    }
    persisted_lifecycle = g_onbd_state.lifecycle;
    persisted_operational_once = g_onbd_state.operational_once;
    persisted_desired_revision = g_onbd_state.desired_revision;
    persisted_applied_revision = g_onbd_state.applied_revision;
    snprintf(persisted_attempt_id, sizeof(persisted_attempt_id), "%s", g_onbd_state.attempt_id);
    snprintf(persisted_config_job_id, sizeof(persisted_config_job_id), "%s", g_onbd_state.config_job_id);
}

static void observe_cb(EV_P_ ev_timer *watcher, int revents)
{
    static char previous[64];
    const char *visible;
    (void)loop; (void)watcher; (void)revents;
    onbd_observe(onbd_ubus_context(), &g_onbd_state);
    visible = onbd_visible_state(&g_onbd_state);
    if (strcmp(previous, visible)) {
        LOG(INFO, "ONBD_TRANSITION visible_state=%s lifecycle=%s connectivity=%s configuration=%s reason=%s shadow=%d",
            visible, onbd_lifecycle_name(g_onbd_state.lifecycle),
            onbd_connectivity_name(g_onbd_state.connectivity),
            onbd_config_name(g_onbd_state.configuration),
            g_onbd_state.reason_code, g_onbd_state.shadow_mode);
        snprintf(previous, sizeof(previous), "%s", visible);
    }
    onbd_recovery_apply(&g_onbd_state);
    maybe_persist_checkpoint();
    if (!onbd_persist_runtime_state(&g_onbd_state))
        LOG(WARNING, "ONBD_RUNTIME_STATE_WRITE_FAILED");
}

int main(int argc, char **argv)
{
    struct ev_loop *loop = EV_DEFAULT;
    (void)argc; (void)argv;
    memset(&g_onbd_state, 0, sizeof(g_onbd_state));
    log_open("ONBD", 0);
    if (!onbd_persist_init(&g_onbd_state)) {
        LOG(ERR, "ONBD_UCI_INIT_FAILED");
        return 1;
    }
    persisted_lifecycle = g_onbd_state.lifecycle;
    persisted_operational_once = g_onbd_state.operational_once;
    persisted_desired_revision = g_onbd_state.desired_revision;
    persisted_applied_revision = g_onbd_state.applied_revision;
    snprintf(persisted_attempt_id, sizeof(persisted_attempt_id), "%s", g_onbd_state.attempt_id);
    snprintf(persisted_config_job_id, sizeof(persisted_config_job_id), "%s", g_onbd_state.config_job_id);
    if (!onbd_ubus_init(loop)) {
        LOG(ERR, "ONBD_UBUS_INIT_FAILED");
        return 1;
    }
    ev_signal_init(&sigterm_watcher, signal_cb, SIGTERM);
    ev_signal_start(loop, &sigterm_watcher);
    ev_signal_init(&sigint_watcher, signal_cb, SIGINT);
    ev_signal_start(loop, &sigint_watcher);
    ev_timer_init(&observe_timer, observe_cb, 0.1, 5.0);
    ev_timer_start(loop, &observe_timer);
    LOG(INFO, "ONBD_STARTED schema=%s shadow_mode=%d", ONBD_SCHEMA, g_onbd_state.shadow_mode);
    ev_run(loop, 0);
    ev_timer_stop(loop, &observe_timer);
    ev_signal_stop(loop, &sigterm_watcher);
    ev_signal_stop(loop, &sigint_watcher);
    onbd_ubus_cleanup();
    LOG(INFO, "ONBD_STOPPED");
    return 0;
}
