#include "onbd.h"
#include "log.h"

#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>

static int s_last_fallback_active = -1;
static int s_last_apply = -1;

void onbd_recovery_apply(const onbd_state_t *state)
{
    char command[256];
    int apply;
    int rc;
    if (!state) return;

    apply = (!state->shadow_mode && state->recovery_apply_enabled) ? 1 : 0;
    if (state->fallback_active == s_last_fallback_active && apply == s_last_apply)
        return;

    s_last_fallback_active = state->fallback_active;
    s_last_apply = apply;

    snprintf(command, sizeof(command), "/usr/sbin/air_onbd_recovery.sh %s %s >/dev/null 2>&1",
             state->fallback_active ? "enable" : "disable",
             apply ? "apply" : "shadow");
    rc = system(command);
    LOG(NOTICE, "RECOVERY_SSID: %s (mode=%s, rc=%d)",
        state->fallback_active ? "ACTIVATED" : "DEACTIVATED",
        apply ? "apply" : "shadow",
        rc);
}
