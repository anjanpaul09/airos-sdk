#include "onbd.h"

#include <errno.h>
#include <fcntl.h>
#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <uci.h>
#include "log.h"

static const char *uci_get_option(struct uci_context *ctx, struct uci_section *section,
                                  const char *name, const char *fallback)
{
    const char *value = uci_lookup_option_string(ctx, section, name);
    return value ? value : fallback;
}

static bool uci_set_path(struct uci_context *ctx, const char *path, const char *value)
{
    struct uci_ptr ptr = {0};
    char expression[160];
    if (snprintf(expression, sizeof(expression), "%s=%s", path, value) >= (int)sizeof(expression))
        return false;
    return uci_lookup_ptr(ctx, &ptr, expression, true) == UCI_OK && uci_set(ctx, &ptr) == UCI_OK;
}

static onbd_lifecycle_t parse_lifecycle(const char *value)
{
    if (!value || !strcmp(value, "init") || !strcmp(value, "fresh")) return ONBD_LIFECYCLE_INIT;
    if (!strcmp(value, "enrolling")) return ONBD_LIFECYCLE_ENROLLING;
    if (!strcmp(value, "enrolled")) return ONBD_LIFECYCLE_ENROLLED;
    if (!strcmp(value, "operational")) return ONBD_LIFECYCLE_OPERATIONAL;
    if (!strcmp(value, "recovery")) return ONBD_LIFECYCLE_RECOVERY;
    return ONBD_LIFECYCLE_INIT;
}

bool onbd_persist_init(onbd_state_t *state)
{
    struct uci_context *ctx = NULL;
    struct uci_package *pkg = NULL;
    struct uci_section *section = NULL;
    struct uci_element *element;
    bool ok = false;

    if (!state || !(ctx = uci_alloc_context()) || uci_load(ctx, "aircnms", &pkg) != UCI_OK)
        goto out;

    uci_foreach_element(&pkg->sections, element) {
        struct uci_section *candidate = uci_to_section(element);
        if (candidate && candidate->e.name && candidate->type &&
            !strcmp(candidate->e.name, "onboarding") && !strcmp(candidate->type, "onboarding")) {
            section = candidate;
            break;
        }
    }

    if (!section) {
        if (!uci_set_path(ctx, "aircnms.onboarding", "onboarding"))
            goto out;
        if (!uci_set_path(ctx, "aircnms.onboarding.schema_version", "1") ||
            !uci_set_path(ctx, "aircnms.onboarding.enabled", "1") ||
            !uci_set_path(ctx, "aircnms.onboarding.shadow_mode", "0") ||
            !uci_set_path(ctx, "aircnms.onboarding.recovery_apply_enabled", "1") ||
            !uci_set_path(ctx, "aircnms.onboarding.lifecycle", "init") ||
            !uci_set_path(ctx, "aircnms.onboarding.operational_once", "0") ||
            !uci_set_path(ctx, "aircnms.onboarding.active_attempt_id", "") ||
            !uci_set_path(ctx, "aircnms.onboarding.active_config_job_id", "") ||
            !uci_set_path(ctx, "aircnms.onboarding.desired_revision", "0") ||
            !uci_set_path(ctx, "aircnms.onboarding.applied_revision", "0") ||
            !uci_set_path(ctx, "aircnms.onboarding.last_good_revision", "0") ||
            !uci_set_path(ctx, "aircnms.onboarding.recovery_ssid_enabled", "0") ||
            !uci_set_path(ctx, "aircnms.onboarding.wifi_suppress_on_cloud_loss", "0") ||
            !uci_set_path(ctx, "aircnms.onboarding.last_failure_code", "") ||
            uci_commit(ctx, &pkg, false) != UCI_OK)
            goto out;
        LOG(INFO, "ONBD_UCI_INIT section=aircnms.onboarding schema=1 shadow_mode=0");
        uci_foreach_element(&pkg->sections, element) {
            struct uci_section *candidate = uci_to_section(element);
            if (candidate && candidate->e.name && !strcmp(candidate->e.name, "onboarding")) {
                section = candidate;
                break;
            }
        }
    }
    if (!section)
        goto out;

    /* Upgrade existing APs without overwriting operator intent.
     * Any uci_set/commit can invalidate section pointers in libuci, so reload
     * before reading options. This is required on fresh boot where procd may
     * restart air-onbd while /etc/config/aircnms is still being normalized. */
    bool changed = false;
    if (!uci_lookup_option_string(ctx, section, "recovery_apply_enabled")) {
        changed |= uci_set_path(ctx, "aircnms.onboarding.recovery_apply_enabled", "1");
    }
    if (!uci_lookup_option_string(ctx, section, "active_attempt_id")) {
        changed |= uci_set_path(ctx, "aircnms.onboarding.active_attempt_id", "");
    }
    if (!uci_lookup_option_string(ctx, section, "active_config_job_id")) {
        changed |= uci_set_path(ctx, "aircnms.onboarding.active_config_job_id", "");
    }
    if (!uci_lookup_option_string(ctx, section, "last_good_revision")) {
        changed |= uci_set_path(ctx, "aircnms.onboarding.last_good_revision", "0");
    }
    if (!uci_lookup_option_string(ctx, section, "wifi_suppress_on_cloud_loss")) {
        changed |= uci_set_path(ctx, "aircnms.onboarding.wifi_suppress_on_cloud_loss", "0");
    }
    if (changed && uci_commit(ctx, &pkg, false) != UCI_OK)
        goto out;
    if (changed) {
        uci_unload(ctx, pkg);
        pkg = NULL;
        section = NULL;
        if (uci_load(ctx, "aircnms", &pkg) != UCI_OK)
            goto out;
        uci_foreach_element(&pkg->sections, element) {
            struct uci_section *candidate = uci_to_section(element);
            if (candidate && candidate->e.name && !strcmp(candidate->e.name, "onboarding") &&
                candidate->type && !strcmp(candidate->type, "onboarding")) {
                section = candidate;
                break;
            }
        }
        if (!section)
            goto out;
    }

    state->enabled = atoi(uci_get_option(ctx, section, "enabled", "1")) != 0;
    state->shadow_mode = atoi(uci_get_option(ctx, section, "shadow_mode", "0")) != 0;
    state->recovery_apply_enabled = atoi(uci_get_option(ctx, section, "recovery_apply_enabled", "1")) != 0;
    state->operational_once = atoi(uci_get_option(ctx, section, "operational_once", "0")) != 0;
    state->recovery_ssid_enabled = atoi(uci_get_option(ctx, section, "recovery_ssid_enabled", "0")) != 0;
    state->wifi_suppress_policy_enabled = atoi(uci_get_option(ctx, section, "wifi_suppress_on_cloud_loss", "0")) != 0;
    state->lifecycle = parse_lifecycle(uci_get_option(ctx, section, "lifecycle", "init"));
    state->desired_revision = strtoull(uci_get_option(ctx, section, "desired_revision", "0"), NULL, 10);
    state->applied_revision = strtoull(uci_get_option(ctx, section, "applied_revision", "0"), NULL, 10);
    snprintf(state->attempt_id, sizeof(state->attempt_id), "%s",
             uci_get_option(ctx, section, "active_attempt_id", ""));
    snprintf(state->config_job_id, sizeof(state->config_job_id), "%s",
             uci_get_option(ctx, section, "active_config_job_id", ""));

    if (!state->operational_once) {
        state->lifecycle = ONBD_LIFECYCLE_INIT;
        state->fallback_active = false;
        state->dhcp_wait_ticks = 0;
        state->dhcp_retry_count = 0;
        state->recovery_bad_ticks = 0;
        state->recovery_good_ticks = 0;
        system("/usr/sbin/air_onbd_recovery.sh disable apply >/dev/null 2>&1");
    }
    system("/usr/sbin/air_wifi_suppress.sh restore >/dev/null 2>&1");

    ok = true;
out:
    if (pkg) uci_unload(ctx, pkg);
    if (ctx) uci_free_context(ctx);
    return ok;
}

bool onbd_persist_runtime_state(const onbd_state_t *state)
{
    struct json_object *root = NULL;
    const char *json;
    char temporary[128];
    int fd = -1;
    size_t length;
    bool ok = false;

    if (!state || (mkdir(ONBD_RUNTIME_DIR, 0755) < 0 && errno != EEXIST))
        return false;
    root = json_object_new_object();
    if (!root) return false;
    json_object_object_add(root, "schema", json_object_new_string(ONBD_SCHEMA));
    json_object_object_add(root, "lifecycle", json_object_new_string(onbd_lifecycle_name(state->lifecycle)));
    json_object_object_add(root, "connectivity", json_object_new_string(onbd_connectivity_name(state->connectivity)));
    json_object_object_add(root, "configuration", json_object_new_string(onbd_config_name(state->configuration)));
    json_object_object_add(root, "visible_state", json_object_new_string(onbd_visible_state(state)));
    json_object_object_add(root, "reason_code", json_object_new_string(state->reason_code));
    json_object_object_add(root, "shadow_mode", json_object_new_boolean(state->shadow_mode));
    json_object_object_add(root, "fallback_active", json_object_new_boolean(state->fallback_active));
    json_object_object_add(root, "wifi_suppressed", json_object_new_boolean(state->wifi_suppressed));
    json_object_object_add(root, "wifi_suppress_policy_enabled", json_object_new_boolean(state->wifi_suppress_policy_enabled));
    json_object_object_add(root, "cloud_down_ticks", json_object_new_int((int)state->cloud_down_ticks));
    json_object_object_add(root, "cloud_down_duration_sec", json_object_new_int((int)state->cloud_down_duration_sec));
    json_object_object_add(root, "recovery_bad_ticks", json_object_new_int((int)state->recovery_bad_ticks));
    json_object_object_add(root, "recovery_good_ticks", json_object_new_int((int)state->recovery_good_ticks));
    json_object_object_add(root, "cloud_host", json_object_new_string(state->cloud_host));
    json_object_object_add(root, "default_gateway", json_object_new_string(state->default_gateway));
    json_object_object_add(root, "updated_monotonic_ms", json_object_new_int64((int64_t)state->updated_monotonic_ms));
    json = json_object_to_json_string_ext(root, JSON_C_TO_STRING_PLAIN);
    length = strlen(json);
    snprintf(temporary, sizeof(temporary), "%s.tmp.%ld", ONBD_STATE_FILE, (long)getpid());
    fd = open(temporary, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (fd >= 0 && write(fd, json, length) == (ssize_t)length && write(fd, "\n", 1) == 1 && fsync(fd) == 0) {
        close(fd); fd = -1;
        ok = rename(temporary, ONBD_STATE_FILE) == 0;
    }
    if (fd >= 0) close(fd);
    if (!ok) unlink(temporary);
    json_object_put(root);
    return ok;
}

static const char *lifecycle_uci_name(onbd_lifecycle_t value)
{
    switch (value) {
    case ONBD_LIFECYCLE_INIT: return "init";
    case ONBD_LIFECYCLE_ENROLLING: return "enrolling";
    case ONBD_LIFECYCLE_ENROLLED: return "enrolled";
    case ONBD_LIFECYCLE_OPERATIONAL: return "operational";
    case ONBD_LIFECYCLE_RECOVERY: return "recovery";
    }
    return "init";
}

bool onbd_persist_checkpoint(const onbd_state_t *state)
{
    struct uci_context *ctx = NULL;
    struct uci_package *pkg = NULL;
    char value[32];
    bool ok = false;

    if (!state || !(ctx = uci_alloc_context()) || uci_load(ctx, "aircnms", &pkg) != UCI_OK)
        goto out;

    snprintf(value, sizeof(value), "%s", lifecycle_uci_name(state->lifecycle));
    if (!uci_set_path(ctx, "aircnms.onboarding.lifecycle", value)) goto out;
    snprintf(value, sizeof(value), "%d", state->operational_once ? 1 : 0);
    if (!uci_set_path(ctx, "aircnms.onboarding.operational_once", value)) goto out;
    snprintf(value, sizeof(value), "%llu", (unsigned long long)state->desired_revision);
    if (!uci_set_path(ctx, "aircnms.onboarding.desired_revision", value)) goto out;
    snprintf(value, sizeof(value), "%llu", (unsigned long long)state->applied_revision);
    if (!uci_set_path(ctx, "aircnms.onboarding.applied_revision", value)) goto out;
    if (!uci_set_path(ctx, "aircnms.onboarding.active_attempt_id", state->attempt_id)) goto out;
    if (!uci_set_path(ctx, "aircnms.onboarding.active_config_job_id", state->config_job_id)) goto out;
    ok = uci_commit(ctx, &pkg, false) == UCI_OK;
out:
    if (pkg) uci_unload(ctx, pkg);
    if (ctx) uci_free_context(ctx);
    return ok;
}
