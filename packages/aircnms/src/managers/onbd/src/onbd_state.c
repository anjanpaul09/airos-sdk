#include "onbd.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

const char *onbd_lifecycle_name(onbd_lifecycle_t value)
{
    static const char *names[] = {"INIT", "ENROLLING", "ENROLLED", "OPERATIONAL", "RECOVERY"};
    return value >= ONBD_LIFECYCLE_INIT && value <= ONBD_LIFECYCLE_RECOVERY ? names[value] : "UNKNOWN";
}

const char *onbd_connectivity_name(onbd_connectivity_t value)
{
    static const char *names[] = {
        "INITIALIZING", "NO_LINK", "DHCP_WAIT", "DHCP_FAILED",
        "NO_DEFAULT_ROUTE", "DNS_FAILED", "INTERNET_UNREACHABLE",
        "CLOUD_UNREACHABLE", "MQTT_DISCONNECTED", "ONLINE"
    };
    return value >= ONBD_CONN_INITIALIZING && value <= ONBD_CONN_ONLINE ? names[value] : "UNKNOWN";
}

const char *onbd_config_name(onbd_config_state_t value)
{
    static const char *names[] = {
        "NONE", "DOWNLOADING", "QUEUED", "APPLYING", "VERIFYING",
        "APPLIED", "FAILED", "ROLLING_BACK", "ROLLED_BACK", "SUPERSEDED"
    };
    return value >= ONBD_CONFIG_NONE && value <= ONBD_CONFIG_SUPERSEDED ? names[value] : "UNKNOWN";
}

bool onbd_valid_device_id(const char *device_id)
{
    size_t i;
    if (!device_id || strlen(device_id) != 10 || strcmp(device_id, "XXXXXXXXXX") == 0)
        return false;
    for (i = 0; i < 10; i++)
        if (!isdigit((unsigned char)device_id[i]))
            return false;
    return true;
}

void onbd_set_reason(onbd_state_t *state, const char *reason)
{
    if (!state)
        return;
    snprintf(state->reason_code, sizeof(state->reason_code), "%s",
             reason ? reason : "UNKNOWN");
}

static bool onbd_recovery_candidate(onbd_connectivity_t connectivity)
{
    return connectivity != ONBD_CONN_ONLINE &&
        connectivity != ONBD_CONN_INITIALIZING &&
        connectivity != ONBD_CONN_DHCP_WAIT;
}

static bool onbd_config_in_progress(onbd_config_state_t configuration)
{
    return configuration == ONBD_CONFIG_DOWNLOADING ||
        configuration == ONBD_CONFIG_QUEUED ||
        configuration == ONBD_CONFIG_APPLYING ||
        configuration == ONBD_CONFIG_VERIFYING ||
        configuration == ONBD_CONFIG_ROLLING_BACK;
}

static bool onbd_operational_ready(const onbd_state_t *state)
{
    return state && state->stored_identity_valid && state->legacy_online &&
        state->connectivity == ONBD_CONN_ONLINE &&
        (state->configuration == ONBD_CONFIG_APPLIED || state->applied_revision > 0);
}

void onbd_derive_shadow_state(onbd_state_t *state)
{
    if (!state)
        return;

    if (!state->stored_identity_valid && state->lifecycle != ONBD_LIFECYCLE_ENROLLING)
        state->lifecycle = ONBD_LIFECYCLE_INIT;
    else if (state->stored_identity_valid && state->lifecycle == ONBD_LIFECYCLE_INIT)
        state->lifecycle = ONBD_LIFECYCLE_ENROLLED;

    if (!state->ubus_available || !state->network_available) {
        state->connectivity = ONBD_CONN_INITIALIZING;
        onbd_set_reason(state, "DEPENDENCY_NOT_READY");
    } else if (!state->carrier_available) {
        state->connectivity = ONBD_CONN_NO_LINK;
        onbd_set_reason(state, "NO_CARRIER");
    } else if (!state->management_ip_available) {
        if (state->dhcp_wait_ticks >= 6 && state->dhcp_retry_count >= 3) {
            state->connectivity = ONBD_CONN_DHCP_FAILED;
            onbd_set_reason(state, "DHCP_TIMEOUT");
        } else {
            state->connectivity = ONBD_CONN_DHCP_WAIT;
            onbd_set_reason(state, "MANAGEMENT_IP_PENDING");
        }
    } else if (!state->default_route_available) {
        state->connectivity = ONBD_CONN_NO_DEFAULT_ROUTE;
        onbd_set_reason(state, "NO_DEFAULT_ROUTE");
    } else if (!state->gateway_reachable) {
        state->connectivity = ONBD_CONN_NO_DEFAULT_ROUTE;
        onbd_set_reason(state, "GATEWAY_UNREACHABLE");
    } else if (!state->dns_available) {
        state->connectivity = ONBD_CONN_DNS_FAILED;
        onbd_set_reason(state, "DNS_NOT_CONFIGURED");
    } else if (!state->dns_resolved) {
        state->connectivity = ONBD_CONN_DNS_FAILED;
        onbd_set_reason(state, "DNS_RESOLUTION_FAILED");
    } else if (!state->internet_available) {
        state->connectivity = ONBD_CONN_INTERNET_UNREACHABLE;
        onbd_set_reason(state, "INTERNET_PROBE_FAILED");
    } else if (!state->cloud_available) {
        state->connectivity = ONBD_CONN_CLOUD_UNREACHABLE;
        onbd_set_reason(state, "CLOUD_HTTPS_FAILED");
    } else if (!state->stored_identity_valid) {
        state->connectivity = ONBD_CONN_ONLINE;
        onbd_set_reason(state, "NETWORK_READY_NOT_ENROLLED");
    } else if (!state->cgwd_available) {
        state->connectivity = ONBD_CONN_CLOUD_UNREACHABLE;
        onbd_set_reason(state, "CGWD_UNAVAILABLE");
    } else if (!state->legacy_online) {
        state->connectivity = ONBD_CONN_MQTT_DISCONNECTED;
        onbd_set_reason(state, "LEGACY_ONLINE_FALSE");
    } else {
        state->connectivity = ONBD_CONN_ONLINE;
        onbd_set_reason(state, "LEGACY_ONLINE_TRUE");
    }

    if (onbd_config_in_progress(state->configuration)) {
        state->recovery_bad_ticks = 0;
        state->recovery_good_ticks = 0;
    } else if (onbd_recovery_candidate(state->connectivity)) {
        if (state->recovery_bad_ticks < UINT32_MAX)
            state->recovery_bad_ticks++;
        state->recovery_good_ticks = 0;
    } else if (state->connectivity == ONBD_CONN_ONLINE) {
        if (state->recovery_good_ticks < UINT32_MAX)
            state->recovery_good_ticks++;
        state->recovery_bad_ticks = 0;
    } else {
        state->recovery_good_ticks = 0;
        state->recovery_bad_ticks = 0;
    }

    state->fallback_active = state->recovery_ssid_enabled &&
        !onbd_config_in_progress(state->configuration) &&
        ((onbd_recovery_candidate(state->connectivity) &&
          state->recovery_bad_ticks >= ONBD_RECOVERY_BAD_LIMIT) ||
         (state->fallback_active && state->connectivity == ONBD_CONN_ONLINE &&
          state->recovery_good_ticks < ONBD_RECOVERY_GOOD_LIMIT));

    if (state->config_job_id[0] == '\0' && state->configuration != ONBD_CONFIG_APPLIED)
        state->configuration = ONBD_CONFIG_NONE;

    if (onbd_operational_ready(state)) {
        state->operational_once = true;
        state->lifecycle = ONBD_LIFECYCLE_OPERATIONAL;
    } else if (state->operational_once) {
        state->fallback_active = false;
        state->lifecycle = ONBD_LIFECYCLE_OPERATIONAL;
    } else if (state->fallback_active && !state->stored_identity_valid) {
        state->lifecycle = ONBD_LIFECYCLE_RECOVERY;
    } else if (state->stored_identity_valid && state->lifecycle != ONBD_LIFECYCLE_ENROLLING) {
        state->lifecycle = ONBD_LIFECYCLE_ENROLLED;
    }
}

const char *onbd_visible_state(const onbd_state_t *state)
{
    if (!state)
        return "UNKNOWN";
    if (state->operational_once && state->lifecycle == ONBD_LIFECYCLE_OPERATIONAL)
        return "OPERATIONAL";
    if (state->configuration == ONBD_CONFIG_ROLLING_BACK)
        return "ROLLBACK";
    if (state->configuration == ONBD_CONFIG_FAILED)
        return "CONFIG_FAILED";
    if (state->configuration == ONBD_CONFIG_APPLYING)
        return "CONFIG_APPLYING";
    if (state->configuration == ONBD_CONFIG_VERIFYING)
        return "CONFIG_VERIFYING";
    if (state->configuration == ONBD_CONFIG_QUEUED)
        return "CONFIG_QUEUED";
    if (state->lifecycle == ONBD_LIFECYCLE_OPERATIONAL)
        return state->connectivity == ONBD_CONN_ONLINE ? "OPERATIONAL" : "OPERATIONAL_DEGRADED";
    if (!strcmp(state->reason_code, "PENDING_CLAIM")) return "CLAIM_REQUIRED";
    if (!strcmp(state->reason_code, "UNKNOWN_DEVICE")) return "UNKNOWN_DEVICE";
    if (state->connectivity == ONBD_CONN_INITIALIZING) return "INITIALIZING";
    if (state->connectivity == ONBD_CONN_NO_LINK) return "NO_LINK";
    if (state->connectivity == ONBD_CONN_DHCP_WAIT) return "DHCP_WAIT";
    if (state->connectivity == ONBD_CONN_DHCP_FAILED) return "DHCP_FAILED";
    if (state->connectivity == ONBD_CONN_NO_DEFAULT_ROUTE) return "NO_DEFAULT_ROUTE";
    if (state->connectivity == ONBD_CONN_DNS_FAILED) return "DNS_FAILED";
    if (state->connectivity == ONBD_CONN_INTERNET_UNREACHABLE) return "INTERNET_UNREACHABLE";
    if (state->connectivity == ONBD_CONN_CLOUD_UNREACHABLE) return "CLOUD_UNREACHABLE";
    if (state->connectivity == ONBD_CONN_MQTT_DISCONNECTED) return "MQTT_DISCONNECTED";
    if (state->lifecycle == ONBD_LIFECYCLE_ENROLLED)
        return "ENROLLED";
    return onbd_lifecycle_name(state->lifecycle);
}
