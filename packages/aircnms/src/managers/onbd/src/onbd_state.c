#include "onbd.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
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

static void onbd_evaluate_connectivity(onbd_state_t *state)
{
    if (!state->ubus_available || !state->network_available) {
        state->connectivity = ONBD_CONN_INITIALIZING;
        onbd_set_reason(state, "DEPENDENCY_NOT_READY");
        return;
    }

    if (!state->carrier_available) {
        state->connectivity = ONBD_CONN_NO_LINK;
        onbd_set_reason(state, "NO_CARRIER");
        return;
    }

    if (!state->management_ip_available) {
        if (state->dhcp_retry_count >= ONBD_DHCP_RETRY_LIMIT) {
            state->connectivity = ONBD_CONN_DHCP_FAILED;
            onbd_set_reason(state, "DHCP_TIMEOUT");
        } else {
            state->connectivity = ONBD_CONN_DHCP_WAIT;
            onbd_set_reason(state, "MANAGEMENT_IP_PENDING");
        }
        return;
    }

    if (!state->default_route_available) {
        state->connectivity = ONBD_CONN_NO_DEFAULT_ROUTE;
        onbd_set_reason(state, "NO_DEFAULT_ROUTE");
        return;
    }

    if (!state->gateway_reachable) {
        state->connectivity = ONBD_CONN_NO_DEFAULT_ROUTE;
        onbd_set_reason(state, "GATEWAY_UNREACHABLE");
        return;
    }

    if (!state->dns_available) {
        state->connectivity = ONBD_CONN_DNS_FAILED;
        onbd_set_reason(state, "DNS_NOT_CONFIGURED");
        return;
    }

    if (!state->dns_resolved) {
        state->connectivity = ONBD_CONN_DNS_FAILED;
        onbd_set_reason(state, "DNS_RESOLUTION_FAILED");
        return;
    }

    if (!state->internet_available) {
        state->connectivity = ONBD_CONN_INTERNET_UNREACHABLE;
        onbd_set_reason(state, "INTERNET_PROBE_FAILED");
        return;
    }

    if (!state->cloud_available) {
        state->connectivity = ONBD_CONN_CLOUD_UNREACHABLE;
        onbd_set_reason(state, "CLOUD_HTTPS_FAILED");
        return;
    }

    if (!state->stored_identity_valid) {
        state->connectivity = ONBD_CONN_ONLINE;
        onbd_set_reason(state, "NETWORK_READY_NOT_ENROLLED");
        return;
    }

    if (!state->cgwd_available) {
        state->connectivity = ONBD_CONN_CLOUD_UNREACHABLE;
        onbd_set_reason(state, "CGWD_UNAVAILABLE");
        return;
    }

    if (!state->legacy_online) {
        state->connectivity = ONBD_CONN_MQTT_DISCONNECTED;
        onbd_set_reason(state, "LEGACY_ONLINE_FALSE");
        return;
    }

    state->connectivity = ONBD_CONN_ONLINE;
    onbd_set_reason(state, "LEGACY_ONLINE_TRUE");
}

static void onbd_fsm_lifecycle(onbd_state_t *state)
{
    /* Transition evaluation based on current lifecycle state */
    switch (state->lifecycle) {
    case ONBD_LIFECYCLE_INIT:
        if (state->stored_identity_valid) {
            state->lifecycle = ONBD_LIFECYCLE_ENROLLED;
        } else if (state->fallback_active) {
            state->lifecycle = ONBD_LIFECYCLE_RECOVERY;
        }
        break;

    case ONBD_LIFECYCLE_ENROLLING:
        if (state->stored_identity_valid) {
            state->lifecycle = ONBD_LIFECYCLE_ENROLLED;
        }
        break;

    case ONBD_LIFECYCLE_ENROLLED:
        if (!state->stored_identity_valid) {
            state->lifecycle = ONBD_LIFECYCLE_INIT;
        } else if (onbd_operational_ready(state)) {
            state->operational_once = true;
            state->lifecycle = ONBD_LIFECYCLE_OPERATIONAL;
        } else if (state->fallback_active) {
            state->lifecycle = ONBD_LIFECYCLE_RECOVERY;
        }
        break;

    case ONBD_LIFECYCLE_OPERATIONAL:
        state->operational_once = true;
        state->fallback_active = false;
        break;

    case ONBD_LIFECYCLE_RECOVERY:
        if (state->operational_once) {
            state->fallback_active = false;
            state->lifecycle = ONBD_LIFECYCLE_OPERATIONAL;
        } else if (!state->fallback_active) {
            state->lifecycle = state->stored_identity_valid ? ONBD_LIFECYCLE_ENROLLED : ONBD_LIFECYCLE_INIT;
        }
        break;

    default:
        state->lifecycle = ONBD_LIFECYCLE_INIT;
        break;
    }

    if (state->operational_once) {
        state->lifecycle = ONBD_LIFECYCLE_OPERATIONAL;
        state->fallback_active = false;
    }
}

void onbd_derive_shadow_state(onbd_state_t *state)
{
    if (!state)
        return;

    /* 1. Evaluate Connectivity Pipeline */
    onbd_evaluate_connectivity(state);

    /* 2. Recovery Debounce Counters */
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

    /* 3. Evaluate Lifecycle State Machine */
    onbd_fsm_lifecycle(state);

    /* 4. Provisioned AP Wi-Fi suppression during cloud outage (60s grace period) */
    if (state->connectivity == ONBD_CONN_ONLINE) {
        state->cloud_down_ticks = 0;
        if (state->wifi_suppressed) {
            state->wifi_suppressed = false;
            system("/usr/sbin/air_wifi_suppress.sh restore >/dev/null 2>&1");
        }
    } else if (state->operational_once) {
        if (state->cloud_down_ticks < UINT32_MAX)
            state->cloud_down_ticks++;
        if (state->cloud_down_ticks >= ONBD_CLOUD_GRACE_TICKS && !state->wifi_suppressed) {
            state->wifi_suppressed = true;
            system("/usr/sbin/air_wifi_suppress.sh suppress >/dev/null 2>&1");
        }
    }
}

const char *onbd_visible_state(const onbd_state_t *state)
{
    if (!state)
        return "UNKNOWN";

    /* Priority 1: Configuration in progress or rollback */
    switch (state->configuration) {
    case ONBD_CONFIG_ROLLING_BACK: return "ROLLBACK";
    case ONBD_CONFIG_FAILED:       return "CONFIG_FAILED";
    case ONBD_CONFIG_APPLYING:     return "CONFIG_APPLYING";
    case ONBD_CONFIG_VERIFYING:    return "CONFIG_VERIFYING";
    case ONBD_CONFIG_QUEUED:
    case ONBD_CONFIG_DOWNLOADING:  return "CONFIG_QUEUED";
    default:                       break;
    }

    /* Priority 2: Operational AP */
    if (state->operational_once && state->lifecycle == ONBD_LIFECYCLE_OPERATIONAL)
        return "OPERATIONAL";

    /* Priority 3: Claim / Enrollment Required */
    if (!strcmp(state->reason_code, "PENDING_CLAIM") ||
        !strcmp(state->reason_code, "CLAIM_REQUIRED") ||
        !strcmp(state->reason_code, "UNKNOWN_DEVICE") ||
        !strcmp(state->reason_code, "NETWORK_READY_NOT_ENROLLED"))
        return "CLAIM_REQUIRED";

    /* Priority 4: Connectivity Pipeline Failures */
    switch (state->connectivity) {
    case ONBD_CONN_INITIALIZING:         return "INITIALIZING";
    case ONBD_CONN_NO_LINK:              return "NO_LINK";
    case ONBD_CONN_DHCP_WAIT:            return "DHCP_WAIT";
    case ONBD_CONN_DHCP_FAILED:          return "DHCP_FAILED";
    case ONBD_CONN_NO_DEFAULT_ROUTE:     return "NO_DEFAULT_ROUTE";
    case ONBD_CONN_DNS_FAILED:           return "DNS_FAILED";
    case ONBD_CONN_INTERNET_UNREACHABLE: return "INTERNET_UNREACHABLE";
    case ONBD_CONN_CLOUD_UNREACHABLE:    return "CLOUD_UNREACHABLE";
    case ONBD_CONN_MQTT_DISCONNECTED:    return "MQTT_DISCONNECTED";
    case ONBD_CONN_ONLINE:               break;
    default:                             break;
    }

    /* Priority 5: Lifecycle Fallbacks */
    switch (state->lifecycle) {
    case ONBD_LIFECYCLE_ENROLLING:
        return "CLOUD_CONNECTING";
    case ONBD_LIFECYCLE_ENROLLED:
        return state->connectivity == ONBD_CONN_ONLINE ? "ENROLLED" : "OPERATIONAL_DEGRADED";
    case ONBD_LIFECYCLE_OPERATIONAL:
        return state->connectivity == ONBD_CONN_ONLINE ? "OPERATIONAL" : "OPERATIONAL_DEGRADED";
    case ONBD_LIFECYCLE_RECOVERY:
        return "RECOVERY";
    case ONBD_LIFECYCLE_INIT:
    default:
        return onbd_lifecycle_name(state->lifecycle);
    }
}
