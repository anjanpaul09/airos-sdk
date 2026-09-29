#ifndef ONBD_H_INCLUDED
#define ONBD_H_INCLUDED

#include <stdbool.h>
#include <stdint.h>
struct ev_loop;
struct ubus_context;

#define ONBD_SCHEMA "air.onboarding.v1"
#define ONBD_RUNTIME_DIR "/run/air-onbd"
#define ONBD_STATE_FILE ONBD_RUNTIME_DIR "/state.json"
#define ONBD_REASON_LEN 64
#define ONBD_ID_LEN 64
#define ONBD_HOST_LEN 128
#define ONBD_RECOVERY_BAD_LIMIT 3
#define ONBD_RECOVERY_GOOD_LIMIT 2

typedef enum {
    ONBD_LIFECYCLE_INIT = 0,
    ONBD_LIFECYCLE_ENROLLING,
    ONBD_LIFECYCLE_ENROLLED,
    ONBD_LIFECYCLE_OPERATIONAL,
    ONBD_LIFECYCLE_RECOVERY
} onbd_lifecycle_t;

typedef enum {
    ONBD_CONN_INITIALIZING = 0,
    ONBD_CONN_NO_LINK,
    ONBD_CONN_DHCP_WAIT,
    ONBD_CONN_DHCP_FAILED,
    ONBD_CONN_NO_DEFAULT_ROUTE,
    ONBD_CONN_DNS_FAILED,
    ONBD_CONN_INTERNET_UNREACHABLE,
    ONBD_CONN_CLOUD_UNREACHABLE,
    ONBD_CONN_MQTT_DISCONNECTED,
    ONBD_CONN_ONLINE
} onbd_connectivity_t;

typedef enum {
    ONBD_CONFIG_NONE = 0,
    ONBD_CONFIG_DOWNLOADING,
    ONBD_CONFIG_QUEUED,
    ONBD_CONFIG_APPLYING,
    ONBD_CONFIG_VERIFYING,
    ONBD_CONFIG_APPLIED,
    ONBD_CONFIG_FAILED,
    ONBD_CONFIG_ROLLING_BACK,
    ONBD_CONFIG_ROLLED_BACK,
    ONBD_CONFIG_SUPERSEDED
} onbd_config_state_t;

typedef struct {
    onbd_lifecycle_t lifecycle;
    onbd_connectivity_t connectivity;
    onbd_config_state_t configuration;
    bool enabled;
    bool shadow_mode;
    bool recovery_apply_enabled;
    bool operational_once;
    bool recovery_ssid_enabled;
    bool ubus_available;
    bool network_available;
    bool cgwd_available;
    bool netconfd_available;
    bool stored_identity_valid;
    bool legacy_online;
    bool carrier_available;
    bool management_ip_available;
    bool default_route_available;
    bool dns_available;
    bool dns_resolved;
    bool internet_available;
    bool gateway_reachable;
    bool cloud_available;
    bool fallback_active;
    uint32_t dhcp_wait_ticks;
    uint32_t dhcp_retry_count;
    uint32_t recovery_bad_ticks;
    uint32_t recovery_good_ticks;
    uint64_t desired_revision;
    uint64_t applied_revision;
    uint64_t updated_monotonic_ms;
    char reason_code[ONBD_REASON_LEN];
    char attempt_id[ONBD_ID_LEN];
    char config_job_id[ONBD_ID_LEN];
    char default_gateway[ONBD_HOST_LEN];
    char cloud_host[ONBD_HOST_LEN];
} onbd_state_t;

extern onbd_state_t g_onbd_state;

const char *onbd_lifecycle_name(onbd_lifecycle_t value);
const char *onbd_connectivity_name(onbd_connectivity_t value);
const char *onbd_config_name(onbd_config_state_t value);
const char *onbd_visible_state(const onbd_state_t *state);
bool onbd_valid_device_id(const char *device_id);
void onbd_derive_shadow_state(onbd_state_t *state);
void onbd_set_reason(onbd_state_t *state, const char *reason);

bool onbd_persist_init(onbd_state_t *state);
bool onbd_persist_runtime_state(const onbd_state_t *state);
bool onbd_persist_checkpoint(const onbd_state_t *state);
void onbd_observe(struct ubus_context *ctx, onbd_state_t *state);
void onbd_probe_network(onbd_state_t *state);
void onbd_recovery_apply(const onbd_state_t *state);

bool onbd_ubus_init(struct ev_loop *loop);
void onbd_ubus_cleanup(void);
struct ubus_context *onbd_ubus_context(void);

#endif
