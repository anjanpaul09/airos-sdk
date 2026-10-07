#ifndef TARGET_PLAN_H_INCLUDED
#define TARGET_PLAN_H_INCLUDED

#include <stdbool.h>
#include <stdint.h>
#include "radio_vif.h"

#define TARGET_RADIO_NONE  0U
#define TARGET_RADIO_WIFI0 (1U << 0)
#define TARGET_RADIO_WIFI1 (1U << 1)

#define TARGET_MAX_DELTAS  32
#define TARGET_MAX_RADIOS  2

typedef enum {
    TARGET_APPLY_NONE = 0,
    TARGET_APPLY_LIVE,
    TARGET_APPLY_VIF_RECONCILE,
    TARGET_APPLY_RADIO_RECONCILE,
    TARGET_APPLY_FULL_RECOVERY,
    TARGET_APPLY_UNSUPPORTED
} target_apply_class_t;

typedef enum {
    TARGET_DELTA_NONE = 0,

    /* Tier 1: Live */
    TARGET_DELTA_CHANNEL,
    TARGET_DELTA_TXPOWER,

    /* Tier 2: VIF Lifecycle */
    TARGET_DELTA_VIF_ADD,
    TARGET_DELTA_VIF_MODIFY,
    TARGET_DELTA_VIF_DISABLE,
    TARGET_DELTA_VIF_REMOVE,

    /* Tier 3: Radio Reconcile */
    TARGET_DELTA_CHANNEL_WIDTH,
    TARGET_DELTA_HWMODE,
    TARGET_DELTA_COUNTRY,
    TARGET_DELTA_MAX_STA,
    TARGET_DELTA_RADIO_ENABLE,
    TARGET_DELTA_RADIO_DISABLE,

    /* Tier 4: Global Recovery */
    TARGET_DELTA_FULL_RECOVERY,

    /* Rejection Gate */
    TARGET_DELTA_UNKNOWN
} target_delta_type_t;

typedef struct {
    char                 object_name[32];   /* e.g. "wlan1", "wifi0" */
    target_delta_type_t  type;
    target_apply_class_t class;
    uint32_t             radio_mask;        /* TARGET_RADIO_WIFI0 or WIFI1 */

    char                 reason[64];        /* e.g. "SSID_CHANGE", "CSA_SWITCH" */
    bool                 client_disconnect_expected;

    char                 old_value[64];
    char                 new_value[64];
} target_delta_item_t;

typedef struct {
    target_delta_item_t deltas[TARGET_MAX_DELTAS];
    int                 num_deltas;

    uint32_t            reconf_radio_mask;     /* Radios needing wifi reconf */
    uint32_t            radio_disruptive_mask; /* Radios where client_disconnect_expected */
    bool                full_reload_required;  /* Explicit global reset */
    bool                unsupported_change;    /* Pre-validation safety gate */
    char                unsupported_reason[128];
} target_apply_plan_t;

/* Snapshot of current UCI wireless configuration in memory */
typedef struct {
    vif_record_t   vifs;
    radio_record_t radios;
} target_current_state_t;

/* UCI reader function prototypes implemented in uci_wireless.c */
int uci_get_radio_params(char *radio_name, struct airpro_mgr_wlan_radio_params *radio_params);
int uci_get_all_section_names(char *pkg, char *sec_type, struct airpro_mgr_get_all_uci_section_names *sec_arr_names);
int uci_get_vap_params(char *vap_name, struct airpro_mgr_wlan_vap_params *vap_params);
int execute_uci_command(const char *command, char *result, size_t result_size);

/*
 * target_read_current_state
 * I/O inspection: Reads current UCI wireless config into in-memory struct.
 * NEVER mutates hardware or configuration.
 */
int target_read_current_state(target_current_state_t *state);

/*
 * target_build_apply_plan
 * PURE FUNCTION: Compares current state against desired state and produces
 * a deterministic target_apply_plan_t.
 * Zero I/O, zero UCI writes, zero ubus calls, zero system() calls.
 */
int target_build_apply_plan(
    const target_current_state_t *current,
    const vif_record_t *desired_vifs,
    const radio_record_t *desired_radios,
    target_apply_plan_t *plan);

/* Structured logger for dry-run verification & telemetry */
void target_dump_apply_plan(const target_apply_plan_t *plan);

/*
 * target_execute_apply_plan_dryrun
 * Consumes target_apply_plan_t and logs the exact coalesced execution sequence
 * without mutating anything. Enforces ordering and radio coalescing rules.
 */
int target_execute_apply_plan_dryrun(const target_apply_plan_t *plan);

#define TARGET_VERIFY_INTERVAL_MS        250
#define TARGET_VERIFY_VIF_MS            15000
#define TARGET_VERIFY_RADIO_RECONF_MS  15000
#define TARGET_VERIFY_RADIO_ENABLE_MS  18000
#define TARGET_VERIFY_TIMEOUT_MS       15000

/* Execution context making ownership explicit across mutation staging and centralized apply */
typedef struct {
    const target_apply_plan_t *plan;
    bool scoped_apply_enabled;
} target_apply_ctx_t;

bool target_config_vif_set_scoped(vif_record_t *record, const target_apply_ctx_t *ctx);
bool target_config_radio_set_scoped(radio_record_t *record, const target_apply_ctx_t *ctx);
bool target_config_vif_post_apply(vif_record_t *record);

typedef enum {
    TARGET_EXEC_OK = 0,
    TARGET_EXEC_ERR_INVALID,
    TARGET_EXEC_ERR_CSA,
    TARGET_EXEC_ERR_TXPOWER,
    TARGET_EXEC_ERR_RECONF,
    TARGET_EXEC_ERR_VERIFY_TIMEOUT,
    TARGET_EXEC_ERR_VERIFY,
    TARGET_EXEC_ERR_UNSUPPORTED
} target_exec_status_t;

typedef struct {
    uint32_t             radio_mask;
    char                 radio_name[16];
    target_apply_class_t class;
    bool                 disconnect_expected;
    bool                 command_succeeded;
    bool                 verification_succeeded;
    int                  command_rc;
} target_radio_exec_result_t;

typedef struct {
    target_exec_status_t       status;
    char                       object[32];
    char                       stage[32];
    char                       reason[256];
    int                        command_rc;
    int                        num_radio_results;
    target_radio_exec_result_t radio_results[TARGET_MAX_RADIOS];
} target_exec_result_t;

typedef struct {
    int  freq;
    int  center_freq1;
    int  center_freq2;
    int  bandwidth;
    bool ht;
    bool vht;
    bool he;
} target_chan_spec_t;

/* Interface resolution helpers */
int target_get_radio_hostapd_iface(const char *radio, char *ifname, size_t len);
int target_get_radio_phy(const char *radio, char *phy, size_t len);
int target_build_chan_spec(const char *radio, int channel, target_chan_spec_t *spec);

/* Tier 1 Live apply primitives */
int target_apply_channel_live(const target_delta_item_t *delta, target_exec_result_t *result);
int target_apply_txpower_live(const target_delta_item_t *delta, target_exec_result_t *result);

/* Milestone 3B: Real scoped reconf and bounded runtime verification */
int target_wifi_reconf(const char *radio_name);
int target_resolve_vif_ifname(const char *section, char *ifname, size_t len);
bool target_verify_vif_state(const target_delta_item_t *delta);
bool target_verify_radio_state(const target_delta_item_t *delta);
int target_verify_radio_reconcile(const target_apply_plan_t *plan, const char *radio_name, uint32_t r_mask, target_exec_result_t *result);

/*
 * target_execute_apply_plan_live
 * Executes real Tier 1 live primitives and Tier 2/3 real scoped reconciliations
 * with bounded post-reconf runtime verification.
 */
int target_execute_apply_plan_live(const target_apply_plan_t *plan, target_exec_result_t *result);

/* Helper to map radio name string ("wifi0", "wifi1") to bitmask */
uint32_t target_radio_name_to_mask(const char *radio_name);

/* Helper to map apply class enum to human-readable string */
const char *target_apply_class_str(target_apply_class_t cls);

/* Helper to map delta type enum to human-readable string */
const char *target_delta_type_str(target_delta_type_t dt);

#endif /* TARGET_PLAN_H_INCLUDED */
