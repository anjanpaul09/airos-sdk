#ifndef NETCONF_JOB_H
#define NETCONF_JOB_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define NETCONF_JOB_ID_LEN 64
#define NETCONF_JOB_HASH_LEN 72
#define NETCONF_JOB_REASON_LEN 64
#define NETCONF_JOB_LEDGER_SIZE 32

typedef enum {
    NETCONF_JOB_EMPTY = 0,
    NETCONF_JOB_QUEUED,
    NETCONF_JOB_APPLYING,
    NETCONF_JOB_APPLIED,
    NETCONF_JOB_FAILED,
    NETCONF_JOB_SUPERSEDED,
    NETCONF_JOB_CANCELLED
} netconf_job_state_t;

typedef struct {
    char job_id[NETCONF_JOB_ID_LEN];
    char config_hash[NETCONF_JOB_HASH_LEN];
    char reason_code[NETCONF_JOB_REASON_LEN];
    uint64_t revision; /* local AP sequence only */
    uint64_t generation;
    netconf_job_state_t state;
} netconf_job_snapshot_t;

void netconf_job_set_journal_path(const char *path);
void netconf_job_init(void);
bool netconf_job_journal_healthy(void);
bool netconf_job_recovery_required(void);
typedef enum {
    NETCONF_JOB_SUBMIT_ERROR = 0,
    NETCONF_JOB_SUBMIT_ACCEPTED,
    NETCONF_JOB_SUBMIT_DUPLICATE
} netconf_job_submit_result_t;

bool netconf_job_submit(const void *payload, size_t payload_len,
                        netconf_job_snapshot_t *snapshot, bool *duplicate);
netconf_job_submit_result_t netconf_job_submit_hash(
                        const void *payload, size_t payload_len,
                        const char *config_hash,
                        netconf_job_snapshot_t *snapshot);
bool netconf_job_transition(const char *job_id, netconf_job_state_t expected,
                            netconf_job_state_t next, const char *reason_code);
size_t netconf_job_supersede_older_queued(const char *current_job_id);
bool netconf_job_get(const char *job_id, netconf_job_snapshot_t *snapshot);
bool netconf_job_latest(netconf_job_snapshot_t *snapshot);
const char *netconf_job_state_string(netconf_job_state_t state);

/* Implemented by the ubus adapter; tests may provide a no-op stub. */
void netconf_ubus_emit_job(const netconf_job_snapshot_t *snapshot);

#endif
