#ifndef CGW_REGISTRATION_ATTEMPT_H
#define CGW_REGISTRATION_ATTEMPT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "cgw_registration_result.h"

#define CGW_ATTEMPT_ID_LEN 80

typedef enum {
    CGW_ATTEMPT_IDLE = 0,
    CGW_ATTEMPT_PREPARING,
    CGW_ATTEMPT_HTTP,
    CGW_ATTEMPT_APPLYING_CONFIG,
    CGW_ATTEMPT_COMMITTING,
    CGW_ATTEMPT_COMPLETE,
    CGW_ATTEMPT_CANCELLED
} cgw_attempt_state_t;

typedef enum {
    CGW_CANCEL_ACCEPTED = 0,
    CGW_CANCEL_NOT_FOUND,
    CGW_CANCEL_TOO_LATE
} cgw_cancel_result_t;

typedef struct {
    char attempt_id[CGW_ATTEMPT_ID_LEN];
    cgw_attempt_state_t state;
    cgw_registration_result_t result;
    uint64_t generation;
} cgw_registration_attempt_snapshot_t;

bool cgw_registration_attempt_begin(char *attempt_id, size_t attempt_id_size,
                                    bool *reused);
bool cgw_registration_attempt_transition(const char *attempt_id,
                                         cgw_attempt_state_t expected,
                                         cgw_attempt_state_t next);
bool cgw_registration_attempt_complete(const char *attempt_id,
                                       cgw_registration_result_t result);
cgw_cancel_result_t cgw_registration_attempt_cancel(const char *attempt_id);
bool cgw_registration_attempt_is_running(const char *attempt_id);
bool cgw_registration_attempt_is_cancellable(const char *attempt_id);
void cgw_registration_attempt_snapshot(cgw_registration_attempt_snapshot_t *snapshot);
const char *cgw_attempt_state_string(cgw_attempt_state_t state);
const char *cgw_cancel_result_string(cgw_cancel_result_t result);
void cgw_registration_attempt_reset_for_test(void);

#endif
