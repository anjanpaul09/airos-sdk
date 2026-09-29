#ifndef CGW_REGISTRATION_RESULT_H
#define CGW_REGISTRATION_RESULT_H

#include <stdbool.h>

typedef enum {
    CGW_REG_RESULT_SUCCESS = 0,
    CGW_REG_RESULT_PENDING_CLAIM,
    CGW_REG_RESULT_UNKNOWN_DEVICE,
    CGW_REG_RESULT_MAC_MISMATCH,
    CGW_REG_RESULT_REJECTED,
    CGW_REG_RESULT_TEMPORARY_FAILURE,
    CGW_REG_RESULT_PERMANENT_FAILURE,
    CGW_REG_RESULT_CANCELLED
} cgw_registration_result_t;

cgw_registration_result_t cgw_classify_registration_result(long http_status,
                                                            bool transport_ok,
                                                            const char *body);
const char *cgw_registration_result_string(cgw_registration_result_t result);

#endif
