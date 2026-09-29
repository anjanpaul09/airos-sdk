#include <assert.h>
#include <stdio.h>
#include "cgw_registration_result.h"

static void expect(cgw_registration_result_t want, long status, int transport, const char *body)
{
    cgw_registration_result_t got = cgw_classify_registration_result(status, transport, body);
    if (got != want) {
        fprintf(stderr, "status=%ld want=%s got=%s\n", status,
                cgw_registration_result_string(want), cgw_registration_result_string(got));
        assert(got == want);
    }
}

int main(void)
{
    expect(CGW_REG_RESULT_TEMPORARY_FAILURE, 0, 0, NULL);
    expect(CGW_REG_RESULT_PENDING_CLAIM, 200, 1, "{\"code\":\"PENDING_CLAIM\",\"retry_after\":30}");
    expect(CGW_REG_RESULT_UNKNOWN_DEVICE, 404, 1, "{\"code\":\"UNKNOWN_DEVICE\"}");
    expect(CGW_REG_RESULT_MAC_MISMATCH, 409, 1, "{\"code\":\"MAC_MISMATCH\"}");
    expect(CGW_REG_RESULT_REJECTED, 403, 1, "{\"code\":\"REJECTED\"}");
    expect(CGW_REG_RESULT_REJECTED, 401, 1, "{}");
    expect(CGW_REG_RESULT_TEMPORARY_FAILURE, 429, 1, "{}");
    expect(CGW_REG_RESULT_TEMPORARY_FAILURE, 503, 1, "not-json");
    expect(CGW_REG_RESULT_PERMANENT_FAILURE, 400, 1, "{\"code\":\"INVALID_REQUEST\"}");
    expect(CGW_REG_RESULT_PERMANENT_FAILURE, 200, 1, "{}");
    expect(CGW_REG_RESULT_PERMANENT_FAILURE, 200, 1, "{} trailing");
    expect(CGW_REG_RESULT_PERMANENT_FAILURE, 200, 1,
           "{\"message\":\"deviceId username password resourceKey configData\"}");
    expect(CGW_REG_RESULT_PERMANENT_FAILURE, 200, 1,
           "{\"deviceId\":\"1\",\"username\":\"u\",\"password\":\"p\","
           "\"resourceKey\":\"k\",\"configData\":[]}");
    expect(CGW_REG_RESULT_PERMANENT_FAILURE, 200, 1, "{\"code\":\"FUTURE_UNKNOWN_CODE\"}");
    expect(CGW_REG_RESULT_PERMANENT_FAILURE, 200, 1, "{\"code\":\"SUCCESS\",\"code\":\"PENDING_CLAIM\"}");
    expect(CGW_REG_RESULT_SUCCESS, 200, 1,
           "{\"deviceId\":\"1\",\"username\":\"u\",\"password\":\"p\","
           "\"resourceKey\":\"k\",\"configData\":{\"vif\":{\"vifList\":[{\"status\":1}]}},"
           "\"statsTopic\":{\"status\":\"dev/to/cloud/status\"}}");
    expect(CGW_REG_RESULT_SUCCESS, 200, 1, "{\"code\":\"SUCCESS\"}");
    expect(CGW_REG_RESULT_CANCELLED, 200, 1, "{\"code\":\"CANCELLED\"}");
    puts("registration result classifier: PASS");
    return 0;
}
