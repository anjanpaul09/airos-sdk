#include <string.h>
#include <json-c/json.h>

#include "cgw_registration_result.h"

static cgw_registration_result_t result_from_code(const char *code)
{
    if (!code || !code[0])
        return CGW_REG_RESULT_PERMANENT_FAILURE;
    if (!strcmp(code, "SUCCESS") || !strcmp(code, "ENROLLED"))
        return CGW_REG_RESULT_SUCCESS;
    if (!strcmp(code, "PENDING_CLAIM"))
        return CGW_REG_RESULT_PENDING_CLAIM;
    if (!strcmp(code, "UNKNOWN_DEVICE") || !strcmp(code, "DEVICE_NOT_FOUND"))
        return CGW_REG_RESULT_UNKNOWN_DEVICE;
    if (!strcmp(code, "MAC_MISMATCH"))
        return CGW_REG_RESULT_MAC_MISMATCH;
    if (!strcmp(code, "REJECTED") || !strcmp(code, "FORBIDDEN") ||
        !strcmp(code, "UNAUTHORIZED"))
        return CGW_REG_RESULT_REJECTED;
    if (!strcmp(code, "TEMPORARY_FAILURE") || !strcmp(code, "RETRY_LATER") ||
        !strcmp(code, "SERVICE_UNAVAILABLE"))
        return CGW_REG_RESULT_TEMPORARY_FAILURE;
    if (!strcmp(code, "CANCELLED"))
        return CGW_REG_RESULT_CANCELLED;
    if (!strcmp(code, "PERMANENT_FAILURE") || !strcmp(code, "INVALID_REQUEST"))
        return CGW_REG_RESULT_PERMANENT_FAILURE;
    return CGW_REG_RESULT_PERMANENT_FAILURE;
}

static unsigned count_key(const char *body, const char *key)
{
    unsigned count = 0;
    size_t key_len = strlen(key);

    while (body && (body = strstr(body, key)) != NULL) {
        count++;
        body += key_len;
    }
    return count;
}

cgw_registration_result_t cgw_classify_registration_result(long http_status,
                                                            bool transport_ok,
                                                            const char *body)
{
    struct json_tokener *tok = NULL;
    struct json_object *root = NULL;
    struct json_object *value = NULL;
    const char *code = NULL;
    size_t body_len = body ? strlen(body) : 0;
    size_t parsed = 0;
    cgw_registration_result_t result = CGW_REG_RESULT_PERMANENT_FAILURE;
    bool valid_object = false;

    if (!transport_ok)
        return CGW_REG_RESULT_TEMPORARY_FAILURE;

    /* Duplicate decision keys are ambiguous and therefore fail closed. */
    if (body && count_key(body, "\"code\"") > 1)
        return CGW_REG_RESULT_PERMANENT_FAILURE;

    if (body_len > 0) {
        tok = json_tokener_new_ex(32);
        if (tok) {
            json_tokener_set_flags(tok, JSON_TOKENER_STRICT | JSON_TOKENER_VALIDATE_UTF8);
            root = json_tokener_parse_ex(tok, body, (int)body_len);
            parsed = json_tokener_get_parse_end(tok);
            while (parsed < body_len && (body[parsed] == ' ' || body[parsed] == '\t' ||
                                         body[parsed] == '\r' || body[parsed] == '\n'))
                parsed++;
            valid_object = root && json_tokener_get_error(tok) == json_tokener_success &&
                           parsed == body_len && json_object_is_type(root, json_type_object);
        }
    }

    if (valid_object) {
        if (json_object_object_get_ex(root, "code", &value) &&
            json_object_is_type(value, json_type_string))
            code = json_object_get_string(value);
        if (!code && json_object_object_get_ex(root, "status", &value) &&
            json_object_is_type(value, json_type_string))
            code = json_object_get_string(value);
        if (code) {
            result = result_from_code(code);
            goto out;
        }
    }

    if (http_status == 429 || http_status >= 500) {
        result = CGW_REG_RESULT_TEMPORARY_FAILURE;
        goto out;
    }
    if (http_status == 401 || http_status == 403) {
        result = CGW_REG_RESULT_REJECTED;
        goto out;
    }
    if (http_status < 200 || http_status >= 300 || !valid_object)
        goto out;

    /* Legacy success is accepted only with correctly typed required fields. */
    {
        static const char *required_strings[] = {
            "deviceId", "username", "password", "resourceKey"
        };
        size_t i;
        bool complete = true;

        for (i = 0; i < sizeof(required_strings) / sizeof(required_strings[0]); i++) {
            if (!json_object_object_get_ex(root, required_strings[i], &value) ||
                !json_object_is_type(value, json_type_string) ||
                !json_object_get_string(value)[0]) {
                complete = false;
                break;
            }
        }
        if (complete && json_object_object_get_ex(root, "configData", &value) &&
            json_object_is_type(value, json_type_object))
            result = CGW_REG_RESULT_SUCCESS;
    }

out:
    if (root)
        json_object_put(root);
    if (tok)
        json_tokener_free(tok);
    return result;
}

const char *cgw_registration_result_string(cgw_registration_result_t result)
{
    switch (result) {
        case CGW_REG_RESULT_SUCCESS: return "SUCCESS";
        case CGW_REG_RESULT_PENDING_CLAIM: return "PENDING_CLAIM";
        case CGW_REG_RESULT_UNKNOWN_DEVICE: return "UNKNOWN_DEVICE";
        case CGW_REG_RESULT_MAC_MISMATCH: return "MAC_MISMATCH";
        case CGW_REG_RESULT_REJECTED: return "REJECTED";
        case CGW_REG_RESULT_TEMPORARY_FAILURE: return "TEMPORARY_FAILURE";
        case CGW_REG_RESULT_PERMANENT_FAILURE: return "PERMANENT_FAILURE";
        case CGW_REG_RESULT_CANCELLED: return "CANCELLED";
        default: return "PERMANENT_FAILURE";
    }
}
