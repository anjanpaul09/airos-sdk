#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <jansson.h>
#include "cgw.h"
#include "log.h"
#include "memutil.h"
#include "os_nif.h"
#include "cgw_state_mgr.h"

#define UCI_BUF_LEN 128
#define DEVICE_CHECK_URL "https://api.cloud.netstream.net.in/api/device_registration/v1/devices-check"

typedef struct {
    char *memory;
    size_t size;
} response_buffer_t;

typedef struct {
    char cloudStatus[32];
    char deviceId[64];
    int deviceId_present;
} device_check_result_t;


/* CURL response callback */
static size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp)
{
    size_t realsize = size * nmemb;
    response_buffer_t *mem = (response_buffer_t *)userp;

    char *ptr = realloc(mem->memory, mem->size + realsize + 1);
    if(ptr == NULL)
        return 0;

    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, realsize);

    mem->size += realsize;
    mem->memory[mem->size] = '\0';

    return realsize;
}


/* Perform HTTP POST request */
static char *post_device_check(const char *json_payload)
{
    CURL *curl;
    CURLcode res;

    response_buffer_t chunk;
    chunk.memory = malloc(1);
    chunk.size = 0;

    struct curl_slist *headers = NULL;

    curl = curl_easy_init();
    if(!curl)
        return NULL;

    headers = curl_slist_append(headers, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, DEVICE_CHECK_URL);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_payload);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

    res = curl_easy_perform(curl);

    if(res != CURLE_OK) {
        fprintf(stderr, "curl error: %s\n", curl_easy_strerror(res));
        free(chunk.memory);
        chunk.memory = NULL;
    }

    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);

    return chunk.memory;
}


/* Parse API JSON response */
static int parse_device_check_response(const char *response,
                                       device_check_result_t *result)
{
    json_error_t error;

    json_t *root = json_loads(response, 0, &error);
    if(!root)
        return -1;

    json_t *status = json_object_get(root, "cloudStatus");
    json_t *deviceid = json_object_get(root, "Deviceid");

    if(json_is_string(status)) {
        strncpy(result->cloudStatus,
                json_string_value(status),
                sizeof(result->cloudStatus) - 1);
        result->cloudStatus[sizeof(result->cloudStatus)-1] = '\0';
    } else {
        result->cloudStatus[0] = '\0';
    }

    if(json_is_string(deviceid)) {
        strncpy(result->deviceId,
                json_string_value(deviceid),
                sizeof(result->deviceId) - 1);
        result->deviceId[sizeof(result->deviceId)-1] = '\0';
        result->deviceId_present = 1;
    } else {
        result->deviceId[0] = '\0';
        result->deviceId_present = 0;
    }

    json_decref(root);
    return 0;
}


/*
 * Public function you can call from your main()
 *
 * Example:
 *
 * device_check_result_t res;
 * int ret = device_check_request("ABC123", &res);
 */
int device_check_request(const char *serial_number,
                         device_check_result_t *result)
{
    json_t *root;
    char *json_payload;
    char *response;

    root = json_object();
    json_object_set_new(root, "serial_number", json_string(serial_number));

    json_payload = json_dumps(root, 0);
    json_decref(root);

    if(!json_payload)
        return -1;

    response = post_device_check(json_payload);

    free(json_payload);

    if(!response)
        return -1;

    int ret = parse_device_check_response(response, result);

    free(response);

    return ret;
}

static void send_device_delete()
{
    char json_payload[256];
    int len;

    len = snprintf(json_payload, sizeof(json_payload),
                   "{\"cmd\":\"device_deleted\"}");

    if (len > 0 && len < sizeof(json_payload))
        cgw_send_msg_to_dm(json_payload, len, NULL);
}

void cgw_check_cloud_reg_status()
{
    device_check_result_t res;

    char buf[UCI_BUF_LEN];
    size_t len = 0;

    memset(buf, 0, sizeof(buf));
    cmd_buf("uci get aircnms.@aircnms[0].serial_num", buf, (size_t)UCI_BUF_LEN);
    len = strlen(buf);

    if (len == 0) {
        LOGI("%s: No UCI serial number found", __func__);
        return;
    }
    /* remove newline if present */
    buf[strcspn(buf, "\r\n")] = 0;

    if (device_check_request(buf, &res) == 0) {
        printf("Cloud Status: %s\n", res.cloudStatus);

        if (strcmp(res.cloudStatus, "Not-Found") == 0 && cgw_check_valid_device_id()) { 
            // device not found on cloud and still device id exist
            send_device_delete();
        } else if (strcmp(res.cloudStatus, "Registered") == 0) {

            if (res.deviceId[0] != '\0' && cgw_check_valid_device_id()) {
                // device Registered and deviceid does not match from cloud
                memset(buf, 0, sizeof(buf));
                cmd_buf("uci get aircnms.@aircnms[0].device_id", buf, (size_t)UCI_BUF_LEN);
                len = strlen(buf);

                if (len == 0) {
                    LOGI("%s: No UCI serial number found", __func__);
                    return;
                }
                /* remove newline if present */
                buf[strcspn(buf, "\r\n")] = 0;

                printf("Device ID: %s\n", res.deviceId);
                if (strcmp(res.deviceId, buf) != 0) {
                    send_device_delete();
                }
            }
        }
    }

}

static ev_timer reg_timer;

static void timer_cb(EV_P_ ev_timer *w, int revents)
{
    printf("Checking Registration Status on Cloud\n");

    cgw_check_cloud_reg_status();
}

void cgw_start_device_reg_monitor()
{
    struct ev_loop *loop = EV_DEFAULT;

    ev_timer_init(&reg_timer, timer_cb, 0.0, 7200.0);
    //ev_timer_init(&reg_timer, timer_cb, 0.0, 15.0);
    ev_timer_start(loop, &reg_timer);
}

void cgw_stop_device_reg_monitor()
{
    struct ev_loop *loop = EV_DEFAULT;

    if (ev_is_active(&reg_timer))
        ev_timer_stop(loop, &reg_timer);
}
