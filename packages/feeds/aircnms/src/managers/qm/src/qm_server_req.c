#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <stdbool.h>
#include <jansson.h>
#include <unistd.h>
#include <iconv.h>
#include <ctype.h>

#include "qm.h"
#include "log.h"
#include "memutil.h"
#include "cm_conn.h"
#include "os_nif.h"

#define MAX_RESPONSE_SIZE 8192  // Increase buffer size for larger responses
#define MAX_CLOUD_DEVICE_DISCOVERY_RETRIES 3
#define MAX_LAN_IP_RETRIES 3
#define UCI_BUF_LEN 256

qm_mqtt_topic_list qm_topic_lst;
stats_topic_t stats_topic;
extern air_device_t air_dev;

struct DeviceInfo {
    char serial_number[32];
    char mac_address[32];
    double alpn;
    int type;
};

void remove_substring(char *str, const char *sub) 
{
    char *pos;
    int len = strlen(sub);

    pos = strstr(str, sub);
    if (pos != NULL) {
        memmove(pos, pos + len, strlen(pos + len) + 1);
    }
}

bool qm_process_initial_data(char *data)
{
    char cmd[512];
    json_error_t error;
    json_t *root;

    root = json_loads(data, 0, &error);
    if (!root) {
        fprintf(stderr, "JSON parsing error at line %d: %s\n", error.line, error.text);
        return NULL;
    }
    cm_response_t res;
    int n_topic = 0;
    bool result = false;

    if (!root) {
        fprintf(stderr, "Error parsing JSON: %s\n", error.text);
        return false;
    }
    json_t *config_obj = json_object_get(root, "configData");

    const char *device_id = json_string_value(json_object_get(root, "deviceId"));
    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set aircnms.@aircnms[0].device_id=%s", device_id);
    system(cmd);
    
    const char *network_id = json_string_value(json_object_get(config_obj, "network"));
    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set aircnms.@aircnms[0].network_id=%s", network_id);
    system(cmd);

    const char *org_id = json_string_value(json_object_get(root, "orgId"));
    strcpy(air_dev.org_id, org_id);
    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set aircnms.@aircnms[0].org_id=%s", org_id);
    system(cmd);

    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set aircnms.@aircnms[0].online=1");
    system(cmd);

    //username    
    const char *username = json_string_value(json_object_get(root, "username"));
    strcpy(air_dev.username, username);
    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set aircnms.@aircnms[0].username=%s", username);
    system(cmd);
    //Password
    const char *resource_key = json_string_value(json_object_get(root, "resourceKey"));
    const char *password = json_string_value(json_object_get(root, "password")); 
    decrypt_aes(password, resource_key, air_dev.password);
    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set aircnms.@aircnms[0].password=%s", air_dev.password);
    system(cmd);

    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci commit aircnms");
    system(cmd);
    //parse topics
    json_t *deviceTopic = json_object_get(root, "deviceTopic");

    strcpy(qm_topic_lst.topic[n_topic], json_string_value(json_object_get(deviceTopic, "config")));
    n_topic++;

    strcpy(qm_topic_lst.topic[n_topic], json_string_value(json_object_get(deviceTopic, "cmd")));
    n_topic++;

    strcpy(qm_topic_lst.topic[n_topic], json_string_value(json_object_get(deviceTopic, "bwList")));
    n_topic++;

    strcpy(qm_topic_lst.topic[n_topic], json_string_value(json_object_get(deviceTopic, "rateLimit")));
    n_topic++;

    strcpy(qm_topic_lst.topic[n_topic], json_string_value(json_object_get(deviceTopic, "broadcast")));
    n_topic++;

    strcpy(qm_topic_lst.topic[n_topic], json_string_value(json_object_get(deviceTopic, "broadcastWithOrgId")));
    n_topic++;

    strcpy(qm_topic_lst.topic[n_topic], json_string_value(json_object_get(deviceTopic, "broadcastWithNetworkConfig")));
    n_topic++;

    strcpy(qm_topic_lst.topic[n_topic], json_string_value(json_object_get(deviceTopic, "broadcastWithNetworkBwList")));
    n_topic++;

    strcpy(qm_topic_lst.topic[n_topic], json_string_value(json_object_get(deviceTopic, "broadcastWithNetworkCmd")));
    n_topic++;

    qm_topic_lst.n_topic = n_topic;
    qm_add_topic_aircnms(&qm_topic_lst);

    //char *config_data = json_dumps(config_obj, JSON_ENSURE_ASCII);
    char *config_data = json_dumps(config_obj, 0);
    if (!config_data) {
        fprintf(stderr, "Error converting JSON to string\n");
        json_decref(config_obj);
        return false;
    }

    json_t *statsTopic = json_object_get(root, "statsTopic");
    strcpy(stats_topic.device, json_string_value(json_object_get(statsTopic, "device")));
    strcpy(stats_topic.vif, json_string_value(json_object_get(statsTopic, "vif")));
    strcpy(stats_topic.client, json_string_value(json_object_get(statsTopic, "client")));
    strcpy(stats_topic.neighbor, json_string_value(json_object_get(statsTopic, "neighbor")));
    strcpy(stats_topic.config, json_string_value(json_object_get(statsTopic, "config")));
    strcpy(stats_topic.cmdr, json_string_value(json_object_get(statsTopic, "cmdr")));
    qm_add_stats_topic_aircnms(&stats_topic);

    size_t config_size = strlen(config_data);
    result = cm_conn_send_stats(config_data, config_size, &res);

    json_decref(root);
    free(config_data);

    return result;
}

// Function to parse DeviceInfo struct to JSON string
char *parse_device_info_to_json_string(struct DeviceInfo device)
{
    char fw_version[UCI_BUF_LEN];
    int retry_count = 0;
    char ipaddr[32] = {0};
    os_ipaddr_t ip;
    json_t *json = json_object();
    if (!json) {
        fprintf(stderr, "Error creating JSON object\n");
        return NULL;
    }
    
    memset(fw_version, 0, sizeof(fw_version));
    get_fw_version(fw_version, UCI_BUF_LEN);

    json_object_set_new(json, "serial_number", json_string(device.serial_number));
    json_object_set_new(json, "mac", json_string(device.mac_address));
    json_object_set_new(json, "fw_info", json_string(fw_version));
    json_object_set_new(json, "hw_name", json_string("MTK7621"));
    json_object_set_new(json, "hw_version", json_string("1.0"));
    
    memset(ipaddr, 0, sizeof(ipaddr));

    while (retry_count < MAX_LAN_IP_RETRIES) {
        if (os_nif_ipaddr_get("br-lan", &ip)) {
            break;  
        } else {
            retry_count++;
            sleep(2);  
        }
    }

    sprintf(ipaddr, "%d.%d.%d.%d", ip.addr[0], ip.addr[1], ip.addr[2], ip.addr[3]);
    json_object_set_new(json, "mgmt_ip", json_string(ipaddr));
    
    memset(ipaddr, 0, sizeof(ipaddr));
    if (!get_public_ip(ipaddr)) {
        LOG(INFO, "Failed to retrieve public IP. Setting IP to 0.0.0.0\n");
        strcpy(ipaddr, "0.0.0.0");
    }

    json_object_set_new(json, "egress_ip", json_string(ipaddr));

    char *json_str = json_dumps(json, JSON_INDENT(4));
    if (!json_str) {
        fprintf(stderr, "Error converting JSON to string\n");
        json_decref(json);
        return NULL;
    }

    json_decref(json);

    return json_str;
}


void get_device_details(struct DeviceInfo *device) 
{
    char buf[UCI_BUF_LEN];
    size_t len;

    memset(buf, 0, sizeof(buf));
    cmd_buf("uci get aircnms.@aircnms[0].serial_num", buf, (size_t)UCI_BUF_LEN);
    len = strlen(buf);
    if (len == 0) {
        LOGI("%s: No uci found", __func__);
    }
    sscanf(buf, "%s", device->serial_number);

    memset(buf, 0, sizeof(buf));
    cmd_buf("uci get aircnms.@aircnms[0].macaddr", buf, (size_t)UCI_BUF_LEN);
    len = strlen(buf);
    if (len == 0)
    {
        LOGI("%s: No uci found", __func__);
    }
    sscanf(buf, "%s", device->mac_address);

    device->alpn = 3.14;
    device->type = 1;
}

int get_cloud_url(char *cloud_url) 
{
    char buf[UCI_BUF_LEN];
    size_t len;
    int rc;

    memset(buf, 0, sizeof(buf));
    rc = cmd_buf("uci get aircnms.@aircnms[0].cloud_url", buf, sizeof(buf));
    if (rc != 0) {
        printf("Failed to execute UCI command.\n");
        //return -1;
    }
    len = strlen(buf);
    if (len == 0) {
        printf("No UCI value found for cloud_url.\n");
        return -1;
    }
    sscanf(buf, "%s", cloud_url);
    return 0;
}

char* utf8_clean(char* input) {
    int len = strlen(input);
    char* cleaned = (char*)malloc(len + 1);  // Allocate memory for the cleaned string
    int j = 0;

    for (int i = 0; i < len; i++) {
        unsigned char byte = input[i];

        // Skip invalid UTF-8 sequences (e.g., 0xFF or control characters)
        if (byte < 32 || byte == 0xFF || !isprint(byte)) {
            continue;  // Skip non-printable characters
        }

        cleaned[j++] = input[i];  // Keep valid characters
    }

    cleaned[j] = '\0';  // Null-terminate the cleaned string
    return cleaned;
}

// Dynamic response buffer
struct curl_buffer {
    char *data;
    size_t size;
};

// Safe write callback
size_t write_callback(void *ptr, size_t size, size_t nmemb, void *userdata) 
{
    size_t realsize = size * nmemb;
    struct curl_buffer *mem = (struct curl_buffer *)userdata;

    char *new_data = realloc(mem->data, mem->size + realsize + 1);
    if (new_data == NULL) {
        return 0; // allocation failed
    }

    mem->data = new_data;
    memcpy(&(mem->data[mem->size]), ptr, realsize);
    mem->size += realsize;
    mem->data[mem->size] = '\0';

    return realsize;
}
#if 0
// Updated send_request function
bool send_request(void) 
{
    struct DeviceInfo device;
    struct curl_buffer response = { .data = malloc(1), .size = 0 };
    char cloud_url[128];
    bool ret = false;
    struct curl_slist *headers = NULL;
    CURL *curl;
    CURLcode res;

    if (response.data == NULL) {
        fprintf(stderr, "Failed to allocate memory for response buffer.\n");
        return false;
    }

    if (get_cloud_url(cloud_url) != 0) {
        free(response.data);
        return false;
    }

    get_device_details(&device);
    char *json_string = parse_device_info_to_json_string(device);
    if (!json_string) {
        free(response.data);
        return false;
    }

    printf("json string = %s\n", json_string);

    curl = curl_easy_init();
    headers = curl_slist_append(headers, "Accept: application/json");
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, "charset: utf-8");

    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, cloud_url);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_string);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&response);

        res = curl_easy_perform(curl);

        if (res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
            curl_easy_cleanup(curl);
            curl_slist_free_all(headers);
            free(json_string);
            free(response.data);
            return false;
        }

        curl_easy_cleanup(curl);
    }

    curl_slist_free_all(headers);

    printf("response = %s\n", response.data);

    // Clean non-printable characters
    for (size_t i = 0; i < response.size; i++) {
        if ((unsigned char)response.data[i] < 32 && response.data[i] != '\n' && response.data[i] != '\r') {
            response.data[i] = ' ';
        }
    }

    char *cleaned_response = utf8_clean(response.data);
    if (!cleaned_response) {
        fprintf(stderr, "utf8_clean() failed\n");
        free(json_string);
        free(response.data);
        return false;
    }

    json_error_t error;
    json_t *json = json_loads(cleaned_response, 0, &error);
    if (!json) {
        fprintf(stderr, "json_loads() failed: %s\n", error.text);
        free(json_string);
        free(cleaned_response);
        free(response.data);
        return false;
    }

    json_t *error_message = json_object_get(json, "error");
    if (json_is_string(error_message)) {
        json_decref(json);
        free(json_string);
        free(cleaned_response);
        free(response.data);
        return false;
    }

    json_decref(json);
    ret = qm_process_initial_data(cleaned_response);

    free(json_string);
    free(cleaned_response);
    free(response.data);

    return ret;
}
#endif

bool send_request(void)
{
    struct DeviceInfo device;
    struct curl_buffer response = { .data = malloc(1), .size = 0 };
    char cloud_url[128];
    struct curl_slist *headers = NULL;
    CURL *curl = NULL;
    CURLcode res;
    char *json_string = NULL;
    char *cleaned_response = NULL;
    json_t *json = NULL;
    bool ret = false;

    if (!response.data) {
        fprintf(stderr, "Failed to allocate memory for response buffer.\n");
        return false;
    }

    if (get_cloud_url(cloud_url) != 0) goto cleanup;

    get_device_details(&device);
    json_string = parse_device_info_to_json_string(device);
    if (!json_string) goto cleanup;
    
    LOG(INFO, "REQUEST JSON = %s\n", json_string);

    curl = curl_easy_init();
    if (!curl) goto cleanup;

    headers = curl_slist_append(NULL, "Accept: application/json");
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, "charset: utf-8");

    curl_easy_setopt(curl, CURLOPT_URL, cloud_url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_string);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&response);

    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        goto cleanup;
    }

    // Clean non-printable characters
    for (size_t i = 0; i < response.size; ++i) {
        if ((unsigned char)response.data[i] < 32 && response.data[i] != '\n' && response.data[i] != '\r')
            response.data[i] = ' ';
    }

    cleaned_response = utf8_clean(response.data);
    if (!cleaned_response) {
        fprintf(stderr, "utf8_clean() failed\n");
        goto cleanup;
    }

    json_error_t error;
    json = json_loads(cleaned_response, 0, &error);
    if (!json) {
        fprintf(stderr, "json_loads() failed: %s\n", error.text);
        goto cleanup;
    }

    json_t *error_message = json_object_get(json, "error");
    if (json_is_string(error_message)) goto cleanup;
    
    LOG(INFO, "RESPONSE JSON = %s\n", response.data);

    ret = qm_process_initial_data(cleaned_response);

cleanup:
    if (json) json_decref(json);
    if (curl) curl_easy_cleanup(curl);
    if (headers) curl_slist_free_all(headers);
    free(json_string);
    free(cleaned_response);
    free(response.data);
    return ret;
}



bool ut_dd_req_put_data()
{
    char cmd[512];
    int n_topic = 0;

    // put dummy data for qm_process_initial_data() 

    const char *device_id = "utdevid123";
    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set aircnms.@aircnms[0].device_id=%s", device_id);
    system(cmd);

    const char *network_id = "utnetid123";
    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set aircnms.@aircnms[0].network_id=%s", network_id);
    system(cmd);

    const char *org_id = "utorgid123";
    strcpy(air_dev.org_id, org_id);
    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set aircnms.@aircnms[0].org_id=%s", org_id);
    system(cmd);

    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set aircnms.@aircnms[0].online=1");
    system(cmd);

    const char *username = "admin";
    strcpy(air_dev.username, username);
    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set aircnms.@aircnms[0].username=%s", username);
    system(cmd);
    
    const char *password = "admin";
    strcpy(air_dev.password, password);
    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set aircnms.@aircnms[0].password=%s", air_dev.password);
    system(cmd);

    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci commit aircnms");
    system(cmd);

    strcpy(qm_topic_lst.topic[n_topic], "utdl_config");
    n_topic++;

    strcpy(qm_topic_lst.topic[n_topic], "utdl_cmd");
    n_topic++;

    strcpy(qm_topic_lst.topic[n_topic], "utdl_bwList");
    n_topic++;

    strcpy(qm_topic_lst.topic[n_topic], "utdl_rateLimit");
    n_topic++; 
    
    strcpy(qm_topic_lst.topic[n_topic], "utdl_broadcast");
    n_topic++;
        
    strcpy(qm_topic_lst.topic[n_topic], "utdl_broadcastWithOrgId");
    n_topic++;

    strcpy(qm_topic_lst.topic[n_topic], "utdl_broadcastWithNetworkConfig");
    n_topic++;

    strcpy(qm_topic_lst.topic[n_topic], "utdl_broadcastWithNetworkBwList");
    n_topic++;

    strcpy(qm_topic_lst.topic[n_topic], "utdl_broadcastWithNetworkCmd");
    n_topic++;

    qm_topic_lst.n_topic = n_topic;
    qm_add_topic_aircnms(&qm_topic_lst);

    return true;
}

bool qm_device_discovery_request()
{
    int retry_count = 0, delay = 10;
    bool result = false;

#ifndef CONFIG_UNIT_TEST_ENABLE
    while (retry_count < MAX_CLOUD_DEVICE_DISCOVERY_RETRIES) {
        result = send_request();
        
        if (result) {
            break;
        }

        sleep(delay);
        retry_count++;
    }
#else
    result = ut_dd_req_put_data();
#endif

    return result;
}
