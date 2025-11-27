#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <stdbool.h>
#include <jansson.h>
#include <unistd.h>
#include <iconv.h>
#include <ctype.h>
#include <math.h>

#include "cgw.h"
#include "log.h"
#include "memutil.h"
#include "os_nif.h"

#define MAX_RESPONSE_SIZE 8192  // Increase buffer size for larger responses
#define MAX_CLOUD_DEVICE_DISCOVERY_RETRIES 3
#define MAX_LAN_IP_RETRIES 3
#define UCI_BUF_LEN 256

cgw_mqtt_topic_list cgw_topic_lst;
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

bool cgw_process_initial_data(char *data)
{
    char cmd[512];
    json_error_t error;
    json_t *root = NULL;
    json_t *config_obj = NULL;
    json_t *deviceTopic = NULL;
    json_t *statsTopic = NULL;
    char *config_data = NULL;
    int n_topic = 0;
    bool result = false;
    int rc;
    int ret;

    if (!data) {
        LOG(ERR, "Invalid data parameter");
        return false;
    }

    root = json_loads(data, 0, &error);
    if (!root) {
        LOG(ERR, "JSON parsing error at line %d: %s", error.line, error.text);
        return false;
    }

    config_obj = json_object_get(root, "configData");
    if (!config_obj) {
        LOG(ERR, "Missing configData in JSON");
        goto cleanup;
    }

    // Helper macro for safe string copy with bounds checking
    #define SAFE_STRCPY(dest, src, dest_size) do { \
        if (src) { \
            size_t len = strnlen(src, (dest_size) - 1); \
            memcpy(dest, src, len); \
            (dest)[len] = '\0'; \
        } else { \
            (dest)[0] = '\0'; \
        } \
    } while(0)

    // Helper function for executing UCI commands safely
    #define SAFE_UCI_SET(key, value) do { \
        memset(cmd, 0, sizeof(cmd)); \
        ret = snprintf(cmd, sizeof(cmd), "uci set aircnms.@aircnms[0].%s=%s", key, value ? value : ""); \
        if (ret < 0 || ret >= (int)sizeof(cmd)) { \
            LOG(ERR, "Command buffer overflow for %s (ret=%d)", key, ret); \
            goto cleanup; \
        } \
        rc = system(cmd); \
        if (rc != 0) { \
            LOG(ERR, "Failed to set %s: command returned %d", key, rc); \
            goto cleanup; \
        } \
    } while(0)

    const char *device_id = json_string_value(json_object_get(root, "deviceId"));
    if (!device_id) {
        LOG(ERR, "Missing deviceId in JSON");
        goto cleanup;
    }
    SAFE_UCI_SET("device_id", device_id);
    
    const char *network_id = json_string_value(json_object_get(config_obj, "network"));
    if (!network_id) {
        LOG(ERR, "Missing network in configData");
        goto cleanup;
    }
    SAFE_STRCPY(air_dev.netwrk_id, network_id, sizeof(air_dev.netwrk_id));
    SAFE_UCI_SET("network_id", network_id);

    const char *org_id = json_string_value(json_object_get(root, "orgId"));
    if (!org_id) {
        LOG(ERR, "Missing orgId in JSON");
        goto cleanup;
    }
    SAFE_STRCPY(air_dev.org_id, org_id, sizeof(air_dev.org_id));
    SAFE_UCI_SET("org_id", org_id);

    memset(cmd, 0, sizeof(cmd));
    ret = snprintf(cmd, sizeof(cmd), "uci set aircnms.@aircnms[0].online=1");
    if (ret < 0 || ret >= (int)sizeof(cmd)) {
        LOG(ERR, "Command buffer overflow for online status");
        goto cleanup;
    }
    rc = system(cmd);
    if (rc != 0) {
        LOG(ERR, "Failed to set online status: command returned %d", rc);
        goto cleanup;
    }

    //username    
    const char *username = json_string_value(json_object_get(root, "username"));
    if (!username) {
        LOG(ERR, "Missing username in JSON");
        goto cleanup;
    }
    SAFE_STRCPY(air_dev.username, username, sizeof(air_dev.username));
    SAFE_UCI_SET("username", username);

    //Password
    const char *resource_key = json_string_value(json_object_get(root, "resourceKey"));
    const char *password = json_string_value(json_object_get(root, "password"));
    if (!resource_key || !password) {
        LOG(ERR, "Missing resourceKey or password in JSON");
        goto cleanup;
    }
    
    decrypt_aes(password, resource_key, air_dev.password);
    SAFE_UCI_SET("password", air_dev.password);

    rc = system("uci commit aircnms");
    if (rc != 0) {
        LOG(ERR, "Failed to commit UCI changes: command returned %d", rc);
        goto cleanup;
    }

    //parse topics
    deviceTopic = json_object_get(root, "deviceTopic");
    if (!deviceTopic) {
        LOG(ERR, "Missing deviceTopic in JSON");
        goto cleanup;
    }

    const char *topic_str;
    topic_str = json_string_value(json_object_get(deviceTopic, "config"));
    if (topic_str && n_topic < 16) {
        SAFE_STRCPY(cgw_topic_lst.topic[n_topic], topic_str, CGW_MAX_TOPIC_LEN);
        n_topic++;
    }

    topic_str = json_string_value(json_object_get(deviceTopic, "cmd"));
    if (topic_str && n_topic < 16) {
        SAFE_STRCPY(cgw_topic_lst.topic[n_topic], topic_str, CGW_MAX_TOPIC_LEN);
        n_topic++;
    }

    topic_str = json_string_value(json_object_get(deviceTopic, "bwList"));
    if (topic_str && n_topic < 16) {
        SAFE_STRCPY(cgw_topic_lst.topic[n_topic], topic_str, CGW_MAX_TOPIC_LEN);
        n_topic++;
    }

    topic_str = json_string_value(json_object_get(deviceTopic, "rateLimit"));
    if (topic_str && n_topic < 16) {
        SAFE_STRCPY(cgw_topic_lst.topic[n_topic], topic_str, CGW_MAX_TOPIC_LEN);
        n_topic++;
    }

    topic_str = json_string_value(json_object_get(deviceTopic, "broadcast"));
    if (topic_str && n_topic < 16) {
        SAFE_STRCPY(cgw_topic_lst.topic[n_topic], topic_str, CGW_MAX_TOPIC_LEN);
        n_topic++;
    }

    topic_str = json_string_value(json_object_get(deviceTopic, "broadcastWithOrgId"));
    if (topic_str && n_topic < 16) {
        SAFE_STRCPY(cgw_topic_lst.topic[n_topic], topic_str, CGW_MAX_TOPIC_LEN);
        n_topic++;
    }

    topic_str = json_string_value(json_object_get(deviceTopic, "broadcastWithNetworkConfig"));
    if (topic_str && n_topic < 16) {
        SAFE_STRCPY(cgw_topic_lst.topic[n_topic], topic_str, CGW_MAX_TOPIC_LEN);
        n_topic++;
    }

    topic_str = json_string_value(json_object_get(deviceTopic, "broadcastWithNetworkBwList"));
    if (topic_str && n_topic < 16) {
        SAFE_STRCPY(cgw_topic_lst.topic[n_topic], topic_str, CGW_MAX_TOPIC_LEN);
        n_topic++;
    }

    topic_str = json_string_value(json_object_get(deviceTopic, "broadcastWithNetworkCmd"));
    if (topic_str && n_topic < 16) {
        SAFE_STRCPY(cgw_topic_lst.topic[n_topic], topic_str, CGW_MAX_TOPIC_LEN);
        n_topic++;
    }

    cgw_topic_lst.n_topic = n_topic;
    cgw_add_topic_aircnms(&cgw_topic_lst);

    config_data = json_dumps(config_obj, 0);
    if (!config_data) {
        LOG(ERR, "Error converting JSON config to string");
        goto cleanup;
    }

    statsTopic = json_object_get(root, "statsTopic");
    if (statsTopic) {
        topic_str = json_string_value(json_object_get(statsTopic, "device"));
        if (topic_str) {
            SAFE_STRCPY(stats_topic.device, topic_str, sizeof(stats_topic.device));
        }
        topic_str = json_string_value(json_object_get(statsTopic, "vif"));
        if (topic_str) {
            SAFE_STRCPY(stats_topic.vif, topic_str, sizeof(stats_topic.vif));
        }
        topic_str = json_string_value(json_object_get(statsTopic, "client"));
        if (topic_str) {
            SAFE_STRCPY(stats_topic.client, topic_str, sizeof(stats_topic.client));
        }
        topic_str = json_string_value(json_object_get(statsTopic, "neighbor"));
        if (topic_str) {
            SAFE_STRCPY(stats_topic.neighbor, topic_str, sizeof(stats_topic.neighbor));
        }
        topic_str = json_string_value(json_object_get(statsTopic, "config"));
        if (topic_str) {
            SAFE_STRCPY(stats_topic.config, topic_str, sizeof(stats_topic.config));
        }
        topic_str = json_string_value(json_object_get(statsTopic, "cmdr"));
        if (topic_str) {
            SAFE_STRCPY(stats_topic.cmdr, topic_str, sizeof(stats_topic.cmdr));
        }
        topic_str = json_string_value(json_object_get(statsTopic, "status"));
        if (topic_str) {
            SAFE_STRCPY(stats_topic.status, topic_str, sizeof(stats_topic.status));
        }
        topic_str = json_string_value(json_object_get(statsTopic, "websiteUsage"));
        if (topic_str) {
            SAFE_STRCPY(stats_topic.website_usage, topic_str, sizeof(stats_topic.website_usage));
        }
        cgw_add_stats_topic_aircnms(&stats_topic);
    }

    size_t config_size = strlen(config_data);
    result = cgw_send_msg_to_cm(config_data, config_size, "config");

cleanup:
    if (root) json_decref(root);
    if (config_data) free(config_data);
    #undef SAFE_STRCPY
    #undef SAFE_UCI_SET
    return result;
}

// Function to parse DeviceInfo struct to JSON string with radio, location, and timezone
char *parse_device_info_to_json_string(struct DeviceInfo device)
{
    char fw_version[UCI_BUF_LEN];
    int retry_count = 0;
    char ipaddr[32] = {0};
    char timezone[64] = {0};
    char uci_value[32] = {0};
    //char cmd[128] = {0};
    os_ipaddr_t ip;

    json_t *json = json_object();
    if (!json) {
        LOG(ERR, "Error creating JSON object");
        return NULL;
    }

    // Get firmware version
    memset(fw_version, 0, sizeof(fw_version));
    get_fw_version(fw_version, UCI_BUF_LEN);

    // Basic device info
    json_object_set_new(json, "serial_number", json_string(device.serial_number));
    json_object_set_new(json, "mac", json_string(device.mac_address));
    json_object_set_new(json, "fw_info", json_string(fw_version));
    json_object_set_new(json, "hw_name", json_string("MTK7621"));
    json_object_set_new(json, "hw_version", json_string("1.0"));

    // Get management IP
    memset(ipaddr, 0, sizeof(ipaddr));
    while (retry_count < MAX_LAN_IP_RETRIES) {
        if (os_nif_ipaddr_get("br-lan", &ip)) {
            break;
        } else {
            retry_count++;
            sleep(2);
        }
    }
    int ret_ip = snprintf(ipaddr, sizeof(ipaddr), "%d.%d.%d.%d",
                          ip.addr[0], ip.addr[1], ip.addr[2], ip.addr[3]);
    if (ret_ip < 0 || ret_ip >= (int)sizeof(ipaddr)) {
        LOG(ERR, "IP address buffer overflow (ret=%d)", ret_ip);
        strncpy(ipaddr, "0.0.0.0", sizeof(ipaddr) - 1);
        ipaddr[sizeof(ipaddr) - 1] = '\0';
    }
    json_object_set_new(json, "mgmt_ip", json_string(ipaddr));

    // Get public IP
    memset(ipaddr, 0, sizeof(ipaddr));
    if (!get_public_ip(ipaddr)) {
        LOG(INFO, "Failed to retrieve public IP. Setting IP to 0.0.0.0");
        strncpy(ipaddr, "0.0.0.0", sizeof(ipaddr) - 1);
        ipaddr[sizeof(ipaddr) - 1] = '\0';
    }
    json_object_set_new(json, "egress_ip", json_string(ipaddr));

    // Create radio object
    json_t *radio_obj = json_object();
    json_t *radio_list = json_array();

    // 2.4GHz radio (wifi1)
    json_t *radio_2g = json_object();
    json_object_set_new(radio_2g, "band", json_string("2.4GHz"));

    memset(uci_value, 0, sizeof(uci_value));
    if (cmd_buf("uci get wireless.wifi1.channel", uci_value, sizeof(uci_value)) == 0) {
        json_object_set_new(radio_2g, "channel", json_string(uci_value));
    } else {
        json_object_set_new(radio_2g, "channel", json_string("0"));
    }

    memset(uci_value, 0, sizeof(uci_value));
    if (cmd_buf("uci get wireless.wifi1.txpower", uci_value, sizeof(uci_value)) == 0) {
        json_object_set_new(radio_2g, "txpower", json_string(uci_value));
    } else {
        json_object_set_new(radio_2g, "txpower", json_string("0"));
    }

    json_array_append_new(radio_list, radio_2g);

    // 5GHz radio (wifi0)
    json_t *radio_5g = json_object();
    json_object_set_new(radio_5g, "band", json_string("5GHz"));

    memset(uci_value, 0, sizeof(uci_value));
    if (cmd_buf("uci get wireless.wifi0.channel", uci_value, sizeof(uci_value)) == 0) {
        json_object_set_new(radio_5g, "channel", json_string(uci_value));
    } else {
        json_object_set_new(radio_5g, "channel", json_string("0"));
    }

    memset(uci_value, 0, sizeof(uci_value));
    if (cmd_buf("uci get wireless.wifi0.txpower", uci_value, sizeof(uci_value)) == 0) {
        json_object_set_new(radio_5g, "txpower", json_string(uci_value));
    } else {
        json_object_set_new(radio_5g, "txpower", json_string("0"));
    }

    json_array_append_new(radio_list, radio_5g);

    json_object_set_new(radio_obj, "radio_list", radio_list);
    json_object_set_new(json, "radio", radio_obj);

    json_t *location_array = json_array();
    char lat[32], lon[32];

    if (get_location_from_ipinfo(lat, sizeof(lat), lon, sizeof(lon))) {
        json_array_append_new(location_array, json_string(lat));
        json_array_append_new(location_array, json_string(lon));
    } else {
        LOG(ERR, "Failed to get location from ipinfo.io");
        json_array_append_new(location_array, json_string("0.0"));
        json_array_append_new(location_array, json_string("0.0"));
    }

    json_object_set_new(json, "location", location_array);

    // Get timezone from ipinfo.io
    memset(timezone, 0, sizeof(timezone));
    if (get_timezone_from_ipapi(timezone, sizeof(timezone))) {
        json_object_set_new(json, "timezone", json_string(timezone));
    } else {
        LOG(ERR, "Failed to get timezone from ipinfo.io");
        json_object_set_new(json, "timezone", json_string("UTC"));
    }

    // Convert JSON to string
    char *json_str = json_dumps(json, JSON_INDENT(4));
    if (!json_str) {
        LOG(ERR, "Error converting JSON to string");
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
        LOG(ERR, "Failed to execute UCI command for cloud_url");
        return -1;
    }
    len = strlen(buf);
    if (len == 0) {
        LOG(ERR, "No UCI value found for cloud_url");
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
        LOG(ERR, "Failed to allocate memory for response buffer");
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
        LOG(ERR, "curl_easy_perform() failed: %s", curl_easy_strerror(res));
        goto cleanup;
    }

    // Clean non-printable characters
    for (size_t i = 0; i < response.size; ++i) {
        if ((unsigned char)response.data[i] < 32 && response.data[i] != '\n' && response.data[i] != '\r')
            response.data[i] = ' ';
    }

    cleaned_response = utf8_clean(response.data);
    if (!cleaned_response) {
        LOG(ERR, "utf8_clean() failed");
        goto cleanup;
    }

    json_error_t error;
    json = json_loads(cleaned_response, 0, &error);
    if (!json) {
        LOG(ERR, "json_loads() failed: %s", error.text);
        goto cleanup;
    }

    json_t *error_message = json_object_get(json, "error");
    if (json_is_string(error_message)) goto cleanup;
    
    LOG(INFO, "RESPONSE JSON = %s\n", response.data);

    ret = cgw_process_initial_data(cleaned_response);
    LOG(DEBUG, "cgw_process_initial_data result: %d", ret);
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
    int rc;
    int ret;

    // put dummy data for cgw_process_initial_data() - UNIT TEST ONLY

    const char *device_id = "utdevid123";
    memset(cmd, 0, sizeof(cmd));
    ret = snprintf(cmd, sizeof(cmd), "uci set aircnms.@aircnms[0].device_id=%s", device_id);
    if (ret >= 0 && ret < (int)sizeof(cmd)) {
        rc = system(cmd);
        if (rc != 0) {
            LOG(ERR, "Failed to set device_id in unit test (exit code: %d)", rc);
        }
    }

    const char *network_id = "utnetid123";
    memset(cmd, 0, sizeof(cmd));
    ret = snprintf(cmd, sizeof(cmd), "uci set aircnms.@aircnms[0].network_id=%s", network_id);
    if (ret >= 0 && ret < (int)sizeof(cmd)) {
        rc = system(cmd);
        if (rc != 0) {
            LOG(ERR, "Failed to set network_id in unit test (exit code: %d)", rc);
        }
    }

    const char *org_id = "utorgid123";
    strncpy(air_dev.org_id, org_id, sizeof(air_dev.org_id) - 1);
    air_dev.org_id[sizeof(air_dev.org_id) - 1] = '\0';
    memset(cmd, 0, sizeof(cmd));
    ret = snprintf(cmd, sizeof(cmd), "uci set aircnms.@aircnms[0].org_id=%s", org_id);
    if (ret >= 0 && ret < (int)sizeof(cmd)) {
        rc = system(cmd);
        if (rc != 0) {
            LOG(ERR, "Failed to set org_id in unit test (exit code: %d)", rc);
        }
    }

    memset(cmd, 0, sizeof(cmd));
    ret = snprintf(cmd, sizeof(cmd), "uci set aircnms.@aircnms[0].online=1");
    if (ret >= 0 && ret < (int)sizeof(cmd)) {
        rc = system(cmd);
        if (rc != 0) {
            LOG(ERR, "Failed to set online in unit test (exit code: %d)", rc);
        }
    }

    const char *username = "admin";
    strncpy(air_dev.username, username, sizeof(air_dev.username) - 1);
    air_dev.username[sizeof(air_dev.username) - 1] = '\0';
    memset(cmd, 0, sizeof(cmd));
    ret = snprintf(cmd, sizeof(cmd), "uci set aircnms.@aircnms[0].username=%s", username);
    if (ret >= 0 && ret < (int)sizeof(cmd)) {
        rc = system(cmd);
        if (rc != 0) {
            LOG(ERR, "Failed to set username in unit test (exit code: %d)", rc);
        }
    }
    
    const char *password = "admin";
    strncpy(air_dev.password, password, sizeof(air_dev.password) - 1);
    air_dev.password[sizeof(air_dev.password) - 1] = '\0';
    memset(cmd, 0, sizeof(cmd));
    ret = snprintf(cmd, sizeof(cmd), "uci set aircnms.@aircnms[0].password=%s", air_dev.password);
    if (ret >= 0 && ret < (int)sizeof(cmd)) {
        rc = system(cmd);
        if (rc != 0) {
            LOG(ERR, "Failed to set password in unit test (exit code: %d)", rc);
        }
    }

    rc = system("uci commit aircnms");
    if (rc != 0) {
        LOG(ERR, "Failed to commit in unit test (exit code: %d)", rc);
    }

    // Safe topic copying with bounds checking
    #define SAFE_TOPIC_COPY(topic_name) do { \
        if (n_topic < 16 && strlen(topic_name) < CGW_MAX_TOPIC_LEN) { \
            strncpy(cgw_topic_lst.topic[n_topic], topic_name, CGW_MAX_TOPIC_LEN - 1); \
            cgw_topic_lst.topic[n_topic][CGW_MAX_TOPIC_LEN - 1] = '\0'; \
            n_topic++; \
        } \
    } while(0)

    SAFE_TOPIC_COPY("utdl_config");
    SAFE_TOPIC_COPY("utdl_cmd");
    SAFE_TOPIC_COPY("utdl_bwList");
    SAFE_TOPIC_COPY("utdl_rateLimit");
    SAFE_TOPIC_COPY("utdl_broadcast");
    SAFE_TOPIC_COPY("utdl_broadcastWithOrgId");
    SAFE_TOPIC_COPY("utdl_broadcastWithNetworkConfig");
    SAFE_TOPIC_COPY("utdl_broadcastWithNetworkBwList");
    SAFE_TOPIC_COPY("utdl_broadcastWithNetworkCmd");

    #undef SAFE_TOPIC_COPY

    cgw_topic_lst.n_topic = n_topic;
    cgw_add_topic_aircnms(&cgw_topic_lst);

    return true;
}

bool cgw_device_discovery_request()
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
