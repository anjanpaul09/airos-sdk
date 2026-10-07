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
#include <openssl/crypto.h>
#include "cgw_uci.h"
#include "cgw_registration_result.h"
#include "cgw_registration_attempt.h"

#define MAX_RESPONSE_SIZE (256 * 1024)  // Increase buffer size for larger responses
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

int mac_to_colon_format(const char *in, char *out, size_t out_len)
{
    if (!in || !out) return -1;

    // Must be exactly 12 hex chars
    if (strlen(in) != 12) return -1;

    // Need space for "xx:xx:xx:xx:xx:xx" + '\0' = 18
    if (out_len < 18) return -1;

    for (int i = 0, j = 0; i < 12; i += 2) {
        // Validate hex chars
        if (!isxdigit(in[i]) || !isxdigit(in[i+1]))
            return -1;

        out[j++] = toupper(in[i]);
        out[j++] = toupper(in[i+1]);

        if (i < 10)
            out[j++] = ':';
    }

    out[17] = '\0';
    return 0;
}

static bool copy_json_string(json_t *obj,const char *key,char *dst,size_t size,bool required){
 json_t *v=obj?json_object_get(obj,key):NULL; const char *s=json_is_string(v)?json_string_value(v):NULL; size_t n;
 if(!s){ if(dst&&size)dst[0]='\0'; return !required; } n=strlen(s); if(!n||n>=size) return false; memcpy(dst,s,n+1); return true;
}
static bool valid_broker(const char *s){
 size_t i,n=s?strlen(s):0; if(!n||n>253) return false;
 for(i=0;i<n;i++) if(!(isalnum((unsigned char)s[i])||s[i]=='.'||s[i]=='-'||s[i]==':'||s[i]=='['||s[i]==']')) return false;
 return true;
}
static bool add_unique_topic(cgw_mqtt_topic_list *list,const char *topic){
 int i; size_t n=topic?strlen(topic):0; if(!n||n>=CGW_MAX_TOPIC_LEN) return false;
 for(i=0;i<list->n_topic;i++) if(!strcmp(list->topic[i],topic)) return true;
 if(list->n_topic>=16) return false;
 memcpy(list->topic[list->n_topic++],topic,n+1);
 return true;
}

static bool cgw_process_initial_data_attempt(char *data, const char *attempt_id)
{
 static const char *topic_keys[]={"config","cmd","bwList","rateLimit","broadcast","broadcastWithOrgId","broadcastWithNetworkConfig","broadcastWithNetworkBwList","broadcastWithNetworkCmd"};
 json_error_t error; json_t *root=NULL,*cfg=NULL,*dev_topics=NULL,*stat_topics=NULL,*port_obj=NULL; char *cfg_json=NULL;
 char device_id[sizeof(air_dev.device_id)]={0},network_id[sizeof(air_dev.netwrk_id)]={0},org_id[sizeof(air_dev.org_id)]={0};
 char username[sizeof(air_dev.username)]={0},password[sizeof(air_dev.password)]={0},broker[254]={0},port[8]={0};
 cgw_mqtt_topic_list new_topics={0}; stats_topic_t new_stats={0}; cgw_enrollment_uci_t values; long port_value; size_t i; bool ok=false;
 if(!data||strlen(data)>MAX_RESPONSE_SIZE){ LOG(ERR,"Invalid or oversized registration response"); return false; }
 root=json_loads(data,JSON_REJECT_DUPLICATES,&error); if(!json_is_object(root)){ LOG(ERR,"Invalid registration JSON: %s",error.text); goto out; }
 cfg=json_object_get(root,"configData"); dev_topics=json_object_get(root,"deviceTopic"); stat_topics=json_object_get(root,"statsTopic");
 if(!json_is_object(cfg)||!json_is_object(dev_topics)||!json_is_object(stat_topics)){ LOG(ERR,"Registration response is missing configuration/topic objects"); goto out; }
 if(!copy_json_string(root,"deviceId",device_id,sizeof(device_id),true)||!copy_json_string(cfg,"network",network_id,sizeof(network_id),true)||
    !copy_json_string(root,"orgId",org_id,sizeof(org_id),true)||!copy_json_string(root,"username",username,sizeof(username),true)||
    !copy_json_string(root,"broker",broker,sizeof(broker),true)||!valid_broker(broker)){ LOG(ERR,"Invalid registration identity or broker fields"); goto out; }
 port_obj=json_object_get(root,"port"); if(!json_is_integer(port_obj)){ LOG(ERR,"Invalid MQTT port type"); goto out; } port_value=json_integer_value(port_obj);
 if(port_value<1||port_value>65535||snprintf(port,sizeof(port),"%ld",port_value)>=(int)sizeof(port)){ LOG(ERR,"Invalid MQTT port"); goto out; }
 { const char *enc=json_string_value(json_object_get(root,"password")); const char *key=json_string_value(json_object_get(root,"resourceKey"));
   if(!enc||!key||!decrypt_aes(enc,key,password,sizeof(password))){ LOG(ERR,"Credential decryption failed"); goto out; } }
 for(i=0;i<sizeof(topic_keys)/sizeof(topic_keys[0]);i++){
  json_t *v=json_object_get(dev_topics,topic_keys[i]); if(!json_is_string(v)||!add_unique_topic(&new_topics,json_string_value(v))){ LOG(ERR,"Invalid device topic: %s",topic_keys[i]); goto out; }
 }
#define STAT(json_key,member) do{if(!copy_json_string(stat_topics,json_key,new_stats.member,sizeof(new_stats.member),true)){LOG(ERR,"Invalid stats topic: %s",json_key);goto out;}}while(0)
 STAT("device",device); STAT("client",client); STAT("vif",vif); STAT("status",status); STAT("websiteUsage",website_usage);
 /* The current cloud contract exposes one authorized event topic.  Older
  * firmware used three names for that same publish channel. */
 { char event_topic[CGW_MAX_TOPIC_LEN]={0};
   if(!copy_json_string(stat_topics,"event",event_topic,sizeof(event_topic),true)){ LOG(ERR,"Invalid stats topic: event"); goto out; }
   memcpy(new_stats.neighbor,event_topic,strlen(event_topic)+1);
   memcpy(new_stats.config,event_topic,strlen(event_topic)+1);
   memcpy(new_stats.cmdr,event_topic,strlen(event_topic)+1);
 }
#undef STAT
 cfg_json=json_dumps(cfg,JSON_COMPACT); if(!cfg_json||strlen(cfg_json)>262144){ LOG(ERR,"Invalid or oversized configData"); goto out; }
 /* Do not persist credentials until netconfd has accepted the initial config. */
 if(!cgw_send_msg_to_cm(cfg_json,(long)strlen(cfg_json),"initial_config")){ LOG(ERR,"Initial configuration was rejected or timed out"); goto out; }
 if(attempt_id && !cgw_registration_attempt_transition(attempt_id, CGW_ATTEMPT_APPLYING_CONFIG, CGW_ATTEMPT_COMMITTING)){ LOG(ERR,"Registration attempt lost before credential commit"); goto out; }
 values=(cgw_enrollment_uci_t){device_id,network_id,org_id,username,password,broker,port,&new_topics,&new_stats};
 if(!cgw_uci_commit_enrollment(&values)) goto out;
 memcpy(air_dev.device_id,device_id,sizeof(device_id)); memcpy(air_dev.netwrk_id,network_id,sizeof(network_id)); memcpy(air_dev.org_id,org_id,sizeof(org_id));
 memcpy(air_dev.username,username,sizeof(username)); memcpy(air_dev.password,password,sizeof(password)); cgw_topic_lst=new_topics; stats_topic=new_stats; ok=true;
 LOG(INFO,"Registration configuration committed: device_id=%s broker=%s port=%s topics=%d",device_id,broker,port,new_topics.n_topic);
 system("/sbin/reload_config >/dev/null 2>&1");
out:
 if(password[0]) OPENSSL_cleanse(password,sizeof(password));
 if(cfg_json) free(cfg_json);
 if(root) json_decref(root);
 return ok;
}

bool cgw_process_initial_data(char *data)
{
    return cgw_process_initial_data_attempt(data, NULL);
}

// Function to parse DeviceInfo struct to JSON string with radio, location, and timezone
char *parse_device_info_to_json_string(struct DeviceInfo device)
{
    char fw_version[UCI_BUF_LEN];
    int retry_count = 0;
    char ipaddr[32] = {0};
    char timezone[64] = {0};
    char uci_value[32] = {0};
    char mac_out[18];
    //char cmd[128] = {0};
    os_ipaddr_t ip = {{0}};

    json_t *json = json_object();
    if (!json) {
        LOG(ERR, "Error creating JSON object");
        return NULL;
    }

    char raw_version[UCI_BUF_LEN] = {0};
    char model[64] = {0};

    // Get firmware version
    if (cmd_buf("uci -q get version.@version[0].version || uci -q get version.version.version", raw_version, sizeof(raw_version)) != 0 || raw_version[0] == '\0') {
        get_fw_version(raw_version, sizeof(raw_version));
    }
    snprintf(fw_version, sizeof(fw_version), "Airos-%.240s", raw_version);

    // Get model from uci show version
    if (cmd_buf("uci -q get version.@version[0].model || uci -q get version.version.model", model, sizeof(model)) != 0 || model[0] == '\0') {
        strncpy(model, "AP520", sizeof(model) - 1);
    }

    // Basic device info
    json_object_set_new(json, "serial_number", json_string(device.serial_number));
    if (mac_to_colon_format(device.mac_address, mac_out, sizeof(mac_out)) == 0) {    
        json_object_set_new(json, "mac", json_string(mac_out));
    } else {
        json_object_set_new(json, "mac", json_string(device.mac_address));
    }
    json_object_set_new(json, "fw_info", json_string(fw_version));
    json_object_set_new(json, "hw_name", json_string(model));
    json_object_set_new(json, "model", json_string(model));
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
    int ret_ip;
    if (retry_count >= MAX_LAN_IP_RETRIES) {
        strncpy(ipaddr, "0.0.0.0", sizeof(ipaddr) - 1);
        ret_ip = (int)strlen(ipaddr);
    } else {
        ret_ip = snprintf(ipaddr, sizeof(ipaddr), "%d.%d.%d.%d", ip.addr[0], ip.addr[1], ip.addr[2], ip.addr[3]);
    }
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
    sscanf(buf, "%31s", device->serial_number);

    memset(buf, 0, sizeof(buf));
    cmd_buf("uci get aircnms.@aircnms[0].macaddr", buf, (size_t)UCI_BUF_LEN);
    len = strlen(buf);
    if (len == 0)
    {
        LOGI("%s: No uci found", __func__);
    }
    sscanf(buf, "%31s", device->mac_address);

    device->alpn = 3.14;
    device->type = 1;
}

#define CGW_DEFAULT_CLOUD_BASE_URL "https://api.cloud.netstream.net.in"
#define CGW_REGISTRATION_ENDPOINT  "/api/device_registration/v1/devices"

int get_cloud_url(char *cloud_url) 
{
    char buf[UCI_BUF_LEN];
    char base_url[128];
    size_t len;
    int rc;

    memset(buf, 0, sizeof(buf));
    rc = cmd_buf("uci get aircnms.@aircnms[0].cloud_url", buf, sizeof(buf));
    if (rc != 0 || strlen(buf) == 0) {
        LOG(NOTICE, "No UCI value found for cloud_url, using default: %s", CGW_DEFAULT_CLOUD_BASE_URL);
        snprintf(base_url, sizeof(base_url), "%s", CGW_DEFAULT_CLOUD_BASE_URL);
    } else {
        if (sscanf(buf, "%127s", base_url) != 1) {
            snprintf(base_url, sizeof(base_url), "%s", CGW_DEFAULT_CLOUD_BASE_URL);
        }
    }

    /* Strip trailing slashes */
    len = strlen(base_url);
    while (len > 0 && base_url[len - 1] == '/') {
        base_url[--len] = '\0';
    }

    snprintf(cloud_url, 256, "%s%s", base_url, CGW_REGISTRATION_ENDPOINT);
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

    if (realsize > MAX_RESPONSE_SIZE || mem->size > MAX_RESPONSE_SIZE - realsize)
        return 0;
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

static int registration_progress_cb(void *clientp, curl_off_t dltotal,
                                    curl_off_t dlnow, curl_off_t ultotal,
                                    curl_off_t ulnow)
{
    const char *attempt_id = clientp;
    (void)dltotal;
    (void)dlnow;
    (void)ultotal;
    (void)ulnow;
    return cgw_registration_attempt_is_running(attempt_id) ? 0 : 1;
}

static bool send_request_internal(const char *existing_attempt_id)
{
    struct DeviceInfo device;
    struct curl_buffer response = { .data = calloc(1, 1), .size = 0 };
    char cloud_url[256];
    struct curl_slist *headers = NULL;
    CURL *curl = NULL;
    CURLcode res;
    long http_code = 0;
    char *json_string = NULL;
    char *cleaned_response = NULL;
    json_t *json = NULL;
    bool ret = false;
    cgw_registration_result_t registration_result = CGW_REG_RESULT_TEMPORARY_FAILURE;
    char attempt_id[CGW_ATTEMPT_ID_LEN] = {0};
    bool attempt_reused = false;

    if (!response.data) {
        LOG(ERR, "Failed to allocate memory for response buffer");
        return false;
    }
    if (existing_attempt_id) {
        if (snprintf(attempt_id, sizeof(attempt_id), "%s", existing_attempt_id) >=
            (int)sizeof(attempt_id) ||
            !cgw_registration_attempt_is_running(attempt_id)) {
            LOG(ERR, "Registration attempt is stale before start");
            goto cleanup;
        }
    } else {
        if (!cgw_registration_attempt_begin(attempt_id, sizeof(attempt_id),
                                            &attempt_reused)) {
            LOG(ERR, "Registration attempt could not be created");
            goto cleanup;
        }
        if (attempt_reused) {
            LOG(INFO, "Registration request coalesced attempt_id=%s", attempt_id);
            goto cleanup;
        }
        LOG(INFO, "Registration attempt started attempt_id=%s", attempt_id);
    }

    if (!cgw_registration_attempt_is_running(attempt_id))
        goto cleanup;
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
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 45L);
    curl_easy_setopt(curl, CURLOPT_LOW_SPEED_LIMIT, 100L);
    curl_easy_setopt(curl, CURLOPT_LOW_SPEED_TIME, 15L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L);
    curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION, registration_progress_cb);
    curl_easy_setopt(curl, CURLOPT_XFERINFODATA, attempt_id);

    if (!cgw_registration_attempt_transition(attempt_id, CGW_ATTEMPT_PREPARING,
                                             CGW_ATTEMPT_HTTP))
        goto cleanup;
    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        registration_result = cgw_classify_registration_result(0, false, NULL);
        LOG(ERR, "Registration result=%s transport=%s",
            cgw_registration_result_string(registration_result), curl_easy_strerror(res));
        goto cleanup;
    }
    if (curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code) != CURLE_OK) {
        registration_result = cgw_classify_registration_result(0, false, NULL);
        LOG(ERR, "Registration result=%s reason=HTTP_STATUS_UNAVAILABLE",
            cgw_registration_result_string(registration_result));
        goto cleanup;
    }

    // Clean non-printable characters
    for (size_t i = 0; i < response.size; ++i) {
        if ((unsigned char)response.data[i] < 32 && response.data[i] != '\n' && response.data[i] != '\r')
            response.data[i] = ' ';
    }

    cleaned_response = response.size ? utf8_clean(response.data) : NULL;
    registration_result = cgw_classify_registration_result(http_code, true, cleaned_response);
    LOG(INFO, "Registration result=%s http_status=%ld",
        cgw_registration_result_string(registration_result), http_code);
    if (registration_result != CGW_REG_RESULT_SUCCESS)
        goto cleanup;
    if (!cleaned_response) {
        LOG(ERR, "Successful registration classification has no response body");
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
    
    /* Response contains credentials and must never be logged. */
    if (!cgw_registration_attempt_transition(attempt_id, CGW_ATTEMPT_HTTP,
                                             CGW_ATTEMPT_APPLYING_CONFIG)) {
        registration_result = CGW_REG_RESULT_CANCELLED;
        goto cleanup;
    }
    ret = cgw_process_initial_data_attempt(cleaned_response, attempt_id);
    if (!ret)
        registration_result = CGW_REG_RESULT_PERMANENT_FAILURE;
    LOG(DEBUG, "cgw_process_initial_data result: %d", ret);
cleanup:
    if (attempt_id[0] && !attempt_reused &&
        !cgw_registration_attempt_complete(attempt_id, registration_result))
        LOG(WARNING, "Ignored stale registration completion attempt_id=%s", attempt_id);
    if (json) json_decref(json);
    if (curl) curl_easy_cleanup(curl);
    if (headers) curl_slist_free_all(headers);
    free(json_string);
    free(cleaned_response);
    free(response.data);
    return ret;
}


bool send_request(void)
{
    return send_request_internal(NULL);
}

bool cgw_run_registration_attempt(const char *attempt_id)
{
    return send_request_internal(attempt_id);
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
