#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <mosquitto.h>
#include <stdarg.h>
#include <time.h>
#include <limits.h>

#define MQTT_HOST "69.30.254.180"
#define MQTT_PORT 35930
#define MQTT_USERNAME "bluesyobsignates"
#define MQTT_PASSWORD "PNJxhzMX2jkRVBG3"

typedef struct MqttIds {
  char device_id[128];
  char serial_num[128];
} MqttIds;

static volatile int g_puback_received = 0;
static void on_publish(struct mosquitto *mosq, void *userdata, int mid) {
  (void)mosq; (void)userdata; (void)mid;
  g_puback_received = 1;
}

static void rstrip(char *s) {
  if (!s) return;
  size_t n = strlen(s);
  while (n && (s[n-1]=='\n' || s[n-1]=='\r' || isspace((unsigned char)s[n-1]))) { s[--n] = '\0'; }
}

static void ltrim_inplace(char **p) {
  if (!p || !*p) return;
  while (**p && isspace((unsigned char)**p)) (*p)++;
}

static int load_ids(MqttIds *ids) {
  memset(ids, 0, sizeof(*ids));
  FILE *f = fopen("config/mqtt.conf", "r");
  if (!f) return -1;
  char line[512];
  while (fgets(line, sizeof(line), f)) {
    rstrip(line);
    if (!line[0] || line[0]=='#') continue;
    char *eq = strchr(line, '='); if (!eq) continue;
    *eq = '\0';
    char *key = line; char *val = eq+1; ltrim_inplace(&key); ltrim_inplace(&val);
    if (!strcasecmp(key, "device_id") || !strcasecmp(key, "device-id")) snprintf(ids->device_id, sizeof(ids->device_id), "%s", val);
    else if (!strcasecmp(key, "serial_num") || !strcasecmp(key, "serial-num")) snprintf(ids->serial_num, sizeof(ids->serial_num), "%s", val);
  }
  fclose(f);
  return (ids->device_id[0] && ids->serial_num[0]) ? 0 : -1;
}

typedef struct StrBuf { char *buf; size_t len; size_t cap; } StrBuf;

static void sb_init(StrBuf *b) { b->buf=NULL; b->len=0; b->cap=0; }
static void sb_free(StrBuf *b) { free(b->buf); b->buf=NULL; b->len=b->cap=0; }
static int sb_reserve(StrBuf *b, size_t need) {
  if (b->cap - b->len >= need) return 0;
  size_t ncap = b->cap ? b->cap*2 : 1024; while (ncap - b->len < need) ncap *= 2;
  char *nb = (char*)realloc(b->buf, ncap); if (!nb) return -1; b->buf=nb; b->cap=ncap; return 0;
}
static int sb_append(StrBuf *b, const char *s) {
  size_t sl = strlen(s); if (sb_reserve(b, sl+1)) return -1; memcpy(b->buf+b->len, s, sl); b->len+=sl; b->buf[b->len]='\0'; return 0;
}
/* unused helper removed to avoid warnings */

static void json_escape_append(StrBuf *b, const char *s) {
  sb_append(b, "\"");
  for (const unsigned char *p=(const unsigned char*)s; *p; ++p) {
    if (*p=='\\' || *p=='\"') { char tmp[3]={'\\', (char)*p, 0}; sb_append(b, tmp); }
    else if (*p=='\n') sb_append(b, "\\n");
    else if (*p=='\r') sb_append(b, "\\r");
    else if (*p=='\t') sb_append(b, "\\t");
    else if (*p<0x20) { char tmp[7]; snprintf(tmp,sizeof(tmp),"\\u%04x",*p); sb_append(b,tmp);} 
    else { char c[2]={(char)*p,0}; sb_append(b,c);} 
  }
  sb_append(b, "\"");
}

static int is_bool_token(const char *v) { return !strcasecmp(v,"true") || !strcasecmp(v,"false"); }
static int is_null_token(const char *v) { return !strcasecmp(v,"null"); }
static int is_number_token(const char *v) {
  if (!*v) return 0;
  const char *p = v;
  if (*p=='-' || *p=='+') p++;
  int has_digit = 0;
  while (*p && isdigit((unsigned char)*p)) { has_digit = 1; p++; }
  return has_digit && !*p;
}

static void json_emit_kv(StrBuf *b, const char *k, const char *v) {
  json_escape_append(b, k); sb_append(b, ":");
  if (is_bool_token(v) || is_null_token(v) || is_number_token(v)) sb_append(b, v); else json_escape_append(b, v);
}

static int build_wifi_json(StrBuf *out) {
  fprintf(stdout, "[mqtt-pub] build_wifi_json: opening config/wifi.conf\n"); fflush(stdout);
  FILE *f = fopen("config/wifi.conf", "r"); if (!f) { perror("wifi.conf open"); return -1; }
  StrBuf json; sb_init(&json); sb_append(&json, "{");
  /* Start vif.vifList */
  sb_append(&json, "\"vif\":{\"vifList\":[");
  int first_vif = 1, first_radio = 1; int in_vif = 0, in_radio = 0, in_section = 0;
  char current_section[64]={0};
  StrBuf obj; sb_init(&obj); int first_kv = 1;
  char line[512];
  int vif_count = 0;
  while (fgets(line, sizeof(line), f)) {
    rstrip(line);
    if (!line[0] || line[0]=='#') continue;
    if (line[0]=='[') {
      /* close previous section object if any */
      if (in_section) { sb_append(&obj, "}"); if (in_vif) { if (!first_vif) sb_append(&json, ","); first_vif=0; sb_append(&json, obj.buf?obj.buf:"{}"); vif_count++; }
                        else if (in_radio) { /* handled later */ }
                        sb_free(&obj); sb_init(&obj); first_kv=1; }
      in_section = 1; in_vif=0; in_radio=0; current_section[0]='\0';
      if (sscanf(line, "[vif.%63[^]]]", current_section)==1) { in_vif=1; sb_append(&obj, "{"); first_kv=1; }
      else if (sscanf(line, "[radio.%63[^]]]", current_section)==1) { in_radio=1; sb_append(&obj, "{"); first_kv=1; }
      else if (strcmp(line, "[network]")==0) { in_vif=0; in_radio=0; sb_append(&obj, "\"network\":{"); first_kv=1; }
      else if (strcmp(line, "[nat]")==0) { in_vif=0; in_radio=0; sb_append(&obj, "\"nat\":{"); first_kv=1; }
      continue;
    }
    char *eq = strchr(line, '='); if (!eq) continue; *eq='\0';
    char *key = line; char *val = eq+1; ltrim_inplace(&key); ltrim_inplace(&val);
    if (in_section) {
      if (!first_kv) {
        sb_append(&obj, ",");
      }
      first_kv = 0;
      json_emit_kv(&obj, key, val);
    }
  }
  /* close last open */
  if (in_section) { sb_append(&obj, "}"); if (in_vif) { if (!first_vif) sb_append(&json, ","); first_vif=0; sb_append(&json, obj.buf?obj.buf:"{}"); vif_count++; }
                    else { /* network or nat: stash to tail */ }
  }
  sb_append(&json, "]}"); /* end vif.vifList and wrap object */
  fprintf(stdout, "[mqtt-pub] build_wifi_json: parsed %d VIF entries\n", vif_count); fflush(stdout);

  /* Re-scan for radio + network + nat to keep code simple */
  fseek(f, 0, SEEK_SET);
  sb_append(&json, ",\"radio\":{\"radioList\":["); first_radio=1; sb_free(&obj); sb_init(&obj); first_kv=1; in_section=0; in_radio=0;
  int radio_count = 0;
  while (fgets(line, sizeof(line), f)) {
    rstrip(line);
    if (!line[0] || line[0]=='#') continue;
    if (line[0]=='[') {
      if (in_radio) { sb_append(&obj, "}"); if (!first_radio) sb_append(&json, ","); first_radio=0; sb_append(&json, obj.buf?obj.buf:"{}"); radio_count++; sb_free(&obj); sb_init(&obj); first_kv=1; in_radio=0; }
      if (strncmp(line, "[radio.", 7)==0) { in_radio=1; sb_append(&obj, "{"); first_kv=1; }
      continue;
    }
    if (in_radio) {
      char *eq = strchr(line, '='); if (!eq) continue; *eq='\0'; char *key=line; char *val=eq+1; ltrim_inplace(&key); ltrim_inplace(&val);
      if (!first_kv) {
        sb_append(&obj, ",");
      }
      first_kv = 0;
      json_emit_kv(&obj, key, val);
    }
  }
  if (in_radio) { sb_append(&obj, "}"); if (!first_radio) sb_append(&json, ","); first_radio=0; sb_append(&json, obj.buf?obj.buf:"{}"); }
  sb_append(&json, "]}"); /* end radio.radioList and wrap object */
  fprintf(stdout, "[mqtt-pub] build_wifi_json: parsed %d radio entries\n", radio_count); fflush(stdout);

  /* network and nat */
  fseek(f, 0, SEEK_SET);
  StrBuf network; sb_init(&network); int have_network=0; first_kv=1; in_section=0;
  char network_value[256]={0};
  while (fgets(line, sizeof(line), f)) {
    rstrip(line); if (!line[0]||line[0]=='#') continue;
    if (!strcmp(line, "[network]")) { in_section=1; first_kv=1; continue; }
    if (line[0]=='[' && strcmp(line, "[network]")!=0) { if (in_section){ in_section=0; have_network=1; } continue; }
    if (in_section) { char *eq=strchr(line,'='); if (!eq) continue; *eq='\0'; char *key=line; char *val=eq+1; ltrim_inplace(&key); ltrim_inplace(&val); if (strcasecmp(key,"network")==0) { snprintf(network_value, sizeof(network_value), "%s", val); have_network=1; } }
  }
  if (in_section) { in_section=0; }

  StrBuf nat; sb_init(&nat); int have_nat=0; first_kv=1; in_section=0; fseek(f,0,SEEK_SET);
  while (fgets(line, sizeof(line), f)) {
    rstrip(line); if (!line[0]||line[0]=='#') continue;
    if (!strcmp(line, "[nat]")) { in_section=1; sb_append(&nat, "{"); first_kv=1; continue; }
    if (line[0]=='[' && strcmp(line, "[nat]")!=0) { if (in_section){ sb_append(&nat, "}"); in_section=0; have_nat=1; } continue; }
    if (in_section) { char *eq=strchr(line,'='); if (!eq) continue; *eq='\0'; char *key=line; char *val=eq+1; ltrim_inplace(&key); ltrim_inplace(&val); if(!first_kv) sb_append(&nat, ","); first_kv=0; json_emit_kv(&nat, key, val);}    
  }
  if (in_section) { sb_append(&nat, "}"); in_section=0; have_nat=1; }

  if (have_network && network_value[0]) { sb_append(&json, ",\"network\":"); json_escape_append(&json, network_value); }
  if (have_nat) { sb_append(&json, ",\"natConfig\":"); sb_append(&json, nat.buf?nat.buf:"{}"); }

  sb_append(&json, "}");
  fclose(f);
  out->buf = json.buf; out->len = json.len; out->cap = json.cap;
  sb_free(&obj); sb_free(&network); sb_free(&nat);
  fprintf(stdout, "[mqtt-pub] build_wifi_json: built JSON length=%zu bytes\n", out->len); fflush(stdout);
  return 0;
}

static int publish_config_json(const char *json) {
  MqttIds ids; if (load_ids(&ids)!=0) return -1;
  struct mosquitto *mosq = NULL; int rc = mosquitto_lib_init(); if (rc!=MOSQ_ERR_SUCCESS) return -2;
  mosq = mosquitto_new(NULL, true, NULL); if (!mosq) { mosquitto_lib_cleanup(); return -3; }
  mosquitto_username_pw_set(mosq, MQTT_USERNAME, MQTT_PASSWORD);
  mosquitto_publish_callback_set(mosq, on_publish);
  rc = mosquitto_connect(mosq, MQTT_HOST, MQTT_PORT, 60);
  if (rc!=MOSQ_ERR_SUCCESS) { mosquitto_destroy(mosq); mosquitto_lib_cleanup(); return -4; }
  char topic[512]; snprintf(topic, sizeof(topic), "cloud/to/device/%s/%s/config", ids.device_id, ids.serial_num);
  fprintf(stdout, "[mqtt-pub] publishing to topic=%s payload_len=%zu\n", topic, strlen(json)); fflush(stdout);
  fprintf(stdout, "[mqtt-pub] payload: %s\n", json);
  fflush(stdout);
  g_puback_received = 0;
  rc = mosquitto_publish(mosq, NULL, topic, (int)strlen(json), json, 1, false);
  if (rc!=MOSQ_ERR_SUCCESS) fprintf(stderr, "[mqtt-pub] publish error: %s (%d)\n", mosquitto_strerror(rc), rc);
  /* Pump network until PUBACK or timeout (QoS1) */
  struct timespec start; clock_gettime(CLOCK_MONOTONIC, &start);
  while (!g_puback_received) {
    int lrc = mosquitto_loop(mosq, 50, 1);
    if (lrc != MOSQ_ERR_SUCCESS) break;
    struct timespec now; clock_gettime(CLOCK_MONOTONIC, &now);
    long elapsed_ms = (now.tv_sec - start.tv_sec) * 1000 + (now.tv_nsec - start.tv_nsec) / 1000000;
    if (elapsed_ms > 1500) break;
  }
  mosquitto_disconnect(mosq); mosquitto_destroy(mosq); mosquitto_lib_cleanup();
  return (rc==MOSQ_ERR_SUCCESS)?0:-5;
}

/* Called by conf_on_change.c or by main via signal */
void on_config_file_changed(const char *dir, const char *name, const char *action) {
  (void)action;
  if (!name) return;
  fprintf(stdout, "[mqtt-pub] file change detected: dir=%s name=%s action=%s\n", dir?dir:"", name, action?action:"" ); fflush(stdout);
  if (strcmp(name, "wifi.conf") == 0) {
    StrBuf json; sb_init(&json);
    if (build_wifi_json(&json)==0) {
      int rc = publish_config_json(json.buf?json.buf:"{}");
      if (rc!=0) fprintf(stderr, "[mqtt-pub] publish failed rc=%d\n", rc);
      else fprintf(stdout, "[mqtt-pub] published config (%zu bytes)\n", json.len);
    } else {
      fprintf(stderr, "[mqtt-pub] failed to build JSON from wifi.conf\n");
    }
    sb_free(&json);
    return;
  }
  const char *suffix = NULL;
  if (strcmp(name, "cmd.conf") == 0) suffix = "cmd";
  else if (strcmp(name, "bw_list.conf") == 0) suffix = "bw_list";
  else if (strcmp(name, "rate_limit.conf") == 0) suffix = "rate_limit";
  if (!suffix) { fprintf(stdout, "[mqtt-pub] no topic mapping for %s; ignored\n", name); fflush(stdout); return; }

  char path[PATH_MAX];
  if (snprintf(path, sizeof(path), "%s/%s", dir?dir:"config", name) >= (int)sizeof(path)) {
    fprintf(stderr, "[mqtt-pub] path too long for %s\n", name); return;
  }
  FILE *f = fopen(path, "r");
  if (!f) { perror("open conf"); return; }
  StrBuf payload; sb_init(&payload);
  
  /* Special handling for cmd.conf: parse lines, ignore #, extract value after cmd= */
  if (strcmp(name, "cmd.conf") == 0) {
    char line[1024];
    int found_cmd = 0;
    while (fgets(line, sizeof(line), f)) {
      rstrip(line);
      /* Skip empty lines and lines starting with # */
      if (!line[0] || line[0] == '#') continue;
      /* Look for cmd= */
      if (strncmp(line, "cmd=", 4) == 0) {
        char *cmd_value = line + 4;
        ltrim_inplace(&cmd_value);
        if (*cmd_value) {
          sb_append(&payload, cmd_value);
          found_cmd = 1;
          break; /* Use first non-commented cmd= line */
        }
      }
    }
    if (!found_cmd) {
      fprintf(stderr, "[mqtt-pub] no valid cmd= line found in cmd.conf\n");
      fclose(f);
      sb_free(&payload);
      return;
    }
  } else {
    /* For other conf files, read entire file content */
    char buf[1024]; size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
      if (sb_reserve(&payload, n+1)) { fclose(f); sb_free(&payload); return; }
      memcpy(payload.buf + payload.len, buf, n); payload.len += n; payload.buf[payload.len] = '\0';
    }
  }
  fclose(f);

  MqttIds ids; if (load_ids(&ids)!=0) { sb_free(&payload); return; }
  struct mosquitto *mosq = NULL; int rc = mosquitto_lib_init(); if (rc!=MOSQ_ERR_SUCCESS) { sb_free(&payload); return; }
  mosq = mosquitto_new(NULL, true, NULL); if (!mosq) { mosquitto_lib_cleanup(); sb_free(&payload); return; }
  mosquitto_username_pw_set(mosq, MQTT_USERNAME, MQTT_PASSWORD);
  mosquitto_publish_callback_set(mosq, on_publish);
  rc = mosquitto_connect(mosq, MQTT_HOST, MQTT_PORT, 60);
  if (rc!=MOSQ_ERR_SUCCESS) { mosquitto_destroy(mosq); mosquitto_lib_cleanup(); sb_free(&payload); return; }
  char topic[512]; snprintf(topic, sizeof(topic), "cloud/to/device/%s/%s/%s", ids.device_id, ids.serial_num, suffix);
  fprintf(stdout, "[mqtt-pub] publishing to topic=%s payload_len=%zu\n", topic, payload.len); fflush(stdout);
  fprintf(stdout, "[mqtt-pub] payload: %.*s\n", (int)payload.len, payload.buf);
  g_puback_received = 0;
  rc = mosquitto_publish(mosq, NULL, topic, (int)payload.len, payload.buf, 1, false);
  if (rc!=MOSQ_ERR_SUCCESS) fprintf(stderr, "[mqtt-pub] publish error: %s (%d)\n", mosquitto_strerror(rc), rc);
  struct timespec start; clock_gettime(CLOCK_MONOTONIC, &start);
  while (!g_puback_received) {
    int lrc = mosquitto_loop(mosq, 50, 1);
    if (lrc != MOSQ_ERR_SUCCESS) break;
    struct timespec now; clock_gettime(CLOCK_MONOTONIC, &now);
    long elapsed_ms = (now.tv_sec - start.tv_sec) * 1000 + (now.tv_nsec - start.tv_nsec) / 1000000;
    if (elapsed_ms > 1500) break;
  }
  mosquitto_disconnect(mosq); mosquitto_destroy(mosq); mosquitto_lib_cleanup();
  sb_free(&payload);
}


