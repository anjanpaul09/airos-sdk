#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <stdint.h>
#include <mosquitto.h>

/*
Simple MQTT subscriber for a fixed list of topics.

Configuration read from "config/mqtt.conf" (key=value):
  device_id=ABCDEF123456
  serial_num=SN001

Broker settings are compiled in via defines below. Add/remove topics by
editing TOPIC_SUFFIXES (one-line change per topic).
*/

/* Compiled-in broker settings */
#define MQTT_HOST "69.30.254.180"
#define MQTT_PORT 35930
#define MQTT_USERNAME "bluesyobsignates"
#define MQTT_PASSWORD "PNJxhzMX2jkRVBG3"

typedef struct MqttConfig {
  char device_id[128];
  char serial_num[128];
} MqttConfig;

/* One-line add/remove to change subscribed topics */
static const char *TOPIC_SUFFIXES[] = {
  "device",
  "vif",
  "client",
  "neighbor",
};

typedef struct SubscribeContext {
  char device_id[128];
  char serial_num[128];
} SubscribeContext;

/* Globals for threaded variant */
static struct mosquitto *g_mosq = NULL;
static int g_lib_initialized = 0;
static SubscribeContext g_ctx;

/* --- Simple JSON-ish extraction helpers (very lightweight, tailored) --- */
static int json_extract_str(const char *buf, size_t buflen, const char *key,
                            const char *scope_start, const char *scope_end,
                            char *out, size_t outsz) {
  char pat[128];
  snprintf(pat, sizeof(pat), "\"%s\"", key);
  const char *start = scope_start ? scope_start : buf;
  const char *end = scope_end ? scope_end : buf + buflen;
  const char *k = strstr(start, pat);
  if (!k || k >= end) return 0;
  const char *colon = strchr(k + strlen(pat), ':'); if (!colon || colon >= end) return 0;
  const char *q1 = strchr(colon, '"'); if (!q1 || q1 >= end) return 0;
  const char *q2 = strchr(q1 + 1, '"'); if (!q2 || q2 > end) return 0;
  size_t copy = (size_t)(q2 - (q1 + 1)); if (copy >= outsz) copy = outsz - 1;
  memcpy(out, q1 + 1, copy); out[copy] = '\0';
  return 1;
}

static int json_extract_int(const char *buf, size_t buflen, const char *key,
                            const char *scope_start, const char *scope_end,
                            long long *out) {
  char pat[128];
  snprintf(pat, sizeof(pat), "\"%s\"", key);
  const char *start = scope_start ? scope_start : buf;
  const char *end = scope_end ? scope_end : buf + buflen;
  const char *k = strstr(start, pat);
  if (!k || k >= end) return 0;
  const char *colon = strchr(k + strlen(pat), ':'); if (!colon || colon >= end) return 0;
  char *nend = NULL;
  long long v = strtoll(colon + 1, &nend, 10);
  if (!nend || nend <= colon + 1) return 0;
  *out = v;
  return 1;
}

/* format milliseconds into HH:MM:SS */
static void format_duration_hms(long long duration_ms, char *out, size_t outsz) {
  if (!out || outsz == 0) return;
  long long total_sec = duration_ms / 1000;
  long long h = total_sec / 3600;
  long long m = (total_sec % 3600) / 60;
  long long s = total_sec % 60;
  if (h < 0) h = 0;
  if (m < 0) m = 0;
  if (s < 0) s = 0;
  snprintf(out, outsz, "%lld:%02lld:%02lld", h, m, s);
}

static void rstrip(char *s) {
  if (!s) return;
  size_t n = strlen(s);
  while (n > 0 && (s[n-1] == '\n' || s[n-1] == '\r' || isspace((unsigned char)s[n-1]))) {
    s[n-1] = '\0';
    n--;
  }
}

static void lstrip_inplace(char **p) {
  if (!p || !*p) return;
  while (**p && isspace((unsigned char)**p)) (*p)++;
}

static void trim_inplace(char **key, char **val) {
  lstrip_inplace(key);
  lstrip_inplace(val);
  if (*key) {
    char *end = *key + strlen(*key);
    while (end > *key && isspace((unsigned char)end[-1])) { end--; }
    *end = '\0';
  }
  if (*val) {
    char *end = *val + strlen(*val);
    while (end > *val && isspace((unsigned char)end[-1])) { end--; }
    *end = '\0';
  }
}

static void set_default_mqtt(MqttConfig *cfg) {
  memset(cfg, 0, sizeof(*cfg));
}

static int load_mqtt_conf(const char *path, MqttConfig *out) {
  set_default_mqtt(out);

  FILE *f = fopen(path, "r");
  if (!f) {
    /* Missing file: proceed with defaults for broker, but device/serial required */
    return 0;
  }

  char line[512];
  while (fgets(line, sizeof(line), f)) {
    rstrip(line);
    if (line[0] == '\0') continue;
    if (line[0] == '#') continue;
    char *eq = strchr(line, '=');
    if (!eq) continue;
    *eq = '\0';
    char *key = line;
    char *val = eq + 1;
    trim_inplace(&key, &val);
    if (strcasecmp(key, "device_id") == 0 || strcasecmp(key, "device-id") == 0) {
      snprintf(out->device_id, sizeof(out->device_id), "%s", val);
    } else if (strcasecmp(key, "serial_num") == 0 || strcasecmp(key, "serial-num") == 0) {
      snprintf(out->serial_num, sizeof(out->serial_num), "%s", val);
    }
  }

  fclose(f);
  return 0;
}

static void on_connect(struct mosquitto *mosq, void *userdata, int rc) {
  if (rc != 0) {
    fprintf(stderr, "[mqtt] connect failed: rc=%d\n", rc);
    return;
  }
  fprintf(stdout, "[mqtt] connected\n");
  fflush(stdout);

  SubscribeContext *ctx = (SubscribeContext *)userdata;
  if (!ctx) return;

  char base[512];
  snprintf(base, sizeof(base), "dev/to/cloud/%s/%s/", ctx->device_id, ctx->serial_num);
  size_t base_len = strlen(base);

  for (size_t i = 0; i < sizeof(TOPIC_SUFFIXES)/sizeof(TOPIC_SUFFIXES[0]); ++i) {
    const char *suffix = TOPIC_SUFFIXES[i];
    char topic[768];
    memcpy(topic, base, base_len);
    strncpy(topic + base_len, suffix, sizeof(topic) - base_len - 1);
    topic[sizeof(topic) - 1] = '\0';
    int s_rc = mosquitto_subscribe(mosq, NULL, topic, 0);
    if (s_rc != MOSQ_ERR_SUCCESS) {
      fprintf(stderr, "[mqtt] subscribe failed: %s (%d) on %s\n", mosquitto_strerror(s_rc), s_rc, topic);
    } else {
      fprintf(stdout, "[mqtt] subscribed %s\n", topic);
    }
  }
  fflush(stdout);
}

static void on_message(struct mosquitto *mosq, void *userdata, const struct mosquitto_message *msg) {
  (void)mosq;
  (void)userdata;
  const char *payload = (const char *)msg->payload;
  size_t len = (size_t)msg->payloadlen;

  /* Decide by topic suffix */
  const char *topic = msg->topic;
  size_t tlen = strlen(topic);
  const char *which = NULL;
  if (tlen >= 4 && strcmp(topic + tlen - 4, "/vif") == 0) which = "vif";
  else if (tlen >= 7 && strcmp(topic + tlen - 7, "/device") == 0) which = "device";
  else if (tlen >= 7 && strcmp(topic + tlen - 7, "/client") == 0) which = "client";
  else if (tlen >= 9 && strcmp(topic + tlen - 9, "/neighbor") == 0) which = "neighbor";

  if (!which) {
    fprintf(stdout, "[mqtt] %s => %.*s\n", topic, (int)len, payload);
    fflush(stdout);
    return;
  }

  /* Common header fields */
  char serial[128] = {0}, devid[128] = {0}, mac[128] = {0};
  long long tms = 0;
  json_extract_str(payload, len, "serialNum", NULL, NULL, serial, sizeof(serial));
  json_extract_str(payload, len, "deviceId", NULL, NULL, devid, sizeof(devid));
  json_extract_str(payload, len, "macAddr", NULL, NULL, mac, sizeof(mac));
  json_extract_int(payload, len, "tms", NULL, NULL, &tms);

  char timestr[64] = {0};
  time_t ts_sec = (time_t)(tms / 1000);
  struct tm ut;
  if (gmtime_r(&ts_sec, &ut) != NULL) {
    strftime(timestr, sizeof(timestr), "%a %b %e %H:%M:%S %Y", &ut);
  }

  if (strcmp(which, "client") == 0) {
    char header[256];
    snprintf(header, sizeof(header), "Topic=Clients (%s) deviceId=%s serialNum=%s macAddr=%s", timestr[0] ? timestr : "", devid, serial, mac);
    fprintf(stdout, "%s\n", header);
    for (size_t i = 0; header[i] != '\0'; ++i) fputc('=', stdout);
    fputc('\n', stdout);
    fprintf(stdout, "%-17s %-16s %-15s %-16s %11s %12s %-11s %-10s %8s %-7s %13s %13s %6s\n",
      "macAddress", "hostname", "ipAddress", "ssid", "isConnected", "duration", "clientType", "osInfo", "channel", "band", "rxBytes", "txBytes", "rssi");
    fprintf(stdout, "%-17s %-16s %-15s %-16s %11s %12s %-11s %-10s %8s %-7s %13s %13s %6s\n",
      "-----------------", "----------------", "---------------", "----------------", "-----------", "----------", "-----------", "----------", "--------", "-------", "-------------", "-------------", "------");
    /* Iterate by occurrences of "macAddress" and extract fields within object scope */
    const char *p = payload;
    while ((p = strstr(p, "\"macAddress\"")) != NULL) {
      const char *obj_start = p; while (obj_start > payload && *obj_start != '{') obj_start--;
      const char *obj_end = strchr(p, '}'); if (!obj_end) break;
      char macAddress[64]={0}, hostname[128]={0}, ipAddress[64]={0}, ssid[128]={0}, clientType[64]={0}, osInfo[64]={0}, band[64]={0};
      long long isConnected=0, durationMs=0, channel=0, rxBytes=0, txBytes=0, rssi=0;
      json_extract_str(payload, len, "macAddress", obj_start, obj_end, macAddress, sizeof(macAddress));
      json_extract_str(payload, len, "hostname", obj_start, obj_end, hostname, sizeof(hostname));
      json_extract_str(payload, len, "ipAddress", obj_start, obj_end, ipAddress, sizeof(ipAddress));
      json_extract_str(payload, len, "ssid", obj_start, obj_end, ssid, sizeof(ssid));
      json_extract_int(payload, len, "isConnected", obj_start, obj_end, &isConnected);
      json_extract_int(payload, len, "durationMs", obj_start, obj_end, &durationMs);
      json_extract_str(payload, len, "clientType", obj_start, obj_end, clientType, sizeof(clientType));
      json_extract_str(payload, len, "osInfo", obj_start, obj_end, osInfo, sizeof(osInfo));
      json_extract_int(payload, len, "channel", obj_start, obj_end, &channel);
      json_extract_str(payload, len, "band", obj_start, obj_end, band, sizeof(band));
      /* stats nested */
      json_extract_int(payload, len, "rxBytes", obj_start, obj_end, &rxBytes);
      json_extract_int(payload, len, "txBytes", obj_start, obj_end, &txBytes);
      json_extract_int(payload, len, "rssi", obj_start, obj_end, &rssi);
      char durationHMS[32];
      format_duration_hms(durationMs, durationHMS, sizeof(durationHMS));
      fprintf(stdout, "%-17s %-16s %-15s %-16s %11lld %12s %-11s %-10s %8lld %-7s %13lld %13lld %6lld\n",
        macAddress, hostname, ipAddress, ssid, isConnected, durationHMS, clientType, osInfo, channel, band, rxBytes, txBytes, rssi);
      p = obj_end + 1;
    }
    fflush(stdout);
    return;
  }

  if (strcmp(which, "vif") == 0) {
    char header[256];
    snprintf(header, sizeof(header), "Topic=VIFs (%s) deviceId=%s serialNum=%s macAddr=%s", timestr[0] ? timestr : "", devid, serial, mac);
    fprintf(stdout, "%s\n", header);
    for (size_t i = 0; header[i] != '\0'; ++i) fputc('=', stdout);
    fputc('\n', stdout);
    fprintf(stdout, "%-8s %8s %8s %21s\n", "band", "channel", "txpower", "channel_utilization");
    fprintf(stdout, "%-8s %8s %8s %21s\n", "--------", "--------", "--------", "---------------------");
    const char *p = payload;
    while ((p = strstr(p, "\"channel_utilization\"")) != NULL) {
      const char *obj_start = p; while (obj_start > payload && *obj_start != '{') obj_start--;
      const char *obj_end = strchr(p, '}'); if (!obj_end) break;
      char band[64]={0}; long long channel=0, txpower=0, util=0;
      json_extract_str(payload, len, "band", obj_start, obj_end, band, sizeof(band));
      json_extract_int(payload, len, "channel", obj_start, obj_end, &channel);
      json_extract_int(payload, len, "txpower", obj_start, obj_end, &txpower);
      json_extract_int(payload, len, "channel_utilization", obj_start, obj_end, &util);
      fprintf(stdout, "%-8s %8lld %8lld %21lld\n", band, channel, txpower, util);
      p = obj_end + 1;
    }

    fprintf(stdout, "\n");
    fprintf(stdout, "%-8s %-24s %12s %13s %16s\n", "radio", "ssid", "statNumSta", "statUplinkMb", "statDownlinkMb");
    fprintf(stdout, "%-8s %-24s %12s %13s %16s\n", "--------", "------------------------", "------------", "-------------", "----------------");
    p = payload;
    while ((p = strstr(p, "\"statDownlinkMb\"")) != NULL) {
      const char *obj_start = p; while (obj_start > payload && *obj_start != '{') obj_start--;
      const char *obj_end = strchr(p, '}'); if (!obj_end) break;
      char radio[64]={0}, ssid[128]={0}; long long num=0, up=0, down=0;
      json_extract_str(payload, len, "radio", obj_start, obj_end, radio, sizeof(radio));
      json_extract_str(payload, len, "ssid", obj_start, obj_end, ssid, sizeof(ssid));
      json_extract_int(payload, len, "statNumSta", obj_start, obj_end, &num);
      json_extract_int(payload, len, "statUplinkMb", obj_start, obj_end, &up);
      json_extract_int(payload, len, "statDownlinkMb", obj_start, obj_end, &down);
      fprintf(stdout, "%-8s %-24s %12lld %13lld %16lld\n", radio, ssid, num, up, down);
      p = obj_end + 1;
    }
    fflush(stdout);
    return;
  }

  if (strcmp(which, "device") == 0) {
    char header[256];
    snprintf(header, sizeof(header), "Topic=Device (%s) deviceId=%s serialNum=%s macAddr=%s", timestr[0] ? timestr : "", devid, serial, mac);
    fprintf(stdout, "%s\n", header);
    for (size_t i = 0; header[i] != '\0'; ++i) fputc('=', stdout);
    fputc('\n', stdout);
    fprintf(stdout, "System\n");
    fprintf(stdout, "%8s %9s %12s %9s %12s %16s\n", "uptime", "downtime", "totalClient", "uplinkMb", "downlinkMb", "totalTrafficMb");
    fprintf(stdout, "%8s %9s %12s %9s %12s %16s\n", "--------", "---------", "------------", "---------", "------------", "----------------");
    long long uptime=0, downtime=0, totalClient=0, uplinkMb=0, downlinkMb=0, totalTrafficMb=0;
    json_extract_int(payload, len, "uptime", NULL, NULL, &uptime);
    json_extract_int(payload, len, "downtime", NULL, NULL, &downtime);
    json_extract_int(payload, len, "totalClient", NULL, NULL, &totalClient);
    json_extract_int(payload, len, "uplinkMb", NULL, NULL, &uplinkMb);
    json_extract_int(payload, len, "downlinkMb", NULL, NULL, &downlinkMb);
    json_extract_int(payload, len, "totalTrafficMb", NULL, NULL, &totalTrafficMb);
    fprintf(stdout, "%8lld %9lld %12lld %9lld %12lld %16lld\n", uptime, downtime, totalClient, uplinkMb, downlinkMb, totalTrafficMb);

    /* Memory and CPU sections intentionally not printed */
    fflush(stdout);
    return;
  }

  if (strcmp(which, "neighbor") == 0) {
    char header[256];
    snprintf(header, sizeof(header), "Topic=Neighbors (%s) deviceId=%s serialNum=%s macAddr=%s", timestr[0] ? timestr : "", devid, serial, mac);
    fprintf(stdout, "%s\n", header);
    for (size_t i = 0; header[i] != '\0'; ++i) fputc('=', stdout);
    fputc('\n', stdout);
    
    /* First pass: count entries */
    int entry_count = 0;
    const char *p_count = payload;
    while ((p_count = strstr(p_count, "\"bssid\"")) != NULL) {
      entry_count++;
      p_count++;
    }
    
    fprintf(stdout, "Entries: %d\n", entry_count);
    fprintf(stdout, "%-18s %-24s %6s %8s %14s %-7s\n", "bssid", "ssid", "rssi", "channel", "channelWidth", "band");
    fprintf(stdout, "%-18s %-24s %6s %8s %14s %-7s\n", "------------------", "------------------------", "------", "--------", "--------------", "-------");
    
    /* Second pass: extract and display entries */
    p_count = payload;
    while ((p_count = strstr(p_count, "\"bssid\"")) != NULL) {
      const char *obj_start = p_count; while (obj_start > payload && *obj_start != '{') obj_start--;
      const char *obj_end = strchr(p_count, '}'); if (!obj_end) break;
      char bssid[64]={0}, ssid[128]={0}, band[64]={0};
      long long rssi=0, channel=0, channelWidth=0;
      json_extract_str(payload, len, "bssid", obj_start, obj_end, bssid, sizeof(bssid));
      json_extract_str(payload, len, "ssid", obj_start, obj_end, ssid, sizeof(ssid));
      json_extract_int(payload, len, "rssi", obj_start, obj_end, &rssi);
      json_extract_int(payload, len, "channel", obj_start, obj_end, &channel);
      json_extract_int(payload, len, "channelWidth", obj_start, obj_end, &channelWidth);
      json_extract_str(payload, len, "band", obj_start, obj_end, band, sizeof(band));
      /* Fix RSSI if it's a wrapped unsigned value (common in WiFi drivers) */
      /* Large negative values indicate unsigned wrap: convert by adding 2^32 */
      /* Example: -4252017705 + 4294967296 = 42949591, then convert to signed: 42949591 - 4294967296 = -105 */
      if (rssi < -1000) {
        unsigned long long unsigned_rssi = (unsigned long long)(rssi + (long long)UINT32_MAX + 1);
        if (unsigned_rssi > INT32_MAX) {
          rssi = (long long)unsigned_rssi - (long long)UINT32_MAX - 1;
        } else {
          rssi = (long long)unsigned_rssi;
        }
      } else if (rssi > 1000) {
        rssi = rssi - (long long)UINT32_MAX - 1;
      }
      fprintf(stdout, "%-18s %-24s %6lld %8lld %14lld %-7s\n", bssid, ssid[0] ? ssid : "(empty)", rssi, channel, channelWidth, band);
      p_count = obj_end + 1;
    }
    fflush(stdout);
    return;
  }
}

int start_mqtt_subscriber(void) {
  MqttConfig cfg;
  load_mqtt_conf("config/mqtt.conf", &cfg);

  if (cfg.device_id[0] == '\0' || cfg.serial_num[0] == '\0') {
    fprintf(stderr, "[mqtt] device_id and serial_num are required in config/mqtt.conf\n");
    return 1;
  }

  int rc = mosquitto_lib_init();
  if (rc != MOSQ_ERR_SUCCESS) {
    fprintf(stderr, "[mqtt] lib init failed: %s\n", mosquitto_strerror(rc));
    return 2;
  }

  SubscribeContext ctx;
  memset(&ctx, 0, sizeof(ctx));
  snprintf(ctx.device_id, sizeof(ctx.device_id), "%s", cfg.device_id);
  snprintf(ctx.serial_num, sizeof(ctx.serial_num), "%s", cfg.serial_num);

  struct mosquitto *mosq = mosquitto_new(NULL, true, &ctx);
  if (!mosq) {
    fprintf(stderr, "[mqtt] new client failed\n");
    mosquitto_lib_cleanup();
    return 3;
  }

  mosquitto_connect_callback_set(mosq, on_connect);
  mosquitto_message_callback_set(mosq, on_message);

  mosquitto_username_pw_set(mosq, MQTT_USERNAME, MQTT_PASSWORD);
  rc = mosquitto_connect(mosq, MQTT_HOST, MQTT_PORT, 60);
  if (rc != MOSQ_ERR_SUCCESS) {
    fprintf(stderr, "[mqtt] connect error: %s (%d)\n", mosquitto_strerror(rc), rc);
    mosquitto_destroy(mosq);
    mosquitto_lib_cleanup();
    return 4;
  }

  /* Loop forever; caller may run in a dedicated thread if needed */
  rc = mosquitto_loop_forever(mosq, -1, 1);
  fprintf(stderr, "[mqtt] loop exited: %s (%d)\n", mosquitto_strerror(rc), rc);

  mosquitto_destroy(mosq);
  mosquitto_lib_cleanup();
  return rc == MOSQ_ERR_SUCCESS ? 0 : 6;
}

#define MQTT_THREADED 1

#if MQTT_THREADED
/* Start subscriber in a background thread; returns 0 on success. */
int start_mqtt_subscriber_threaded(void) {
  if (!g_lib_initialized) {
    int rc = mosquitto_lib_init();
    if (rc != MOSQ_ERR_SUCCESS) {
      fprintf(stderr, "[mqtt] lib init failed: %s\n", mosquitto_strerror(rc));
      return 2;
    }
    g_lib_initialized = 1;
  }

  MqttConfig cfg;
  load_mqtt_conf("config/mqtt.conf", &cfg);
  if (cfg.device_id[0] == '\0' || cfg.serial_num[0] == '\0') {
    fprintf(stderr, "[mqtt] device_id and serial_num are required in config/mqtt.conf\n");
    return 1;
  }

  memset(&g_ctx, 0, sizeof(g_ctx));
  snprintf(g_ctx.device_id, sizeof(g_ctx.device_id), "%s", cfg.device_id);
  snprintf(g_ctx.serial_num, sizeof(g_ctx.serial_num), "%s", cfg.serial_num);

  g_mosq = mosquitto_new(NULL, true, &g_ctx);
  if (!g_mosq) {
    fprintf(stderr, "[mqtt] new client failed\n");
    return 3;
  }

  mosquitto_connect_callback_set(g_mosq, on_connect);
  mosquitto_message_callback_set(g_mosq, on_message);
  mosquitto_username_pw_set(g_mosq, MQTT_USERNAME, MQTT_PASSWORD);

  int rc = mosquitto_connect(g_mosq, MQTT_HOST, MQTT_PORT, 60);
  if (rc != MOSQ_ERR_SUCCESS) {
    fprintf(stderr, "[mqtt] connect error: %s (%d)\n", mosquitto_strerror(rc), rc);
    mosquitto_destroy(g_mosq);
    g_mosq = NULL;
    return 4;
  }

  rc = mosquitto_loop_start(g_mosq);
  if (rc != MOSQ_ERR_SUCCESS) {
    fprintf(stderr, "[mqtt] loop start error: %s (%d)\n", mosquitto_strerror(rc), rc);
    mosquitto_disconnect(g_mosq);
    mosquitto_destroy(g_mosq);
    g_mosq = NULL;
    return 5;
  }

  fprintf(stdout, "[mqtt] threaded subscriber started\n");
  fflush(stdout);
  return 0;
}

/* Stop the background thread and clean up. */
void stop_mqtt_subscriber_threaded(void) {
  if (g_mosq) {
    mosquitto_disconnect(g_mosq);
    mosquitto_loop_stop(g_mosq, false);
    mosquitto_destroy(g_mosq);
    g_mosq = NULL;
  }
  if (g_lib_initialized) {
    mosquitto_lib_cleanup();
    g_lib_initialized = 0;
  }
  fprintf(stdout, "[mqtt] threaded subscriber stopped\n");
  fflush(stdout);
}
#endif

#ifndef MOS_SUB_LIBRARY
int main(void) {
  return start_mqtt_subscriber();
}
#endif


