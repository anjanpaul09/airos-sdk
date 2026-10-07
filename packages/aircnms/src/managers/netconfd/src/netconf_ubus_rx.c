#include <libubus.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <json-c/json.h>
#include <openssl/evp.h>
#include <ev.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <stdint.h>
#include "netconf.h"

bool netconf_validate_config_string(const char *data, size_t len, char *error, size_t error_len);

static struct ubus_context *ctx = NULL;
static struct ev_loop *loop = NULL;
static ev_io ubus_watcher;

#define IPC_BUFFER_SIZE 8064
#define MAX_UBUS_METHODS 2
#define MAX_RATE_MBPS 10000

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

enum {
    RL_INTERFACE,
    RL_INTERFACE_UPLINK,
    RL_INTERFACE_DOWNLINK,
    __RL_INTERFACE_MAX
};

enum {
    RL_CLIENT_MAC,
    RL_CLIENT_UPLINK,
    RL_CLIENT_DOWNLINK,
    __RL_CLIENT_MAX
};

static const struct blobmsg_policy rl_interface_policy[__RL_INTERFACE_MAX] = {
    [RL_INTERFACE] = { .name = "interface", .type = BLOBMSG_TYPE_STRING },
    [RL_INTERFACE_UPLINK] = { .name = "uplink", .type = BLOBMSG_TYPE_INT32 },
    [RL_INTERFACE_DOWNLINK] = { .name = "downlink", .type = BLOBMSG_TYPE_INT32 },
};

static const struct blobmsg_policy rl_client_policy[__RL_CLIENT_MAX] = {
    [RL_CLIENT_MAC] = { .name = "mac", .type = BLOBMSG_TYPE_STRING },
    [RL_CLIENT_UPLINK] = { .name = "uplink", .type = BLOBMSG_TYPE_INT32 },
    [RL_CLIENT_DOWNLINK] = { .name = "downlink", .type = BLOBMSG_TYPE_INT32 },
};

static bool parse_macaddr(const char *macstr, uint8_t mac[6])
{
    unsigned int octets[6];
    char tail;

    if (!macstr)
        return false;

    if (sscanf(macstr, "%02x:%02x:%02x:%02x:%02x:%02x%c",
               &octets[0], &octets[1], &octets[2],
               &octets[3], &octets[4], &octets[5], &tail) != 6) {
        return false;
    }

    for (int i = 0; i < 6; i++) {
        if (octets[i] > 0xff)
            return false;
        mac[i] = (uint8_t)octets[i];
    }

    return true;
}

static int rl_rate_from_attr(struct blob_attr *attr)
{
    return attr ? (int)blobmsg_get_u32(attr) : 0;
}

static int ubus_reply_rate_limit(struct ubus_context *ctx,
                                 struct ubus_request_data *req,
                                 bool success,
                                 const char *target_type,
                                 const char *target,
                                 int uplink,
                                 int downlink,
                                 const char *message)
{
    struct blob_buf b = {0};

    blob_buf_init(&b, 0);
    blobmsg_add_u8(&b, "success", success);
    blobmsg_add_string(&b, "targetType", target_type);
    blobmsg_add_string(&b, "target", target ? target : "");
    blobmsg_add_u32(&b, "uplink", uplink);
    blobmsg_add_u32(&b, "downlink", downlink);
    blobmsg_add_string(&b, "message", message);
    ubus_send_reply(ctx, req, b.head);
    blob_buf_free(&b);

    return UBUS_STATUS_OK;
}

static int ubus_reply_config(struct ubus_context *ctx,
                             struct ubus_request_data *req,
                             bool accepted,
                             const char *message,
                             const netconf_job_snapshot_t *job,
                             bool duplicate)
{
    struct blob_buf reply = {0};

    blob_buf_init(&reply, 0);
    blobmsg_add_u8(&reply, "accepted", accepted);
    blobmsg_add_string(&reply, "status", job ? netconf_job_state_string(job->state) :
                                      (accepted ? "QUEUED" : "REJECTED"));
    blobmsg_add_string(&reply, "message", message ? message : "");
    blobmsg_add_u32(&reply, "queueDepth", (uint32_t)netconf_queue_length());
    if (job) {
        blobmsg_add_string(&reply, "schema", "air.netconfd.job.v1");
        blobmsg_add_string(&reply, "job_id", job->job_id);
        blobmsg_add_u64(&reply, "revision", job->revision);
        blobmsg_add_u64(&reply, "local_seq", job->revision);
        blobmsg_add_string(&reply, "config_hash", job->config_hash);
        blobmsg_add_string(&reply, "reason_code", job->reason_code);
        blobmsg_add_u8(&reply, "duplicate", duplicate);
    }
    ubus_send_reply(ctx, req, reply.head);
    blob_buf_free(&reply);
    return accepted ? UBUS_STATUS_OK : UBUS_STATUS_INVALID_ARGUMENT;
}

static int compare_json_keys(const void *a, const void *b)
{
    const char * const *sa = a;
    const char * const *sb = b;
    return strcmp(*sa, *sb);
}

static struct json_object *canonicalize_json(struct json_object *obj)
{
    if (!obj) return NULL;
    enum json_type type = json_object_get_type(obj);

    if (type == json_type_object) {
        struct json_object *canon = json_object_new_object();
        int count = 0;
        json_object_object_foreach(obj, k1, v1) {
            (void)k1; (void)v1;
            count++;
        }
        if (count == 0) return canon;

        const char **keys = malloc(count * sizeof(const char *));
        if (!keys) return canon;

        int idx = 0;
        json_object_object_foreach(obj, k2, v2) {
            (void)v2;
            keys[idx++] = k2;
        }

        qsort(keys, count, sizeof(const char *), compare_json_keys);

        for (int i = 0; i < count; i++) {
            struct json_object *child = json_object_object_get(obj, keys[i]);
            json_object_object_add(canon, keys[i], canonicalize_json(child));
        }
        free(keys);
        return canon;
    } else if (type == json_type_array) {
        struct json_object *canon = json_object_new_array();
        size_t len = json_object_array_length(obj);
        for (size_t i = 0; i < len; i++) {
            struct json_object *elem = json_object_array_get_idx(obj, i);
            json_object_array_add(canon, canonicalize_json(elem));
        }
        return canon;
    }

    /* Clone scalar values via string serialization to avoid json-c / jansson symbol conflict */
    const char *s = json_object_to_json_string_ext(obj, JSON_C_TO_STRING_PLAIN);
    return s ? json_tokener_parse(s) : NULL;
}

static bool payload_managed_config_hash(const void *data, size_t length,
                                        char out[NETCONF_JOB_HASH_LEN])
{
    static const char *managed_keys[] = { "natConfig", "network", "radio", "vif" };
    struct json_tokener *tokener = NULL;
    struct json_object *root = NULL;
    struct json_object *managed = NULL;
    struct json_object *canonical = NULL;
    enum json_tokener_error error;
    const char *canon_str;
    size_t canon_len;
    EVP_MD_CTX *evp_ctx = NULL;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    bool ok = false;

    if (!data || !length || !out) return false;

    tokener = json_tokener_new();
    if (!tokener) return false;

    root = json_tokener_parse_ex(tokener, data, (int)length);
    error = json_tokener_get_error(tokener);
    if (error != json_tokener_success || !root ||
        json_object_get_type(root) != json_type_object) {
        goto out;
    }

    managed = json_object_new_object();
    if (!managed) goto out;

    /* Extract managed blocks only, in sorted key order */
    for (size_t i = 0; i < ARRAY_SIZE(managed_keys); i++) {
        struct json_object *val = NULL;
        if (json_object_object_get_ex(root, managed_keys[i], &val)) {
            const char *val_str = json_object_to_json_string_ext(val, JSON_C_TO_STRING_PLAIN);
            if (val_str) {
                struct json_object *val_clone = json_tokener_parse(val_str);
                if (val_clone)
                    json_object_object_add(managed, managed_keys[i], val_clone);
            }
        }
    }

    canonical = canonicalize_json(managed);
    if (!canonical) goto out;

    canon_str = json_object_to_json_string_ext(canonical, JSON_C_TO_STRING_PLAIN);
    if (!canon_str) goto out;
    canon_len = strlen(canon_str);

    evp_ctx = EVP_MD_CTX_new();
    if (!evp_ctx || EVP_DigestInit_ex(evp_ctx, EVP_sha256(), NULL) != 1 ||
        EVP_DigestUpdate(evp_ctx, canon_str, canon_len) != 1 ||
        EVP_DigestFinal_ex(evp_ctx, digest, &digest_len) != 1 || digest_len != 32) {
        goto out;
    }

    memcpy(out, "sha256:", 7);
    for (size_t i = 0; i < digest_len; i++)
        snprintf(out + 7 + i * 2, 3, "%02x", digest[i]);
    out[71] = '\0';
    ok = true;

out:
    if (evp_ctx) EVP_MD_CTX_free(evp_ctx);
    if (canonical) json_object_put(canonical);
    if (managed) json_object_put(managed);
    if (root) json_object_put(root);
    if (tokener) json_tokener_free(tokener);
    return ok;
}

static int ubus_netconf_config_handler(struct ubus_context *ctx,
                                       struct ubus_object *obj,
                                       struct ubus_request_data *req,
                                       const char *method,
                                       struct blob_attr *msg)
{
    enum { DATA, SIZE, __MAX };
    static const struct blobmsg_policy policy[__MAX] = {
        [DATA] = { .name = "data", .type = BLOBMSG_TYPE_UNSPEC },
        [SIZE] = { .name = "size", .type = BLOBMSG_TYPE_INT32 }
    };
    struct blob_attr *tb[__MAX] = {0};
    netconf_item_t *qi = NULL;
    netconf_response_t res = {0};
    uint32_t declared_size;
    void *data;
    int actual_size;
    netconf_job_snapshot_t job = {0};
    bool duplicate = false;
    char config_hash[NETCONF_JOB_HASH_LEN] = {0};
    netconf_job_submit_result_t submit_result;

    (void)obj;
    (void)method;
    if (!ctx || !req || !msg)
        return UBUS_STATUS_INVALID_ARGUMENT;

    blobmsg_parse(policy, __MAX, tb, blob_data(msg), blob_len(msg));
    if (!tb[DATA] || !tb[SIZE]) {
        LOG(ERR, "Rejected config message with missing data/size");
        return ubus_reply_config(ctx, req, false, "missing data or size", NULL, false);
    }

    declared_size = blobmsg_get_u32(tb[SIZE]);
    data = blobmsg_data(tb[DATA]);
    actual_size = blobmsg_data_len(tb[DATA]);
    if (!data || declared_size == 0 || declared_size != (uint32_t)actual_size ||
        declared_size > NETCONF_MAX_QUEUE_SIZE_BYTES) {
        LOG(ERR, "Rejected config size: declared=%u actual=%d", declared_size,
            actual_size);
        return ubus_reply_config(ctx, req, false, "invalid payload size", NULL, false);
    }

    /* Pre-validation safety gate: validate payload schema/values before queueing */
    char val_err[192] = {0};
    if (!netconf_validate_config_string((const char *)data, declared_size, val_err, sizeof(val_err))) {
        LOG(ERR, "[NETCONF] Config rejected: %s", val_err[0] ? val_err : "Invalid configuration");
        return ubus_reply_config(ctx, req, false, val_err[0] ? val_err : "invalid config payload", NULL, false);
    }

    if (!payload_managed_config_hash(data, declared_size, config_hash)) {
        LOG(ERR, "[NETCONF] Config rejected: Unable to parse payload JSON");
        return ubus_reply_config(ctx, req, false, "invalid config payload", NULL, false);
    }

    submit_result = netconf_job_submit_hash(data, declared_size, config_hash, &job);
    duplicate = (submit_result == NETCONF_JOB_SUBMIT_DUPLICATE);

    if (duplicate) {
        const char *reason = (job.state == NETCONF_JOB_APPLIED) ?
                             "already_applied" : "already_pending";
        LOG(INFO, "[NETCONF] Config received (Job ID: %s): Identical configuration already active. Skipping apply.",
            job.job_id);
        return ubus_reply_config(ctx, req, true, reason, &job, true);
    }

    if (submit_result != NETCONF_JOB_SUBMIT_ACCEPTED) {
        LOG(ERR, "[NETCONF] Config rejected: Job creation failed for Job ID: %s", job.job_id[0] ? job.job_id : config_hash);
        return ubus_reply_config(ctx, req, false, "job creation failed", NULL, false);
    }

    qi = CALLOC(1, sizeof(*qi));
    if (!qi) {
        netconf_job_transition(job.job_id, NETCONF_JOB_QUEUED,
                               NETCONF_JOB_FAILED, "ALLOCATION_FAILED");
        netconf_job_get(job.job_id, &job);
        return ubus_reply_config(ctx, req, false, "allocation failed", &job, false);
    }
    qi->buf = MALLOC(declared_size);
    if (!qi->buf) {
        netconf_queue_item_free(qi);
        netconf_job_transition(job.job_id, NETCONF_JOB_QUEUED,
                               NETCONF_JOB_FAILED, "ALLOCATION_FAILED");
        netconf_job_get(job.job_id, &job);
        return ubus_reply_config(ctx, req, false, "allocation failed", &job, false);
    }

    memcpy(qi->buf, data, declared_size);
    qi->size = declared_size;
    qi->req.data_type = NETCONF_DATA_CONF;
    snprintf(qi->job_id, sizeof(qi->job_id), "%s", job.job_id);
    snprintf(qi->config_hash, sizeof(qi->config_hash), "%s", job.config_hash);

    if (!netconf_queue_put(&qi, &res)) {
        if (qi)
            netconf_queue_item_free(qi);
        LOG(ERR, "[NETCONF] Config rejected: Queue insertion failed for Job ID: %s", job.job_id);
        netconf_job_transition(job.job_id, NETCONF_JOB_QUEUED,
                               NETCONF_JOB_FAILED, "QUEUE_REJECTED");
        netconf_job_get(job.job_id, &job);
        return ubus_reply_config(ctx, req, false, "queue rejected request", &job, false);
    }

    /* Supersede older queued jobs when new config is enqueued */
    netconf_job_supersede_older_queued(job.job_id);

    /* ONLY emit QUEUED once safely in the queue */
    netconf_ubus_emit_job(&job);

    LOG(INFO, "[NETCONF] Config received (Job ID: %s, Size: %u bytes)",
        job.job_id, declared_size);
    return ubus_reply_config(ctx, req, true, "configuration queued", &job, false);
}

static int ubus_enqueue_payload(struct ubus_context *ctx,
                                struct ubus_request_data *req,
                                struct blob_attr *msg,
                                int data_type,
                                const char *label)
{
    enum { DATA, SIZE, __MAX };
    static const struct blobmsg_policy policy[__MAX] = {
        [DATA] = { .name = "data", .type = BLOBMSG_TYPE_UNSPEC },
        [SIZE] = { .name = "size", .type = BLOBMSG_TYPE_INT32 }
    };
    struct blob_attr *tb[__MAX] = {0};
    netconf_item_t *qi;
    netconf_response_t res = {0};
    uint32_t declared_size;
    int actual_size;
    void *data;

    if (!ctx || !req || !msg)
        return UBUS_STATUS_INVALID_ARGUMENT;

    blobmsg_parse(policy, __MAX, tb, blob_data(msg), blob_len(msg));
    if (!tb[DATA] || !tb[SIZE])
        return ubus_reply_config(ctx, req, false, "missing data or size", NULL, false);

    declared_size = blobmsg_get_u32(tb[SIZE]);
    actual_size = blobmsg_data_len(tb[DATA]);
    data = blobmsg_data(tb[DATA]);
    if (!data || declared_size == 0 || declared_size != (uint32_t)actual_size ||
        declared_size > NETCONF_MAX_QUEUE_SIZE_BYTES) {
        LOG(ERR, "Rejected %s size: declared=%u actual=%d", label,
            declared_size, actual_size);
        return ubus_reply_config(ctx, req, false, "invalid payload size", NULL, false);
    }

    qi = CALLOC(1, sizeof(*qi));
    if (!qi)
        return ubus_reply_config(ctx, req, false, "allocation failed", NULL, false);
    qi->buf = MALLOC(declared_size);
    if (!qi->buf) {
        netconf_queue_item_free(qi);
        return ubus_reply_config(ctx, req, false, "allocation failed", NULL, false);
    }
    memcpy(qi->buf, data, declared_size);
    qi->size = declared_size;
    qi->req.data_type = data_type;

    if (!netconf_queue_put(&qi, &res)) {
        if (qi) netconf_queue_item_free(qi);
        LOG(ERR, "Rejected %s because queue insertion failed: error=%u",
            label, res.error);
        return ubus_reply_config(ctx, req, false, "queue rejected request", NULL, false);
    }

    LOG(INFO, "MSG_ACCEPTED type=%s msglen=%u qlen=%d", label,
        declared_size, netconf_queue_length());
    return ubus_reply_config(ctx, req, true, "request queued", NULL, false);
}

static int ubus_netconf_acl_handler(struct ubus_context *ctx,
                                    struct ubus_object *obj,
                                    struct ubus_request_data *req,
                                    const char *method,
                                    struct blob_attr *msg)
{
    (void)obj;
    (void)method;
    return ubus_enqueue_payload(ctx, req, msg, NETCONF_DATA_ACL, "ACL");
}

static int ubus_netconf_rl_handler(struct ubus_context *ctx,
                                   struct ubus_object *obj,
                                   struct ubus_request_data *req,
                                   const char *method,
                                   struct blob_attr *msg)
{
    (void)obj;
    (void)method;
    return ubus_enqueue_payload(ctx, req, msg, NETCONF_DATA_RL, "RL");
}

static int ubus_netconf_rl_interface_handler(struct ubus_context *ctx,
                                             struct ubus_object *obj,
                                             struct ubus_request_data *req,
                                             const char *method,
                                             struct blob_attr *msg)
{
    struct blob_attr *tb[__RL_INTERFACE_MAX];
    const char *ifname;
    int uplink;
    int downlink;
    bool success;

    (void)obj;
    (void)method;

    if (!msg)
        return UBUS_STATUS_INVALID_ARGUMENT;

    blobmsg_parse(rl_interface_policy, __RL_INTERFACE_MAX, tb,
                  blob_data(msg), blob_len(msg));

    if (!tb[RL_INTERFACE]) {
        return ubus_reply_rate_limit(ctx, req, false, "interface", "",
                                     0, 0, "missing interface");
    }

    ifname = blobmsg_get_string(tb[RL_INTERFACE]);
    uplink = rl_rate_from_attr(tb[RL_INTERFACE_UPLINK]);
    downlink = rl_rate_from_attr(tb[RL_INTERFACE_DOWNLINK]);

    if (uplink < 0 || downlink < 0 || uplink > MAX_RATE_MBPS || downlink > MAX_RATE_MBPS) {
        return ubus_reply_rate_limit(ctx, req, false, "interface", ifname,
                                     uplink, downlink, "rate must be between 0 and 10000 Mbps");
    }

    success = air_ifname_rate_limit((char *)ifname, uplink, downlink);
    return ubus_reply_rate_limit(ctx, req, success, "interface", ifname,
                                 uplink, downlink,
                                 success ? "applied" : "failed");
}

static int ubus_netconf_rl_client_handler(struct ubus_context *ctx,
                                          struct ubus_object *obj,
                                          struct ubus_request_data *req,
                                          const char *method,
                                          struct blob_attr *msg)
{
    struct blob_attr *tb[__RL_CLIENT_MAX];
    const char *macstr;
    uint8_t mac[6];
    int uplink;
    int downlink;
    bool success;

    (void)obj;
    (void)method;

    if (!msg)
        return UBUS_STATUS_INVALID_ARGUMENT;

    blobmsg_parse(rl_client_policy, __RL_CLIENT_MAX, tb,
                  blob_data(msg), blob_len(msg));

    if (!tb[RL_CLIENT_MAC]) {
        return ubus_reply_rate_limit(ctx, req, false, "client", "",
                                     0, 0, "missing mac");
    }

    macstr = blobmsg_get_string(tb[RL_CLIENT_MAC]);
    uplink = rl_rate_from_attr(tb[RL_CLIENT_UPLINK]);
    downlink = rl_rate_from_attr(tb[RL_CLIENT_DOWNLINK]);

    if (!parse_macaddr(macstr, mac)) {
        return ubus_reply_rate_limit(ctx, req, false, "client", macstr,
                                     uplink, downlink, "invalid mac");
    }

    if (uplink < 0 || downlink < 0 || uplink > MAX_RATE_MBPS || downlink > MAX_RATE_MBPS) {
        return ubus_reply_rate_limit(ctx, req, false, "client", macstr,
                                     uplink, downlink, "rate must be between 0 and 10000 Mbps");
    }

    success = air_user_rate_limit(mac, uplink, downlink);
    return ubus_reply_rate_limit(ctx, req, success, "client", macstr,
                                 uplink, downlink,
                                 success ? "applied" : "failed");
}



static void ubus_add_job(struct blob_buf *b, const netconf_job_snapshot_t *job)
{
    blobmsg_add_string(b, "schema", "air.netconfd.job.v1");
    blobmsg_add_string(b, "job_id", job->job_id);
    blobmsg_add_string(b, "status", netconf_job_state_string(job->state));
    blobmsg_add_u64(b, "revision", job->revision); /* rev is legacy; value is AP-local sequence, not cloud revision */
    blobmsg_add_u64(b, "local_seq", job->revision);
    blobmsg_add_string(b, "config_hash", job->config_hash);
    blobmsg_add_string(b, "reason_code", job->reason_code);
    blobmsg_add_u64(b, "generation", job->generation);
}

void netconf_ubus_emit_job(const netconf_job_snapshot_t *snapshot)
{
    struct blob_buf b = {0};
    if (!ctx || !snapshot) return;
    blob_buf_init(&b, 0);
    ubus_add_job(&b, snapshot);
    ubus_send_event(ctx, "air.netconfd.job", b.head);
    blob_buf_free(&b);
}

enum { JOB_STATUS_ID, __JOB_STATUS_MAX };
static const struct blobmsg_policy job_status_policy[__JOB_STATUS_MAX] = {
    [JOB_STATUS_ID] = { .name = "job_id", .type = BLOBMSG_TYPE_STRING },
};

static int ubus_job_status_handler(struct ubus_context *ubus,
                                   struct ubus_object *obj,
                                   struct ubus_request_data *req,
                                   const char *method, struct blob_attr *msg)
{
    struct blob_attr *tb[__JOB_STATUS_MAX] = {0};
    netconf_job_snapshot_t job;
    struct blob_buf b = {0};
    (void)obj; (void)method;
    if (!msg) return UBUS_STATUS_INVALID_ARGUMENT;
    blobmsg_parse(job_status_policy, __JOB_STATUS_MAX, tb,
                  blob_data(msg), blob_len(msg));
    if (!tb[JOB_STATUS_ID] ||
        !netconf_job_get(blobmsg_get_string(tb[JOB_STATUS_ID]), &job))
        return UBUS_STATUS_NOT_FOUND;
    blob_buf_init(&b, 0);
    ubus_add_job(&b, &job);
    ubus_send_reply(ubus, req, b.head);
    blob_buf_free(&b);
    return UBUS_STATUS_OK;
}

static int ubus_netconf_status_handler(struct ubus_context *ubus,
                                       struct ubus_object *obj,
                                       struct ubus_request_data *req,
                                       const char *method, struct blob_attr *msg)
{
    netconf_job_snapshot_t job;
    struct blob_buf b = {0};
    (void)obj; (void)method; (void)msg;
    blob_buf_init(&b, 0);
    blobmsg_add_string(&b, "schema", "air.netconfd.status.v1");
    blobmsg_add_u8(&b, "ready", netconf_job_journal_healthy() &&
                                      !netconf_job_recovery_required());
    blobmsg_add_u8(&b, "journal_healthy", netconf_job_journal_healthy());
    blobmsg_add_u8(&b, "recovery_required", netconf_job_recovery_required());
    blobmsg_add_u32(&b, "queue_depth", (uint32_t)netconf_queue_length());
    if (netconf_job_latest(&job)) {
        void *table = blobmsg_open_table(&b, "latest_job");
        ubus_add_job(&b, &job);
        blobmsg_close_table(&b, table);
    }
    ubus_send_reply(ubus, req, b.head);
    blob_buf_free(&b);
    return UBUS_STATUS_OK;
}

static void ubus_io_cb(EV_P_ struct ev_io *w, int revents)
{
    if (!ctx)
        return;

    // Process ubus messages
    ubus_handle_event(ctx);
}

bool netconf_ubus_service_init()
{
    static struct ubus_object obj;
    static struct ubus_object_type object_type;

    loop = EV_DEFAULT;
    ctx = ubus_connect(NULL);
    if (!ctx) {
        fprintf(stderr, "Failed to connect to ubus\n");
        return false;
    }

    printf("Connected to ubus\n");

    obj.name = "netconfd";
    object_type.name = "netconfd";
    obj.type = &object_type;
    static struct ubus_method methods[7];
    methods[0].name = "set.cgwd.conf";            // cloud config
    methods[0].handler = ubus_netconf_config_handler;
    methods[0].policy = NULL;
    methods[0].n_policy = 0;
    methods[1].name = "set.cgwd.acl";             // acl
    methods[1].handler = ubus_netconf_acl_handler;
    methods[1].policy = NULL;
    methods[1].n_policy = 0;
    methods[2].name = "set.cgwd.rl";              // ratelimit
    methods[2].handler = ubus_netconf_rl_handler;
    methods[2].policy = NULL;
    methods[2].n_policy = 0;
    methods[3].name = "rate.limit.interface";
    methods[3].handler = ubus_netconf_rl_interface_handler;
    methods[3].policy = rl_interface_policy;
    methods[3].n_policy = ARRAY_SIZE(rl_interface_policy);
    methods[4].name = "rate.limit.client";
    methods[4].handler = ubus_netconf_rl_client_handler;
    methods[4].policy = rl_client_policy;
    methods[4].n_policy = ARRAY_SIZE(rl_client_policy);
    methods[5].name = "status";
    methods[5].handler = ubus_netconf_status_handler;
    methods[6].name = "job.status";
    methods[6].handler = ubus_job_status_handler;
    methods[6].policy = job_status_policy;
    methods[6].n_policy = ARRAY_SIZE(job_status_policy);
    object_type.methods = methods;
    object_type.n_methods = ARRAY_SIZE(methods);
    obj.methods = methods;
    obj.n_methods = ARRAY_SIZE(methods);

    if (ubus_add_object(ctx, &obj) != 0) {
        fprintf(stderr, "Failed to add ubus object\n");
        ubus_free(ctx);
        ctx = NULL;
        return false;
    }

    // Get the ubus socket FD
    int fd = ctx->sock.fd;
    if (fd < 0) {
        fprintf(stderr, "Invalid ubus fd\n");
        return false;
    }

    // Register libev watcher for ubus socket
    ev_io_init(&ubus_watcher, ubus_io_cb, fd, EV_READ);
    ev_io_start(loop, &ubus_watcher);

    printf("UBus integrated with libev loop ✅\n");

    return true;
}

void netconf_ubus_service_cleanup(void)
{
    /* ------------------ CLEANUP ------------------ */

    if (loop) {
        ev_io_stop(loop, &ubus_watcher);
    }
    
    if (ctx) {
        ubus_free(ctx);
        ctx = NULL;
    }
}
