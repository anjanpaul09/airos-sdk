#include <libubus.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <json-c/json.h>
#include <ev.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <stdint.h>
#include "netconf.h"

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
        if (job->has_cloud_revision)
            blobmsg_add_u64(&reply, "cloud_revision", job->cloud_revision);
        blobmsg_add_string(&reply, "config_hash", job->config_hash);
        blobmsg_add_string(&reply, "reason_code", job->reason_code);
        blobmsg_add_u8(&reply, "duplicate", duplicate);
    }
    ubus_send_reply(ctx, req, reply.head);
    blob_buf_free(&reply);
    return accepted ? UBUS_STATUS_OK : UBUS_STATUS_INVALID_ARGUMENT;
}

static bool payload_cloud_revision(const void *data, size_t length,
                                   bool *has_revision, uint64_t *revision)
{
    struct json_tokener *tokener;
    struct json_object *root = NULL, *value = NULL;
    enum json_tokener_error error;
    int64_t signed_revision;
    bool ok = false;

    if (!data || !length || !has_revision || !revision)
        return false;
    *has_revision = false;
    *revision = 0;
    tokener = json_tokener_new();
    if (!tokener)
        return false;
    root = json_tokener_parse_ex(tokener, data, (int)length);
    error = json_tokener_get_error(tokener);
    if (error != json_tokener_success || !root ||
        json_object_get_type(root) != json_type_object)
        goto out;
    if (!json_object_object_get_ex(root, "revision", &value)) {
        ok = true; /* Compatibility: initial/legacy configuration. */
        goto out;
    }
    if (json_object_get_type(value) != json_type_int)
        goto out;
    signed_revision = json_object_get_int64(value);
    if (signed_revision <= 0)
        goto out;
    *has_revision = true;
    *revision = (uint64_t)signed_revision;
    ok = true;
out:
    if (root) json_object_put(root);
    json_tokener_free(tokener);
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
    bool has_cloud_revision = false;
    uint64_t cloud_revision = 0;
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

    if (!payload_cloud_revision(data, declared_size, &has_cloud_revision,
                                &cloud_revision))
        return ubus_reply_config(ctx, req, false, "invalid cloud revision", NULL, false);

    submit_result = netconf_job_submit_revision(data, declared_size,
                                                has_cloud_revision,
                                                cloud_revision, &job);
    duplicate = submit_result == NETCONF_JOB_SUBMIT_DUPLICATE;
    if (submit_result == NETCONF_JOB_SUBMIT_STALE)
        return ubus_reply_config(ctx, req, false, "stale cloud revision", NULL, false);
    if (submit_result == NETCONF_JOB_SUBMIT_CONFLICT)
        return ubus_reply_config(ctx, req, false, "cloud revision conflict",
                                 job.job_id[0] ? &job : NULL, false);
    if (submit_result == NETCONF_JOB_SUBMIT_RECOVERY_REQUIRED)
        return ubus_reply_config(ctx, req, false,
                                 "recovery required before configuration", NULL, false);
    if (submit_result == NETCONF_JOB_SUBMIT_ERROR)
        return ubus_reply_config(ctx, req, false, "job creation failed", NULL, false);
    if (duplicate)
        return ubus_reply_config(ctx, req, true, "duplicate configuration coalesced",
                                 &job, true);

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
    if (!netconf_queue_put(&qi, &res)) {
        if (qi)
            netconf_queue_item_free(qi);
        LOG(ERR, "Rejected config because queue insertion failed: error=%u",
            res.error);
        netconf_job_transition(job.job_id, NETCONF_JOB_QUEUED,
                               NETCONF_JOB_FAILED, "QUEUE_REJECTED");
        netconf_job_get(job.job_id, &job);
        return ubus_reply_config(ctx, req, false, "queue rejected request", &job, false);
    }

    if (has_cloud_revision)
        netconf_job_supersede_older_queued(cloud_revision);
    LOG(INFO, "MSG_ACCEPTED type=CONF msglen=%u qlen=%d", declared_size,
        netconf_queue_length());
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
    blobmsg_add_u64(b, "revision", job->revision);
    if (job->has_cloud_revision)
        blobmsg_add_u64(b, "cloud_revision", job->cloud_revision);
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
