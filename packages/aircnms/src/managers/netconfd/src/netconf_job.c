#include <openssl/evp.h>
#include <json-c/json.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include "netconf_job.h"

typedef struct {
    netconf_job_snapshot_t records[NETCONF_JOB_LEDGER_SIZE];
    size_t next_slot;
    uint64_t revision; /* local sequence only */
    uint64_t generation;
} netconf_job_ledger_t;

static netconf_job_ledger_t ledger;
static char journal_path[PATH_MAX] = "/etc/airpro/netconfd-jobs.json";
static bool journal_healthy = true;
static bool recovery_required = false;

static bool ensure_parent_dir(const char *path)
{
    char dir[PATH_MAX];
    char *slash;

    if (!path || strlen(path) >= sizeof(dir))
        return false;
    snprintf(dir, sizeof(dir), "%s", path);
    slash = strrchr(dir, '/');
    if (!slash || slash == dir)
        return true;
    *slash = '\0';
    if (mkdir(dir, 0750) == 0 || errno == EEXIST)
        return true;
    return false;
}

void netconf_job_set_journal_path(const char *path)
{
    if (path && path[0] && strlen(path) < sizeof(journal_path))
        snprintf(journal_path, sizeof(journal_path), "%s", path);
}

bool netconf_job_journal_healthy(void)
{
    return journal_healthy;
}

bool netconf_job_recovery_required(void)
{
    return recovery_required;
}

static bool fsync_parent_dir(const char *path)
{
    char dir[PATH_MAX];
    char *slash;
    int fd;
    bool ok;

    if (!path || strlen(path) >= sizeof(dir))
        return false;
    snprintf(dir, sizeof(dir), "%s", path);
    slash = strrchr(dir, '/');
    if (!slash)
        snprintf(dir, sizeof(dir), ".");
    else if (slash == dir)
        slash[1] = '\0';
    else
        *slash = '\0';
    fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0)
        return false;
    ok = fsync(fd) == 0;
    close(fd);
    return ok;
}

static bool journal_write(void)
{
    struct json_object *root = NULL, *records = NULL, *item;
    const char *encoded;
    char temporary[PATH_MAX];
    int fd = -1;
    size_t i, length;
    bool ok = false;

    if (!ensure_parent_dir(journal_path) ||
        snprintf(temporary, sizeof(temporary), "%s.tmp", journal_path) >=
            (int)sizeof(temporary))
        return false;
    root = json_object_new_object();
    records = json_object_new_array();
    if (!root || !records)
        goto out;
    json_object_object_add(root, "schema", json_object_new_string("air.netconfd.journal.v1"));
    json_object_object_add(root, "revision", json_object_new_uint64(ledger.revision));
    json_object_object_add(root, "generation", json_object_new_uint64(ledger.generation));
    for (i = 0; i < NETCONF_JOB_LEDGER_SIZE; i++) {
        netconf_job_snapshot_t *r = &ledger.records[i];
        if (r->state == NETCONF_JOB_EMPTY)
            continue;
        item = json_object_new_object();
        if (!item)
            goto out;
        json_object_object_add(item, "job_id", json_object_new_string(r->job_id));
        json_object_object_add(item, "config_hash", json_object_new_string(r->config_hash));
        json_object_object_add(item, "reason_code", json_object_new_string(r->reason_code));
        json_object_object_add(item, "revision", json_object_new_uint64(r->revision));
        json_object_object_add(item, "generation", json_object_new_uint64(r->generation));
        json_object_object_add(item, "state", json_object_new_int((int)r->state));
        json_object_array_add(records, item);
    }
    json_object_object_add(root, "records", records);
    records = NULL;
    encoded = json_object_to_json_string_ext(root, JSON_C_TO_STRING_PLAIN);
    length = strlen(encoded);
    fd = open(temporary, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0 || write(fd, encoded, length) != (ssize_t)length ||
        write(fd, "\n", 1) != 1 || fsync(fd) != 0)
        goto out;
    if (close(fd) != 0) {
        fd = -1;
        goto out;
    }
    fd = -1;
    if (rename(temporary, journal_path) != 0 || !fsync_parent_dir(journal_path))
        goto out;
    ok = true;
out:
    if (fd >= 0) close(fd);
    if (!ok) unlink(temporary);
    if (records) json_object_put(records);
    if (root) json_object_put(root);
    return ok;
}

static bool copy_json_string(struct json_object *obj, const char *name,
                             char *out, size_t out_len)
{
    struct json_object *value;
    const char *text;
    if (!json_object_object_get_ex(obj, name, &value) ||
        json_object_get_type(value) != json_type_string)
        return false;
    text = json_object_get_string(value);
    if (!text || strlen(text) >= out_len)
        return false;
    snprintf(out, out_len, "%s", text);
    return true;
}

static bool journal_load(void)
{
    struct json_object *root = NULL, *records = NULL, *item, *value;
    size_t i, count;
    bool ok = false;

    root = json_object_from_file(journal_path);
    if (!root)
        return errno == ENOENT;
    if (json_object_get_type(root) != json_type_object ||
        !json_object_object_get_ex(root, "schema", &value) ||
        json_object_get_type(value) != json_type_string ||
        strcmp(json_object_get_string(value), "air.netconfd.journal.v1") != 0 ||
        !json_object_object_get_ex(root, "records", &records) ||
        json_object_get_type(records) != json_type_array)
        goto out;
    if (json_object_object_get_ex(root, "revision", &value))
        ledger.revision = json_object_get_uint64(value);
    if (json_object_object_get_ex(root, "generation", &value))
        ledger.generation = json_object_get_uint64(value);
    count = json_object_array_length(records);
    if (count > NETCONF_JOB_LEDGER_SIZE)
        goto out;
    for (i = 0; i < count; i++) {
        netconf_job_snapshot_t *r = &ledger.records[i];
        int state;
        item = json_object_array_get_idx(records, i);
        if (!item || json_object_get_type(item) != json_type_object ||
            !copy_json_string(item, "job_id", r->job_id, sizeof(r->job_id)) ||
            !copy_json_string(item, "config_hash", r->config_hash, sizeof(r->config_hash)) ||
            !copy_json_string(item, "reason_code", r->reason_code, sizeof(r->reason_code)) ||
            !json_object_object_get_ex(item, "revision", &value))
            goto out;
        r->revision = json_object_get_uint64(value);
        if (!json_object_object_get_ex(item, "generation", &value)) goto out;
        r->generation = json_object_get_uint64(value);
        if (!json_object_object_get_ex(item, "state", &value)) goto out;
        state = json_object_get_int(value);
        if (state <= NETCONF_JOB_EMPTY || state > NETCONF_JOB_CANCELLED) goto out;
        r->state = (netconf_job_state_t)state;
    }
    ledger.next_slot = count % NETCONF_JOB_LEDGER_SIZE;
    ok = true;
out:
    json_object_put(root);
    if (!ok) memset(&ledger, 0, sizeof(ledger));
    return ok;
}

static bool payload_hash(const void *payload, size_t payload_len,
                         char out[NETCONF_JOB_HASH_LEN])
{
    EVP_MD_CTX *ctx = NULL;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    size_t i;
    bool ok = false;

    if (!payload || !payload_len || !out)
        return false;
    ctx = EVP_MD_CTX_new();
    if (!ctx || EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1 ||
        EVP_DigestUpdate(ctx, payload, payload_len) != 1 ||
        EVP_DigestFinal_ex(ctx, digest, &digest_len) != 1 || digest_len != 32)
        goto out;
    memcpy(out, "sha256:", 7);
    for (i = 0; i < digest_len; i++)
        snprintf(out + 7 + i * 2, 3, "%02x", digest[i]);
    out[71] = '\0';
    ok = true;
out:
    EVP_MD_CTX_free(ctx);
    return ok;
}

void netconf_job_init(void)
{
    size_t i;
    bool reconciled = false;

    memset(&ledger, 0, sizeof(ledger));
    recovery_required = false;
    journal_healthy = journal_load();
    if (!journal_healthy)
        return;
    for (i = 0; i < NETCONF_JOB_LEDGER_SIZE; i++) {
        netconf_job_snapshot_t *r = &ledger.records[i];
        if (r->state == NETCONF_JOB_QUEUED) {
            r->state = NETCONF_JOB_FAILED;
            snprintf(r->reason_code, sizeof(r->reason_code),
                     "PAYLOAD_LOST_AFTER_RESTART");
            r->generation = ++ledger.generation;
            reconciled = true;
        } else if (r->state == NETCONF_JOB_APPLYING) {
            r->state = NETCONF_JOB_FAILED;
            snprintf(r->reason_code, sizeof(r->reason_code),
                     "FAILED_NEEDS_ROLLBACK");
            r->generation = ++ledger.generation;
            recovery_required = true;
            reconciled = true;
        } else if (r->state == NETCONF_JOB_FAILED &&
                   strcmp(r->reason_code, "FAILED_NEEDS_ROLLBACK") == 0) {
            recovery_required = true;
        }
    }
    if (reconciled && !journal_write())
        journal_healthy = false;
}

netconf_job_submit_result_t netconf_job_submit_hash(
                        const void *payload, size_t payload_len,
                        const char *config_hash,
                        netconf_job_snapshot_t *snapshot)
{
    netconf_job_snapshot_t *record;
    size_t i;

    (void)payload;
    (void)payload_len;

    if (!journal_healthy || !snapshot || !config_hash || !config_hash[0])
        return NETCONF_JOB_SUBMIT_ERROR;

    /* Check if an in-flight job (QUEUED or APPLYING) already has the same hash */
    for (i = 0; i < NETCONF_JOB_LEDGER_SIZE; i++) {
        record = &ledger.records[i];
        if (record->state == NETCONF_JOB_EMPTY)
            continue;
        if (strcmp(record->config_hash, config_hash) != 0)
            continue;
        if (record->state == NETCONF_JOB_QUEUED ||
            record->state == NETCONF_JOB_APPLYING) {
            *snapshot = *record;
            return NETCONF_JOB_SUBMIT_DUPLICATE;
        }
    }

    /* Check if the latest completed job is already APPLIED with the exact same hash */
    netconf_job_snapshot_t latest_job = {0};
    if (netconf_job_latest(&latest_job)) {
        if (latest_job.state == NETCONF_JOB_APPLIED &&
            strcmp(latest_job.config_hash, config_hash) == 0) {
            *snapshot = latest_job;
            return NETCONF_JOB_SUBMIT_DUPLICATE;
        }
    }

    record = NULL;
    for (i = 0; i < NETCONF_JOB_LEDGER_SIZE; i++) {
        size_t slot = (ledger.next_slot + i) % NETCONF_JOB_LEDGER_SIZE;
        netconf_job_state_t state = ledger.records[slot].state;
        if (state == NETCONF_JOB_EMPTY || state == NETCONF_JOB_APPLIED ||
            state == NETCONF_JOB_FAILED || state == NETCONF_JOB_SUPERSEDED ||
            state == NETCONF_JOB_CANCELLED) {
            record = &ledger.records[slot];
            ledger.next_slot = (slot + 1) % NETCONF_JOB_LEDGER_SIZE;
            break;
        }
    }
    if (!record)
        return NETCONF_JOB_SUBMIT_ERROR;

    {
        netconf_job_snapshot_t before = *record;
        uint64_t revision_before = ledger.revision;
        uint64_t generation_before = ledger.generation;
        memset(record, 0, sizeof(*record));
        record->revision = ++ledger.revision;   /* local AP sequence only */
        record->generation = ++ledger.generation;
        record->state = NETCONF_JOB_QUEUED;
        snprintf(record->job_id, sizeof(record->job_id), "cfg-%llu-%llu",
                 (unsigned long long)record->revision,
                 (unsigned long long)record->generation);
        snprintf(record->config_hash, sizeof(record->config_hash), "%s", config_hash);
        snprintf(record->reason_code, sizeof(record->reason_code), "QUEUED");
        if (!journal_write()) {
            *record = before;
            ledger.revision = revision_before;
            ledger.generation = generation_before;
            journal_healthy = false;
            return NETCONF_JOB_SUBMIT_ERROR;
        }
    }
    *snapshot = *record;
    /* Do NOT emit QUEUED here; emit only after queue insertion succeeds in ubus handler */
    return NETCONF_JOB_SUBMIT_ACCEPTED;
}

bool netconf_job_submit(const void *payload, size_t payload_len,
                        netconf_job_snapshot_t *snapshot, bool *duplicate)
{
    char hash[NETCONF_JOB_HASH_LEN];
    netconf_job_submit_result_t result;
    if (!duplicate || !payload_hash(payload, payload_len, hash))
        return false;
    result = netconf_job_submit_hash(payload, payload_len, hash, snapshot);
    *duplicate = (result == NETCONF_JOB_SUBMIT_DUPLICATE);
    return (result == NETCONF_JOB_SUBMIT_ACCEPTED ||
            result == NETCONF_JOB_SUBMIT_DUPLICATE);
}

bool netconf_job_transition(const char *job_id, netconf_job_state_t expected,
                            netconf_job_state_t next, const char *reason_code)
{
    size_t i;

    if (!journal_healthy || !job_id || !job_id[0] ||
        next == NETCONF_JOB_EMPTY)
        return false;
    for (i = 0; i < NETCONF_JOB_LEDGER_SIZE; i++) {
        netconf_job_snapshot_t *record = &ledger.records[i];
        if (strcmp(record->job_id, job_id) != 0)
            continue;
        if (record->state != expected)
            return false;
        {
            netconf_job_snapshot_t before = *record;
            uint64_t generation_before = ledger.generation;
            record->state = next;
            record->generation = ++ledger.generation;
            snprintf(record->reason_code, sizeof(record->reason_code), "%s",
                     reason_code ? reason_code : netconf_job_state_string(next));
            if (!journal_write()) {
                *record = before;
                ledger.generation = generation_before;
                journal_healthy = false;
                return false;
            }
        }
        netconf_ubus_emit_job(record);
        return true;
    }
    return false;
}

size_t netconf_job_supersede_older_queued(const char *current_job_id)
{
    size_t i, count = 0;
    char job_id[NETCONF_JOB_ID_LEN];

    if (!current_job_id || !current_job_id[0])
        return 0;
    for (i = 0; i < NETCONF_JOB_LEDGER_SIZE; i++) {
        netconf_job_snapshot_t *record = &ledger.records[i];
        if (record->state != NETCONF_JOB_QUEUED ||
            strcmp(record->job_id, current_job_id) == 0)
            continue;
        snprintf(job_id, sizeof(job_id), "%s", record->job_id);
        if (netconf_job_transition(job_id, NETCONF_JOB_QUEUED,
                                   NETCONF_JOB_SUPERSEDED,
                                   "NEWER_CONFIG_QUEUED"))
            count++;
    }
    return count;
}

bool netconf_job_get(const char *job_id, netconf_job_snapshot_t *snapshot)
{
    size_t i;

    if (!job_id || !snapshot)
        return false;
    for (i = 0; i < NETCONF_JOB_LEDGER_SIZE; i++)
        if (strcmp(ledger.records[i].job_id, job_id) == 0) {
            *snapshot = ledger.records[i];
            return true;
        }
    return false;
}

bool netconf_job_latest(netconf_job_snapshot_t *snapshot)
{
    size_t i;
    const netconf_job_snapshot_t *latest = NULL;

    if (!snapshot)
        return false;
    for (i = 0; i < NETCONF_JOB_LEDGER_SIZE; i++)
        if (ledger.records[i].state != NETCONF_JOB_EMPTY &&
            (!latest || ledger.records[i].generation > latest->generation))
            latest = &ledger.records[i];
    if (!latest)
        return false;
    *snapshot = *latest;
    return true;
}

const char *netconf_job_state_string(netconf_job_state_t state)
{
    switch (state) {
    case NETCONF_JOB_QUEUED: return "QUEUED";
    case NETCONF_JOB_APPLYING: return "APPLYING";
    case NETCONF_JOB_APPLIED: return "APPLIED";
    case NETCONF_JOB_FAILED: return "FAILED";
    case NETCONF_JOB_SUPERSEDED: return "SUPERSEDED";
    case NETCONF_JOB_CANCELLED: return "CANCELLED";
    default: return "EMPTY";
    }
}
