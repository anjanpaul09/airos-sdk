#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "netconf_job.h"

static unsigned events;
void netconf_ubus_emit_job(const netconf_job_snapshot_t *snapshot)
{
    assert(snapshot && snapshot->job_id[0]);
    events++;
}

int main(void)
{
    netconf_job_snapshot_t a, b, out;
    bool duplicate;
    char applied_job_id[NETCONF_JOB_ID_LEN];
    const char payload[] = "{\"network\":\"test\"}";

    const char *journal = "/tmp/test-netconf-job-journal.json";
    unlink(journal);
    netconf_job_set_journal_path(journal);
    netconf_job_init();
    assert(!netconf_job_latest(&out));
    assert(netconf_job_submit(payload, strlen(payload), &a, &duplicate));
    assert(!duplicate && a.state == NETCONF_JOB_QUEUED && a.revision == 1);
    assert(strncmp(a.config_hash, "sha256:", 7) == 0);
    assert(netconf_job_submit(payload, strlen(payload), &b, &duplicate));
    assert(duplicate && strcmp(a.job_id, b.job_id) == 0 && events == 1);
    assert(netconf_job_transition(a.job_id, NETCONF_JOB_QUEUED,
                                  NETCONF_JOB_APPLYING, "APPLYING"));
    assert(!netconf_job_transition(a.job_id, NETCONF_JOB_QUEUED,
                                   NETCONF_JOB_FAILED, "STALE"));
    assert(netconf_job_transition(a.job_id, NETCONF_JOB_APPLYING,
                                  NETCONF_JOB_APPLIED, "APPLIED"));
    assert(netconf_job_get(a.job_id, &out));
    assert(out.state == NETCONF_JOB_APPLIED && out.generation == 3);
    assert(netconf_job_latest(&out) && out.state == NETCONF_JOB_APPLIED);
    snprintf(applied_job_id, sizeof(applied_job_id), "%s", a.job_id);
    assert(events == 3);

    /* Authoritative cloud revision contract. */
    assert(netconf_job_submit_revision("{\"revision\":10}", 15, true, 10, &b) ==
           NETCONF_JOB_SUBMIT_ACCEPTED);
    assert(b.has_cloud_revision && b.cloud_revision == 10);
    assert(netconf_job_submit_revision("{\"revision\":10}", 15, true, 10, &out) ==
           NETCONF_JOB_SUBMIT_DUPLICATE);
    assert(strcmp(b.job_id, out.job_id) == 0);
    assert(netconf_job_submit_revision("{\"revision\":10,\"x\":1}", 21, true, 10, &out) ==
           NETCONF_JOB_SUBMIT_CONFLICT);
    assert(netconf_job_submit_revision("{\"revision\":9}", 14, true, 9, &out) ==
           NETCONF_JOB_SUBMIT_STALE);
    assert(netconf_job_submit_revision("{\"revision\":11}", 15, true, 11, &out) ==
           NETCONF_JOB_SUBMIT_ACCEPTED);
    assert(out.cloud_revision == 11);
    assert(netconf_job_supersede_older_queued(11) == 1);
    assert(netconf_job_get(b.job_id, &a));
    assert(a.state == NETCONF_JOB_SUPERSEDED);
    assert(strcmp(a.reason_code, "NEWER_CLOUD_REVISION") == 0);
    assert(netconf_job_supersede_older_queued(11) == 0);

    netconf_job_init();
    assert(netconf_job_journal_healthy());
    assert(netconf_job_get(applied_job_id, &out));
    assert(out.state == NETCONF_JOB_APPLIED);

    assert(netconf_job_submit("queued", 6, &b, &duplicate) && !duplicate);
    netconf_job_init();
    assert(netconf_job_get(b.job_id, &out));
    assert(out.state == NETCONF_JOB_FAILED);
    assert(strcmp(out.reason_code, "PAYLOAD_LOST_AFTER_RESTART") == 0);

    assert(netconf_job_submit("applying", 8, &b, &duplicate) && !duplicate);
    assert(netconf_job_transition(b.job_id, NETCONF_JOB_QUEUED,
                                  NETCONF_JOB_APPLYING, "APPLYING"));
    netconf_job_init();
    assert(netconf_job_get(b.job_id, &out));
    assert(out.state == NETCONF_JOB_FAILED);
    assert(strcmp(out.reason_code, "FAILED_NEEDS_ROLLBACK") == 0);
    assert(netconf_job_recovery_required());
    assert(netconf_job_submit_revision("{\"revision\":12}", 15, true, 12, &out) ==
           NETCONF_JOB_SUBMIT_RECOVERY_REQUIRED);
    netconf_job_init();
    assert(netconf_job_recovery_required());
    assert(netconf_job_submit("blocked", 7, &out, &duplicate) == false);
    unlink(journal);
    puts("netconf job ledger: PASS");
    return 0;
}
