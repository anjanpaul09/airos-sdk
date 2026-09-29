#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include "cgw_registration_attempt.h"

typedef struct { char id[CGW_ATTEMPT_ID_LEN]; bool reused; } result_t;
static void *begin_thread(void *arg) {
    result_t *r = arg;
    assert(cgw_registration_attempt_begin(r->id, sizeof(r->id), &r->reused));
    return NULL;
}
int main(void) {
    char first[CGW_ATTEMPT_ID_LEN], second[CGW_ATTEMPT_ID_LEN];
    bool reused;
    cgw_registration_attempt_snapshot_t snap;
    pthread_t threads[4]; result_t results[4] = {0};
    cgw_registration_attempt_reset_for_test();
    assert(cgw_registration_attempt_begin(first, sizeof(first), &reused) && !reused);
    assert(cgw_registration_attempt_begin(second, sizeof(second), &reused) && reused);
    assert(!strcmp(first, second));
    assert(cgw_registration_attempt_is_running(first));
    assert(!cgw_registration_attempt_complete("stale-attempt", CGW_REG_RESULT_SUCCESS));
    assert(cgw_registration_attempt_transition(first, CGW_ATTEMPT_PREPARING, CGW_ATTEMPT_HTTP));
    assert(cgw_registration_attempt_complete(first, CGW_REG_RESULT_PENDING_CLAIM));
    assert(!cgw_registration_attempt_complete(first, CGW_REG_RESULT_SUCCESS));
    cgw_registration_attempt_snapshot(&snap);
    assert(snap.state == CGW_ATTEMPT_COMPLETE && snap.result == CGW_REG_RESULT_PENDING_CLAIM);
    assert(cgw_registration_attempt_begin(second, sizeof(second), &reused) && !reused);
    assert(strcmp(first, second));
    assert(cgw_registration_attempt_cancel(second) == CGW_CANCEL_ACCEPTED);
    assert(!cgw_registration_attempt_is_running(second));
    assert(cgw_registration_attempt_cancel(second) == CGW_CANCEL_NOT_FOUND);
    assert(cgw_registration_attempt_begin(second, sizeof(second), &reused) && !reused);
    assert(cgw_registration_attempt_transition(second, CGW_ATTEMPT_PREPARING, CGW_ATTEMPT_HTTP));
    assert(cgw_registration_attempt_transition(second, CGW_ATTEMPT_HTTP, CGW_ATTEMPT_APPLYING_CONFIG));
    assert(cgw_registration_attempt_cancel(second) == CGW_CANCEL_TOO_LATE);
    assert(cgw_registration_attempt_transition(second, CGW_ATTEMPT_APPLYING_CONFIG, CGW_ATTEMPT_COMMITTING));
    assert(cgw_registration_attempt_complete(second, CGW_REG_RESULT_SUCCESS));
    cgw_registration_attempt_reset_for_test();
    for (int i=0;i<4;i++) assert(!pthread_create(&threads[i], NULL, begin_thread, &results[i]));
    for (int i=0;i<4;i++) pthread_join(threads[i], NULL);
    for (int i=1;i<4;i++) assert(!strcmp(results[0].id, results[i].id));
    cgw_registration_attempt_snapshot(&snap);
    assert(snap.state == CGW_ATTEMPT_PREPARING && snap.generation == 1);
    puts("registration attempt state: PASS");
    return 0;
}
