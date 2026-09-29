#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "cgw_registration_attempt.h"

typedef struct { pthread_mutex_t lock; cgw_registration_attempt_snapshot_t snapshot; uint64_t counter; } attempt_context_t;
static attempt_context_t g_attempt = { .lock=PTHREAD_MUTEX_INITIALIZER, .snapshot={.state=CGW_ATTEMPT_IDLE,.result=CGW_REG_RESULT_PERMANENT_FAILURE} };

static bool active(cgw_attempt_state_t s) { return s>=CGW_ATTEMPT_PREPARING && s<=CGW_ATTEMPT_COMMITTING; }
static bool cancellable(cgw_attempt_state_t s) { return s==CGW_ATTEMPT_PREPARING || s==CGW_ATTEMPT_HTTP; }
static void make_id(char *out,size_t n,uint64_t gen){ struct timespec ts={0}; char boot[37]="unknown-boot"; FILE *f=fopen("/proc/sys/kernel/random/boot_id","r"); if(f){if(!fgets(boot,sizeof(boot),f))strcpy(boot,"unknown-boot");boot[strcspn(boot,"\r\n")]=0;fclose(f);} clock_gettime(CLOCK_MONOTONIC,&ts);snprintf(out,n,"%.36s-%llu-%lld",boot,(unsigned long long)gen,(long long)ts.tv_sec); }

bool cgw_registration_attempt_begin(char *id,size_t n,bool *reused){bool ok=false;if(!id||n<CGW_ATTEMPT_ID_LEN||!reused)return false;pthread_mutex_lock(&g_attempt.lock);if(active(g_attempt.snapshot.state)){*reused=true;}else{g_attempt.counter++;g_attempt.snapshot.generation=g_attempt.counter;make_id(g_attempt.snapshot.attempt_id,sizeof(g_attempt.snapshot.attempt_id),g_attempt.counter);g_attempt.snapshot.state=CGW_ATTEMPT_PREPARING;g_attempt.snapshot.result=CGW_REG_RESULT_PERMANENT_FAILURE;*reused=false;}if(snprintf(id,n,"%s",g_attempt.snapshot.attempt_id)<(int)n)ok=true;pthread_mutex_unlock(&g_attempt.lock);return ok;}
bool cgw_registration_attempt_transition(const char *id,cgw_attempt_state_t expected,cgw_attempt_state_t next){bool ok=false;if(!id||!id[0]||!active(expected)||!active(next)||next!=expected+1)return false;pthread_mutex_lock(&g_attempt.lock);if(g_attempt.snapshot.state==expected&&!strcmp(g_attempt.snapshot.attempt_id,id)){g_attempt.snapshot.state=next;ok=true;}pthread_mutex_unlock(&g_attempt.lock);return ok;}
bool cgw_registration_attempt_complete(const char *id,cgw_registration_result_t r){bool ok=false;if(!id||!id[0])return false;pthread_mutex_lock(&g_attempt.lock);if(active(g_attempt.snapshot.state)&&!strcmp(g_attempt.snapshot.attempt_id,id)){g_attempt.snapshot.state=CGW_ATTEMPT_COMPLETE;g_attempt.snapshot.result=r;ok=true;}pthread_mutex_unlock(&g_attempt.lock);return ok;}
cgw_cancel_result_t cgw_registration_attempt_cancel(const char *id){cgw_cancel_result_t r=CGW_CANCEL_NOT_FOUND;if(!id||!id[0])return r;pthread_mutex_lock(&g_attempt.lock);if(!strcmp(g_attempt.snapshot.attempt_id,id)){if(cancellable(g_attempt.snapshot.state)){g_attempt.snapshot.state=CGW_ATTEMPT_CANCELLED;g_attempt.snapshot.result=CGW_REG_RESULT_CANCELLED;r=CGW_CANCEL_ACCEPTED;}else if(active(g_attempt.snapshot.state))r=CGW_CANCEL_TOO_LATE;}pthread_mutex_unlock(&g_attempt.lock);return r;}
bool cgw_registration_attempt_is_running(const char *id){bool v=false;if(!id||!id[0])return false;pthread_mutex_lock(&g_attempt.lock);v=active(g_attempt.snapshot.state)&&!strcmp(g_attempt.snapshot.attempt_id,id);pthread_mutex_unlock(&g_attempt.lock);return v;}
bool cgw_registration_attempt_is_cancellable(const char *id){bool v=false;if(!id||!id[0])return false;pthread_mutex_lock(&g_attempt.lock);v=cancellable(g_attempt.snapshot.state)&&!strcmp(g_attempt.snapshot.attempt_id,id);pthread_mutex_unlock(&g_attempt.lock);return v;}
void cgw_registration_attempt_snapshot(cgw_registration_attempt_snapshot_t *s){if(!s)return;pthread_mutex_lock(&g_attempt.lock);*s=g_attempt.snapshot;pthread_mutex_unlock(&g_attempt.lock);}
const char *cgw_attempt_state_string(cgw_attempt_state_t s){switch(s){case CGW_ATTEMPT_IDLE:return "IDLE";case CGW_ATTEMPT_PREPARING:return "PREPARING";case CGW_ATTEMPT_HTTP:return "HTTP";case CGW_ATTEMPT_APPLYING_CONFIG:return "APPLYING_CONFIG";case CGW_ATTEMPT_COMMITTING:return "COMMITTING";case CGW_ATTEMPT_COMPLETE:return "COMPLETE";case CGW_ATTEMPT_CANCELLED:return "CANCELLED";default:return "IDLE";}}
const char *cgw_cancel_result_string(cgw_cancel_result_t r){switch(r){case CGW_CANCEL_ACCEPTED:return "CANCELLED";case CGW_CANCEL_TOO_LATE:return "TOO_LATE_TO_CANCEL";default:return "ATTEMPT_NOT_FOUND";}}
void cgw_registration_attempt_reset_for_test(void){pthread_mutex_lock(&g_attempt.lock);memset(&g_attempt.snapshot,0,sizeof(g_attempt.snapshot));g_attempt.snapshot.state=CGW_ATTEMPT_IDLE;g_attempt.snapshot.result=CGW_REG_RESULT_PERMANENT_FAILURE;g_attempt.counter=0;pthread_mutex_unlock(&g_attempt.lock);}
