#include <unistd.h>
#include <stdbool.h>
#include <syslog.h>
#include <sys/syscall.h>

#include "log.h"
#include "util.h"
#include "const.h"

static void
logger_traceback_log(logger_t *l, logger_msg_t *msg)
{
    static char msgs[32][1024];
    static size_t cur = 0;
    size_t i, j;

    if (msg->lm_module == LOG_MODULE_ID_TRACEBACK)
        return;

    if (msg->lm_severity <= LOG_SEVERITY_WARNING) {
        for (i = 0; i < ARRAY_SIZE(msgs); i++) {
            j = (cur + i) % ARRAY_SIZE(msgs);
            if (*msgs[j])
                mlog(msg->lm_severity, LOG_MODULE_ID_TRACEBACK, "%s", msgs[j]);
            *msgs[j] = 0;
        }
        return;
    }

    snprintf(msgs[cur], sizeof(msgs[cur]), "%s: %s", msg->lm_tag, msg->lm_text);
    cur++;
    cur %= ARRAY_SIZE(msgs);
}

static bool
logger_traceback_match(log_severity_t sev, log_module_t module)
{
    /* Traceback is intended to collect all possible
     * messages in a ring buffer to provide context for
     * errors with the need to increase log verbosity. The
     * goal is to make debugging easier.
     */
    return true;
}

bool
logger_traceback_new(logger_t *l)
{
    memset(l, 0, sizeof(*l));
    l->logger_fn = logger_traceback_log;
    l->match_fn = logger_traceback_match;
    return true;
}
