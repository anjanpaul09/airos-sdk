#include <unistd.h>
#include <stdbool.h>
#include <syslog.h>
#include <sys/syscall.h>

#include "log.h"

static logger_fn_t logger_stdout_log;

bool logger_stdout_new(logger_t *self, bool quiet_mode)
{
    memset(self, 0, sizeof(*self));
    self->logger_fn = logger_stdout_log;
    self->log_stdout.quiet = quiet_mode;

    return true;
}

void logger_stdout_log(logger_t *self, logger_msg_t *msg)
{
    if (msg->lm_severity == LOG_SEVERITY_STDOUT)
    {
        /*
         * LOG_INFO can be used as replacement for the standard printf().
         */
        printf("%s\n", msg->lm_text);
        fflush(stdout);
        return;
    }

    /*
     * In quiet mode we log just LOG_SEVERITY_STDOUT no matter what
     */
    if (self->log_stdout.quiet) return;

    char *color_none = "";
    char *color_log = "";
    log_severity_entry_t *se;

    se = log_severity_get_by_id(msg->lm_severity);
    /* Use isatty() here to check if if stdout is actually a terminal */
    if (se->color != LOG_COLOR_NONE && isatty(1))
    {
        color_log = se->color;
        color_none = LOG_COLOR_NORMAL;
    }

    /* By default, everything except LOG_INFO is logged to stderr */
    fprintf(stderr, "%s[%5ld] %s %s: %s: %s%s\n",
            color_log,
            syscall(SYS_gettid),
            msg->lm_timestamp,
            log_get_name(),
            msg->lm_tag,
            msg->lm_text,
            color_none);

    fflush(stderr);
}

