#include <stdbool.h>
#include <syslog.h>

#include "log.h"

static logger_fn_t logger_syslog_log;

bool logger_syslog_new(logger_t *self)
{
    /* Open syslog facilities */
    openlog(log_get_name(), LOG_NDELAY|LOG_PID, LOG_USER);

    memset(self, 0, sizeof(*self));

    self->logger_fn = logger_syslog_log;

    return true;
}

void logger_syslog_log(logger_t *self, logger_msg_t *msg)
{
    int syslog_sev = LOG_DEBUG;

    /* Translate logger severity to syslog severity */
    switch (msg->lm_severity)
    {
        case LOG_SEVERITY_EMERG:
            syslog_sev = LOG_EMERG;
            break;

        case LOG_SEVERITY_ALERT:
            syslog_sev = LOG_ALERT;
            break;

        case LOG_SEVERITY_CRIT:
            syslog_sev = LOG_CRIT;
            break;

        case LOG_SEVERITY_ERR:
            syslog_sev = LOG_ERR;
            break;

        case LOG_SEVERITY_WARNING:
            syslog_sev = LOG_WARNING;
            break;

        case LOG_SEVERITY_NOTICE:
            syslog_sev = LOG_NOTICE;
            break;

        case LOG_SEVERITY_INFO:
            syslog_sev = LOG_INFO;
            break;

        default:
            break;
    }

#if defined(CONFIG_LOG_USE_PREFIX)
    syslog(syslog_sev, "%s %s: %s", CONFIG_LOG_PREFIX, msg->lm_tag, msg->lm_text);
#else
    syslog(syslog_sev, "%s: %s", msg->lm_tag, msg->lm_text);
#endif
}
