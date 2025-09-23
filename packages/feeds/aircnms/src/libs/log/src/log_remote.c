#include <unistd.h>
#include <stdbool.h>
#include <syslog.h>
#include <sys/syscall.h>

#include "log.h"
#include "qm_conn.h"

extern log_module_entry_t log_module_remote[LOG_MODULE_ID_LAST];
extern bool log_remote_enabled;

void logger_remote_log(logger_t *self, logger_msg_t *msg)
{
    static bool inside_log = false;
    char msg_str[1024];

    if (!log_remote_enabled) return;

    if (inside_log) return; // prevent recursion

    inside_log = true;

    snprintf(msg_str, sizeof(msg_str), "[%5ld] %s %s: %s: %s\n",
            syscall(SYS_gettid),
            msg->lm_timestamp,
            log_get_name(),
            msg->lm_tag,
            msg->lm_text);

    qm_conn_send_log(msg_str, NULL);
    // ignore send errors

    inside_log = false;
}

bool logger_remote_match(log_severity_t sev, log_module_t module)
{
    return sev <= log_module_remote[module].severity;
}

bool logger_remote_new(logger_t *self)
{
    memset(self, 0, sizeof(*self));
    self->logger_fn = logger_remote_log;
    self->match_fn = logger_remote_match;
    return true;
}

