#ifndef OS_BACKTRACE_H_INCLUDED
#define OS_BACKTRACE_H_INCLUDED

#include <stdbool.h>

/**
 * Executables that want to take advantage of backtracing should be compiled with -fasynchronous-unwind-tables
 * and linked with -rdynamic to get the best results.
 *
 * Executables with debug symbols can be used post-mortem to get more accurate information about the stack trace;
 * for example the line number and source file. This is the syntax one would normally use is:
 *
 * # addr2line -e EXECUTABLE -ifp ADDRESS
 *
 * Where ADDRESS in this case is the address reported by the backtrack library.
 *
 */
typedef enum {
    BTRACE_FILE_LOG = 0,
    BTRACE_LOG_ONLY
} btrace_type;

typedef bool        backtrace_func_t(void *ctx, void *addr, const char *func, const char *object);

extern void         backtrace_init(void);
extern void         backtrace_dump(void);
extern void         sig_crash_report(int signum);
extern bool         backtrace(backtrace_func_t *handler, void *ctx);
bool backtrace_copy(void **addr, int size, int *count, int *all);
bool backtrace_resolve(void *addr, const char **func, const char **fname);

// Path where crashdump is generated
#define BTRACE_DUMP_PATH        "/var/log/lm/crash"

#define CRASH_REPORTS_TMP_DIR    "/tmp/osync_crash_reports"

#endif /* OS_BACKTRACE_H_INCLUDED */
