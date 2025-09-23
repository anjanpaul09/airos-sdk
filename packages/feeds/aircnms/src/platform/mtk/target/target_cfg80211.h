#include "nl80211.h"
#include "target_nl80211.h"

#define D(name, fallback) ((name ## _exists) ? (name) : (fallback))
#define A(size) alloca(size), size
#define F(fmt, ...) ({ char *__p = alloca(4096); memset(__p, 0, 4096); snprintf(__p, 4095, fmt, ##__VA_ARGS__); __p; })
#define E(prog, ...) forkexec(prog, (const char *[]){ prog, __VA_ARGS__, NULL }, NULL, NULL, 0)
#define R(...) file_geta(__VA_ARGS__)
#define timeout_arg "timeout", "-s", "KILL", "-t", "3"
#define runcmd(...) readcmd(__VA_ARGS__)
#define WARN(cond, ...) (cond && (LOGW(__VA_ARGS__), 1))
#define util_exec_read(xfrm, buf, len, prog, ...) forkexec(prog, (const char *[]){ prog, __VA_ARGS__,  NULL }, xfrm, buf, len)
#define util_exec_simple(prog, ...) forkexec(prog, (const char *[]){ prog, __VA_ARGS__, NULL }, NULL, NULL, 0)
#define util_exec_expect(str, ...) ({ \
            char buf[32]; \
            int err = util_exec_read(rtrimnl, buf, sizeof(buf), __VA_ARGS__); \
            err || strcmp(str, buf); \
        })

int util_get_opmode(const char *vif, char *opmode, int len);
int util_get_vif_radio(const char *in_vif, char *phy_buf, int len);
void nl_wm_deinit();
void nl_sm_deinit();
