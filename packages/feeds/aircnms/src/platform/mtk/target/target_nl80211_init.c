#define _GNU_SOURCE
#include <stdbool.h>
#include <stdio.h>
#include <errno.h>

#include "target.h"
#include "nl80211.h"
#include "target_cfg80211.h"

#define MODULE_ID LOG_MODULE_ID_TARGET

static ev_signal        _ev_sigterm;
static ev_signal        _ev_sigkill;
static ev_signal        _ev_sigint;
static ev_signal        _ev_sigsegv;

/******************************************************************************
 *  TARGET definitions
 *****************************************************************************/
struct ev_loop *target_mainloop;

static void
handle_signal(struct ev_loop *loop, ev_signal *w, int revents)
{
    LOGEM("Received signal %d, triggering shutdown", w->signum);
    ev_break(loop, EVBREAK_ALL);
    return;
}

static void
reg_signal_handlers(struct ev_loop *loop)
{
    ev_signal_init(&_ev_sigterm, handle_signal, SIGTERM);
    ev_signal_start(loop, &_ev_sigterm);
    ev_signal_init(&_ev_sigkill, handle_signal, SIGKILL);
    ev_signal_start(loop, &_ev_sigkill);
    ev_signal_init(&_ev_sigint, handle_signal, SIGINT);
    ev_signal_start(loop, &_ev_sigint);
    ev_signal_init(&_ev_sigsegv, handle_signal, SIGSEGV);
    ev_signal_start(loop, &_ev_sigsegv);
}

bool target_init(target_init_opt_t opt, struct ev_loop *loop)
{
    if (opt == TARGET_INIT_MGR_SM) {
        if (nl_sm_init(loop) < 0) {
            LOGE("%s: Initializing SM (Failed to init)",__func__);
            return false;
        }
        reg_signal_handlers(loop);
        LOGI("%s: sm event loop initialized", __func__);
    } else if (opt == TARGET_INIT_MGR_WM) {
        target_mainloop = loop;
        reg_signal_handlers(loop);
    }
    return true;
}

bool target_close(target_init_opt_t opt, struct ev_loop *loop)
{
    //Anjan: TODO
#if 0
    if (opt == TARGET_INIT_MGR_WM) {
        nl_wm_deinit();
    } else if (TARGET_INIT_MGR_SM) {
        nl_sm_deinit();
    }
#endif

    return true;
}
