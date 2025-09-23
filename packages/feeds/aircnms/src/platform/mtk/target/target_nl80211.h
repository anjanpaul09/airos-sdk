#ifndef TARGET_NL80211_H_INCLUDED
#define TARGET_NL80211_H_INCLUDED

#include "nl80211.h"

extern struct ev_loop *target_mainloop;

struct nl_global_info* get_nl_sm_global(void);

#endif /* TARGET_NL80211_H_INCLUDED */
