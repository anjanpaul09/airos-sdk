#ifndef WIPHY_INFO_H_INCLUDED
#define WIPHY_INFO_H_INCLUDED

#include "nl80211.h"

/* local types */
enum {
    CHAN_2GHZ = 1 << 0,
    CHAN_5GHZ_LOWER = 1 << 1,
    CHAN_5GHZ_UPPER = 1 << 2,
    CHAN_6GHZ = 1 << 3,
};

struct wiphy_info
{
    const char *chip;
    const char *codename;
    const char *band;
    const char *mode;
    const char *max_width;
};

const char* wiphy_info_get_2ghz_ifname(void);
const struct wiphy_info* wiphy_info_get(const char *ifname);
int wiphy_info_init(struct nl_global_info *nl_global);
void chan_classify(int c, int *flags);

#endif /* WIPHY_INFO_H_INCLUDED */
