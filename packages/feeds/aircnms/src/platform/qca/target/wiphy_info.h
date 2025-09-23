#ifndef WIPHY_INFO_H_INCLUDED
#define WIPHY_INFO_H_INCLUDED

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
int wiphy_info_init(void);

#endif /* WIPHY_INFO_H_INCLUDED */
