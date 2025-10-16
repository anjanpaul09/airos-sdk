/*
 * ieee80211 private ioctl interface
 */

#ifndef IOCTL80211_PRIV_H_INCLUDED
#define IOCTL80211_PRIV_H_INCLUDED

/***************************************************************************************/

typedef void*   ioctl80211_priv_t;

/***************************************************************************************/

extern ioctl80211_priv_t    ioctl80211_priv_init(const char *ifname, int fd);
extern void                 ioctl80211_priv_free(ioctl80211_priv_t priv);

extern bool                 ioctl80211_priv_set_int(ioctl80211_priv_t priv,
                                            const char *cmd, uint32_t *vals, int nvals);
extern bool                 ioctl80211_priv_get_int(ioctl80211_priv_t priv,
                                           const char *cmd, uint32_t *vals, int *nvals);

extern bool                 ioctl80211_priv_set(ioctl80211_priv_t priv,
                                                   const char *cmd, void *buf, int len);
extern bool                 ioctl80211_priv_get(ioctl80211_priv_t priv,
                                                 const char *cmd, void *dest, int *len);

extern uint32_t             ioctl80211_priv_get_inum(ioctl80211_priv_t priv,
                                                                       const char *cmd);

#endif /* IOCTL80211_PRIV_H_INCLUDED */
