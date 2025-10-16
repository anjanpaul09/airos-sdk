#ifndef TARGET_QCA_H_INCLUDED
#define TARGET_QCA_H_INCLUDED

#include "ioctl80211_client.h"
#include "ioctl80211_survey.h"
#include "ioctl80211_scan.h"
#include "ioctl80211_device.h"
#include "ioctl80211_capacity.h"
#include "ioctl80211_radio.h"

extern struct ev_loop *target_mainloop;

typedef ioctl80211_client_record_t target_client_record_t;
typedef ioctl80211_survey_record_t target_survey_record_t;
typedef ioctl80211_capacity_data_t target_capacity_data_t;

#endif /* TARGET_QCA_H_INCLUDED */
