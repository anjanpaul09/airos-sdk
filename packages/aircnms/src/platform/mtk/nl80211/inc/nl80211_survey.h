#ifndef NL80211_SURVEY_H_INCLUDED
#define NL80211_SURVEY_H_INCLUDED


#if 0
#include "dpp_survey.h"

typedef struct
{
    DPP_TARGET_SURVEY_RECORD_COMMON_STRUCT;
    uint32_t chan_active;
    uint32_t chan_busy;
    uint32_t chan_busy_ext;
    uint32_t chan_self;
    uint32_t chan_rx;
    uint32_t chan_tx;
    int32_t chan_noise;
    uint32_t duration_ms;
} target_survey_record_t;

bool nl80211_stats_survey_get(
        radio_entry_t *radio_cfg,
        uint32_t *chan_list,
        uint32_t chan_num,
        radio_scan_type_t scan_type,
        ds_dlist_t *survey_list,
        void *survey_ctx
);

bool nl80211_stats_survey_convert(
        radio_entry_t *,
        radio_scan_type_t,
        target_survey_record_t *,
        target_survey_record_t *,
        dpp_survey_record_t *
);

void target_survey_record_free(target_survey_record_t *record);

typedef bool target_stats_survey_cb_t(
        ds_dlist_t *survey_list,
        void *survey_ctx,
        int  status);
#endif
#endif /* NL80211_SURVEY_H_INCLUDED */
