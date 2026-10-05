#ifndef LOGD_FILTER_H_INCLUDED
#define LOGD_FILTER_H_INCLUDED

#include "logd.h"

void logd_filter_init(void);
bool logd_filter_match(const char *tag, int priority);
bool logd_filter_rate_check(const char *tag, char *warning_buf, size_t warning_sz);
size_t logd_filter_format(char *out, size_t out_sz, int64_t timestamp_sec,
                          bool kernel, int priority, const char *msg);

#endif /* LOGD_FILTER_H_INCLUDED */
