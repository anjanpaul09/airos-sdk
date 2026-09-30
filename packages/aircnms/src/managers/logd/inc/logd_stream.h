#ifndef LOGD_STREAM_H_INCLUDED
#define LOGD_STREAM_H_INCLUDED

#include "logd.h"

bool logd_stream_init(void);
void logd_stream_start(void);
void logd_stream_cleanup(void);

#endif /* LOGD_STREAM_H_INCLUDED */
