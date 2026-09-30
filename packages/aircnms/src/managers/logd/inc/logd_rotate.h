#ifndef LOGD_ROTATE_H_INCLUDED
#define LOGD_ROTATE_H_INCLUDED

#include "logd.h"

bool logd_rotate_init(void);
bool logd_rotate_write(const char *data, size_t len);
bool logd_rotate_do(void);
bool logd_rotate_clear(void);
void logd_rotate_close(void);

#endif /* LOGD_ROTATE_H_INCLUDED */
