#ifndef OS_UTIL_H_INCLUDED
#define OS_UTIL_H_INCLUDED

#include <stdint.h>
#include <stdbool.h>
#include "os.h"
//#include "os_common.h"

extern bool os_strtoul(char *str, long *out, int base);
extern bool os_atol(char *str, long *out);
extern bool os_atof(char *str, double *out);
extern char *os_util_strncpy(char *dest, const char *src, int32_t n);
extern bool os_util_is_valid_mac_str(const char *mac_str);

#endif /* OS_UTIL_H_INCLUDED */
