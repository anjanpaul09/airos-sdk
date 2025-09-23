#ifndef OS_REGEX_H_INCLUDED
#define OS_REGEX_H_INCLUDED

#include <regex.h>
#include <inttypes.h>

#include "os.h"

#define OS_REG_LIST_ENTRY(id, str)      \
{                                       \
    .re_id = (id),                      \
    .re_str = (str),                    \
    .__re_flags = 0x0                   \
}

#define OS_REG_LIST_END(id)   OS_REG_LIST_ENTRY(id, NULL)

#define OS_REG_FLAG_INIT      (1 << 0)
#define OS_REG_FLAG_INVALID   (1 << 1)      /* Relist entry is invalid */

/*
 * Macros for easier handling of regular expressions
 */
#define RE_GROUP(x) "(" x ")"
#define RE_SPACE    "[[:space:]]+"
#define RE_IFNAME   "[a-zA-Z0-9_.-]+"
#define RE_IPADDR   "[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}"
#define RE_XIPADDR  "[[:xdigit:]]+"
#define RE_NUM      "[0-9]+"
#define RE_XNUM     "0x[[:xdigit:]]+"
#define RE_MAC_N    "[[:xdigit:]]{2}"
#define RE_MAC      RE_MAC_N "[:-]?" RE_MAC_N "[:-]?" RE_MAC_N "[:-]?" RE_MAC_N "[:-]?" RE_MAC_N "[:-]?" RE_MAC_N

typedef struct
{
    const char*     re_str;
    int32_t         re_id;

    regex_t         __re_ex;
    uint32_t        __re_flags;
} os_reg_list_t;

extern int os_reg_list_match(
        os_reg_list_t* relist,
        char*  str,
        regmatch_t* pmatch,
        size_t nmatch);

extern void os_reg_match_cpy(
        char* dest,
        size_t destsz,
        const char* src,
        regmatch_t srm);

#endif /* OS_REGEX_H_INCLUDED */

