#ifndef OS_TYPES_H_INCLUDED
#define OS_TYPES_H_INCLUDED

#include <inttypes.h>
//#include "const.h"

#define PRI_os_macaddr_t        "%02X:%02X:%02X:%02X:%02X:%02X"
#define PRI_os_macaddr_lower_t  "%02x:%02x:%02x:%02x:%02x:%02x"
#define PRI_os_macaddr_plain_t  "%02X%02X%02X%02X%02X%02X"
#define FMT_os_macaddr_t(x)     (x).addr[0], (x).addr[1], (x).addr[2], (x).addr[3], (x).addr[4], (x).addr[5]
#define FMT_os_macaddr_pt(x)    (x)->addr[0], (x)->addr[1], (x)->addr[2], (x)->addr[3], (x)->addr[4], (x)->addr[5]

#define PRI_os_ipaddr_t         "%d.%d.%d.%d"
#define FMT_os_ipaddr_t(x)      (x).addr[0], (x).addr[1], (x).addr[2], (x).addr[3]

/* Formats a UFID as a string, in the conventional format.
 *
 * Example:
 *   struct ufid ufid = ...;
 *   printf("This UFID is "PRI_os_ufid_t"\n", FMT_os_ufid_t_pt(&ufid));
 *
 */
#define UFID_LEN (36)

#define PRI_os_ufid_t "%08x-%04x-%04x-%04x-%04x%08x"
#define FMT_os_ufid_t_pt(UFID)                             \
    ((unsigned int) ((UFID)->u32[0])),            \
    ((unsigned int) ((UFID)->u32[1] >> 16)),      \
    ((unsigned int) ((UFID)->u32[1] & 0xffff)),   \
    ((unsigned int) ((UFID)->u32[2] >> 16)),      \
    ((unsigned int) ((UFID)->u32[2] & 0xffff)),   \
    ((unsigned int) ((UFID)->u32[3]))


/* Plain MAC string takes exactly 13 chars. Because alignment it is better
 * to use 16 bytes instead
 */
#define OS_MACSTR_PLAIN_SZ      (16)

/* Non plain MAC string takes exactly 18 chars.
 */
#define OS_MACSTR_SZ            (18)

/**
 * Avoid using fixed-length arrays in typedefs; this leads to all sorts of problems.
 * Instead, wrap it inside an anonymous struct.
 *
 * The main problem is that arrays are passed to function arguments as references and not
 * as values. If we wrap this into a typedef, the user WILL NOT know it's passing a reference.
 */
typedef struct { uint8_t addr[6]; } os_macaddr_t;
typedef struct { uint8_t addr[4]; } os_ipaddr_t;
typedef struct { uint32_t u32[4]; } os_ufid_t;

#endif /* OS_TYPES_H_INCLUDED */
