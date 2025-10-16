#include <errno.h>
#include <stdlib.h>
#include <limits.h>

//#include "os_common.h"
#include "os.h"
#include "os_util.h"
#include "util.h"

/**
 * Convert string @P str to a long type and store the result to the location
 * pointed to by @p out.
 *
 * This function returns false if the conversion fails or if not the whole string
 * @p str is used during conversion.
 */
bool os_strtoul(char *str, long *out, int base)
{
    char *pend;

    if (str == NULL) return false;

    errno = 0;

    *out = strtoul(str, &pend, base);

    if (str == pend || *pend != '\0')
    {
        return false;
    }

    if (*out == LONG_MAX && errno != 0)
    {
        return false;
    }

    return true;
}


/**
 * Wrapper around os_strtoul; mostly for historical reasons
 */
bool os_atol(char *str, long *out)
{
    return os_strtoul(str, out, 0);
}

/**
 * Convert string @P str to a double type and store the result to the location
 * pointed to by @p out.
 *
 * This function returns false if the conversion fails or if not the whole string
 * @p str is used during conversion.
 */
bool os_atof(char *str, double *out)
{
    char *pend;

    if (str == NULL) return false;

    errno = 0;

    *out = strtod(str, &pend);

    if (str == pend || *pend != '\0' || errno != 0)
    {
        return false;
    }

    return true;

}

/* Purpose: Safe copying function.
            Returns char pointer to be inline with strncpy Call */
char *os_util_strncpy(char *dest, const char *src, int32_t n)
{
    strscpy(dest, src, n);
    return dest;
}

static bool os_util_is_hex_char(const char c)
{
    if ((c >= '0') && (c <= '9'))
        return true;

    if ((c >= 'a') && (c <= 'f'))
        return true;

    if ((c >= 'A') && (c <= 'F'))
        return true;

    return false;
}

bool os_util_is_valid_mac_str(const char *mac_str)
{
    int i,j;
    bool rc = false;               /* 0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15 16  17   */
    int max = MAC_ADDR_STR_SIZE-1; /* X  X  :  X  X  :  X  X  :  X  X  :  X  X  :  X  X '\0' */

    for (i = 0; i < max; i++) {
        for (j = 0; j < 2; j++, i++) {
            if (os_util_is_hex_char(mac_str[i]) != true)
                break;
        }
        if (2 != j || mac_str[i] != ':') {
            break;
        }
    }
    if (max == i)
        rc = true;

    return rc;
}

