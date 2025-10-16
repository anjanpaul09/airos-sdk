#ifndef UTIL_H_INCLUDED
#define UTIL_H_INCLUDED

#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <assert.h>

#include "memutil.h"

#define IGNORE_VALUE(a) do { (void)(a); } while (0)

#ifndef MIN
#define MIN(a,b) \
    ({ __typeof__ (a) _a = (a); \
    __typeof__ (b) _b = (b); \
    _a < _b ? _a : _b; })
#endif

#ifndef MAX
#define MAX(a,b) \
    ({ __typeof__ (a) _a = (a); \
    __typeof__ (b) _b = (b); \
    _a > _b ? _a : _b; })
#endif

// Return number of elements in array
#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x)       (sizeof(x) / sizeof(x[0]))
#endif /* ARRAY_SIZE */

// Same as ARRAY_SIZE, except returned signed value
#ifndef ARRAY_LEN
#define ARRAY_LEN(x)  ((int)ARRAY_SIZE(x))
#endif /* ARRAY_LEN */

#ifndef ARRAY_AND_SIZE
#define ARRAY_AND_SIZE(x)   (x),ARRAY_SIZE(x)
#endif /* ARRAY_AND_SIZE */

#define BFR_SIZE_32                 32
#define BFR_SIZE_64                 64
#define BFR_SIZE_128                128
#define BFR_SIZE_256                256
#define BFR_SIZE_512                512
#define BFR_SIZE_1K                 1024
#define BFR_SIZE_4K                 4098

int bin2hex(const unsigned char *in, size_t in_size, char *out, size_t out_size);
ssize_t hex2bin(const char *in, size_t in_size, unsigned char *out, size_t out_size);
bool ascii2hex(const char *input, char *output, size_t size);
int csnprintf(char **str, size_t *size, const char *fmt, ...);
#define append_snprintf csnprintf
int tsnprintf(char *str, size_t size, const char *fmt, ...) __attribute__((format(printf, 3, 4)));
char* strargv(char **cmd, bool with_quotes);
int strcmp_len(char *a, size_t alen, char *b, size_t blen);
ssize_t base64_encode(char *out, ssize_t out_sz, void *input, ssize_t input_sz);
ssize_t base64_decode(void *out, ssize_t out_sz, char *input);
char *str_unescape_hex(char *str);
char *strchomp(char *str, char *delim);

int count_nt_array(char **array);
char* strfmt_nt_array(char *str, size_t size, char **array);
bool is_inarray(const char * key, int argc, char ** argv);
int filter_out_nt_array(char **array, char **filter);
bool is_array_in_array(char **src, char **dest);
char *str_bool(bool a);
char *str_success(bool a);

void delimiter_append(char *dest, int size, char *src, int i, char d);
void comma_append(char *dest, int size, char *src, int i);
void remove_character(char *str, const char character);

int fsa_find_str(const void *array, int size, int len, const char *str);
void fsa_copy(const void *array, int size, int len, int num, void *dest, int dsize, int dlen, int *dnum);

#define fsa_find_key_val_def(keys, ksize, vals, vsize, len, key, def) \
    (fsa_find_str(keys, ksize, len, key) < 0 \
     ? (def) \
     : (vals) + fsa_find_str(keys, ksize, len, key) * (vsize))

#define fsa_find_key_val_null(keys, ksize, vals, vsize, len, key) \
    fsa_find_key_val_def(keys, ksize, vals, vsize, len, key, NULL)

#define fsa_find_key_val(keys, ksize, vals, vsize, len, key) \
    fsa_find_key_val_def(keys, ksize, vals, vsize, len, key, "")

#define fsa_item(arr, size, len, i) \
    ((i) >= (len) \
     ? (LOG(CRIT, "FSA out of bounds %d >= %d", i, len), NULL) \
     : (arr) + (i) * (size))

char *str_tolower(char *str);
char *str_toupper(char *str);
char *str_trimws(char *s);
bool str_is_mac_address(const char *mac);
bool parse_uri(char *uri, char *proto, size_t proto_size, char *host, size_t host_size, int *port);


#ifdef static_assert
#define ASSERT_ARRAY(A) \
    ({ \
        static_assert( /* is array */ \
            !__builtin_types_compatible_p(typeof(A), typeof(&(A)[0])), \
            "NOT AN ARRAY: " #A \
        ); \
        A; \
    })
#else
#define ASSERT_ARRAY(A) A
#endif

#define STRSCPY(dest, src)  strscpy(ASSERT_ARRAY(dest), (src), sizeof(dest))
#define STRSCPY_WARN(dest, src) IGNORE_VALUE(WARN_ON(STRSCPY((dest), (src)) < 0))
ssize_t strscpy(char *dest, const char *src, size_t size);
#define STRSCPY_LEN(dest, src, len)  strscpy_len(ASSERT_ARRAY(dest), (src), sizeof(dest), len)
ssize_t strscpy_len(char *dest, const char *src, size_t size, ssize_t src_len);
#define STRSCAT(dest, src)  strscat((dest), (src), sizeof(dest))
ssize_t strscat(char *dest, const char *src, size_t size);
char *strschr(const char *s, int c, size_t n);
char *strsrchr(const char *s, int c, size_t n);
#define strdupafree(s) ({ char *__p = s, *__q = __p ? strdupa(__p) : NULL; FREE(__p); __q; })
char *strfmt(const char *fmt, ...) __attribute__ ((format(printf, 1, 2)));
#define strfmta(fmt, ...) strdupafree(strfmt(fmt, ##__VA_ARGS__))
char *argvstr(const char *const*argv);
#define argvstra(argv) strdupafree(argvstr(argv))
char *strexread(const char *prog, const char *const*argv);
#define strexreada(prog, argv) strdupafree(strexread(prog, argv))
#define __strexa_arg1(x, ...) x
#define strexa(...) strdupafree(strchomp(strexread(__strexa_arg1(__VA_ARGS__), (const char *[]){ __VA_ARGS__, NULL }), " \t\r\n"))
#define strexpect(str, prog, ...) ({ char *__p = strexa(prog, ##__VA_ARGS__); __p && !strcmp(__p, str); })
char *strdel(char *heystack, const char *needle, int (*strcmp_fun) (const char*, const char*));
char *strgrow(char **buf, const char *fmt, ...) __attribute__ ((format(printf, 2, 3)));

int    str_count_lines(char *s);
bool   str_split_lines_to(char *s, char **lines, int size, int *count);
char** str_split_lines(char *s, int *count);
bool   str_join(char *str, int size, char **list, int num, char *delim);
bool   str_join_int(char *str, int size, int *list, int num, char *delim);
bool   str_startswith(const char *str, const char *start);
bool   str_endswith(const char *str, const char *end);

char  *ini_get(const char *buf, const char *key);
#define ini_geta(buf, key) strdupafree(ini_get(buf, key))
int    file_put(const char *path, const char *buf);
char  *file_get(const char *path);
#define file_geta(path) strdupafree(file_get(path))
const int *unii_5g_chan2list(int chan, int width);
const int *unii_6g_chan2list(int chan, int width);
int chanlist_to_center(const int *chans);
bool is_private_ip(char *ip_str);

bool osp_unit_id_get(char *buff, size_t buffsz);
#endif /* UTIL_H_INCLUDED */
