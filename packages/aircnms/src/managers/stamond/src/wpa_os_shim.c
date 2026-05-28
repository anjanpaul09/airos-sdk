#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

/* Minimal shims to satisfy wpa_ctrl.o references */

typedef long os_time_t;

struct os_reltime {
	os_time_t sec;
	os_time_t usec;
};

int os_get_reltime(struct os_reltime *t)
{
	struct timeval tv;
	if (gettimeofday(&tv, NULL) != 0) return -1;
	t->sec = (os_time_t)tv.tv_sec;
	t->usec = (os_time_t)tv.tv_usec;
	return 0;
}

void os_sleep(os_time_t sec, os_time_t usec)
{
	/* sleep seconds + microseconds */
	if (sec > 0) sleep((unsigned int)sec);
	if (usec > 0) usleep((useconds_t)usec);
}

void * os_zalloc(size_t size)
{
	void *p = calloc(1, size);
	return p;
}

size_t os_strlcpy(char *dst, const char *src, size_t siz)
{
	size_t srclen = strlen(src);
	if (siz) {
		size_t copy = (srclen >= siz) ? siz - 1 : srclen;
		memcpy(dst, src, copy);
		dst[copy] = '\0';
	}
	return srclen;
}
