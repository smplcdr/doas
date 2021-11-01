/*
 * Copyright (c) 2021 Sergey Sushilin <sergeysushilin@protonmail.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef _WRAPPERS_H
#define _WRAPPERS_H 1

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <pwd.h>
#include <shadow.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#if !defined(NDEBUG)
# include <string.h>
#endif
#include <sys/stat.h>
#include <unistd.h>

#include "compat.h"

#define streq(s1, s2)		(strcmp((s1), (s2)) == 0)
#define strneq(s1, s2, n)	(strncmp((s1), (s2), (n)) == 0)

static inline __malloc __alloc_size((1)) __returns_nonnull __wur void *xmalloc(size_t size)
{
	void *pointer;

	if (size == 0)
		errc(EXIT_FAILURE, EINVAL, "xmalloc: zero-size allocation");

	pointer = malloc(size);

	if (pointer == NULL)
		err(EXIT_FAILURE, "malloc: allocating %zu bytes", size);

	return pointer;
}
static inline __alloc_size((1, 2)) __returns_nonnull __wur void *xcalloc(size_t count, size_t size)
{
	void *pointer;

	if (count == 0 || size == 0)
		errc(EXIT_FAILURE, EINVAL, "xcalloc: zero-size allocation");

	pointer = calloc(count, size);

	if (pointer == NULL)
		err(EXIT_FAILURE, "calloc: allocating %zu * %zu bytes", count, size);

	return pointer;
}
static inline __alloc_size((2)) __returns_nonnull __wur void *xrealloc(void *pointer, size_t size)
{
	if (pointer == NULL && size == 0)
		errc(EXIT_FAILURE, EINVAL, "realloc(NULL, 0)");

	if (size == 0)
		warnx("reallocating to zero size (use free() instead)");
	/*
	 * if (pointer == NULL)
	 *	warnx("reallocating NULL to %zu (use malloc() instead)", size);
	 */

	pointer = realloc(pointer, size);

	if (pointer == NULL)
		err(EXIT_FAILURE, "realloc");

	return pointer;
}
static inline __alloc_size((2, 3)) __returns_nonnull __wur void *xreallocarray(void *pointer, size_t count, size_t size)
{
	if (pointer == NULL && (count == 0 || size == 0))
		errc(EXIT_FAILURE, EINVAL, "reallocarray(NULL, 0)");

	if (count == 0 || size == 0)
		warnx("reallocating to zero size (use free() instead)");
	/*
	 * Do not warn since reallocarray(NULL, count, size) can be used
	 * for safe allocating memory with size equal to count * size.
	 *
	 * if (pointer == NULL)
	 *	warnx("reallocating NULL to %zu (use malloc() instead)", size);
	 */

	pointer = reallocarray(pointer, count, size);

	if (pointer == NULL)
		err(EXIT_FAILURE, "reallocarray");

	return pointer;
}
static inline __nonnull((1)) void xfree(const void *pointer)
{
	void **p = (void **)pointer;
	if (*p != NULL) {
		free(*p);
		*p = NULL;
	}
}
#define xfree(p) xfree(&p)

static inline __malloc __alloc_size((2)) __returns_nonnull __wur __nonnull((1)) void *xmemdup(const void *pointer, size_t size)
{
	return memcpy(xmalloc(size), pointer, size);
}
static inline __malloc __returns_nonnull __wur __nonnull((1)) char *xstrdup(char const *string)
{
	return xmemdup(string, strlen(string) + 1);
}
static inline __malloc __returns_nonnull __wur __nonnull((1)) char *xstrndup(char const *string, size_t size)
{
	char *s = memchr(string, '\0', size);

	if (s != NULL)
		size = s - string;

	s = memcpy(xmalloc(size + 1), string, size);
	s[size] = '\0';

	return s;
}

static inline __wur __nonnull((1)) long long int safe_strtonum(char const *s, long long int minval, long long int maxval, bool *succeed)
{
	char const *ep = NULL;
	long long int num = strtonum(s, minval, maxval, &ep);

	if (ep != NULL)
		warn("strtonum(%s): %s", s, ep);

	if (succeed != NULL)
		*succeed = (ep == NULL);

	return num;
}
static inline __wur __nonnull((1)) unsigned long long int safe_strtounum(char const *s, unsigned long long int maxval, bool *succeed)
{
	char const *ep = NULL;
	unsigned long long int num = strtounum(s, maxval, &ep);

	if (ep != NULL)
		warn("strtounum(%s): %s", s, ep);

	if (succeed != NULL)
		*succeed = (ep == NULL);

	return num;
}

static inline __format_printf(2, 0) __nonnull((1, 2)) int xvfprintf(FILE *restrict fp, char const *restrict fmt, va_list ap)
{
	int n = vfprintf(fp, fmt, ap);

	if (n < 0)
		err(EXIT_FAILURE, "vfprintf");

	return n;
}

static inline __format_printf(2, 3) __nonnull((1, 2)) int xfprintf(FILE *restrict fp, char const *restrict fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	int n = xvfprintf(fp, fmt, ap);
	va_end(ap);

	return n;
}

static inline __format_printf(2, 0) __nonnull((1, 2)) int xvsprintf(char *restrict buf, char const *restrict fmt, va_list ap)
{
	int n = vsprintf(buf, fmt, ap);

	if (n < 0)
		err(EXIT_FAILURE, "vsprintf");

	return n;
}
static inline __format_printf(2, 3) __nonnull((1, 2)) int xsprintf(char *restrict buf, char const *restrict fmt, ...)
{
	va_list ap;
	int n;

	va_start(ap, fmt);
	n = xvsprintf(buf, fmt, ap);
	va_end(ap);

	return n;
}

static inline __format_printf(3, 0) __nonnull((1, 3)) int safe_vsnprintf(char *restrict buf, size_t size, char const *restrict fmt, va_list ap)
{
	int n;

	if (size > INT_MAX) {
		warnc(EINVAL, "vsnprintf");
		return -1;
	}

	n = vsnprintf(buf, size, fmt, ap);

	if (n < 0) {
		warn("vsnprintf");
		return -1;
	}
	if ((size_t)n >= size) {
		warnc(EOVERFLOW, "vsnprintf");
		return -1;
	}

	return n;
}
static inline __format_printf(3, 4) __nonnull((1, 3)) int safe_snprintf(char *restrict buf, size_t size, char const *restrict fmt, ...)
{
	va_list ap;
	int n;

	va_start(ap, fmt);
	n = safe_vsnprintf(buf, size, fmt, ap);
	va_end(ap);

	return n;
}

static inline __wur __format_printf(3, 0) __nonnull((1, 3)) int xvsnprintf(char *restrict buf, size_t size, char const *restrict fmt, va_list ap)
{
	int n = safe_vsnprintf(buf, size, fmt, ap);

	if (n < 0)
		exit(EXIT_FAILURE);

	return n;
}
static inline __format_printf(3, 4) __nonnull((1, 3)) int xsnprintf(char *restrict buf, size_t size, char const *restrict fmt, ...)
{
	va_list ap;
	int n;

	va_start(ap, fmt);
	n = xvsnprintf(buf, size, fmt, ap);
	va_end(ap);

	return n;
}

static inline __nonnull((1)) void safe_pledge(char const *restrict promises,
					      char const *const restrict *restrict paths)
{
	/* Pledge is available only on OpenBSD.	 */
#if defined(__OpenBSD__)
	if (pledge(promises, paths) < 0)
		err(EXIT_FAILURE, "pledge(%s)", promises);
#else
	(void)promises;
	(void)paths;
	return;
#endif
}

#pragma GCC poison pledge

static inline __nonnull((1)) int safe_open(char const *file, int flags, mode_t mode)
{
	int fd = open(file, flags, mode);

	if (fd < 0)
		err(EXIT_FAILURE, "open: %s", file);

	return fd;
}
static inline void safe_close(int fd)
{
	if (close(fd) < 0)
		err(EXIT_FAILURE, "close");
}

static inline void safe_fstat(int fd, struct stat *sb)
{
	if (fstat(fd, sb) != 0)
		err(EXIT_FAILURE, "fstat");
}

/*
 * DATA -- Available information about user (uid or name),
 *	   the XX entry we are searching for.
 * STRUCT_SIZE -- the size of the struct keeping entry data.
 * F -- pointer to reentrant function to access the entry data.
 * NAME -- name of function F.
 */
static inline void *safe_getxxyyy(const void *restrict data,
				  size_t struct_size,
				  const void *restrict f,
				  char const *restrict name,
				  char const *restrict error_format)
	__format_printf(5, 0) __nonnull((1, 3, 4, 5)) __wur __malloc;
static inline void *safe_getxxyyy(const void *restrict data,
				  size_t struct_size,
				  const void *restrict f,
				  char const *restrict name,
				  char const *restrict error_format)
{
	int s;
	size_t size = 64;
	char *p = xmalloc(struct_size + size);
	void *result = NULL;

	while (true) {
		s = ((int (*)(const void *, void *, char *,
			      size_t, void **))f)(data, p, p + struct_size,
						  size, &result);

		if (s == EINTR)
			continue; /* Try again.  */

		if (s == ERANGE) {
			if (__builtin_mul_overflow(2, size, &size))
				errc(EXIT_FAILURE, ENOMEM, "%s", name);

			p = xrealloc(p, struct_size + size);
			continue;
		}

		/* We either got an error, or we succeeded and the
		   returned name fit in the buffer.  */
		break;
	}

	if (s != 0) {
		free(p);
		result = NULL;
		errno = s;
		warn("%s", name);
	} else if (result == NULL) {
#if !defined(NDEBUG)
		/* Verify the error format string... Just for safety,
		   no more and yet no less.  */
		char *s = strchr(error_format, '%');

		if (s == NULL || (*(s + 1) != 's' && (*(s + 1) != 'l' && *(s + 2) != 'u')) || strchr(s + 1, '%') != NULL)
			errx(EXIT_FAILURE, "wrong error format in getxxyyy_r: %s", error_format);
#endif
		free(p);
		warnx(error_format, data);
	}

	return result;
}

#define SAFE_GETXXNAM_GENERATE_STATIC(struct_name, function_name, error_format) \
	static inline __malloc __nonnull((1)) struct struct_name *safe_##function_name(char const *name) \
	{								\
		return safe_getxxyyy(name,				\
				     sizeof(struct struct_name),	\
				     function_name##_r,			\
				     #function_name"_r",		\
				     error_format);			\
	}								\
	static inline __malloc __nonnull((1)) __returns_nonnull struct struct_name *x##function_name(char const *name) \
	{								\
		struct struct_name *p = safe_##function_name(name);	\
		if (p == NULL)						\
			exit(EXIT_FAILURE);				\
		return p;						\
	}
#define SAFE_GETXXYID_GENERATE_STATIC(struct_name, function_name, xid_t, error_format) \
	static inline __malloc struct struct_name *safe_##function_name(xid_t id) \
	{								\
		return safe_getxxyyy((void *)(uintptr_t)id,		\
				     sizeof(struct struct_name),	\
				     function_name##_r,			\
				     #function_name"_r",		\
				     error_format);			\
	}								\
	static inline __malloc __returns_nonnull struct struct_name *x##function_name(xid_t id) \
	{								\
		struct struct_name *p = safe_##function_name(id);	\
		if (p == NULL)						\
			exit(EXIT_FAILURE);				\
		return p;						\
	}

SAFE_GETXXNAM_GENERATE_STATIC(passwd, getpwnam, "no matching password record was found for '%s' user");
SAFE_GETXXNAM_GENERATE_STATIC(group,  getgrnam, "no matching group record was found for '%s' group");
SAFE_GETXXYID_GENERATE_STATIC(passwd, getpwuid, uid_t, "no matching password record was found for user with %lu UID");
SAFE_GETXXYID_GENERATE_STATIC(group,  getgrgid, gid_t, "no matching group record was found for group with %lu GID");

#if USE_SHADOW
SAFE_GETXXNAM_GENERATE_STATIC(spwd, getspnam, "no matching shadow record was found for '%s' user");
#endif

/* Poison all these functions to do not allow to use them in code below
   instead of safe_getxxyyy functions.  */
#pragma GCC poison getpwnam getgrnam getpwnam_r getgrnam_r
#pragma GCC poison getpwuid getgruid getpwuid_r getgrgid_r
#if USE_SHADOW
# pragma GCC poison getspnam getspnam_r
#endif

#if defined(FLEX_SCANNER) || defined(YYBISON) || defined(YYBYACC)
# define malloc		xmalloc
# define calloc		xcalloc
# define realloc	xrealloc
# define reallocarray	xreallocarray
# define strdup		xstrdup
# define strndup	xstrndup
#else
# undef malloc
# undef calloc
# undef realloc
# undef reallocarray
# undef free
# undef strdup
# undef strndup
# pragma GCC poison malloc calloc realloc reallocarray strdup strndup free
#endif

#endif /* _WRAPPERS_H */
