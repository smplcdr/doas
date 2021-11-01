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

#ifndef _COMPAT_H
#define _COMPAT_H 1

#include <stdarg.h>
#include <sys/types.h>

#include "attributes.h"

#if !defined(va_copy)
# if defined(__va_copy)
#  define va_copy(d, s) __va_copy(d, s)
# else
#  define va_copy(d, s) memcpy(&(d), &(s), sizeof(va_list))
# endif
#endif /* !defined(va_copy) */

#if !defined(GLOBAL_PATH)
# define GLOBAL_PATH "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
#endif

#if !defined(UID_MAX)
# define UID_MAX 65535
#endif /* UID_MAX */
#if !defined(GID_MAX)
# define GID_MAX 65535
#endif /* GID_MAX */

#if !defined(ROOT_UID)
# if defined(__TANDEM)
#  define ROOT_UID 65535
# else
#  define ROOT_UID 0
# endif
#endif /* ROOT_UID */

#if !defined(PATH_MAX)
# if defined(MAX_PATH)
#  define PATH_MAX MAX_PATH
# elif defined(MAXPATHLEN)
#  define PATH_MAX MAXPATHLEN
# else
#  define PATH_MAX 4096
# endif
#endif /* PATH_MAX */

#if !defined(NGROUPS_MAX)
# define NGROUPS_MAX 65535
#endif /* NGROUPS_MAX */

#if !defined(LINE_MAX)
# define LINE_MAX 4096
#endif /* LINE_MAX */

#if !defined(_PW_NAME_LEN)
# define _PW_NAME_LEN 32
#endif /* _PW_NAME_LEN */

#if !defined(SAFE_PATH)
# define SAFE_PATH "/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin"
#endif /* SAFE_PATH */

#if __STDC_VERSION__ >= 199901L
# include <stdbool.h>
#else
# undef _Bool
# undef bool
# undef true
# undef false
/* For the sake of symbolic names in gdb, define true and false as
   enum constants, not only as macros.
   It is tempting to write
   typedef enum { false = 0, true = 1 } _Bool;
   so that gdb prints values of type 'bool' symbolically.  */
typedef enum { _False = 0, _True = 1 } __bool;
# define _Bool __bool
# define bool  _Bool
# define true  _True
# define false _False
#endif /* __STDC_VERSION__ >= 199901L */

#if __STDC_VERSION__ < 199901L
# if __GNUC__ >= 2 || defined(__clang__) || defined(__TINYC__) || defined(__PCC__)
#  define inline __inline__
# else
#  define inline /* Nothing.  */
# endif
#endif

/*
 * GCC 2.95 provides `__restrict' as an extension to C90 to support the
 * C99-specific `restrict' type qualifier.  We happen to use `__restrict' as
 * a way to define the `restrict' type qualifier without disturbing older
 * software that is unaware of C99 keywords.
 */
#if __STDC_VERSION__ < 199901L
# if __GNUC__ >= 2 || (__GNUC__ == 2 && __GNUC_MINOR__ >= 95)
#  define restrict __restrict
# else
#  define restrict /* Nothing.  */
# endif
#endif

#if !defined(HOST_NAME_MAX)
# if defined(_POSIX_HOST_NAME_MAX)
#  define HOST_NAME_MAX _POSIX_HOST_NAME_MAX
# else
#  define HOST_NAME_MAX 512
# endif
#endif

extern size_t full_read(int fd, void *buf, size_t len)
	__nonnull((2)) __wur;
extern size_t full_write(int fd, void const *buf, size_t len)
	__nonnull((2)) __wur;

#if !defined(__NetBSD__)
extern void closefrom(int lowfd);
#endif

#if !defined(_GNU_SOURCE)
extern int execvpe(char const *restrict file,
		   char *const *restrict argv,
		   char *const *restrict envp);
#endif

extern char const *__progname;

extern void setprogname(char const *progname) __nonnull((1));
extern char const *getprogname(void) __wur;

#if !defined(__NetBSD__)
extern void *reallocarray(void *pointer, size_t count, size_t size);
#endif

extern int setresuid(uid_t ruid, uid_t euid, uid_t suid);
extern int setresuid(gid_t rgid, gid_t egid, gid_t sgid);

extern size_t strlcpy(char *restrict dst, char const *restrict src, size_t dsize) __nonnull((1, 2));
extern size_t strlcat(char *restrict dst, char const *restrict src, size_t dsize) __nonnull((1, 2));

#if !defined(__FreeBSD__)
extern long long int strtonum(char const *restrict numstr,
			      long long int minval, long long int maxval,
			      char const *restrict *restrict errstrp)
	__nonnull((1)) __wur;
#endif
extern unsigned long long int strtounum(char const *restrict numstr,
					unsigned long long int maxval,
					char const *restrict *restrict errstrp)
	__nonnull((1)) __wur;

extern void vwarnc(int code, char const *fmt, va_list ap) __format_printf(2, 0);
extern void warnc(int code, char const *fmt, ...) __format_printf(2, 3);

extern void verrc(int eval, int code, char const *fmt, va_list ap) __format_printf(3, 0) __noreturn;
extern void errc(int eval, int code, char const *fmt, ...) __format_printf(3, 4) __noreturn;

extern char *strchrnul(char const *string, int character) __pure __nonnull((1)) __wur;

#if (!defined(__GNUC__) || __GNUC__ < 5) \
  && (!defined(__clang_major__) \
   || (__clang_major__ < 3 || __clang_major__ == 3 && __clang_minor__ < 8)) \
  || defined(__ICC)
#include <limits.h>
/* https://stackoverflow.com/a/1815371 */
static inline __nonnull((3)) __wur __const bool __builtin_mul_overflow(size_t a, size_t b, size_t *c)
{
# define HALF_SIZE_BIT	(sizeof(size_t) * CHAR_BIT / 2)
# define HI(x)		(x >> HALF_SIZE_BIT)
# define LO(x)		(x & ((1 << HALF_SIZE_BIT) - 1))
	size_t s0, s1, s2, s3, x, result, carry;

	x = LO(a) * LO(b);
	s0 = LO(x);

	x = HI(a) * LO(b) + HI(x);
	s1 = LO(x);
	s2 = HI(x);

	x = s1 + LO(a) * HI(b);
	s1 = LO(x);

	x = s2 + HI(a) * HI(b) + HI(x);
	s2 = LO(x);
	s3 = HI(x);

	result = (s1 << HALF_SIZE_BIT) | s0;
	carry = (s3 << HALF_SIZE_BIT) | s2;

	*c = result;
	return (carry != 0);
}
#endif

#define BARF_IF_FAIL(e) (sizeof(char [1 - 2 * ((e) ? 0 : 1)]) - 1)

#if (__GNUC__ > 3 || (__GNUC__ == 3 && __GNUC_MINOR__ >= 1)) \
	|| defined(__clang__) || defined(__PCC__) || defined(__TINYC__)
# define is_same_type(a, b) __builtin_types_compatible_p(__typeof__(a),	\
							 __typeof__(b))
#else
# define is_same_type(a, b) 0 /* (sizeof(a) == sizeof(b)) */
#endif

#define countof(a) \
	(sizeof(a) / sizeof((a)[0]) \
	 + BARF_IF_FAIL(!is_same_type((a), &(a)[0])))
#define endof(a) \
	(&(a)[countof(a)])

#endif /* _COMPAT_H */
