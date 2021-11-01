/*	$OpenBSD: strlcpy.c,v 1.16 2019/01/25 00:19:25 millert Exp $	*/

/*
 * Copyright (c) 1998, 2015 Todd C. Miller <millert@openbsd.org>
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

#include <limits.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>

#include "compat.h"

/*
 * Copy string SRC to buffer DST of size DSIZE.  At most DSIZE-1
 * characters will be copied.  Always NUL terminates (unless DSIZE == 0).
 * Returns strlen(SRC).
 * If strlen(SRC) >= DSIZE, truncation occurred.
 */
size_t strlcpy(char *const dst, const char *const src, size_t dsize)
{
	char *d = dst;
	const char *s = src;
	size_t n;

	/* It might happen if we were called after another strlcpy()
	   which wrote all buffer out, so just ignore this case.  */
	if (dsize == 0)
		return 0;

	dsize--;

#if (__GNUC__ > 3 || (__GNUC__ == 3 && __GNUC_MINOR__ >= 3)) \
	&& !defined(_ICC) && !defined(__SUNPRO_C)
# define ALIGN		(sizeof(word_t) - 1)
# define ONES		(~(word_t)0 / UCHAR_MAX)
# define HIGHS		(ONES * (1 << (CHAR_BIT - 1)))
# define HASZERO(x)	(((x) - ONES) & ~(x) & HIGHS)
	/* Native word size == sizeof(pointer).  */
	typedef uintptr_t word_t __attribute__((__may_alias__));

	if (((word_t)s & ALIGN) == ((word_t)d & ALIGN)) {
		word_t *wd;
		const word_t *ws;

		while (((word_t)s & ALIGN) && dsize != 0 && *s != '\0') {
			*d++ = *s++;
			dsize--;
		}

		wd = (word_t *)d;
		ws = (const word_t *)s;

		while (dsize >= sizeof(word_t) && !HASZERO(*ws)) {
			*wd++ = *ws++;
			dsize -= sizeof(word_t);
		}

		d = (char *)wd;
		s = (const char *)ws;
	}
#endif

	while (dsize != 0 && *s != '\0') {
		*d++ = *s++;
		dsize--;
	}

	*d = '\0';

	n = s - src;
	if (dsize == 0)
		n += strlen(s);

	return n;
}
