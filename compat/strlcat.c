/*	$OpenBSD: strlcat.c,v 1.19 2019/01/25 00:19:25 millert Exp $	*/

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

#include <string.h>
#include <sys/types.h>

#include "compat.h"

/*
 * Appends SRC to string DST of size DSIZE (unlike strncat(), DSIZE is the
 * full size of DST, not space left).  At most DSIZE-1 characters
 * will be copied.  Always NUL terminates (unless dsize <= strlen(dst)).
 * Returns strlen(SRC) + MIN(DSIZE, strlen(DST)).
 * If returned value >= dsize, truncation occurred.
 */
size_t strlcat(char *const dst, const char *const src, const size_t dsize)
{
	char *d;
	size_t dlen;

	d = memchr(dst, '\0', dsize);
	if (d == NULL)
		return dsize + strlen(src);

	dlen = d - dst;
	if (dlen == dsize)
		return dlen + strlen(src);

	return dlen + strlcpy(d, src, dsize - dlen);
}
