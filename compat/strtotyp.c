/*	$OpenBSD: strtonum.c,v 1.8 2015/09/13 08:31:48 guenther Exp $	*/

/*
 * Copyright (c) 2004 Ted Unangst and Todd Miller
 * All rights reserved.
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

#include <errno.h>
#include <limits.h>
#include <stdlib.h>

enum { INVALID = 1, TOOSMALL = 2, TOOLARGE = 3 };

type function(const char *numstr,
#if TYPE_IS_SIGNED
	      type minval,
#endif
	      type maxval,
	      const char **errstrp)
{
	type x = 0;
	int error = 0;
	char *ep;

	struct errval {
		const char *const errstr;
		int err;
	} ev[4] = {
		{ NULL, 0 },
		{ "invalid", EINVAL },
		{ "too small", ERANGE },
		{ "too large", ERANGE },
	};

	ev[0].err = errno;
	errno = 0;

#if TYPE_IS_SIGNED
	if (minval > maxval) {
		error = INVALID;
	} else
#endif
	{
		x = convert_function(numstr, &ep, 10);
		if (errno == EINVAL || numstr == ep || *ep != '\0')
			error = INVALID;
#if TYPE_IS_SIGNED
		else if ((x == TYPE_MIN && errno == ERANGE) || x < minval)
			error = TOOSMALL;
#endif
		else if ((x == TYPE_MAX && errno == ERANGE) || x > maxval)
			error = TOOLARGE;
	}

	if (errstrp != NULL)
		*errstrp = ev[error].errstr;

	errno = ev[error].err;

	if (error != 0)
		x = 0;

	return x;
}
