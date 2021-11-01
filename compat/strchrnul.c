/*
  Copyright © 2005-2020 Rich Felker, et al.

  Permission is hereby granted, free of charge, to any person obtaining
  a copy of this software and associated documentation files (the
  "Software"), to deal in the Software without restriction, including
  without limitation the rights to use, copy, modify, merge, publish,
  distribute, sublicense, and/or sell copies of the Software, and to
  permit persons to whom the Software is furnished to do so, subject to
  the following conditions:

  The above copyright notice and this permission notice shall be
  included in all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
  CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
  TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
  SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.  */

/* Original: musl/src/string/strchrnul.c */

#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "compat.h"

char *strchrnul(char const *s, int c)
{
	c = (unsigned char)c;

	if (c == '\0')
		return (char *)s + strlen(s);

#if (__GNUC__ > 3 || (__GNUC__ == 3 && __GNUC_MINOR__ >= 3)) \
	&& !defined(_ICC) && !defined(__SUNPRO_C)
# define ALIGN		(sizeof(word_t) - 1)
# define ONES		(~(word_t)0 / UCHAR_MAX)
# define HIGHS		(ONES * (1 << (CHAR_BIT - 1)))
# define HASZERO(x)	(((x) - ONES) & ~(x) & HIGHS)
	{
		/* Native word size == sizeof(pointer).  */
		typedef uintptr_t word_t __attribute__((__may_alias__));

		const word_t *w;
		size_t k;

		while ((word_t)s & ALIGN) {
			if (*s == '\0' || *(unsigned char *)s == c)
				return (char *)s;
			s++;
		}

		k = ONES * c;

		for (w = (word_t const *)s; !HASZERO(*w) && !HASZERO(*w ^ k); w++)
			continue;

		s = (void *)w;
	}
#endif

	while (*s != '\0' && *(unsigned char *)s != c)
		s++;

	return (char *)s;
}
