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

#ifndef _ENV_H
#define _ENV_H 1

#include <pwd.h>

#include "attributes.h"
#include "rule.h"

struct env;

extern struct env *createenv(void)
	__returns_nonnull __wur;

extern void defaultenv(struct env *const restrict env,
		       struct passwd const *const restrict original,
		       struct passwd const *const restrict target)
	__nonnull((1, 2, 3));
extern void inheritenv(struct env *env)
	__nonnull((1));
extern int keepenv(struct env *const restrict env,
		   char const *const restrict *const restrict envlist)
	__nonnull((1, 2));
extern int fillenv(struct env *restrict env,
		   char const *const restrict *const restrict envlist)
	__nonnull((1, 2));
extern int unfillenv(struct env *restrict env,
		     char const *const restrict *const restrict envlist)
	__nonnull((1, 2));

extern char **prepenv(struct env *const restrict env)
	__malloc __returns_nonnull __nonnull((1));

#endif /* _ENV_H */
