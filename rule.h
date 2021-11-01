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

#ifndef _RULE_H
#define _RULE_H 1

#include <grp.h>
#include <pwd.h>
#include <sys/types.h>

#include "attributes.h"

#define RULE_ENTRY(declaration)						\
	declaration {							\
		struct {						\
			struct passwd const *pw;			\
			struct group const *gr;				\
		} ident;						\
		struct {						\
			struct passwd const *pw;			\
		} target;						\
		struct {						\
			int argc;					\
			char const *const *const *argv;			\
		};							\
		struct {						\
			struct env *env;				\
			char const *const *keepenvlist;			\
			char const *const *setenvlist;			\
			char const *const *unsetenvlist;		\
			time_t persist_time;				\
			u_int inheritenv:1;				\
			u_int nopass:1;					\
			u_int nolog:1;					\
		};							\
		u_int permit:1;						\
	}

RULE_ENTRY(struct __packed rule);

#endif /* _RULE_H */
