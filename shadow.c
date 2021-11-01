/*
 * Copyright (c) 2020 Duncan Overbruck <mail@duncano.de>
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

#include <crypt.h>
#include <err.h>
#include <errno.h>
#include <limits.h>
#include <pwd.h>
#include <shadow.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "compat.h"
#include "wrappers.h"
#include "readpassphrase.h"

void shadowauth(char const *doas_prompt, char const *name)
{
	char *response, *encrypted, rbuf[1024];
	char const *challenge;
	struct passwd *pw = xgetpwnam(name);
	char const *hash = pw->pw_passwd;

	if (hash[0] == 'x' && hash[1] == '\0') {
		struct spwd *sp = xgetspnam(name);
		hash = xstrdup(sp->sp_pwdp);
		xfree(sp);
	} else if (hash[0] != '*' || hash[1] != '\0') {
		/* TODO: does last check is required? */
		errx(EXIT_FAILURE, "Authentication failed");
	}

	challenge = doas_prompt;

	response = readpassphrase(challenge, rbuf, sizeof(rbuf), RPP_REQUIRE_TTY);

	if (response == NULL && errno == ENOTTY) {
		syslog(LOG_AUTHPRIV | LOG_NOTICE, "tty required for %s", name);
		errx(EXIT_FAILURE, "a tty is required");
	}

	if (response == NULL)
		err(EXIT_FAILURE, "readpassphrase");

	encrypted = crypt(response, hash);

	if (encrypted == NULL) {
		explicit_bzero(rbuf, sizeof(rbuf));
		errx(EXIT_FAILURE, "Authentication failed");
	}

	explicit_bzero(rbuf, sizeof(rbuf));

	if (!streq(encrypted, hash)) {
		syslog(LOG_AUTHPRIV | LOG_NOTICE, "failed auth for %s", name);
		errx(EXIT_FAILURE, "Authentication failed");
	}

	if (hash != pw->pw_passwd)
		xfree(hash);

	xfree(pw);
}
