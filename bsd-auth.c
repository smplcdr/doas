/*
 * Copyright (c) 2015 Ted Unangst <tedu@openbsd.org>
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

#include <bsd_auth.h>
#include <readpassphrase.h>

void authuser(char const *doas_prompt, char const *restrict name, char const *restrict login_style, bool persist)
{
	char *challenge = NULL, *response, rbuf[1024];
	auth_session_t *as;
	int fd = -1;

	if (persist)
		fd = open(_PATH_TTY, O_RDWR);

	if (fd >= 0 && ioctl(fd, TIOCCHKVERAUTH) == 0)
		goto good;

	if ((as = auth_userchallenge(name, login_style, "auth-doas", &challenge)) == NULL)
		errx(EXIT_FAILURE, "Authorization failed");

	if (challenge == NULL)
		challenge = doas_prompt;

	response = readpassphrase(challenge, rbuf, sizeof(rbuf), RPP_REQUIRE_TTY);

	if (response == NULL && errno == ENOTTY) {
		syslog(LOG_AUTHPRIV | LOG_NOTICE, "tty required for %s", name);
		errx(EXIT_FAILURE, "a tty is required");
	}

	if (auth_userresponse(as, response, 0) == NULL) {
		syslog(LOG_AUTHPRIV | LOG_NOTICE, "failed auth for %s", name);
		errc(EXIT_FAILURE, EPERM, "auth_userresponse");
	}

	explicit_bzero(rbuf, sizeof(rbuf));

good:
	if (fd >= 0) {
		int secs = 5 * 60;
		ioctl(fd, TIOCSETVERAUTH, &secs);
		close(fd);
	}
}
