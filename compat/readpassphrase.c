/*	$OpenBSD: readpassphrase.c,v 1.26 2016/10/18 12:47:18 millert Exp $	*/

/*
 * Copyright (c) 2000-2002, 2007, 2010
 *	Todd C. Miller <Todd.Miller@courtesan.com>
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
 *
 * Sponsored in part by the Defense Advanced Research Projects
 * Agency (DARPA) and Air Force Research Laboratory, Air Force
 * Materiel Command, USAF, under agreement number F39502-99-1-0512.
 */

/* OPENBSD ORIGINAL: lib/libc/gen/readpassphrase.c */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <paths.h>
#include <signal.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#if !defined(TCSASOFT)
/* If we do not have TCSASOFT define it so that ORing it it below is a no-op.  */
# define TCSASOFT 0
#endif
/* SunOS 4.x which lacks _POSIX_VDISABLE, but has VDISABLE.  */
#if !defined(_POSIX_VDISABLE) && defined(VDISABLE)
# define _POSIX_VDISABLE VDISABLE
#endif
#include "readpassphrase.h"

#include "compat.h"

#if !defined(_NSIG)
# if defined(NSIG)
#  define _NSIG NSIG
# else
#  define _NSIG 128
# endif
#endif

static volatile sig_atomic_t signo[_NSIG] = { 0 };

static void handler(int s)
{
	signo[s] = 1;
}

char *readpassphrase(const char *prompt, char *buf, size_t bufsiz, int flags)
{
	size_t nr;
	int input, output, saved_errno, i;
	bool need_restart;
	char *p, *end;
	unsigned char c;
	struct termios term, oterm;
	struct sigaction sa, savealrm, saveint, savehup, savequit, saveterm;
	struct sigaction savetstp, savettin, savettou, savepipe;

	/* I suppose we could alloc on demand in this case (XXX).  */
	if (bufsiz == 0) {
		errno = EINVAL;
		return (NULL);
	}

restart:
	for (i = 0; i < _NSIG; i++)
		signo[i] = 0;
	nr = 0;
	saved_errno = 0;
	need_restart = false;
	/*
	 * Read and write to /dev/tty if available.  If not, read from
	 * stdin and write to stderr unless a tty is required.
	 */
	if ((flags & RPP_STDIN) || (input = output = open(_PATH_TTY, O_RDWR)) < 0) {
		if (flags & RPP_REQUIRE_TTY) {
			errno = ENOTTY;
			return (NULL);
		}

		input = STDIN_FILENO;
		output = STDERR_FILENO;
	}

	/*
	 * Turn off echo if possible.
	 * If we are using a tty but are not the foreground pgrp this will
	 * generate SIGTTOU, so do it *before* installing the signal handlers.
	 */
	if (input != STDIN_FILENO && tcgetattr(input, &oterm) == 0) {
		memcpy(&term, &oterm, sizeof(term));
		if (!(flags & RPP_ECHO_ON))
			term.c_lflag &= ~(ECHO | ECHONL);
#if defined(VSTATUS)
		if (term.c_cc[VSTATUS] != _POSIX_VDISABLE)
			term.c_cc[VSTATUS] = _POSIX_VDISABLE;
#endif
		(void)tcsetattr(input, TCSAFLUSH | TCSASOFT, &term);
	} else {
		memset(&term, '\0', sizeof(term));
		term.c_lflag |= ECHO;
		memset(&oterm, '\0', sizeof(oterm));
		oterm.c_lflag |= ECHO;
	}

	/*
	 * Catch signals that would otherwise cause the user to end
	 * up with echo turned off in the shell.  Do not worry about
	 * things like SIGXCPU and SIGVTALRM for now.
	 */
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0; /* Do not restart system calls.  */
	sa.sa_handler = handler;

	(void)sigaction(SIGALRM, &sa, &savealrm);
	(void)sigaction(SIGHUP, &sa, &savehup);
	(void)sigaction(SIGINT, &sa, &saveint);
	(void)sigaction(SIGPIPE, &sa, &savepipe);
	(void)sigaction(SIGQUIT, &sa, &savequit);
	(void)sigaction(SIGTERM, &sa, &saveterm);
	(void)sigaction(SIGTSTP, &sa, &savetstp);
	(void)sigaction(SIGTTIN, &sa, &savettin);
	(void)sigaction(SIGTTOU, &sa, &savettou);

	if (!(flags & RPP_STDIN))
		(void)full_write(output, prompt, strlen(prompt));

	end = buf + bufsiz - 1;
	p = buf;
	while ((nr = full_read(input, &c, 1)) == 1 && c != '\n' && c != '\r') {
		if (p < end) {
			if ((flags & RPP_SEVENBIT))
				c &= 0x7F;
			if (isalpha(c)) {
				if ((flags & RPP_FORCELOWER))
					c = tolower(c);
				if ((flags & RPP_FORCEUPPER))
					c = toupper(c);
			}
			*p++ = c;
		}
	}
	*p = '\0';
	saved_errno = errno;
	if (!(term.c_lflag & ECHO))
		(void)full_write(output, "\n", 1);

	/* Restore old terminal settings and signals.  */
	if (memcmp(&term, &oterm, sizeof(term)) != 0) {
		const int sigttou = signo[SIGTTOU];

		/* Ignore SIGTTOU generated when we are not the fg pgrp.  */
		while (tcsetattr(input, TCSAFLUSH | TCSASOFT, &oterm) < 0 && errno == EINTR && !signo[SIGTTOU])
			continue;

		signo[SIGTTOU] = sigttou;
	}

	(void)sigaction(SIGALRM, &savealrm, NULL);
	(void)sigaction(SIGHUP, &savehup, NULL);
	(void)sigaction(SIGINT, &saveint, NULL);
	(void)sigaction(SIGQUIT, &savequit, NULL);
	(void)sigaction(SIGPIPE, &savepipe, NULL);
	(void)sigaction(SIGTERM, &saveterm, NULL);
	(void)sigaction(SIGTSTP, &savetstp, NULL);
	(void)sigaction(SIGTTIN, &savettin, NULL);
	(void)sigaction(SIGTTOU, &savettou, NULL);

	if (input != STDIN_FILENO)
		(void)close(input);

	/*
	 * If we were interrupted by a signal, resend it to ourselves
	 * now that we have restored the signal handlers.
	 */
	for (i = 0; i < _NSIG; i++) {
		if (signo[i] != 0) {
			kill(getpid(), i);
			switch (i) {
			case SIGTSTP:
			case SIGTTIN:
			case SIGTTOU:
				goto restart;
			}
		}
	}
	if (need_restart)
		goto restart;

	if (saved_errno != 0)
		errno = saved_errno;

	return (nr == 0 ? NULL : buf);
}
