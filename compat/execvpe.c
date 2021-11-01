/*	$OpenBSD: exec.c,v 1.23 2016/03/13 18:34:20 guenther Exp $ */
/*-
 * Copyright (c) 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/types.h>
#include <sys/uio.h>

#include <errno.h>
#include <limits.h>
#include <paths.h>
#include <stdarg.h>
//#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

int execvpe(const char *restrict name,
	    char *const *restrict argv,
	    char *const *restrict envp)
{
	char **memp;
	int cnt;
	size_t lp, ln, len;
	char *p;
	int eacces = 0;
	char *bp, *cur, *path, buf[PATH_MAX];

	/* Do not allow null name.  */
	if (name == NULL || *name == '\0') {
		errno = ENOENT;
		return (-1);
	}

	/* If it is an absolute or relative path name, it is easy.  */
	if (strchr(name, '/') != NULL) {
		bp = (char *)name;
		cur = path = NULL;
		goto retry;
	}
	bp = buf;

	/* Get the path we are searching.  */
	if ((path = getenv("PATH")) == NULL || *path == '\0')
		path = _PATH_DEFPATH;

	len = strlen(path) + 1;
	cur = malloc(len);
	if (cur == NULL) {
		errno = ENOMEM;
		return (-1);
	}
	strlcpy(cur, path, len);
	while ((p = strsep(&cur, ":")) != NULL) {
		/*
		 * It is a SHELL path -- double, leading and trailing colons
		 * mean the current directory.
		 */
		if (*p == '\0') {
			p = ".";
			lp = 1;
		} else {
			lp = strlen(p);
		}
		ln = strlen(name);

		/*
		 * If the path is too long int complain.  This is a possible
		 * security issue; given a way to make the path too long int
		 * the user may execute the wrong program.
		 */
		if (lp + ln + 2 > sizeof(buf)) {
			struct iovec iov[3] = {
#define STRING_LENGTH_PAIR(s) .iov_base = s, .iov_len = sizeof(s) - 1
				{ STRING_LENGTH_PAIR("execvp: ") },
				{ .iov_base = p, .iov_len = lp },
				{ STRING_LENGTH_PAIR(": path too long int\n") }
			};

			(void)writev(STDERR_FILENO, iov, 3);
			continue;
		}

		bcopy(p, buf, lp);
		buf[lp] = '/';
		bcopy(name, buf + lp + 1, ln);
		buf[lp + ln + 1] = '\0';
	retry:
		(void)execve(bp, argv, envp);
		switch (errno) {
		case E2BIG:
			goto done;
		case EISDIR:
		case ELOOP:
		case ENAMETOOLONG:
		case ENOENT:
			break;
		case ENOEXEC:
			for (cnt = 0; argv[cnt]; cnt++)
				continue;
			memp = malloc((cnt + 2) * sizeof(char *));
			if (memp == NULL)
				goto done;
			memp[0] = "sh";
			memp[1] = bp;
			bcopy(argv + 1, memp + 2, cnt * sizeof(char *));
			(void)execve(_PATH_BSHELL, memp, envp);
			free(memp);
			goto done;
		case ENOMEM:
			goto done;
		case ENOTDIR:
			break;
		case ETXTBSY:
			/* We used to retry here, but sh(1) does not.  */
			goto done;
		case EACCES:
			eacces = 1;
			break;
		default:
			goto done;
		}
	}
	if (eacces != 0)
		errno = EACCES;
	else if (errno == 0)
		errno = ENOENT;
done:
	free(cur);
	return (-1);
}
