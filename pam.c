/*
 * Copyright (c) 2015 Nathan Holstein <nathan.holstein@gmail.com>
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

#include <sys/types.h>
#include <sys/wait.h>

#include <err.h>
#include <errno.h>
#include <limits.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <security/pam_appl.h>

#include "compat.h"
#include "readpassphrase.h"
#include "wrappers.h"

#ifndef HOST_NAME_MAX
# define HOST_NAME_MAX _POSIX_HOST_NAME_MAX
#endif

#define PAM_SERVICE_NAME "doas"

static pam_handle_t *pamh = NULL;

static char const *doas_prompt;

static __nonnull((1, 3)) char *pamprompt(char const *restrict msg, bool echo_on, int *restrict ret)
{
	char const *prompt;
	char *pass, buf[PAM_MAX_RESP_SIZE];
	int flags = RPP_REQUIRE_TTY | (echo_on ? RPP_ECHO_ON : RPP_ECHO_OFF);

	/* Overwrite default prompt if it matches "Password:[ ]".  */
	if (strneq(msg, "Password:", 9) && (msg[9] == '\0' || (msg[9] == ' ' && msg[10] == '\0')))
		prompt = doas_prompt;
	else
		prompt = msg;

	pass = readpassphrase(prompt, buf, sizeof(buf), flags);

	if (pass == NULL)
		*ret = PAM_CONV_ERR;
	else {
		pass = xstrdup(pass);
		*ret = PAM_SUCCESS;
	}

	explicit_bzero(buf, sizeof(buf));
	return pass;
}

static int pamconv(int nmsgs, struct pam_message const *restrict *restrict msgs, struct pam_response *restrict *restrict rsps, void *restrict ptr __unused)
{
	int i, style;
	struct pam_response *rsp = xcalloc(nmsgs, sizeof(*rsp));

	for (i = 0; i < nmsgs; i++) {
		switch (style = msgs[i]->msg_style) {
		case PAM_PROMPT_ECHO_OFF:
		case PAM_PROMPT_ECHO_ON: {
			int ret;

			rsp[i].resp = pamprompt(msgs[i]->msg,
						style == PAM_PROMPT_ECHO_ON,
						&ret);

			if (ret != PAM_SUCCESS)
				goto fail;

			break;
		}
		case PAM_ERROR_MSG:
		case PAM_TEXT_INFO: {
			int fd = style != PAM_ERROR_MSG ? STDOUT_FILENO : STDERR_FILENO;
			size_t msglen = strlen(msgs[i]->msg);

			if (full_write(fd, msgs[i]->msg, msglen) != msglen)
				goto fail;

			break;
		}
		default:
			errx(EXIT_FAILURE, "invalid PAM msg_style %d", style);
		}
	}

	*rsps = rsp;
	rsp = NULL;
	return PAM_SUCCESS;

fail:
	/* Overwrite and free response buffers.  */
	for (i = 0; i < nmsgs; i++) {
		if (rsp[i].resp == NULL)
			continue;

		switch (msgs[i]->msg_style) {
		case PAM_PROMPT_ECHO_OFF:
		case PAM_PROMPT_ECHO_ON:
			explicit_bzero(rsp[i].resp, strlen(rsp[i].resp));
			xfree(rsp[i].resp);
		}

		rsp[i].resp = NULL;
	}

	xfree(rsp);
	return PAM_CONV_ERR;
}

static void pamcleanup(int ret, bool sess, bool cred)
{
	if (sess) {
		ret = pam_close_session(pamh, 0);

		if (ret != PAM_SUCCESS)
			errx(EXIT_FAILURE, "pam_close_session: %s", pam_strerror(pamh, ret));
	}

	if (cred) {
		ret = pam_setcred(pamh, PAM_DELETE_CRED | PAM_SILENT);

		if (ret != PAM_SUCCESS)
			warn("pam_setcred(?, PAM_DELETE_CRED | PAM_SILENT): %s", pam_strerror(pamh, ret));
	}

	pam_end(pamh, ret);
}

void pamauth(char const *restrict prompt, char const *target_name, char const *original_name)
{
	static struct pam_conv const conv = { .conv = pamconv, .appdata_ptr = NULL };
	char const *ttydev;
	int ret;
	bool sess = false, cred = false;

	doas_prompt = prompt;

	if (target_name == NULL || original_name == NULL)
		errx(EXIT_FAILURE, "Authentication failed");

	ret = pam_start(PAM_SERVICE_NAME, original_name, &conv, &pamh);

	if (ret != PAM_SUCCESS)
		errx(EXIT_FAILURE, "pam_start(\"%s\", \"%s\", ?, ?): failed", PAM_SERVICE_NAME, original_name);

	ret = pam_set_item(pamh, PAM_RUSER, original_name);

	if (ret != PAM_SUCCESS)
		warn("pam_set_item(?, PAM_RUSER, \"%s\"): %s", pam_strerror(pamh, ret), original_name);

	if (isatty(STDIN_FILENO) && (ttydev = ttyname(STDIN_FILENO)) != NULL) {
		if (strneq(ttydev, "/dev/", 5))
			ttydev += 5;

		ret = pam_set_item(pamh, PAM_TTY, ttydev);

		if (ret != PAM_SUCCESS)
			warn("pam_set_item(?, PAM_TTY, \"%s\"): %s", ttydev, pam_strerror(pamh, ret));
	}

	/* Authenticate.  */
	ret = pam_authenticate(pamh, 0);

	if (ret != PAM_SUCCESS) {
		pamcleanup(ret, sess, cred);
		syslog(LOG_AUTHPRIV | LOG_NOTICE, "failed auth for %s", original_name);
		errx(EXIT_FAILURE, "Authentication failed");
	}

	ret = pam_acct_mgmt(pamh, 0);

	if (ret == PAM_NEW_AUTHTOK_REQD)
		ret = pam_chauthtok(pamh, PAM_CHANGE_EXPIRED_AUTHTOK);

	/* Account not vaild or changing the auth token failed.  */
	if (ret != PAM_SUCCESS) {
		pamcleanup(ret, sess, cred);
		syslog(LOG_AUTHPRIV | LOG_NOTICE, "failed auth for %s", original_name);
		errx(EXIT_FAILURE, "Authentication failed");
	}

	/* Set PAM_USER to the user we want to be.  */
	ret = pam_set_item(pamh, PAM_USER, target_name);

	if (ret != PAM_SUCCESS)
		warn("pam_set_item(?, PAM_USER, \"%s\"): %s", target_name, pam_strerror(pamh, ret));

	ret = pam_setcred(pamh, PAM_REINITIALIZE_CRED);

	if (ret != PAM_SUCCESS)
		warn("pam_setcred(?, PAM_REINITIALIZE_CRED): %s", pam_strerror(pamh, ret));
	else
		cred = true;

	/* Open session.  */
	ret = pam_open_session(pamh, 0);

	if (ret != PAM_SUCCESS)
		errx(EXIT_FAILURE, "pam_open_session: %s", pam_strerror(pamh, ret));

	sess = true;
	pamcleanup(PAM_SUCCESS, sess, cred);
}
