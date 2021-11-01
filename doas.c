/* $OpenBSD: doas.c,v 1.57 2016/06/19 19:29:43 martijn Exp $ */
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

#if defined(HAVE_INTTYPES_H)
# include <inttypes.h>
#endif

#if _POSIX_C_SOURCE >= 200809L || _GNU_SOURCE
# define HAVE_FEXECVE 1
#else
# define HAVE_FEXECVE 0
#endif

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <paths.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <syslog.h>
#include <unistd.h>

#if defined(HAVE_LOGIN_CAP_H)
# include <login_cap.h>
#endif /* HAVE_LOGIN_CAP_H */

#include "compat.h"
#include "env.h"
#include "rule.h"
#if USE_TIMESTAMP
# include "timestamp.h"
#endif
#include "wrappers.h"

#if defined(USE_BSD_AUTH)
extern __nonnull((1, 2)) void authuser(char const *restrict doas_prompt, char const *restrict name, char const *restrict login_style, bool persist);
#elif defined(USE_PAM)
extern void pamauth(char const *restrict doas_prompt, char const *restrict target_name, char const *restrict original_name);
#elif defined(USE_SHADOW)
extern __nonnull((1)) void shadowauth(char const *restrict doas_prompt, char const *name);
#endif

extern struct rule const *const rules;
extern size_t const nrules;

extern void check_permissions(char const *filename)
	__nonnull((1));
extern u_int parse_config(char const *filename)
	__nonnull((1));

static inline __noreturn void usage(void)
{
	fputs("usage: doas [-dnSs] [-a style] [-c command] [-C config]"
	      " [-u user] program [args]\n", stderr);
	exit(EXIT_FAILURE);
}

static __nonnull((1)) void print_rule(struct rule const *rule)
{
	printf("%s", rule->permit ? "permit" : "deny");

	if (rule->keepenvlist != NULL) {
		char const *const *e;

		printf(" keepenv {");

		for (e = rule->keepenvlist; *e != NULL; e++)
			printf(" \"%s\"%s", *e, *(e + 1) != NULL ? "," : "");

		printf(" }");
	}

	if (rule->setenvlist != NULL) {
		char const *const *e;

		printf(" setenv {");

		for (e = rule->setenvlist; *e != NULL; e++)
			printf(" \"%s\"%s", *e, *(e + 1) != NULL ? "," : "");

		printf(" }");
	}

	if (rule->unsetenvlist != NULL) {
		char const *const *e;

		printf(" unsetenv {");

		for (e = rule->unsetenvlist; *e != NULL; e++)
			printf(" \"%s\"%s", *e, *(e + 1) != NULL ? "," : "");

		printf(" }");
	}

	if (rule->persist_time != 0)
		printf(" persist(%lu)", (u_long)rule->persist_time);

	if (rule->inheritenv)
		printf(" inheritenv");

	if (rule->nopass)
		printf(" nopass");

	if (rule->nolog)
		printf(" nolog");

	if (rule->ident.pw != NULL)
		printf(" '%s'", rule->ident.pw->pw_name);

	if (rule->ident.gr != NULL)
		printf(" from '%s'", rule->ident.gr->gr_name);

	printf(" as '%s'", rule->target.pw->pw_name);

	if (rule->argc != 0) {
		if (rule->argv == NULL) {
			printf(" execute { ... }");
		} else {
			int i;

			printf(" execute { ");

			/* TODO: optimize comparation and commas.  */
			for (i = 0; rule->argv[i] != NULL; i++) {
				assert(rule->argv[i][0] != NULL);

				if (rule->argv[i][1] == NULL)
					printf("\"%s\"", rule->argv[i][0]);
				else {
					int j = 0;
					printf("[");

					while (rule->argv[i][j] != NULL) {
						printf("\"%s\"", rule->argv[i][j]);

						if (rule->argv[i][++j] != NULL)
							printf(", ");
					}

					printf("]");
				}

				if (rule->argv[i + 1] != NULL)
					printf(", ");
			}

			if (i != rule->argc)
				printf(" ...");

			printf(" }");
		}
	}

	printf("\n");
}

static bool match(uid_t uid, gid_t const *restrict groups, u_int ngroups,
		  uid_t target_uid, int argc, char const *const restrict *restrict argv,
		  struct rule const *restrict r)
{
	if (uid != ROOT_UID)
		if (r->ident.pw != NULL && r->ident.pw->pw_uid != uid)
			return false;

	if (r->ident.gr != NULL) {
		u_int i;
		gid_t rgid = r->ident.gr->gr_gid;

		for (i = 0; i < ngroups && rgid != groups[i]; i++)
			continue;

		if (i == ngroups)
			return false;
	}

	if (r->target.pw != NULL && r->target.pw->pw_uid != target_uid)
		return false;

	if (r->argv != NULL) {
		int i;

		if (r->argv[r->argc] == NULL && r->argc != argc)
			return false;

		/* Do not rely on r->argc since r->argv[r->argc] does not
		   point to NULL, when ellipsis used in rule
		   (in case r->argv[r->argc] != NULL && r->argc != argc).  */
		for (i = 0; r->argv[i] != NULL; i++) {
			int j;

			if (argv[i] == NULL)
				return false;

			for (j = 0; r->argv[i][j] != NULL; j++)
				if (streq(r->argv[i][j], argv[i]))
					break;

			if (r->argv[i][j] == NULL)
				return false;
		}
	}

	return true;
}

static bool permit(uid_t uid, gid_t const *restrict groups, u_int ngroups,
		   uid_t target, int argc, char const *const restrict *restrict argv,
		   struct rule const *restrict *restrict lastr)
{
	u_int i = nrules;

	static struct rule basic_rule = {
		/* Do not keep environ to allow user execute command
		   with clean environ.	*/
		.nopass = true,
		.nolog = true,
		.permit = true
	};

	if (basic_rule.env == NULL)
		basic_rule.env = createenv();

	if (uid == ROOT_UID) {
		/* But nothing else matters.  */
		/* Root is allowed to do anything (not necessarily
		   for love).  */
		*lastr = &basic_rule;
		return true;
	}

	while (i-- != 0) {
		if (match(uid, groups, ngroups, target, argc, argv, &rules[i])) {
			*lastr = &rules[i];
			return (*lastr)->permit;
		}
	}

	if (uid == target) {
		*lastr = &basic_rule;
		return true;
	} else {
		*lastr = NULL;
		return false;
	}
}

static __noreturn void check_config(char const *restrict confpath,
				    int argc, char const *const restrict *restrict argv,
				    uid_t uid, gid_t const *restrict groups,
				    u_int ngroups, uid_t target)
{
	struct rule const *rule;
	int status;

	if (setresuid(uid, uid, uid) < 0)
		errx(EXIT_FAILURE, "unable to set uid to %lu", (u_long)uid);

	if (parse_config(confpath) != 0)
		exit(EXIT_FAILURE);

	if (argc == 0)
		exit(EXIT_SUCCESS);

	status = permit(uid, groups, ngroups, target, argc, argv, &rule) ? EXIT_SUCCESS : EXIT_FAILURE;

	if (rule != NULL)
		print_rule(rule);

	exit(status);
}

static __nonnull((1, 2, 3)) void authenticate(struct passwd *restrict original_pw, struct passwd *restrict target_pw, char *restrict login_style, bool persist)
{
	static char host[HOST_NAME_MAX + 1] = { '\0' };
	char format[] = "\rdoas (%s@%s) password: ";
	char prompt[256];

	if (host[0] == '\0' && gethostname(host, sizeof(host)) < 0) {
		host[0] = '?';
		host[1] = '\0';
	}

	if (sizeof(format) - 1 + strlen(original_pw->pw_name) + strlen(host) + 1 >= sizeof(prompt))
		strcpy(prompt, "Password: ");
	else
		xsnprintf(prompt, sizeof(prompt), format, original_pw->pw_name, host);

#if defined(USE_BSD_AUTH)
	authuser(prompt, target_pw->pw_name, login_style, persist);
#elif defined(USE_PAM)
	(void)login_style;
	(void)persist;
	pamauth(prompt, target_pw->pw_name, original_pw->pw_name);
#elif defined(USE_SHADOW)
	(void)target_pw;
	(void)login_style;
	(void)persist;
	shadowauth(prompt, original_pw->pw_name);
#else
	(void)original_pw;
	(void)target_pw;
	(void)login_style;
	(void)persist;
	/* No authentication provider, only allow nopass rules.  */
	errx(EXIT_FAILURE, "no authentication module");
#endif
}

/* Substitute current user by user given in pw.  */
static inline __nonnull((1)) void substitute(struct passwd const *pw)
{
#if defined(HAVE_LOGIN_CAP_H)
	if (setusercontext(NULL, pw, pw->pw_uid, LOGIN_SETGROUP | LOGIN_SETPRIORITY | LOGIN_SETRESOURCES | LOGIN_SETUMASK | LOGIN_SETUSER) != 0)
		errx(EXIT_FAILURE, "failed to set user context for target");
#else
	umask(022);

	if (setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) < 0)
		err(EXIT_FAILURE, "setresgid");

	if (initgroups(pw->pw_name, pw->pw_gid) < 0)
		err(EXIT_FAILURE, "initgroups");

	if (setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid) < 0)
		err(EXIT_FAILURE, "setresuid");
#endif
}

static inline bool checkshell(char const *shell)
{
	struct stat sb;

	return shell != NULL && *shell == '/'
		&& (eaccess(shell, X_OK) == 0
		    || (stat(shell, &sb) == 0 && S_ISREG(sb.st_mode)
			&& (geteuid() != ROOT_UID || (sb.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) != 0)));
}

static inline __returns_nonnull char *getshell(struct passwd const *target_pw)
{
	size_t i;
	char const *const shells[] = { getenv("SHELL"), target_pw->pw_shell, _PATH_BSHELL };

	for (i = 0; i < countof(shells); i++)
		if (checkshell(shells[i]))
			return xstrdup(shells[i]);

	errx(EXIT_FAILURE, "can not find shell");
}

static inline __nonnull((1)) void path_filter(char *const path)
{
	char *colon = path;
	char *s = path;

	/*
	 * Every entry in $PATH must:
	 *   1) exist
	 *   2) be directory
	 *   3) not be writable by group or other
	 *   4) be owned by root
	 */

	while (true) {
		struct stat sb;
		char const *directory = colon;

		colon = strchr(colon, ':');

		if (colon == NULL)
			break;

		*colon++ = '\0';

		if (stat(directory, &sb) != 0) {
			warn("%s", directory);
			goto skip;
		}

		if (!S_ISDIR(sb.st_mode)) {
			warnc(ENOTDIR, "%s", directory);
			goto skip;
		}

		if (sb.st_mode & (S_IWGRP | S_IWOTH)) {
			warnx("%s is writable by group or other", directory);
			goto skip;
		}

		if (sb.st_uid != ROOT_UID || sb.st_gid != ROOT_UID) {
			warnx("%s is not owned by root", directory);
			goto skip;
		}

		size_t directory_length = colon - directory - 1;
		memcpy(s, directory, directory_length);
		s[directory_length] = ':';
		s += directory_length + 1;
		continue;

	skip:
		warnx("%s is not kept in $PATH", directory);
	}

	s[-1] = '\0';
}

#if HAVE_FEXECVE
/* Returns only valid file descriptor.  */
static inline __nonnull((1, 2)) __wur int find_and_open_program(char const *const restrict name, char const *const restrict path)
{
	int fd;
	char *full_path;
	size_t longest_path_size = 0;
	char const *p1 = path;
	char const *p2 = strchrnul(path, ':');

	/* If program name contain '/', then do not search program in the $PATH
	   or if $PATH is not set, the default search path is implementation
	   dependent.  */
	if (strchr(name, '/') != NULL || *p1 == '\0') {
		fd = safe_open(name, O_RDONLY, 0);

		if (faccessat(fd, "", X_OK, AT_EACCESS | AT_EMPTY_PATH) != 0)
			err(EXIT_FAILURE, "%s: file is not executable", name);

		return fd;
	}

	do {
		if (p2 - p1 > longest_path_size)
			longest_path_size = p2 - p1;

		p1 = p2 + 1;
	} while (*p2 != '\0' && (p2 = strchrnul(p2 + 1, ':')) != NULL);

	full_path = xmalloc(longest_path_size + strlen(name) + 1);

	p1 = path;
	p2 = strchrnul(path, ':');

	do {
		struct stat sb;
		size_t const path_length = p2 - p1;
		char *p = memcpy(full_path, p1, path_length);

		p[path_length] = '/';
		strcpy(p + path_length + 1, name);

		fd = open(full_path, O_RDONLY);

		if (fd < 0) {
			if (errno == ENOENT)
				continue;
			else
				err(EXIT_FAILURE, "can not open %s", full_path);
		}

		if (faccessat(fd, "", X_OK, AT_EACCESS | AT_EMPTY_PATH) != 0)
			err(EXIT_FAILURE, "%s: file is not executable", full_path);

		/* Check that the progpathname does not point to a directory.  */
		if (fstatat(fd, "", &sb, AT_EMPTY_PATH) != 0)
			err(EXIT_FAILURE, "can not stat %s", full_path);
		else if (S_ISDIR(sb.st_mode))
			errc(EXIT_FAILURE, EISDIR, "%s", full_path);

		xfree(full_path);

		return fd;
	} while (*p2 != '\0' && (p1 = p2 + 1, p2 = strchrnul(p2 + 1, ':')) != NULL);

	err(EXIT_FAILURE, "can not find %s", name);
}
#endif

int main(int argc, char **argv)
{
	char safepath[] = SAFE_PATH;
	char *formerpath;
	char const *confpath = NULL;
	char *path;
	char const *cmd = NULL;
	char *argv0;
	char cmdline[LINE_MAX];
	struct rule const *rule;
	gid_t *groups;
	int ngroups;
	int i, optc;
	bool Sflag = false, sflag = false, nflag = false;
	char *login_style = NULL;
	char **envp;
#if defined(USE_TIMESTAMP)
	int timestamp_fd = -1;
	bool timestamp_valid = false;
#endif
#if HAVE_FEXECVE
	int execfd;
	char hashbang[2];
#endif
	extern struct passwd *original_pw, *target_pw;

	setprogname(argv[0]);

	closefrom(STDERR_FILENO + 1);

	if (!isatty(STDERR_FILENO))
		exit(EXIT_FAILURE);

	if (!isatty(STDIN_FILENO))
		err(EXIT_FAILURE, "stdin is not a tty");

	while ((optc = getopt(argc, argv, "+a:c:C:eLu:nSs")) >= 0) {
		switch (optc) {
		case 'a':
			login_style = optarg;
			break;
		case 'C':
			confpath = optarg;
			break;
		case 'c':
			cmd = optarg;
			break;
		case 'L':
#if defined(USE_TIMESTAMP)
			exit(timestamp_clear() == 0 ? EXIT_SUCCESS : EXIT_FAILURE);
#elif defined(TIOCCLRVERAUTH)
			exit((i = open(_PATH_TTY, O_RDWR)) >= 0 && ioctl(i, TIOCCLRVERAUTH) == 0 ? EXIT_SUCCESS : EXIT_FAILURE);
#else
			warn("no timestamp module");
			exit(EXIT_SUCCESS);
#endif
		case 'u':
			target_pw = xgetpwnam(optarg);
			break;
		case 'n':
			nflag = true;
			break;
		case 'S':
			Sflag = true;
			fallthrough;
		case 's':
			sflag = true;
			break;
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	if (sflag == (cmd != NULL || confpath != NULL || argc != 0)
	 || (cmd != NULL && argc != 0))
		usage();

	original_pw = xgetpwuid(getuid());

	if (target_pw == NULL)
		target_pw = xgetpwuid(ROOT_UID);

	/* Get number of groups.  */
	ngroups = getgroups(0, NULL);

	if (ngroups < 0)
		err(EXIT_FAILURE, "can not get count of groups");

	groups = xmalloc((ngroups + 1) * sizeof(*groups));
	ngroups = getgroups(ngroups, groups);

	if (ngroups < 0)
		err(EXIT_FAILURE, "can not get groups");

	groups[ngroups++] = getgid();

	if (cmd != NULL) {
		argc = 3;
		argv -= optind;

		argv[0] = getshell(target_pw);
		argv[1] = (char *)"-c";
		argv[2] = (char *)cmd;
		argv[3] = NULL;
	}

	if (sflag) {
		argc = 1;
		argv -= optind;

		argv[0] = getshell(target_pw);
		argv[1] = NULL;
	}

	if (confpath != NULL) {
		safe_pledge("stdio rpath getpw id", NULL);
		check_config(confpath, argc, (char const *const *)argv,
			     original_pw->pw_uid, groups, ngroups,
			     target_pw->pw_uid);
	}

	if (geteuid() != ROOT_UID)
		errc(EXIT_FAILURE, EPERM, "not installed setuid");

	check_permissions(DOAS_CONF);

	if (parse_config(DOAS_CONF) != 0)
		exit(EXIT_FAILURE);

	/* cmdline is used only for logging, no need to abort
	   on truncate.	 */
	(void)strlcpy(cmdline, argv[0], sizeof(cmdline));

	for (i = 1; i < argc; i++)
		if (strlcat(cmdline, " ", sizeof(cmdline)) >= sizeof(cmdline)
		 || strlcat(cmdline, argv[i], sizeof(cmdline)) >= sizeof(cmdline))
			break;

	if (!permit(original_pw->pw_uid, groups, ngroups, target_pw->pw_uid, argc, (char const *const *)argv, &rule)) {
		syslog(LOG_AUTHPRIV | LOG_NOTICE, "failed command for %s: %s",
		       original_pw->pw_name, cmdline);
		errc(EXIT_FAILURE, EPERM, "%s", original_pw->pw_name);
	}

	xfree(groups);

	if (cmd != NULL)
		if (rule->argv != NULL)
			errx(EXIT_FAILURE, "-c option is not allowed if arguments are specified in rule");

	formerpath = getenv("PATH");

	if (formerpath == NULL)
		formerpath = (char *)"";

	argv0 = argv[0];

	if (Sflag)
		argv[0] = (char *)"-doas";

#if defined(USE_TIMESTAMP)
	if (rule->persist_time != 0)
		timestamp_fd = timestamp_open(&timestamp_valid, rule->persist_time);

	if (!rule->nopass && (timestamp_fd < 0 || !timestamp_valid)) {
#else
	if (!rule->nopass) {
#endif
		if (nflag)
			errx(EXIT_FAILURE, "Authorization required");

		authenticate(original_pw, target_pw, login_style, rule->persist_time);
#if defined(USE_TIMESTAMP)
		if (timestamp_fd >= 0) {
			timestamp_set(timestamp_fd, rule->persist_time);
			close(timestamp_fd);
		}
#endif
	}

	safe_pledge("stdio rpath exec getpw id", NULL);

	substitute(target_pw);

	safe_pledge("stdio rpath exec", NULL);

	/* Skip logging if NOLOG is set.  */
	if (!rule->nolog) {
		char cwdpath[PATH_MAX];
		char const *cwd;

		if (getcwd(cwdpath, sizeof(cwdpath)) == NULL)
			cwd = "(failed)";
		else
			cwd = cwdpath;

		syslog(LOG_AUTHPRIV | LOG_INFO, "%s ran command %s as %s from %s",
		       original_pw->pw_name, cmdline, target_pw->pw_name, cwd);
	}

	safe_pledge("stdio exec", NULL);

	envp = prepenv(rule->env);

	xfree(original_pw);
	xfree(target_pw);

	path = (rule->argv != NULL ? safepath : formerpath);
	path_filter(path);

#if HAVE_FEXECVE
	execfd = find_and_open_program(argv0, path);

	if (full_read(execfd, &hashbang, 2) != 2)
		err(EXIT_FAILURE, "can not determine whether file is script or real executable");

	/* Unfortunately, we can not use close-on-execute flag with scripts ran using shebang
	   due to bug in fexecve() syscall.  */
	if (hashbang[0] != '#' || hashbang[1] != '!') {
		int flags = fcntl(execfd, F_GETFD);

		if (flags < 0)
			err(EXIT_FAILURE, "can not get flags of file descriptor");

		if (!(flags & FD_CLOEXEC) && fcntl(execfd, F_SETFD, flags | FD_CLOEXEC) != 0)
			err(EXIT_FAILURE, "can not set close-on-execute flag");
	}
#endif

	/* setusercontext set path for the next process, so reset it for us.  */
	if (setenv("PATH", path, 1) < 0)
		err(EXIT_FAILURE, "failed to set PATH '%s'", path);

#if HAVE_FEXECVE
	fexecve(execfd, argv, envp);
#else
	execvpe(argv0, argv, envp);
#endif

	if (errno == ENOENT)
		errx(EXIT_FAILURE, "%s: command not found", argv[0]);

	err(EXIT_FAILURE, "%s", argv[0]);
}
