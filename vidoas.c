/* Edit a temporary copy of the doas.conf file and check it for syntax
   errors before installing it as the actual doas.conf file.  */
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

/* Based on vidoas.sh */

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <libgen.h>
#include <paths.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#if _POSIX_MAPPED_FILES > 0
# define HAVE_MMAP 1
#else
# define HAVE_MMAP 0
#endif

#if HAVE_MMAP
# include <sys/mman.h>
#endif

#if defined(__gnu_linux__)
# include <linux/fs.h>
# if !defined(FICLONE) && defined(_IOW)
#  define FICLONE _IOW(0x94, 9, int)
# endif
#endif

#if defined(FICLONE)
# include <sys/ioctl.h>
#endif

#if defined(__gnu_linux__)
# include <sys/sendfile.h>
#endif

#include "compat.h"
#include "wrappers.h"

extern u_int parse_config(char const *file_name) __nonnull((1));
extern void free_rules(void);

static int special_signals[] = { SIGINT, SIGQUIT };

#define set_action_for_signals(act)					\
	do {								\
		size_t i;						\
		struct sigaction sa;					\
									\
		sa.sa_flags = 0;					\
		sigemptyset(&sa.sa_mask);				\
		sa.sa_handler = act;					\
									\
		for (i = 0; i < countof(special_signals); i++)		\
			sigaction(special_signals[i], &sa, NULL);	\
	} while (0)

static inline void ignore_signals(void)
{
	set_action_for_signals(SIG_IGN);
}
static inline void default_signals(void)
{
	set_action_for_signals(SIG_DFL);
}

static inline void safe_stat(char const *file, struct stat *sb)
{
	if (stat(file, sb) != 0)
		err(EXIT_FAILURE, "%s", file);
}

static inline off_t safe_lseek(int fd, off_t offset, int whence)
{
	off_t o = lseek(fd, offset, whence);

	if (o < 0)
		err(EXIT_FAILURE, "lseek");

	return o;
}

static inline __returns_nonnull __nonnull((1)) char *ownerof(char const *file)
{
	struct stat sb;
	struct passwd *pw;
	char *owner;

	safe_stat(file, &sb);
	pw = xgetpwuid(sb.st_uid);
	owner = xstrdup(pw->pw_name);
	xfree(pw);
	return owner;
}

static inline __noreturn void usage(int status)
{
	fprintf(status == EXIT_SUCCESS ? stdout : stderr, "\
Usage: %s [-e editor] [-n] [file]\n\
       %s -h\n\
\n\
Edit a temporary copy of a doas configuration file and check it for\n\
syntax errors before installing it as the actual configuration file.\n\
\n\
When no file is named, %s will edit the default configuration file\n\
for doas(1): "DOAS_CONF"\n\
\n\
Options:\n\
-e EDITOR	Force EDITOR as editor, if -n option specified, this option is ignored.\n\
-h		Show this usage.\n\
-n		Do not edit the file, just perform prerequisite checks. If this\n\
		switch is repeated, all output will be suppressed and the check\n\
		result is only indicated by the exit status.\n\
",
		getprogname(), getprogname(), getprogname());
	exit(status);
}

#if !defined(S_ISNAM) /* Xenix */
# if defined(S_IFNAM)
#  define S_ISNAM(m) (((m) & S_IFMT) == S_IFNAM)
# else
#  define S_ISNAM(m) 0
# endif
#endif

#if !defined(S_TYPEISSHM)
# if defined(S_INSHD)
#  define S_TYPEISSHM(p) (S_ISNAM((p)->st_mode) && (p)->st_rdev == S_INSHD)
# else
#  define S_TYPEISSHM(p) 0
# endif
#endif

#if !defined(S_TYPEISTMO)
# define S_TYPEISTMO(p) 0
#endif

/* Return a boolean indicating whether SB->st_size is defined.  */
static inline __wur __nonnull((1)) bool
reliable_st_size (struct stat const *sb)
{
  return (S_ISREG(sb->st_mode) || S_ISLNK(sb->st_mode) || S_TYPEISSHM(sb) || S_TYPEISTMO(sb));
}

static inline __wur size_t get_file_size(int fd)
{
	struct stat sb;

	safe_fstat(fd, &sb);

	if (!reliable_st_size(&sb))
		errx(EXIT_FAILURE, "can not determine file size");

	return sb.st_size;
}

static inline __wur int cmp(int fd1, int fd2)
{
	int r;
	void *p1, *p2;
	size_t s1, s2;
	size_t sz;

	safe_lseek(fd1, 0, SEEK_SET);
	safe_lseek(fd2, 0, SEEK_SET);

	s1 = get_file_size(fd1);
	s2 = get_file_size(fd2);

	if (s1 != s2)
		return s1 > s2 ? +1 : -1;

	sz = s1;
	if (sz == 0)
		return 0;

#if HAVE_MMAP
	p1 = mmap(NULL, sz, PROT_READ, MAP_PRIVATE | MAP_LOCKED, fd1, 0);
	p2 = mmap(NULL, sz, PROT_READ, MAP_PRIVATE | MAP_LOCKED, fd2, 0);

	if (p1 != MAP_FAILED && p2 != MAP_FAILED) {
		r = memcmp(p1, p2, sz);

		munmap(p1, sz);
		munmap(p2, sz);
	} else
#endif
	{
		size_t bytes1, bytes2;
		char buf1[BUFSIZ], buf2[BUFSIZ];

		errno = 0;

		while (true) {
			bytes1 = full_read(fd1, buf1, sizeof(buf1));

			if (errno != 0)
				err(EXIT_FAILURE, "read");

			bytes2 = full_read(fd2, buf2, sizeof(buf2));

			if (errno != 0)
				err(EXIT_FAILURE, "read");

			if ((bytes1 | bytes2) == 0) {
				r = 0;
				break;
			}

			if ((r = (bytes1 > bytes2) - (bytes1 < bytes2)) != 0)
				break;

			if ((r = memcmp(buf1, buf2, bytes1)) != 0)
				break;
		}
	}

	return r;
}

static inline void cp(int srcfd, int dstfd)
{
	void *sp;
	size_t sz = get_file_size(srcfd);

	safe_lseek(srcfd, 0, SEEK_SET);
	safe_lseek(dstfd, 0, SEEK_SET);

	if (ftruncate(dstfd, sz) < 0)
		err(EXIT_FAILURE, "ftruncate");

#if defined(__APPLE__)
	if (fcopyfile(srcfd, dstfd, 0, COPYFILE_ALL) >= 0)
		goto lend;
#endif

#if defined(FICLONE)
	if (ioctl(dstfd, FICLONE, srcfd) >= 0)
		goto lend;
#endif
#if defined(__gnu_linux__)
	/* Do not use copy_file_range() since it has some issues
	   on versions <5.3.  */
	if (sendfile(dstfd, srcfd, NULL, sz) >= 0)
		goto lend;
#endif
	sp = mmap(NULL, sz, PROT_READ, MAP_PRIVATE | MAP_LOCKED, srcfd, 0);

	if (sp == MAP_FAILED) {
		sp = xmalloc(sz);

		if (full_read(srcfd, sp, sz) != sz)
			err(EXIT_FAILURE, "read");

		if (full_write(dstfd, sp, sz) != sz)
			err(EXIT_FAILURE, "write");

		xfree(sp);
	} else {
		if (full_write(dstfd, sp, sz) != sz)
			err(EXIT_FAILURE, "write");

		if (munmap(sp, sz) < 0)
			warn("munmap");
	}

lend:
	if (fsync(dstfd) < 0)
	  err(EXIT_FAILURE, "fsync");
}

/* The dirname() may modify its argument, so use the weird wrapper.  */
static inline __returns_nonnull __nonnull((1)) char *get_directory_name(char const *path)
{
	char *p = xstrdup(path);
	char *dn = dirname(p);
	size_t sz = strlen(dn) + 1;

	return xrealloc(memmove(p, dn, sz), sz);
}

static inline __nonnull((1)) void check_directory_permissions(char const *directory, u_int noedit)
{
	struct stat sb;

	safe_stat(directory, &sb);

	if (!S_ISDIR(sb.st_mode))
		errc(EXIT_FAILURE, ENOTDIR, "%s", directory);

	if (!(sb.st_mode & S_IWUSR) && noedit == 0)
		errx(EXIT_FAILURE,
		     "%s is not writable, you probably need to run %s as %s",
		     directory, getprogname(), ownerof(directory));
}

static inline __nonnull((1)) bool yes(char const *prompt)
{
	bool yes = false;
	char *response = NULL;
	size_t size = 0;
	ssize_t length = 0;

	fprintf(stderr, "%s: (yes or no) %s ", getprogname(), prompt);

repeat:
	/* EOF is accepted as «no».  */
	if ((length = getline(&response, &size, stdin)) <= 0) {
		fputc('\n', stderr);
		yes = false;
	} else {
		if ((response[0] == 'Y' || response[0] == 'y')
		 && (response[1] == 'E' || response[1] == 'e')
		 && (response[2] == 'S' || response[2] == 's')
		 && response[3] == '\n' && response[4] == '\0') {
			yes = true;
		} else if ((response[0] == 'N' || response[0] == 'n')
			&& (response[1] == 'O' || response[1] == 'o')
			&& response[2] == '\n' && response[3] == '\0') {
			yes = false;
		} else {
			fprintf(stderr, "%s: (please, answer yes or no) %s ",
				getprogname(), prompt);
			goto repeat;
		}
	}

	xfree(response);

	return yes;
}

static __nonnull((1)) u_int check_config(char const *file)
{
	u_int errors = parse_config(file);

	free_rules();

	return errors;
}

static __nonnull((1, 2)) void run_editor(char const *editor, char const *file)
{
	char const *const argv[] = { editor, file, NULL };
	int status;
	pid_t pid = fork();

	if (pid < 0)
		err(EXIT_FAILURE, "fork");

	if (pid == 0) {
		default_signals();
		execvp(argv[0], (char *const *)argv);
		err(EXIT_FAILURE, "can not execute '%s'", argv[0]);
	}

	do {
		while (waitpid(pid, &status, 0) < 0)
			if (errno != EINTR)
				err(EXIT_FAILURE, "waitpid");
	} while (!WIFEXITED(status) && !WIFSIGNALED(status));
}

static void install_config(const char *file, int configfd, int tmpfd, mode_t mode, uid_t uid, gid_t gid)
{
	if (get_file_size(tmpfd) == 0) {
		warnx("not installing an empty doas.conf file, %s unchanged", file);
		return;
	}

	if (cmp(tmpfd, configfd) == 0) {
		warnx("no changes made, %s unchanged", file);
		return;
	}

	cp(tmpfd, configfd);

	if (fchmod(configfd, mode) != 0)
		err(EXIT_FAILURE, "can not change permissions");

	if (fchown(configfd, uid, gid) != 0)
		err(EXIT_FAILURE, "can not change owner");

	warnx("%s updated", file);
}

int main(int argc, char **argv)
{
	int optc;
	u_int noedit = 0;
	char const *editor = NULL;
	int flags;
	char const *config;
	struct stat config_sb;
	int config_descriptor;
	char *directory;
	char *temporary_copy;
	int temporary_copy_descriptor;
	char *lock_file;
	extern struct passwd *original_pw, *target_pw;

	setprogname(argv[0]);

	if (setvbuf(stdout, NULL, _IOLBF, 0) != 0)
		err(EXIT_FAILURE, "setvbuf");

	if (!isatty(STDERR_FILENO))
		exit(EXIT_FAILURE);

	if (!isatty(STDIN_FILENO))
		err(EXIT_FAILURE, "stdin is not a tty");

	if (!isatty(STDOUT_FILENO))
		err(EXIT_FAILURE, "stdout is not a tty");

	while ((optc = getopt(argc, argv, "+e:hn")) >= 0) {
		switch (optc) {
		case 'e':
			editor = optarg;
			break;
		case 'h':
			usage(EXIT_SUCCESS);
		case 'n':
			noedit++;
			break;
		default:
			usage(EXIT_FAILURE);
		}
	}

	if (argc > optind + 1)
		usage(EXIT_FAILURE);

	ignore_signals();

	closefrom(STDERR_FILENO + 1);

	umask(077);

	config = (argc == optind + 1 ? argv[optind] : DOAS_CONF);
	directory = get_directory_name(config);

	lock_file = xmalloc(strlen(config) + sizeof(".lock"));
	xsprintf(lock_file, "%s.lock", config);

	check_directory_permissions(directory, noedit);

	config_descriptor = safe_open(config, O_RDWR | O_NONBLOCK | O_CLOEXEC, 0);

	safe_fstat(config_descriptor, &config_sb);

	if (fchmod(config_descriptor, config_sb.st_mode | S_ISVTX) != 0)
		err(EXIT_FAILURE, "can not change mode of %s", config);

	if (noedit != 0) {
		bool ok = (check_config(config) == 0);

		if (noedit < 2)
			warnx(ok ? "OK: All prerequisite checks in %s are passed"
			         : "%s contains syntax errors",
			      config);

		exit(ok ? EXIT_SUCCESS : EXIT_FAILURE);
	}

	temporary_copy = xmalloc(strlen(config) + sizeof(".XXXXXX"));
	xsprintf(temporary_copy, "%s.XXXXXX", config);

	temporary_copy_descriptor = mkstemp(temporary_copy);

	if (temporary_copy_descriptor < 0)
		err(EXIT_FAILURE, "mkstemp: %s", temporary_copy);

	if (fchmod(temporary_copy_descriptor, S_IRUSR | S_IWUSR | S_ISVTX) != 0)
		err(EXIT_FAILURE, "can not change mode of %s", temporary_copy);

	if (fchown(temporary_copy_descriptor, geteuid(), getegid()) != 0)
		err(EXIT_FAILURE, "can not change owner of %s", temporary_copy);

	flags = fcntl(temporary_copy_descriptor, F_GETFD);

	if (flags < 0)
		err(EXIT_FAILURE, "can not get file descriptor flags");

	if (!(flags & FD_CLOEXEC) && fcntl(temporary_copy_descriptor, F_SETFD, flags | FD_CLOEXEC) < 0)
		err(EXIT_FAILURE, "can not set file descriptor flags");

	cp(config_descriptor, temporary_copy_descriptor);

	/* Link the temporary file to the lock file.  */
	if (link(temporary_copy, lock_file) < 0)
		err(EXIT_FAILURE,
		    (errno == EEXIST) ? "%s is already locked"
		                      : "can not create lock file %s",
		    config);

	if (editor == NULL) {
		editor = getenv("EDITOR");

		if (editor == NULL || *editor == '\0')
			editor = _PATH_VI;
	}

	original_pw = xgetpwuid(getuid());
	target_pw = xgetpwuid(ROOT_UID);

	do
		run_editor(editor, temporary_copy);
	while (check_config(temporary_copy) != 0 && yes("edit again to fix it?"));

	install_config(config, config_descriptor, temporary_copy_descriptor, config_sb.st_mode, config_sb.st_uid, config_sb.st_gid);

	unlink(temporary_copy);
	unlink(lock_file);

	safe_close(config_descriptor);
	xfree(directory);
	xfree(temporary_copy);
	safe_close(temporary_copy_descriptor);
	xfree(lock_file);

	return 0;
}
