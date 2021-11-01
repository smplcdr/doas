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

/*
 * 1) Timestamp files and directories
 *
 * Timestamp files MUST NOT be accessible to users other than root,
 * this includes the name, metadata and the content of timestamp files
 * and directories.
 *
 * Symlinks can be used to create, manipulate or delete wrong files
 * and directories. The Implementation MUST reject any symlinks for
 * timestamp files or directories.
 *
 * To avoid race conditions the implementation MUST use the same
 * file descriptor for permission checks and do read or write
 * write operations after the permission checks.
 *
 * The timestamp files MUST be opened with openat(2) using the
 * timestamp directory file descriptor. Permissions of the directory
 * MUST be checked before opening the timestamp file descriptor.
 *
 * 2) Clock sources for timestamps
 *
 * Timestamp files MUST NOT rely on only one clock source, using the
 * wall clock would allow to reset the clock to an earlier point in
 * time to reuse a timestamp.
 *
 * The timestamp MUST consist of multiple clocks and MUST reject the
 * timestamp if there is a change to any clock because there is no way
 * to differentiate between malicious and legitimate clock changes.
 *
 * 3) Timestamp lifetime
 *
 * The implementation MUST NOT use the user controlled stdin, stdout
 * and stderr file descriptors to determine the controlling terminal.
 * On linux the /proc/$pid/stat file MUST be used to get the terminal
 * number.
 *
 * There is no reliable way to determine the lifetime of a tty/pty.
 * The start time of the session leader MUST be used as part of the
 * timestamp to determine if the tty is still the same.
 * If the start time of the session leader changed the timestamp MUST
 * be rejected.
 */

#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/vfs.h>

#if !defined(timespecisset) || !defined(timespeccmp) || !defined(timespecadd)
# include "sys/time.h"
#endif

#include <ctype.h>
#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "compat.h"
#include "wrappers.h"

#if !defined(TIMESTAMP_DIR)
# define TIMESTAMP_DIR "/run/doas"
#endif

#if defined(__linux__)
# define PROC_STATUS_PATH_FORMAT "/proc/%lu/stat"
# define TTY_NUMBER_FIELD_NUMBER 7
# define START_TIME_FIELD_NUMBER 22
#elif defined(__FreeBSD__)
# define PROC_STATUS_PATH_FORMAT "/proc/%lu/status"
# define TTY_NUMBER_FIELD_NUMBER 6
# define START_TIME_FIELD_NUMBER 8
#endif

#define TTY_NUMBER_SIZE 16

#if defined(__linux__) || defined(__FreeBSD__)
/* Use tty_nr from /proc/self/stat instead of using
 * ttyname(3), stdin, stdout and stderr are user
 * controllable and would allow to reuse timestamps
 * from another writable terminal.
 * See https://www.sudo.ws/alerts/tty_tickets.html
 */
static int proc_info(pid_t pid, char ttynr[TTY_NUMBER_SIZE], unsigned long long int *starttime)
{
	char path[128], buf[1024], *p, *saveptr;
	int fd;
	size_t n;
	bool succeed = true;

	if (pid < 0) {
		errno = EINVAL;
		return -1;
	}

	p = buf;

	if (safe_snprintf(path, sizeof(path), PROC_STATUS_PATH_FORMAT, (u_long)pid) < 0)
		return -1;

	if ((fd = open(path, O_RDONLY | O_NOFOLLOW)) < 0) {
		warn("failed to open: %s", path);
		return -1;
	}

	errno = 0;

	while ((n = full_read(fd, p, endof(buf) - p - 1)) != 0) {
		p += n;

		if (p >= endof(buf) - 1)
			break;
	}

	if (errno != 0) {
		warn("read: %s", path);
		close(fd);
		return -1;
	}

	close(fd);

	/* Error if it contains NULL bytes.  */
	if (memchr(buf, '\0', p - buf - 1) != NULL) {
		warn("NUL in: %s", path);
		return -1;
	}

	*p = '\0';

#if defined(__linux__)
	/*
	 * Get the 7th field, 5 fields after the last ')',
	 * (2th field) because the 5th field 'comm' can include
	 * spaces and closing paranthesis too.
	 * See https://www.sudo.ws/alerts/linux_tty.html
	 */
	/* Be careful: program name may include ')' character,
	   so we find the last ')' entry searching from the end.  */
	if ((p = strrchr(buf, ')')) == NULL)
		return -1;

	n = 2;
#elif defined(__FreeBSD__)
	n = 1;
#endif

	for (p = strtok_r(p, " ", &saveptr); p != NULL; p = strtok_r(NULL, " ", &saveptr)) {
		switch (n++) {
		case TTY_NUMBER_FIELD_NUMBER: {
			size_t ttylen = saveptr - p - 1;

			if (ttylen >= TTY_NUMBER_SIZE) {
				errno = EOVERFLOW;
				return -1;
			}

			memcpy(ttynr, p, ttylen);
			break;
		}
		case START_TIME_FIELD_NUMBER:
			*starttime = safe_strtounum(p, ULLONG_MAX, &succeed);
			return succeed ? 0 : -1;
		}
	}

	return -1;
}
#else
/* proc_info not implemented.  */
static int proc_info(pid_t pid __unused, int *ttynr __unused, unsigned long long int *starttime __unused)
{
	errno = ENOSYS;
	return -1;
}
#endif

static char *timestamp_name(char *buf, size_t len)
{
	pid_t ppid, sid;
	unsigned long long starttime;
	char ttynr[16];

	ppid = getppid();

	if (proc_info(ppid, ttynr, &starttime) < 0)
		return NULL;

	if ((sid = getsid(0)) < 0)
		return NULL;

	if (safe_snprintf(buf, len, "%d-%d-%s-%llu-%ld",
			  ppid, sid, ttynr, starttime, (long)getuid()) < 0)
		return NULL;

	return buf;
}

int timestamp_set(int fd, time_t secs)
{
	struct timespec ts[2], timeout = { .tv_sec = secs, .tv_nsec = 0 };

	if (clock_gettime(CLOCK_BOOTTIME, &ts[0]) < 0
	 || clock_gettime(CLOCK_REALTIME, &ts[1]) < 0)
		return -1;

	timespecadd(&ts[0], &timeout, &ts[0]);
	timespecadd(&ts[1], &timeout, &ts[1]);

	return futimens(fd, ts);
}

/* Returns true if the timestamp is valid, false if it is invalid.  */
static bool timestamp_check(int fd, time_t secs)
{
	struct timespec ts[2], timeout = { .tv_sec = secs, .tv_nsec = 0 };
	struct stat st;

	if (secs < 0) {
		errno = EINVAL;
		return false;
	}

	if (fstat(fd, &st) != 0) {
		warn("can not get file status");
		return false;
	}

	if (st.st_uid != ROOT_UID || st.st_gid != getgid() || st.st_mode != (S_IFREG | 0000)) {
		warnx("timestamp uid, gid or mode wrong");
		return false;
	}

	/* This timestamp was created, but never set.
	   Invalid, but no error.  */
	if (!timespecisset(&st.st_atim)
	 || !timespecisset(&st.st_mtim))
		return false;

	if (clock_gettime(CLOCK_BOOTTIME, &ts[0]) < 0
	 || clock_gettime(CLOCK_REALTIME, &ts[1]) < 0) {
		warn("clock_gettime");
		return false;
	}

	/* Check if timestamp is too old.  */
	if (timespeccmp(&st.st_atim, &ts[0], <)
	 || timespeccmp(&st.st_mtim, &ts[1], <))
		return false;

	/* Check if timestamp is too far in the future.  */
	timespecadd(&ts[0], &timeout, &ts[0]);
	timespecadd(&ts[1], &timeout, &ts[1]);

	if (timespeccmp(&st.st_atim, &ts[0], >)
	 || timespeccmp(&st.st_mtim, &ts[1], >)) {
		warnx("timestamp too far in the future");
		return false;
	}

	return true;
}

int timestamp_open(bool *valid, time_t secs)
{
	struct timespec ts[2] = { 0 };
	struct stat st;
	int dirfd, fd;
	char name[256];

	if (secs < 0) {
		errno = EINVAL;
		return -1;
	}

	*valid = false;

	dirfd = open(TIMESTAMP_DIR, O_DIRECTORY | O_NOFOLLOW);

	if (dirfd < 0) {
		if (errno != ENOENT)
			return -1;

		if (mkdir(TIMESTAMP_DIR, 0700) < 0)
			return -1;

		dirfd = open(TIMESTAMP_DIR, O_DIRECTORY | O_NOFOLLOW);

		if (dirfd < 0)
			return -1;
	}

	if (fstat(dirfd, &st) < 0) {
		return -1;
	} else if (st.st_uid != ROOT_UID || st.st_gid != ROOT_UID || st.st_mode != (S_IFDIR | 0700)) {
		if (!S_ISDIR(st.st_mode)) {
			errno = ENOTDIR;
			return -1;
		}

		/* If directory exists make sure that it has required mode and owner.  */
		if (fchmod(dirfd, 0700) < 0)
			return -1;

		if (fchown(dirfd, ROOT_UID, ROOT_UID) < 0)
			return -1;
	}

	if (timestamp_name(name, sizeof(name)) == NULL)
		return -1;

	fd = openat(dirfd, name, O_RDONLY | O_NOFOLLOW);

	if (fd < 0) {
		char tmp[64];

		if (errno != ENOENT) {
			warn("can not open %s", name);
			return -1;
		}

		if (safe_snprintf(tmp, sizeof(tmp), ".tmp-%ld", (long int)getpid()) < 0)
			return -1;

		fd = openat(dirfd, tmp, O_RDONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0000);

		if (fd < 0) {
			warn("can not open "TIMESTAMP_DIR"/%s", tmp);
			return -1;
		}

		if (futimens(fd, ts) < 0 || renameat(dirfd, tmp, dirfd, name) < 0) {
			int saved_errno = errno;

			close(fd);
			unlinkat(dirfd, tmp, 0);
			errno = saved_errno;
			return -1;
		}
	} else {
		*valid = timestamp_check(fd, secs);
	}

	return fd;
}

int timestamp_clear(void)
{
	char name[256];
	int dirfd = open(TIMESTAMP_DIR, O_DIRECTORY | O_NOFOLLOW);

	if (dirfd < 0)
		return -1;

	if (timestamp_name(name, sizeof(name)) == NULL)
		return -1;

	if (unlinkat(dirfd, name, 0) < 0 && errno != ENOENT)
		return -1;

	return 0;
}
