
#include <errno.h>
#include <unistd.h>

size_t full_write(int fd, const void *buf, size_t len)
{
	const char *s = buf;
	size_t n = len;

	if (len == 0) {
		errno = EINVAL;
		return 0;
	}

	do {
		int saved_errno = errno;
		ssize_t ret = write(fd, s, n);

		if (ret < 0) {
			if (errno == EINTR
			 || errno == EWOULDBLOCK
			 || errno == EAGAIN) {
				errno = saved_errno;
				continue;
			}
			break;
		}

		if (ret == 0) {
			/* According to gnulib note.
			   Some buggy drivers return 0 when one tries
			   to write beyond a device's end.
			   (Example: Linux 1.2.13 on /dev/fd0.)
			   Set errno to ENOSPC so they get a sensible
			   diagnostic.  */
			errno = ENOSPC;
			break;
		}

		s += ret;
		n -= ret;
	} while (n != 0);

	return len - n;
}

size_t full_read(int fd, void *buf, size_t len)
{
	char *s = buf;
	size_t n = len;

	if (len == 0) {
		errno = EINVAL;
		return 0;
	}

	do {
		int saved_errno = errno;
		ssize_t ret = read(fd, s, n);

		if (ret < 0) {
			if (errno == EWOULDBLOCK
			    || (errno != EINTR && errno != EAGAIN)) {
				break;
			} else {
				errno = saved_errno;
				continue;
			}
		}

		if (ret == 0)
			break;

		s += ret;
		n -= ret;
	} while (n != 0);


	return len - n;
}
