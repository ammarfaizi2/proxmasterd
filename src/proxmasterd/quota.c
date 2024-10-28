
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <proxmasterd/quota.h>

#include <poll.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>


#ifndef __packed
#define __packed	__attribute__((__packed__))
#endif

struct quota_pkt {
	uint8_t		type;
	union {
		uint64_t	add;
		uint64_t	sub;
		uint64_t	set;
		uint64_t	res;
	};
} __packed;

int qo_connect(const char *path)
{
	struct sockaddr_un addr;
	struct timeval tv;
	int fd, err;

	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
	if (fd < 0)
		return -errno;

	// Set recv timeout to 3 seconds
	tv.tv_sec = 3;
	tv.tv_usec = 0;
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, path, sizeof(addr.sun_path));
	addr.sun_path[sizeof(addr.sun_path) - 1] = '\0';
	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		struct pollfd pfd;

		err = -errno;
		if (err != -EINPROGRESS && err != -EAGAIN) {
			close(fd);
			return err;
		}

		pfd.fd = fd;
		pfd.events = POLLOUT;
		while (1) {
			err = poll(&pfd, 1, 3000);
			if (err < 0) {
				if (errno == EINTR)
					continue;
				close(fd);
				return -errno;
			}

			if (err == 0) {
				close(fd);
				return -ETIMEDOUT;
			}

			if (pfd.revents & POLLOUT)
				break;
		}
	}

	return fd;
}

int qo_send_cmd(int fd, uint8_t cmd, uint64_t val, uint64_t *ret_p)
{
	struct quota_pkt pkt;
	ssize_t ret;
	size_t len;

	pkt.type = cmd;
	switch (cmd) {
	case QUOTA_PKT_ADD:
		pkt.add = val;
		break;
	case QUOTA_PKT_SUB:
		pkt.sub = val;
		break;
	case QUOTA_PKT_SET:
		pkt.set = val;
		break;
	case QUOTA_PKT_GET:
		break;
	}

	if (cmd == QUOTA_PKT_GET)
		len = 1;
	else
		len = sizeof(pkt);

	ret = send(fd, &pkt, len, MSG_WAITALL);
	if (ret < 0)
		return -errno;

	while (1) {
		struct pollfd pfd;

		pfd.fd = fd;
		pfd.events = POLLIN;
		ret = poll(&pfd, 1, 3000);
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			return -errno;
		}

		if (ret == 0)
			return -ETIMEDOUT;

		if (pfd.revents & POLLIN) {
			ret = recv(fd, &pkt, sizeof(pkt), MSG_WAITALL);
			if (ret < 0)
				return -errno;
		} else {
			ret = -EIO;
		}

		break;
	}

	if (ret != sizeof(pkt))
		return -EIO;

	if (pkt.type != QUOTA_PKT_RES)
		return -EIO;

	if (ret_p)
		*ret_p = pkt.res;

	return 0;		
}

int main(void)
{
	const char *path = "./q.sock";
	int fd, err;
	uint64_t q;

	fd = qo_connect(path);
	if (fd < 0) {
		fprintf(stderr, "qo_connect: %s\n", strerror(-fd));
		return 1;
	}

	err = qo_send_cmd(fd, QUOTA_PKT_GET, 0, &q);
	if (err) {
		fprintf(stderr, "qo_send: %s\n", strerror(-err));
		close(fd);
		return 1;
	}

	printf("last quota: %lu\n", q);
	close(fd);
	return 0;
}
