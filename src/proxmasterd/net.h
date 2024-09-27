// SPDX-License-Identifier: GPL-2.0-only
#ifndef PROXMASTERD__NET_H
#define PROXMASTERD__NET_H

#include <sys/eventfd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/epoll.h>

#include <netinet/in.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <errno.h>

struct sockaddr_in46 {
	union {
		struct sockaddr		sa;
		struct sockaddr_in	v4;
		struct sockaddr_in6	v6;
	};
};

struct pm_buf {
	size_t		len;
	size_t		cap;
	char		*buf;
};

struct pm_net_client {
	int			fd;
	struct pm_buf		recv_buf;
	struct pm_buf		send_buf;
	struct sockaddr_in46	src_addr;
};

struct pm_stack_u32 {
	size_t		bp;
	size_t		sp;
	uint32_t	*arr;
	pthread_mutex_t	lock;
};

struct pm_net_ctx;

struct pm_net_wrk {
	int			ep_fd;
	int			ev_fd;
	uint32_t		idx;
	uint32_t		nr_events;
	struct epoll_event	*events;
	struct pm_net_ctx	*ctx;
	struct pm_net_client	**clients;
	struct pm_stack_u32	stack;
	size_t			client_cap;
	size_t			nr_online_conn;
	pthread_t		thread;
	volatile bool		need_join_thread;
};

struct pm_net_ctx_arg {
	uint16_t		nr_workers;
	uint32_t		client_init_cap;
	int			sock_backlog;
	struct sockaddr_in46	bind_addr;
};

struct pm_net_ctx {
	volatile bool		should_stop;
	volatile bool		started;
	pthread_mutex_t		start_lock;
	pthread_cond_t		start_cond;
	int			tcp_fd;
	struct pm_net_wrk	*workers;
	struct pm_net_ctx_arg	arg;
};

int pm_buf_init(struct pm_buf *b, size_t cap);
int pm_buf_append(struct pm_buf *b, const void *data, size_t len);
int pm_buf_resize(struct pm_buf *b, size_t new_cap);
void pm_buf_destroy(struct pm_buf *b);

void pm_net_ctx_run(struct pm_net_ctx *ctx);
void pm_net_ctx_stop(struct pm_net_ctx *ctx);
void pm_net_ctx_destroy(struct pm_net_ctx *ctx);

#endif /* #ifndef PROXMASTERD__NET_H */
