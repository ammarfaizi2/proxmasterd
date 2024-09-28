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
	uint32_t		idx;
	uint32_t		ep_mask;
	struct pm_buf		recv_buf;
	struct pm_buf		send_buf;
	struct sockaddr_in46	src_addr;

	void *udata;
	int (*recv_cb)(struct pm_net_client *c, ssize_t recv_ret);
	int (*send_cb)(struct pm_net_client *c, ssize_t send_ret);
	int (*close_cb)(struct pm_net_client *c);
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
	_Atomic(uint32_t)	nr_online_conn;
	struct epoll_event	*events;
	struct pm_net_ctx	*ctx;
	struct pm_net_client	**clients;
	struct pm_stack_u32	stack;
	size_t			client_cap;
	pthread_t		thread;
	volatile bool		need_join_thread;
	volatile bool		handle_event_should_break;
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
	volatile bool		accept_stopped;
	pthread_mutex_t		accept_mutex;
	pthread_mutex_t		start_lock;
	pthread_cond_t		start_cond;
	int			tcp_fd;
	struct pm_net_wrk	*workers;
	struct pm_net_ctx_arg	arg;

	void *udata;
	int (*accept_cb)(struct pm_net_ctx *ctx, struct pm_net_client *c);
};

int __pm_stack_u32_push(struct pm_stack_u32 *s, uint32_t v);
int pm_stack_u32_push(struct pm_stack_u32 *s, uint32_t v);
int __pm_stack_u32_pop(struct pm_stack_u32 *s, uint32_t *v);
int pm_stack_u32_pop(struct pm_stack_u32 *s, uint32_t *v);

int pm_buf_init(struct pm_buf *b, size_t cap);
int pm_buf_append(struct pm_buf *b, const void *data, size_t len);
int pm_buf_resize(struct pm_buf *b, size_t new_cap);
void pm_buf_destroy(struct pm_buf *b);

int pm_net_ctx_init(struct pm_net_ctx *ctx, const struct pm_net_ctx_arg *arg);
void pm_net_ctx_run(struct pm_net_ctx *ctx);
void pm_net_ctx_wait(struct pm_net_ctx *ctx);
void pm_net_ctx_stop(struct pm_net_ctx *ctx);
void pm_net_ctx_destroy(struct pm_net_ctx *ctx);

static inline
void pm_net_ctx_set_accept_cb(struct pm_net_ctx *ctx, int (*accept_cb)(struct pm_net_ctx *ctx, struct pm_net_client *c))
{
	ctx->accept_cb = accept_cb;
}

static inline
void *pm_net_ctx_set_udata(struct pm_net_ctx *ctx, void *udata)
{
	void *old_udata;

	old_udata = ctx->udata;
	ctx->udata = udata;
	return old_udata;
}

static inline
void *pm_net_ctx_get_udata(struct pm_net_ctx *ctx)
{
	return ctx->udata;
}

static inline
void *pm_net_client_set_udata(struct pm_net_client *c, void *udata)
{
	void *old_udata;

	old_udata = c->udata;
	c->udata = udata;
	return old_udata;
}

static inline
void *pm_net_client_get_udata(struct pm_net_client *c)
{
	return c->udata;
}

static inline
void pm_net_client_set_recv_cb(struct pm_net_client *c, int (*recv_cb)(struct pm_net_client *c, ssize_t recv_ret))
{
	c->recv_cb = recv_cb;
}

static inline
void pm_net_client_set_send_cb(struct pm_net_client *c, int (*send_cb)(struct pm_net_client *c, ssize_t send_ret))
{
	c->send_cb = send_cb;
}

static inline
void pm_net_client_set_close_cb(struct pm_net_client *c, int (*close_cb)(struct pm_net_client *c))
{
	c->close_cb = close_cb;
}

#endif /* #ifndef PROXMASTERD__NET_H */
