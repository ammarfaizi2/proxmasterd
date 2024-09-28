// SPDX-License-Identifier: GPL-2.0-only

#include <proxmasterd/net_tcp.h>

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


struct pm_net_tcp_client {
	int			fd;
	uint32_t		idx;
	uint32_t		ep_mask;
	struct pm_buf		recv_buf;
	struct pm_buf		send_buf;
	struct sockaddr_in46	src_addr;

	void *udata;
	recv_cb_t		recv_cb;
	send_cb_t		send_cb;
	close_cb_t		close_cb;
};

struct pm_net_tcp_wrk {
	int				ep_fd;
	int				ev_fd;
	uint32_t			idx;
	uint32_t			nr_events;
	_Atomic(uint32_t)		nr_online_conn;
	struct epoll_event		*events;
	struct pm_net_tcp_ctx		*ctx;
	struct pm_net_tcp_client	**clients;
	struct pm_stack_u32		stack;
	size_t				client_cap;
	pthread_t			thread;
	volatile bool			need_join_thread;
	volatile bool			handle_event_should_break;
};

struct pm_net_tcp_ctx {
	volatile bool		should_stop;
	volatile bool		started;
	volatile bool		accept_stopped;
	int			tcp_fd;
	accept_cb_t		accept_cb;
	void			*ctx_udata;
	struct pm_net_tcp_wrk	*workers;
	struct pm_net_tcp_arg	arg;
	pthread_mutex_t		accept_lock;
	pthread_mutex_t		start_lock;
	pthread_cond_t		start_cond;
};

enum {
	EPL_EVT_EVENTFD	= (1ull << 48ull),
	EPL_EVT_CLIENT	= (2ull << 48ull),
	EPL_EVT_ACCEPT	= (3ull << 48ull),
};

#define EPL_EV_MASK		(0xffffull << 48ull)
#define GET_EPL_EV(data)	((data) & EPL_EV_MASK)
#define GET_EPL_DT(data)	((void *)((data) & ~EPL_EV_MASK))
#define INIT_BUF_SIZE		4096

int pm_stack_u32_init(struct pm_stack_u32 *s, size_t cap)
{
	int ret;

	s->arr = malloc(cap * sizeof(uint32_t));
	if (!s->arr)
		return -1;

	ret = pthread_mutex_init(&s->lock, NULL);
	if (ret) {
		free(s->arr);
		return -1;
	}

	s->sp = 0;
	s->bp = cap;
	return 0;
}

void pm_stack_u32_destroy(struct pm_stack_u32 *s)
{
	pthread_mutex_destroy(&s->lock);
	free(s->arr);
	memset(s, 0, sizeof(*s));
}

int __pm_stack_u32_push(struct pm_stack_u32 *s, uint32_t v)
{
	if (s->sp == s->bp)
		return -EAGAIN;

	s->arr[s->sp++] = v;
	return 0;
}

int pm_stack_u32_push(struct pm_stack_u32 *s, uint32_t v)
{
	int ret;

	pthread_mutex_lock(&s->lock);
	ret = __pm_stack_u32_push(s, v);
	pthread_mutex_unlock(&s->lock);
	return ret;
}

int __pm_stack_u32_pop(struct pm_stack_u32 *s, uint32_t *v)
{
	if (s->sp == 0)
		return -EAGAIN;

	*v = s->arr[--s->sp];
	return 0;
}

int pm_stack_u32_pop(struct pm_stack_u32 *s, uint32_t *v)
{
	int ret;

	pthread_mutex_lock(&s->lock);
	ret = __pm_stack_u32_pop(s, v);
	pthread_mutex_unlock(&s->lock);
	return ret;
}

static int sock_init(struct pm_net_tcp_ctx *ctx)
{
	int family, fd, err;
	socklen_t len;
	int tmp;

	ctx->tcp_fd = -1;
	family = ctx->arg.bind_addr.sa.sa_family;
	if (family != AF_INET && family != AF_INET6)
		return -EINVAL;

	if (family == AF_INET)
		len = sizeof(struct sockaddr_in);
	else
		len = sizeof(struct sockaddr_in6);

	fd = socket(family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -errno;

	tmp = 1;
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &tmp, sizeof(tmp));

	if (bind(fd, &ctx->arg.bind_addr.sa, len) < 0) {
		err = -errno;
		close(fd);
		return err;
	}

	if (listen(fd, ctx->arg.sock_backlog) < 0) {
		err = -errno;
		close(fd);
		return err;
	}

	ctx->tcp_fd = fd;
	return 0;
}

static void sock_destroy(struct pm_net_tcp_ctx *ctx)
{
	if (ctx->tcp_fd >= 0) {
		close(ctx->tcp_fd);
		ctx->tcp_fd = -1;
	}
}

int pm_buf_init(struct pm_buf *b, size_t cap)
{
	b->buf = malloc(cap);
	if (!b->buf)
		return -ENOMEM;

	b->len = 0;
	b->cap = cap;
	return 0;
}

void pm_buf_destroy(struct pm_buf *b)
{
	free(b->buf);
	memset(b, 0, sizeof(*b));
}

int pm_buf_append(struct pm_buf *b, const void *data, size_t len)
{
	size_t new_len;

	if (!len)
		return 0;

	new_len = b->len + len;
	if (new_len > b->cap) {
		if (pm_buf_resize(b, (new_len + 1) * 2))
			return -ENOMEM;
	}

	memcpy(b->buf + b->len, data, len);
	b->len = new_len;
	return 0;
}

int pm_buf_resize(struct pm_buf *b, size_t new_cap)
{
	char *new_buf;

	new_buf = realloc(b->buf, new_cap);
	if (!new_buf)
		return -ENOMEM;

	b->buf = new_buf;
	b->cap = new_cap;
	if (b->len > new_cap)
		b->len = new_cap;

	return 0;
}

static int client_init(struct pm_net_tcp_client *c)
{
	int ret;

	c->fd = -1;
	memset(&c->src_addr, 0, sizeof(c->src_addr));
	ret = pm_buf_init(&c->recv_buf, 4096);
	if (ret)
		return ret;

	ret = pm_buf_init(&c->send_buf, 4096);
	if (ret) {
		pm_buf_destroy(&c->recv_buf);
		return ret;
	}

	return 0;
}

static struct pm_net_tcp_client *client_alloc(void)
{
	struct pm_net_tcp_client *c;

	c = calloc(1, sizeof(*c));
	if (!c)
		return NULL;

	if (client_init(c)) {
		free(c);
		return NULL;
	}

	return c;
}

static void client_destroy(struct pm_net_tcp_client *c)
{
	if (!c)
		return;

	if (c->close_cb)
		c->close_cb(c);

	if (c->fd >= 0)
		close(c->fd);

	pm_buf_destroy(&c->recv_buf);
	pm_buf_destroy(&c->send_buf);
	memset(c, 0, sizeof(*c));
}

static void clients_destroy(struct pm_net_tcp_wrk *w)
{
	uint32_t i;

	if (!w->clients)
		return;

	for (i = 0; i < w->client_cap; i++)
		client_destroy(w->clients[i]);

	free(w->clients);
	w->clients = NULL;
}

static int clients_init(struct pm_net_tcp_wrk *w)
{
	struct pm_net_tcp_client **clients, *c;
	uint32_t i;
	int ret;

	clients = calloc(w->ctx->arg.client_init_cap, sizeof(*clients));
	if (!clients)
		return -ENOMEM;

	ret = pm_stack_u32_init(&w->stack, w->ctx->arg.client_init_cap);
	if (ret) {
		free(clients);
		return ret;
	}

	w->client_cap = w->ctx->arg.client_init_cap;
	w->clients = clients;
	for (i = 0; i < w->client_cap; i++) {
		c = client_alloc();
		if (!c) {
			clients_destroy(w);
			pm_stack_u32_destroy(&w->stack);
			return -ENOMEM;
		}

		c->fd = -1;
		c->idx = i;
		clients[i] = c;
		__pm_stack_u32_push(&w->stack, i);
	}

	return 0;
}

static int epoll_add(int ep_fd, int fd, uint32_t events, union epoll_data data)
{
	struct epoll_event ev = { .events = events, .data = data };
	return epoll_ctl(ep_fd, EPOLL_CTL_ADD, fd, &ev);
}

static int epoll_del(int ep_fd, int fd)
{
	return epoll_ctl(ep_fd, EPOLL_CTL_DEL, fd, NULL);
}

static int epoll_mod(int ep_fd, int fd, uint32_t events, union epoll_data data)
{
	struct epoll_event ev = { .events = events, .data = data };
	return epoll_ctl(ep_fd, EPOLL_CTL_MOD, fd, &ev);
}

static int send_event_fd(struct pm_net_tcp_wrk *w)
{
	uint64_t val = 1;
	ssize_t ret;

	ret = write(w->ev_fd, &val, sizeof(val));
	if (ret < 0)
		return -errno;

	return 0;
}

static int recv_event_fd(struct pm_net_tcp_wrk *w)
{
	uint64_t val;
	ssize_t ret;

	ret = read(w->ev_fd, &val, sizeof(val));
	if (ret < 0)
		return -errno;

	return 0;
}

static int epoll_init(struct pm_net_tcp_wrk *w)
{
	static const uint32_t nr_events = 128;
	struct epoll_event *events;
	union epoll_data data;
	int ep_fd, ev_fd, err;

	w->ep_fd = w->ev_fd = -1;
	ep_fd = epoll_create(128);
	if (ep_fd < 0)
		return -errno;

	ev_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
	if (ev_fd < 0) {
		err = -errno;
		close(ep_fd);
		return err;
	}

	events = calloc(nr_events, sizeof(*events));
	if (!events) {
		close(ev_fd);
		close(ep_fd);
		return -ENOMEM;
	}

	data.u64 = EPL_EVT_EVENTFD;
	err = epoll_add(ep_fd, ev_fd, EPOLLIN, data);
	if (err) {
		free(events);
		close(ev_fd);
		close(ep_fd);
		return err;
	}

	w->ep_fd = ep_fd;
	w->ev_fd = ev_fd;
	w->nr_events = nr_events;
	w->events = events;
	return 0;
}

static void epoll_destroy(struct pm_net_tcp_wrk *w)
{
	if (w->ep_fd >= 0) {
		close(w->ep_fd);
		w->ep_fd = -1;
	}

	if (w->ev_fd >= 0) {
		close(w->ev_fd);
		w->ev_fd = -1;
	}

	if (w->events) {
		free(w->events);
		w->events = NULL;
	}
}

static void *worker_entry(void *arg);

static int worker_init(struct pm_net_tcp_wrk *w)
{
	int ret;

	ret = clients_init(w);
	if (ret)
		return ret;

	ret = epoll_init(w);
	if (ret) {
		clients_destroy(w);
		return ret;
	}

	if (w->idx == 0) {
		union epoll_data data;

		data.u64 = EPL_EVT_ACCEPT;
		ret = epoll_add(w->ep_fd, w->ctx->tcp_fd, EPOLLIN, data);
		if (ret) {
			epoll_destroy(w);
			clients_destroy(w);
			return ret;
		}
	}

	ret = pthread_create(&w->thread, NULL, &worker_entry, w);
	if (ret) {
		epoll_destroy(w);
		clients_destroy(w);
		return -ret;
	}

	w->need_join_thread = true;
	return ret;
}

static void worker_destroy(struct pm_net_tcp_wrk *w)
{
	if (!w)
		return;

	if (w->need_join_thread) {
		pthread_join(w->thread, NULL);
		w->need_join_thread = false;
	}

	epoll_destroy(w);
	clients_destroy(w);
}

static void workers_destroy(struct pm_net_tcp_ctx *ctx)
{
	uint32_t i;

	if (!ctx->workers)
		return;

	pm_net_tcp_ctx_stop(ctx);
	for (i = 0; i < ctx->arg.nr_workers; i++)
		worker_destroy(&ctx->workers[i]);

	free(ctx->workers);
	ctx->workers = NULL;
}

static int workers_init(struct pm_net_tcp_ctx *ctx)
{
	struct pm_net_tcp_wrk *workers;
	uint32_t i;
	int ret;

	if (ctx->arg.nr_workers == 0)
		return -EINVAL;

	workers = calloc(ctx->arg.nr_workers, sizeof(*ctx->workers));
	if (!workers)
		return -ENOMEM;

	for (i = 0; i < ctx->arg.nr_workers; i++) {
		struct pm_net_tcp_wrk *w = &workers[i];

		w->idx = i;
		w->ctx = ctx;
		ret = worker_init(w);
		if (ret) {
			while (i--)
				worker_destroy(&workers[i]);
			free(workers);
			return ret;
		}
	}

	ctx->workers = workers;
	return 0;
}

static int get_client_slot(struct pm_net_tcp_wrk *w, struct pm_net_tcp_client **cp)
{
	struct pm_net_tcp_client *c;
	uint32_t idx;
	int ret;

	pthread_mutex_lock(&w->stack.lock);
	ret = __pm_stack_u32_pop(&w->stack, &idx);
	if (ret) {
		pthread_mutex_unlock(&w->stack.lock);
		return -EAGAIN;
	}
	c = w->clients[idx];
	pthread_mutex_unlock(&w->stack.lock);

	assert(c);
	assert(c->fd < 0);
	assert(!c->recv_buf.len);
	assert(!c->send_buf.len);
	assert(!c->recv_cb);
	assert(!c->send_cb);
	assert(!c->close_cb);
	*cp = c;
	atomic_fetch_add(&w->nr_online_conn, 1u);
	return ret;
}

static int __put_client_slot(struct pm_net_tcp_wrk *w, struct pm_net_tcp_client *c, bool del_epoll)
{
	int ret;

	pthread_mutex_lock(&w->stack.lock);

	if (c->close_cb)
		c->close_cb(c);

	if (c->fd >= 0) {
		if (del_epoll) {
			ret = epoll_del(w->ep_fd, c->fd);
			assert(!ret);
		}
		close(c->fd);
		c->fd = -1;
	}

	if (c->recv_buf.cap > INIT_BUF_SIZE)
		pm_buf_resize(&c->recv_buf, INIT_BUF_SIZE);
	if (c->send_buf.cap > INIT_BUF_SIZE)
		pm_buf_resize(&c->send_buf, INIT_BUF_SIZE);

	c->recv_buf.len = 0;
	c->send_buf.len = 0;
	c->recv_cb = NULL;
	c->send_cb = NULL;
	c->close_cb = NULL;
	ret = __pm_stack_u32_push(&w->stack, w->idx);
	assert(!ret);
	pthread_mutex_unlock(&w->stack.lock);
	atomic_fetch_sub(&w->nr_online_conn, 1u);
	return ret;
}

static int put_client_slot(struct pm_net_tcp_wrk *w, struct pm_net_tcp_client *c)
{
	return __put_client_slot(w, c, true);
}

static int put_client_slot_no_epoll(struct pm_net_tcp_wrk *w, struct pm_net_tcp_client *c)
{
	return __put_client_slot(w, c, false);
}

static struct pm_net_tcp_wrk *pick_worker_for_new_conn(struct pm_net_tcp_ctx *ctx)
{
	struct pm_net_tcp_wrk *w = &ctx->workers[0];
	uint32_t i, min, min_idx = 0, tmp;

	if (ctx->arg.nr_workers == 1)
		return w;

	min = atomic_load_explicit(&w->nr_online_conn, memory_order_relaxed);
	for (i = 1; i < ctx->arg.nr_workers; i++) {
		w = &ctx->workers[i];
		tmp = atomic_load_explicit(&w->nr_online_conn, memory_order_relaxed);

		if (tmp < min) {
			min = tmp;
			min_idx = i;
		}
	}

	return &ctx->workers[min_idx];
}

static int handle_accept_error(int err, struct pm_net_tcp_wrk *w)
{
	if (err == EAGAIN || err == EINTR)
		return 0;

	if (err == EMFILE || err == ENFILE) {
		pthread_mutex_lock(&w->ctx->accept_lock);
		w->ctx->accept_stopped = true;
		pthread_mutex_unlock(&w->ctx->accept_lock);
		return epoll_del(w->ep_fd, w->ctx->tcp_fd);
	}

	return -err;
}

/*
 * @fd: The ownership is taken by give_client_fd_to_a_worker().
 */
static int give_client_fd_to_a_worker(struct pm_net_tcp_ctx *ctx, int fd,
				      const struct sockaddr_in46 *addr)
{	
	struct pm_net_tcp_client *c;
	struct pm_net_tcp_wrk *w;
	union epoll_data data;
	int r;

	w = pick_worker_for_new_conn(ctx);
	r = get_client_slot(w, &c);
	if (r) {
		close(fd);
		return -ENOMEM;
	}

	c->fd = fd;
	c->src_addr = *addr;
	c->ep_mask = EPOLLIN;

	data.u64 = 0;
	data.ptr = c;
	data.u64 |= EPL_EVT_CLIENT;
	r = epoll_add(w->ep_fd, fd, c->ep_mask, data);
	if (r) {
		put_client_slot_no_epoll(w, c);
		return r;
	}

	if (ctx->accept_cb)
		ctx->accept_cb(ctx, c);

	return 0;
}

static int handle_event_accept(struct pm_net_tcp_wrk *w)
{
	static const uint32_t NR_MAX_ACCEPT_CYCLE = 4;
	struct sockaddr_in46 addr;
	uint32_t counter = 0;
	socklen_t len;
	int ret;

do_accept:
	memset(&addr, 0, sizeof(addr));
	if (w->ctx->arg.bind_addr.sa.sa_family == AF_INET)
		len = sizeof(struct sockaddr_in);
	else
		len = sizeof(struct sockaddr_in6);

	ret = accept4(w->ctx->tcp_fd, &addr.sa, &len, SOCK_NONBLOCK | SOCK_CLOEXEC);
	if (ret < 0)
		return handle_accept_error(errno, w);

	if (len > sizeof(addr)) {
		close(ret);
		return -EINVAL;
	}

	ret = give_client_fd_to_a_worker(w->ctx, ret, &addr);
	if (ret)
		return 0;

	if (++counter < NR_MAX_ACCEPT_CYCLE)
		goto do_accept;

	return 0;
}

static int apply_ep_mask(struct pm_net_tcp_wrk *w, struct pm_net_tcp_client *c)
{
	union epoll_data data;

	data.u64 = 0;
	data.ptr = c;
	data.u64 |= EPL_EVT_CLIENT;
	return epoll_mod(w->ep_fd, c->fd, c->ep_mask, data);
}

static int handle_event_client_send(struct pm_net_tcp_wrk *w,
				    struct pm_net_tcp_client *c)
{
	struct pm_buf *b = &c->send_buf;
	ssize_t ret;
	size_t len;
	int err;

	len = b->len;
	if (!len)
		return 0;

	err = 0;
	ret = send(c->fd, b->buf, len, MSG_DONTWAIT);
	if (ret > 0) {
		memmove(b->buf, b->buf + ret, len - ret);
		b->len -= (size_t)ret;
		if (c->send_cb)
			err = c->send_cb(c);
	} else if (ret == 0) {
		err = -ECONNRESET;
	} else {
		err = -errno;
	}

	if (err == -EAGAIN || err == -EINTR)
		err = 0;

	if (!err) {
		if (b->len) {
			if (!(c->ep_mask & EPOLLOUT)) {
				c->ep_mask |= EPOLLOUT;
				err = apply_ep_mask(w, c);
			}
		} else if (c->ep_mask & EPOLLOUT) {
			c->ep_mask &= ~EPOLLOUT;
			err = apply_ep_mask(w, c);
		}
	}

	return err;
}

static int handle_event_client_recv(struct pm_net_tcp_wrk *w,
				    struct pm_net_tcp_client *c)
{
	struct pm_buf *b = &c->recv_buf;
	ssize_t ret;
	size_t len;
	int err;

	len = b->cap - b->len;
	if (!len) {
		if (pm_buf_resize(b, (b->cap + 1) * 2))
			return -ENOMEM;
		len = b->cap - b->len;
	}

	err = 0;
	ret = recv(c->fd, b->buf + b->len, len, MSG_DONTWAIT);
	if (ret > 0) {
		b->len += (size_t)ret;
		if (c->recv_cb)
			err = c->recv_cb(c);
	} else if (ret == 0) {
		err = -ECONNRESET;
	} else {
		err = -errno;
	}

	if (err == -EAGAIN || err == -EINTR)
		err = 0;

	if (!err && c->send_buf.len)
		err = handle_event_client_send(w, c);

	return err;
}

static int handle_event_client(struct pm_net_tcp_wrk *w, struct epoll_event *ev)
{
	struct pm_net_tcp_client *c = GET_EPL_DT(ev->data.u64);
	uint32_t events = ev->events;
	int ret = 0;

	if (events & EPOLLIN) {
		ret = handle_event_client_recv(w, c);
		if (ret)
			return ret;
	}

	if (events & EPOLLOUT) {
		ret = handle_event_client_send(w, c);
		if (ret)
			return ret;
	}

	if (events & (EPOLLERR | EPOLLHUP))
		ret = -ECONNRESET;

	return ret;
}

/*
 * Accept and event FD are low priority events.
 * Handle them after all other events.
 */
struct epl_handle_ev {
	bool	has_event_accept;
	bool	has_event_evfd;
};

static int handle_event(struct pm_net_tcp_wrk *w, struct epoll_event *ev,
			struct epl_handle_ev *he)
{
	uint64_t ev_type = GET_EPL_EV(ev->data.u64);
	int ret = 0;

	switch (ev_type) {
	case EPL_EVT_CLIENT:
		ret = handle_event_client(w, ev);
		if (ret) {
			struct pm_net_tcp_client *c = GET_EPL_DT(ev->data.u64);

			put_client_slot(w, c);
			ret = 0;
		}
		break;
	case EPL_EVT_ACCEPT:
		he->has_event_accept = true;
		break;
	case EPL_EVT_EVENTFD:
		he->has_event_evfd = true;
		break;
	default:
		break;
	}


	return ret;
}

static int handle_low_priority_events(struct pm_net_tcp_wrk *w,
				      struct epl_handle_ev *he)
{
	struct pm_net_tcp_ctx *ctx = w->ctx;
	int ret = 0;

	if (ctx->should_stop)
		return ret;

	if (he->has_event_evfd) {
		ret = recv_event_fd(w);
		if (ret)
			return ret;
	}

	if (he->has_event_accept) {
		ret = handle_event_accept(w);
		if (ret)
			return ret;
	}

	return ret;
}

static int handle_events(struct pm_net_tcp_wrk *w, int nr_events)
{
	struct pm_net_tcp_ctx *ctx = w->ctx;
	struct epl_handle_ev he;
	int ret = 0, i;

	if (!nr_events)
		return 0;

	memset(&he, 0, sizeof(he));
	for (i = 0; i < nr_events; i++) {
		struct epoll_event *ev = &w->events[i];

		ret = handle_event(w, ev, &he);
		if (ret < 0)
			break;

		if (ctx->should_stop)
			break;
	}

	if (!ret)
		ret = handle_low_priority_events(w, &he);

	return ret;
}

static int poll_events(struct pm_net_tcp_wrk *w)
{
	struct epoll_event *events = w->events;
	uint32_t nr_events = w->nr_events;
	int ret;

	ret = epoll_wait(w->ep_fd, events, nr_events, -1);
	if (ret < 0) {
		ret = -errno;
		if (ret == -EINTR)
			return 0;
	}

	return ret;
}

enum {
	WORKER_WAIT_RUN  = 0,
	WORKER_WAIT_STOP = 1,
};

static int worker_wait_for_start_signal(struct pm_net_tcp_wrk *w)
{
	struct pm_net_tcp_ctx *ctx = w->ctx;
	int ret;

	pthread_mutex_lock(&ctx->start_lock);
	while (1) {
		if (ctx->should_stop) {
			ret = WORKER_WAIT_STOP;
			break;
		}

		if (ctx->started) {
			ret = WORKER_WAIT_RUN;
			break;
		}

		pthread_cond_wait(&ctx->start_cond, &ctx->start_lock);
	}
	pthread_mutex_unlock(&ctx->start_lock);
	return ret;
}

static void *worker_entry(void *arg)
{
	struct pm_net_tcp_wrk *w = arg;
	struct pm_net_tcp_ctx *ctx = w->ctx;
	int ret;

	ret = worker_wait_for_start_signal(w);
	if (ret == WORKER_WAIT_STOP)
		goto out;

	while (!ctx->should_stop) {
		ret = poll_events(w);
		if (ret < 0)
			break;

		ret = handle_events(w, ret);
		if (ret < 0)
			break;
	}

out:
	pm_net_tcp_ctx_stop(ctx);
	return NULL;
}

int pm_net_tcp_ctx_init(pm_net_tcp_ctx_t **ctx_p, const struct pm_net_tcp_arg *arg)
{
	pm_net_tcp_ctx_t *ctx;
	int ret;

	ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
		return -ENOMEM;

	memset(ctx, 0, sizeof(*ctx));
	ctx->arg = *arg;

	ret = pthread_mutex_init(&ctx->start_lock, NULL);
	if (ret)
		goto out_ctx;
	ret = pthread_mutex_init(&ctx->accept_lock, NULL);
	if (ret)
		goto out_start_lock;
	ret = pthread_cond_init(&ctx->start_cond, NULL);
	if (ret)
		goto out_accept_lock;
	ret = sock_init(ctx);
	if (ret)
		goto out_start_cond;
	ret = workers_init(ctx);
	if (ret)
		goto out_sock;

	*ctx_p = ctx;
	return 0;

out_sock:
	sock_destroy(ctx);
out_start_cond:
	pthread_cond_destroy(&ctx->start_cond);
out_accept_lock:
	pthread_mutex_destroy(&ctx->accept_lock);
out_start_lock:
	pthread_mutex_destroy(&ctx->start_lock);
out_ctx:
	free(ctx);
	return ret;
}

void pm_net_tcp_ctx_run(struct pm_net_tcp_ctx *ctx)
{
	pthread_mutex_lock(&ctx->start_lock);
	ctx->started = true;
	pthread_cond_broadcast(&ctx->start_cond);
	pthread_mutex_unlock(&ctx->start_lock);
}

void pm_net_tcp_ctx_wait(struct pm_net_tcp_ctx *ctx)
{
	pthread_mutex_lock(&ctx->start_lock);
	while (!ctx->should_stop)
		pthread_cond_wait(&ctx->start_cond, &ctx->start_lock);
	pthread_mutex_unlock(&ctx->start_lock);
}

void pm_net_tcp_ctx_stop(struct pm_net_tcp_ctx *ctx)
{
	uint32_t i;

	pthread_mutex_lock(&ctx->start_lock);
	ctx->should_stop = true;
	pthread_cond_broadcast(&ctx->start_cond);
	for (i = 0; i < ctx->arg.nr_workers; i++) {
		struct pm_net_tcp_wrk *w = &ctx->workers[i];

		if (w->need_join_thread)
			send_event_fd(w);
	}
	pthread_mutex_unlock(&ctx->start_lock);
}

void pm_net_tcp_ctx_destroy(struct pm_net_tcp_ctx *ctx)
{
	pm_net_tcp_ctx_stop(ctx);
	workers_destroy(ctx);
	sock_destroy(ctx);
	pthread_cond_destroy(&ctx->start_cond);
	pthread_mutex_destroy(&ctx->start_lock);
	pthread_mutex_destroy(&ctx->accept_lock);
	memset(ctx, 0, sizeof(*ctx));
}

void pm_net_tcp_ctx_set_udata(pm_net_tcp_ctx_t *ctx, void *udata)
{
	ctx->ctx_udata = udata;
}

void *pm_net_tcp_ctx_get_udata(pm_net_tcp_ctx_t *ctx)
{
	return ctx->ctx_udata;
}

void pm_net_tcp_ctx_set_accept_cb(pm_net_tcp_ctx_t *ctx, accept_cb_t accept_cb)
{
	ctx->accept_cb = accept_cb;
}

void pm_net_tcp_client_set_udata(pm_net_tcp_client_t *c, void *udata)
{
	c->udata = udata;
}

void *pm_net_tcp_client_get_udata(pm_net_tcp_client_t *c)
{
	return c->udata;
}

void pm_net_tcp_client_set_recv_cb(pm_net_tcp_client_t *c, recv_cb_t recv_cb)
{
	c->recv_cb = recv_cb;
}

void pm_net_tcp_client_set_send_cb(pm_net_tcp_client_t *c, send_cb_t send_cb)
{
	c->send_cb = send_cb;	
}

void pm_net_tcp_client_set_close_cb(pm_net_tcp_client_t *c, close_cb_t close_cb)
{
	c->close_cb = close_cb;
}

struct pm_buf *pm_net_tcp_client_get_recv_buf(pm_net_tcp_client_t *c)
{
	return &c->recv_buf;
}

struct pm_buf *pm_net_tcp_client_get_send_buf(pm_net_tcp_client_t *c)
{
	return &c->send_buf;
}

const struct sockaddr_in46 *pm_net_tcp_client_get_src_addr(pm_net_tcp_client_t *c)
{
	return &c->src_addr;
}
