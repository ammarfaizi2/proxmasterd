// SPDX-License-Identifier: GPL-2.0-only

#include <proxmasterd/net.h>

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

enum {
	EPL_EVT_EVENTFD		= (1ull << 48ull),
	EPL_EVT_CLIENT_POLLIN	= (2ull << 48ull),
	EPL_EVT_CLIENT_POLLOUT	= (3ull << 48ull),
	EPL_EVT_ACCEPT		= (4ull << 48ull),
};

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

static int sock_init(struct pm_net_ctx *ctx)
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

static void sock_destroy(struct pm_net_ctx *ctx)
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

	new_len = b->len + len + 1;
	if (new_len > b->cap) {
		if (pm_buf_resize(b, new_len * 2))
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

static int client_init(struct pm_net_client *c)
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

static struct pm_net_client *client_alloc(void)
{
	struct pm_net_client *c;

	c = calloc(1, sizeof(*c));
	if (!c)
		return NULL;

	if (client_init(c)) {
		free(c);
		return NULL;
	}

	return c;
}

static void client_destroy(struct pm_net_client *c)
{
	if (!c)
		return;

	if (c->fd >= 0)
		close(c->fd);

	pm_buf_destroy(&c->recv_buf);
	pm_buf_destroy(&c->send_buf);
	memset(c, 0, sizeof(*c));
}

static void clients_destroy(struct pm_net_wrk *w)
{
	uint32_t i;

	if (!w->clients)
		return;

	for (i = 0; i < w->client_cap; i++)
		client_destroy(w->clients[i]);

	free(w->clients);
	w->clients = NULL;
}

static int clients_init(struct pm_net_wrk *w)
{
	struct pm_net_client **clients, *c;
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

static int epoll_init(struct pm_net_wrk *w)
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

static void epoll_destroy(struct pm_net_wrk *w)
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

static int worker_init(struct pm_net_wrk *w)
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

	ret = pthread_create(&w->thread, NULL, &worker_entry, w);
	if (ret) {
		epoll_destroy(w);
		clients_destroy(w);
		return -ret;
	}

	w->need_join_thread = true;
	return ret;
}

static void worker_destroy(struct pm_net_wrk *w)
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

static void workers_destroy(struct pm_net_ctx *ctx)
{
	uint32_t i;

	if (!ctx->workers)
		return;

	pm_net_ctx_stop(ctx);
	for (i = 0; i < ctx->arg.nr_workers; i++)
		worker_destroy(&ctx->workers[i]);

	free(ctx->workers);
	ctx->workers = NULL;
}

static int workers_init(struct pm_net_ctx *ctx)
{
	struct pm_net_wrk *workers;
	uint32_t i;
	int ret;

	if (ctx->arg.nr_workers == 0)
		return -EINVAL;

	workers = calloc(ctx->arg.nr_workers, sizeof(*ctx->workers));
	if (!workers)
		return -ENOMEM;

	for (i = 0; i < ctx->arg.nr_workers; i++) {
		struct pm_net_wrk *w = &workers[i];

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

enum {
	WORKER_WAIT_RUN  = 0,
	WORKER_WAIT_STOP = 1,
};

static int poll_events(struct pm_net_wrk *w)
{
	struct epoll_event *events = w->events;
	uint32_t nr_events = w->nr_events;
	int ret;

	ret = epoll_wait(w->ep_fd, events, nr_events, -1);
	if (ret < 0) {
		ret = -errno;
		if (ret == -EINTR)
			return 0;

		return ret;
	}

	return ret;
}

static int worker_wait_for_start_signal(struct pm_net_wrk *w)
{
	struct pm_net_ctx *ctx = w->ctx;
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
	struct pm_net_wrk *w = arg;
	int ret;

	ret = worker_wait_for_start_signal(w);
	if (ret == WORKER_WAIT_STOP)
		goto out;




out:
	pm_net_ctx_stop(w->ctx);
	return NULL;
}

int pm_net_ctx_init(struct pm_net_ctx *ctx, const struct pm_net_ctx_arg *arg)
{
	int ret;

	memset(ctx, 0, sizeof(*ctx));
	ctx->arg = *arg;

	ret = pthread_mutex_init(&ctx->start_lock, NULL);
	if (ret)
		return ret;

	ret = pthread_cond_init(&ctx->start_cond, NULL);
	if (ret) {
		pthread_mutex_destroy(&ctx->start_lock);
		return ret;
	}

	ret = sock_init(ctx);
	if (ret) {
		pthread_cond_destroy(&ctx->start_cond);
		pthread_mutex_destroy(&ctx->start_lock);
		return ret;
	}

	ret = workers_init(ctx);
	if (ret) {
		sock_destroy(ctx);
		pthread_cond_destroy(&ctx->start_cond);
		pthread_mutex_destroy(&ctx->start_lock);
		return ret;
	}

	return 0;
}

void pm_net_ctx_run(struct pm_net_ctx *ctx)
{
	pthread_mutex_lock(&ctx->start_lock);
	ctx->started = true;
	pthread_cond_broadcast(&ctx->start_cond);
	pthread_mutex_unlock(&ctx->start_lock);
}

void pm_net_ctx_stop(struct pm_net_ctx *ctx)
{
	pthread_mutex_lock(&ctx->start_lock);
	ctx->should_stop = true;
	pthread_cond_broadcast(&ctx->start_cond);
	pthread_mutex_unlock(&ctx->start_lock);
}

void pm_net_ctx_destroy(struct pm_net_ctx *ctx)
{
	pm_net_ctx_stop(ctx);
	workers_destroy(ctx);
	sock_destroy(ctx);
	pthread_cond_destroy(&ctx->start_cond);
	pthread_mutex_destroy(&ctx->start_lock);
}
