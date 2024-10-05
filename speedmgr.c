// SPDX-License-Identifier: GPL-2.0-only

/*
 *
 * Copyright (C) 2024  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 *
 * speedmgr - A simple speed manager for Linux.
 * 
 * Key features:
 *   - Raw TCP proxy.
 *   - Speed limit.
 *   - socks5 proxy.
 * 
 * # Run transparent TCP proxy:
 *    sudo ./speedmgr -b [::]:4444 -t [::]:0 -o 1111;
 *
 * # Run transparent TCP proxy with speed limit (upload 5MB/s, download 5MB/s; note that 5MB/s = 40Mbps):
 *    sudo ./speedmgr -b [::]:4444 -t [::]:0 -U 1M -I 1000 -D 1M -d 1000 -o 1111 -U 5M -I 1s -D 5M -d 1s;
 *
 * # iptables settings for local transparent proxy:
 *    sudo iptables -t nat -I OUTPUT -p tcp -m mark ! --mark 1111 -j REDIRECT --to-ports 4444;
 *
 * # iptables settings for gateway transparent proxy (as a router):
 *    sudo iptables -t nat -I PREROUTING -p tcp -m mark ! --mark 1111 -j REDIRECT --to-ports 4444;
 * 
 * # Delete iptables rules:
 *    sudo iptables -t nat -D OUTPUT -p tcp -m mark ! --mark 1111 -j REDIRECT --to-ports 4444;
 *    sudo iptables -t nat -D PREROUTING -p tcp -m mark ! --mark 1111 -j REDIRECT --to-ports 4444;
 *
 * # Run socks5 proxy (no root required):
 *    ./speedmgr -b [::]:4444 -S;
 *
 * # Run socks5 proxy with username and password:
 *    SPEEDMGR_SOCKS5_USER=user SPEEDMGR_SOCKS5_PASS=pass ./speedmgr -b [::]:4444 -S;
 *
 * The socks5 proxy also supports speed limit.
 *
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifndef likely
#define likely(x)	__builtin_expect(!!(x), 1)
#endif

#ifndef unlikely
#define unlikely(x)	__builtin_expect(!!(x), 0)
#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x)	(sizeof(x) / sizeof((x)[0]))
#endif

#ifndef MIN
#define MIN(a, b)	((a) < (b) ? (a) : (b))
#endif

#ifndef MAX
#define MAX(a, b)	((a) > (b) ? (a) : (b))
#endif


/*
 * The number of `struct epoll_event` array members.
 */
#define NR_EPOLL_EVENTS 128

/*
 * The number of initial client slots.
 */
#define NR_INIT_CLIENT_ARR	2

#define NR_INIT_SPD_BUCKET_ARR	32

#define NR_INIT_RECV_BUF_BYTES	4096
#define NR_MAX_RECV_BUF_BYTES	4096

#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <stdio.h>
#include <errno.h>

#include <netinet/in.h>
#include <sys/time.h>
#include <sys/timerfd.h>
#include <sys/resource.h>
#include <netinet/tcp.h>
#include <sys/eventfd.h>
#include <sys/signal.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <pthread.h>
#include <signal.h>
#include <getopt.h>
#include <unistd.h>
#include <fcntl.h>

#include "ht.h"

#ifndef SO_ORIGINAL_DST
#define SO_ORIGINAL_DST 80
#endif

#ifndef IP6T_SO_ORIGINAL_DST
#define IP6T_SO_ORIGINAL_DST 80
#endif

#define g_dbg_level (1)
static volatile bool *g_stop;
static uint8_t g_verbose;

#ifndef __unused
#define __unused __attribute__((__unused__))
#endif

#ifndef atomic_load_relaxed
#define atomic_load_relaxed(p) atomic_load_explicit(p, memory_order_relaxed)
#endif

#ifndef atomic_store_relaxed
#define atomic_store_relaxed(p, v) atomic_store_explicit(p, v, memory_order_relaxed)
#endif

#if 1
#define pr_debug(fmt, ...)	printf("[%08d] dbug: " fmt "\n", gettid(), ##__VA_ARGS__)
#else
#define pr_debug(fmt, ...) do { } while (0)
#endif

#define pr_error(fmt, ...)	printf("[%08d] perr: " fmt "\n", gettid(), ##__VA_ARGS__)
#define pr_info(fmt, ...)	printf("[%08d] info: " fmt "\n", gettid(), ##__VA_ARGS__)

#define pr_vl_dbg(level, fmt, ...)		\
do {						\
	if (g_dbg_level >= level)		\
		pr_debug(fmt, ##__VA_ARGS__);	\
} while (0)

#define pr_errorv(fmt, ...)			\
do {						\
	if (g_verbose)				\
		pr_error(fmt, ##__VA_ARGS__);	\
} while (0)

#define pr_infov(fmt, ...)			\
do {						\
	if (g_verbose)				\
		pr_info(fmt, ##__VA_ARGS__);	\
} while (0)

struct sockaddr_in46 {
	union {
		struct sockaddr sa;
		struct sockaddr_in in4;
		struct sockaddr_in6 in6;
	};
};

struct spd_tkn {
	uint64_t	tkn;
	uint64_t	last_fill;
	uint64_t	nr_fill;
	uint64_t	fill_intv;
	uint64_t	max;
};

struct ip_spd_bucket {
	struct spd_tkn	up_tkn;
	struct spd_tkn	dn_tkn;
	uint16_t	nr_conns;
	int32_t		wrk_idx;
};

struct ip_spd_map {
	ht_t			ht;
	size_t			cap;
	size_t			len;
	pthread_mutex_t		lock;
	struct ip_spd_bucket	**bucket_arr;
};

struct client_endp {
	int			fd;
	uint32_t		ep_mask;
	size_t			len;
	size_t			cap;
	char			*buf;
	struct sockaddr_in46	addr;
};

enum {
	RTF_UP_RATE_LIMITED	= (1u << 0u),
	RTF_DN_RATE_LIMITED	= (1u << 1u),
};

enum {
	SOCKS5_STATE_INIT	= 0,
	SOCKS5_STATE_AUTH	= 1,
	SOCKS5_STATE_REQ	= 2,
	SOCKS5_STATE_SPLICE	= 3,
};

enum {
	SOCKS5_AUTH_NONE	= 0x00,
	SOCKS5_AUTH_GSSAPI	= 0x01,
	SOCKS5_AUTH_USERPASS	= 0x02,
	SOCKS5_AUTH_NOACCEPT	= 0xff,
};

enum {
	SOCKS5_CMD_CONNECT	= 0x01,
	SOCKS5_CMD_BIND		= 0x02,
	SOCKS5_CMD_UDP_ASSOC	= 0x03,
};

enum {
	SOCKS5_ATYP_IPV4	= 0x01,
	SOCKS5_ATYP_DOMAIN	= 0x03,
	SOCKS5_ATYP_IPV6	= 0x04,
};

struct socks5_data {
	uint8_t			state;
	uint8_t			auth_method;
	char			*buf;
	size_t			len;
	size_t			cap;
	uint8_t			atyp;
	union {
		uint8_t		ipv4[4];
		uint8_t		ipv6[16];
	};
	uint16_t		port;
};

struct client_state {
	struct client_endp	client_ep;
	struct client_endp	target_ep;
	struct ip_spd_bucket	*spd;
	struct socks5_data	*socks5;
	uint32_t		idx;
	uint8_t			rate_limit_flags;
	bool			target_connected;
	bool			is_used;
};

struct stack_u32 {
	pthread_mutex_t	lock;
	uint32_t	sp;
	uint32_t	bp;
	uint32_t	*data;
};

struct server_ctx;

struct server_wrk {
	int			ep_fd;
	int			ev_fd;
	int			timer_fd;
	int			ep_timeout;

	uint32_t		idx;
	uint32_t		client_arr_size;
	_Atomic(uint32_t)	nr_online_clients;
	struct timespec		next_timer_fire;
	struct timespec		next_intv;

	pthread_t		thread;
	pthread_mutex_t		epass_mutex;	/* When passing a client to another worker */
	struct server_ctx	*ctx;
	struct client_state	**clients;
	struct stack_u32	cl_stack;

	uint16_t		nr_zero_limited;
	bool			handle_events_should_stop;
	bool			timer_is_armed;
	struct epoll_event	events[NR_EPOLL_EVENTS];
};

/*
 * Server configuration.
 */
struct server_cfg {
	uint8_t			verbose;
	uint8_t			as_socks5;
	int			backlog;
	uint32_t		nr_workers;
	uint32_t		out_mark;
	uint64_t		up_limit;
	uint64_t		up_interval;
	uint64_t		down_limit;
	uint64_t		down_interval;
	struct sockaddr_in46	bind_addr;
	struct sockaddr_in46	target_addr;
	const char		*socks5_user;
	const char		*socks5_pass;
};

/*
 * Server context.
 */
struct server_ctx {
	volatile bool		should_stop;
	bool			accept_stopped;
	bool			need_timer;
	int			tcp_fd;
	struct server_wrk	*workers;
	struct server_cfg	cfg;
	struct ip_spd_map	spd_map;
	pthread_mutex_t		accept_mutex;
};

enum {
	EPL_EV_EVENTFD			= (0x0001ull << 48ull),
	EPL_EV_TCP_ACCEPT		= (0x0002ull << 48ull),
	EPL_EV_TCP_CLIENT_DATA		= (0x0003ull << 48ull),
	EPL_EV_TCP_TARGET_DATA		= (0x0004ull << 48ull),
	EPL_EV_TCP_TARGET_CONN		= (0x0005ull << 48ull),
	EPL_EV_TIMERFD			= (0x0006ull << 48ull),
	EPL_EV_TCP_CLIENT_SOCKS5	= (0x0007ull << 48ull),
	EPL_EV_TCP_TARGET_SOCKS5_CONN	= (0x0008ull << 48ull),
};

#define EPL_EV_MASK		(0xffffull << 48ull)
#define GET_EPL_EV(data)	((data) & EPL_EV_MASK)
#define GET_EPL_DT(data)	((void *)((data) & ~EPL_EV_MASK))

static const struct option long_options[] = {
	{ "help",		no_argument,		NULL,	'h' },
	{ "version",		no_argument,		NULL,	'V' },
	{ "workers",		required_argument,	NULL,	'w' },
	{ "bind",		required_argument,	NULL,	'b' },
	{ "target",		required_argument,	NULL,	't' },
	{ "verbose",		no_argument,		NULL,	'v' },
	{ "backlog",		required_argument,	NULL,	'B' },
	{ "up-limit",		required_argument,	NULL,	'U' },
	{ "up-interval",	required_argument,	NULL,	'I' },
	{ "down-limit",		required_argument,	NULL,	'D' },
	{ "down-interval",	required_argument,	NULL,	'd' },
	{ "out-mark",		required_argument,	NULL,	'o' },
	{ "as-socks5",		no_argument,		NULL,	'S' },
	{ NULL,			0,			NULL,	0 },
};
static const char short_options[] = "hVw:b:t:vB:U:I:D:d:o:S";
static const uint64_t spd_min_fill = 1024*32;

static void show_help(const void *app)
{
	printf("Usage: %s [OPTIONS]\n", (const char *)app);
	printf("Options:\n");
	printf("  -h, --help\t\t\tShow this help message\n");
	printf("  -V, --version\t\t\tShow version information\n");
	printf("  -w, --workers=NUM\t\tNumber of worker threads\n");
	printf("  -b, --bind=ADDR\t\tBind address, addr:port\n");
	printf("  -t, --target=ADDR\t\tTarget address, addr:port\n");
	printf("  -v, --verbose\t\t\tVerbose mode\n");
	printf("  -B, --backlog=NUM\t\tBacklog size\n");
	printf("  -U, --up-limit=NUM\t\tUpload speed limit (bytes)\n");
	printf("  -I, --up-interval=NUM\t\tUpload fill interval (seconds)\n");
	printf("  -D, --down-limit=NUM\t\tDownload speed limit (bytes)\n");
	printf("  -d, --down-interval=NUM\tDownload fill interval (seconds)\n");
	printf("  -o, --out-mark=NUM\t\tOutgoing connection packet mark\n");
	printf("  -S, --as-socks5\t\tUse as a SOCKS5 proxy server\n");
}

static int parse_addr_and_port(const char *str, struct sockaddr_in46 *out)
{
	char *addr, *port;
	in_port_t *port_p;
	int ret;

	addr = strdup(str);
	if (!addr)
		return -ENOMEM;

	port = strchr(addr, ']');
	if (port)
		port++;
	else
		port = addr;

	port = strchr(port, ':');
	if (!port) {
		pr_error("Invalid address and port combination: \"%s\"", str);
		pr_error("Missing port number");
		ret = -EINVAL;
		goto out;
	}

	*port = '\0';
	port++;

	memset(out, 0, sizeof(*out));
	if (addr[0] == '[' && addr[strlen(addr) - 1] == ']') {
		addr[strlen(addr) - 1] = '\0';

		out->sa.sa_family = AF_INET6;
		ret = inet_pton(AF_INET6, addr + 1, &out->in6.sin6_addr);
		if (ret != 1) {
			pr_error("Invalid IPv6 address: %s", addr);
			ret = -EINVAL;
			goto out;
		}

		port_p = &out->in6.sin6_port;
	} else {
		out->sa.sa_family = AF_INET;
		ret = inet_pton(AF_INET, addr, &out->in4.sin_addr);
		if (ret != 1) {
			pr_error("Invalid IPv4 address: %s", addr);
			ret = -EINVAL;
			goto out;
		}

		port_p = &out->in4.sin_port;
	}

	ret = atoi(port);
	if (ret < 0 || ret > 65535) {
		pr_error("Invalid port in the address and port combination: \"%s\"", str);
		pr_error("Port must be between 0 and 65535");
		ret = -EINVAL;
		goto out;
	}

	*port_p = htons((uint16_t)ret);
	ret = 0;

out:
	free(addr);
	return ret;
}

static int parse_args(int argc, char *argv[], struct server_cfg *cfg)
{
	struct parse_state {
		bool got_bind_addr;
		bool got_target_addr;

		bool got_up_limit;
		bool got_up_interval;

		bool got_down_limit;
		bool got_down_interval;
	} p;

	cfg->backlog = 4096;
	cfg->nr_workers = 4;
	cfg->verbose = 0;

	memset(&p, 0, sizeof(p));
	while (1) {
		int q, i;
		char *t;

		q = getopt_long(argc, argv, short_options, long_options, &i);
		if (q == -1)
			break;

		switch (q) {
		case 'h':
			show_help(argv[0]);
			return 1;
		case 'V':
			printf("speedmgr 0.1\n");
			return 1;
		case 'w':
			cfg->nr_workers = atoi(optarg);
			if (cfg->nr_workers <= 0) {
				pr_error("Invalid number of workers: %s", optarg);
				return -EINVAL;
			}
			break;
		case 'b':
			if (parse_addr_and_port(optarg, &cfg->bind_addr)) {
				pr_error("Invalid bind address: %s", optarg);
				return -EINVAL;
			}

			p.got_bind_addr = true;
			break;
		case 't':
			if (parse_addr_and_port(optarg, &cfg->target_addr)) {
				pr_error("Invalid target address: %s", optarg);
				return -EINVAL;
			}

			p.got_target_addr = true;
			break;
		case 'v':
			cfg->verbose = 1;
			break;
		case 'B':
			cfg->backlog = atoi(optarg);
			if (cfg->backlog <= 0) {
				pr_error("Invalid backlog size: %s", optarg);
				return -EINVAL;
			}
			break;
		case 'U':
			cfg->up_limit = strtoull(optarg, &t, 10);
			p.got_up_limit = true;
			if (!t || *t == '\0') {
				/* nothing */
			} else if (*t == 'K' || *t == 'k') {
				cfg->up_limit *= 1024;
			} else if (*t == 'M' || *t == 'm') {
				cfg->up_limit *= 1024 * 1024;
			} else if (*t == 'G' || *t == 'g') {
				cfg->up_limit *= 1024 * 1024 * 1024;
			} else if (*t != '\0') {
				pr_error("Invalid upload limit: %s", optarg);
				return -EINVAL;
			}
			break;
		case 'I':
			cfg->up_interval = strtoull(optarg, &t, 10);
			p.got_up_interval = true;
			if (!t || *t == '\0') {
				/* nothing */
			} else if (*t == 'h') {
				cfg->up_interval *= 1000 * 3600;
			} else if (*t == 'm') {
				cfg->up_interval *= 1000 * 60;
			} else if (*t == 's') {
				cfg->up_interval *= 1000;
			} else {
				pr_error("Invalid upload interval: %s", optarg);
				return -EINVAL;
			}
			break;
		case 'D':
			cfg->down_limit = strtoull(optarg, &t, 10);
			p.got_down_limit = true;
			if (!t || *t == '\0') {
				/* nothing */
			} else if (*t == 'K' || *t == 'k') {
				cfg->down_limit *= 1024;
			} else if (*t == 'M' || *t == 'm') {
				cfg->down_limit *= 1024 * 1024;
			} else if (*t == 'G' || *t == 'g') {
				cfg->down_limit *= 1024 * 1024 * 1024;
			} else if (*t != '\0') {
				pr_error("Invalid download limit: %s", optarg);
				return -EINVAL;
			}
			break;
		case 'd':
			cfg->down_interval = strtoull(optarg, &t, 10);
			p.got_down_interval = true;
			if (!t || *t == '\0') {
				/* nothing */
			} else if (*t == 'h') {
				cfg->down_interval *= 1000 * 3600;
			} else if (*t == 'm') {
				cfg->down_interval *= 1000 * 60;
			} else if (*t == 's') {
				cfg->down_interval *= 1000;
			} else {
				pr_error("Invalid download interval: %s", optarg);
				return -EINVAL;
			}
			break;
		case 'o':
			cfg->out_mark = strtoul(optarg, &t, 10);
			if (!t || *t != '\0') {
				pr_error("Invalid outgoing packet mark: %s", optarg);
				return -EINVAL;
			}
			break;
		case 'S':
			cfg->as_socks5 = 1;
			break;
		case '?':
			return -EINVAL;
		default:
			break;
		}
	}

	if (!p.got_bind_addr) {
		pr_error("Missing bind address (the -b option)");
		show_help(argv[0]);
		return -EINVAL;
	}

	if (!cfg->as_socks5 && !p.got_target_addr) {
		pr_error("Missing target address (the -t option)");
		show_help(argv[0]);
		return -EINVAL;
	}

	if (p.got_up_limit ^ p.got_up_interval) {
		pr_error("Upload limit and upload interval must be specified together");
		show_help(argv[0]);
		return -EINVAL;
	}

	if (p.got_down_limit ^ p.got_down_interval) {
		pr_error("Download limit and download interval must be specified together");
		show_help(argv[0]);
		return -EINVAL;
	}

	cfg->socks5_user = getenv("SPEEDMGR_SOCKS5_USER");
	cfg->socks5_pass = getenv("SPEEDMGR_SOCKS5_PASS");
	return 0;
}

static const char *sockaddr_to_str(struct sockaddr_in46 *addr)
{
	static __thread char _buf[8][INET6_ADDRSTRLEN + sizeof("[]:65535")];
	static __thread uint8_t _counter;
	char *buf = _buf[_counter++ % ARRAY_SIZE(_buf)];

	if (addr->sa.sa_family == AF_INET) {
		inet_ntop(AF_INET, &addr->in4.sin_addr, buf, INET_ADDRSTRLEN);
		snprintf(buf + strlen(buf), sizeof(_buf[0]) - strlen(buf), 
			 ":%hu", ntohs(addr->in4.sin_port));
		return buf;
	}


	if (IN6_IS_ADDR_V4MAPPED(&addr->in6.sin6_addr)) {
		inet_ntop(AF_INET, &addr->in6.sin6_addr.s6_addr32[3], buf, INET_ADDRSTRLEN);
		snprintf(buf + strlen(buf), sizeof(_buf[0]) - strlen(buf), ":%hu",
			 ntohs(addr->in6.sin6_port));
	} else {
		*buf = '[';
		inet_ntop(AF_INET6, &addr->in6.sin6_addr, buf + 1, INET6_ADDRSTRLEN);
		snprintf(buf + strlen(buf), sizeof(_buf[0]) - strlen(buf), "]:%hu",
			 ntohs(addr->in6.sin6_port));
	}

	return buf;
}

static int init_stack_u32(struct stack_u32 *stack, uint32_t size)
{
	uint32_t *arr;
	int ret;

	arr = malloc(size * sizeof(*arr));
	if (!arr)
		return -ENOMEM;

	ret = pthread_mutex_init(&stack->lock, NULL);
	if (ret) {
		free(arr);
		return -ret;
	}

	stack->data = arr;
	stack->sp = 0;
	stack->bp = size;
	return 0;
}

static void free_stack_u32(struct stack_u32 *stack)
{
	pr_vl_dbg(3, "free_stack_u32: stack=%p; stack_size=%u", stack, stack->bp);
	pthread_mutex_lock(&stack->lock);
	pthread_mutex_unlock(&stack->lock);
	pthread_mutex_destroy(&stack->lock);
	free(stack->data);
}

static int __upsize_stack_u32(struct stack_u32 *stack, uint32_t new_size)
{
	uint32_t *new_data;

	new_data = realloc(stack->data, new_size * sizeof(*new_data));
	if (!new_data)
		return -ENOMEM;

	stack->data = new_data;
	stack->bp = new_size;
	return 0;
}

static int __push_stack_u32(struct stack_u32 *stack, uint32_t data)
{
	if (stack->sp >= stack->bp)
		return -EAGAIN;

	stack->data[stack->sp++] = data;
	return 0;
}

static int __pop_stack_u32(struct stack_u32 *stack, uint32_t *data)
{
	if (stack->sp == 0)
		return -EAGAIN;

	*data = stack->data[--stack->sp];
	return 0;
}

static int push_stack_u32(struct stack_u32 *stack, uint32_t data)
{
	int ret;

	pthread_mutex_lock(&stack->lock);
	ret = __push_stack_u32(stack, data);
	pthread_mutex_unlock(&stack->lock);
	return ret;
}

static int pop_stack_u32(struct stack_u32 *stack, uint32_t *data)
{
	int ret;

	pthread_mutex_lock(&stack->lock);
	ret = __pop_stack_u32(stack, data);
	pthread_mutex_unlock(&stack->lock);
	return ret;
}

static int init_client_stack(struct server_wrk *w)
{
	uint32_t i;
	int ret;

	w->client_arr_size = NR_INIT_CLIENT_ARR;
	ret = init_stack_u32(&w->cl_stack, w->client_arr_size);
	if (ret) {
		pr_error("init_client_stack: Failed to initialize client stack: %s", strerror(-ret));
		return ret;
	}

	i = w->client_arr_size;
	while (i--) {
		ret = __push_stack_u32(&w->cl_stack, i);
		if (ret) {
			free_stack_u32(&w->cl_stack);
			pr_error("init_client_stack: Failed to push client index to stack: %s", strerror(-ret));
			return ret;
		}
	}

	return 0;
}

static void free_client_stack(struct server_wrk *w)
{
	free_stack_u32(&w->cl_stack);
}

static int try_increase_rlimit_nofile(void)
{
	struct rlimit rlim;
	int ret;

	ret = getrlimit(RLIMIT_NOFILE, &rlim);
	if (ret) {
		ret = errno;
		pr_error("Failed to get RLIMIT_NOFILE: %s", strerror(ret));
		return -ret;
	}

	if (rlim.rlim_cur >= rlim.rlim_max)
		return 0;

	rlim.rlim_cur = rlim.rlim_max;
	ret = setrlimit(RLIMIT_NOFILE, &rlim);
	if (ret) {
		ret = errno;
		pr_error("Failed to set RLIMIT_NOFILE: %s", strerror(ret));
		return -ret;
	}

	return 0;
}

static void signal_handler(int sig)
{
	*g_stop = true;
	(void)sig;
}

static int install_signal_handlers(struct server_ctx *ctx)
{
	struct sigaction sa = { .sa_handler = signal_handler };
	int ret = 0;

	g_stop = &ctx->should_stop;
	ret |= sigaction(SIGINT, &sa, NULL);
	ret |= sigaction(SIGTERM, &sa, NULL);
	ret |= sigaction(SIGHUP, &sa, NULL);
	sa.sa_handler = SIG_IGN;
	ret |= sigaction(SIGPIPE, &sa, NULL);
	if (ret)
		goto out_err;

	return 0;

out_err:
	pr_error("Failed to install signal handlers: %s", strerror(errno));
	return ret;
}

static int init_spd_map(struct server_ctx *ctx)
{
	struct ip_spd_map *map = &ctx->spd_map;
	int ret;

	if (!ctx->need_timer)
		return 0;

	ret = ht_create(&map->ht);
	if (ret)
		return ret;

	map->len = 0;
	map->cap = NR_INIT_SPD_BUCKET_ARR;
	map->bucket_arr = calloc(map->cap, sizeof(*map->bucket_arr));
	if (!map->bucket_arr) {
		ht_destroy(&map->ht);
		return -ENOMEM;
	}

	ret = pthread_mutex_init(&map->lock, NULL);
	if (ret) {
		free(map->bucket_arr);
		ht_destroy(&map->ht);
		return -ret;
	}

	return 0;
}

static void free_spd_map(struct server_ctx *ctx)
{
	struct ip_spd_map *map = &ctx->spd_map;
	size_t i;

	if (!ctx->need_timer)
		return;

	if (!map->bucket_arr)
		return;

	for (i = 0; i < map->len; i++)
		free(map->bucket_arr[i]);

	free(map->bucket_arr);
	pthread_mutex_destroy(&map->lock);
	ht_destroy(&map->ht);
}

static int init_socket(struct server_ctx *ctx)
{
	int tcp_fd, ret, family;
	socklen_t len;

	ctx->accept_stopped = false;
	family = ctx->cfg.bind_addr.sa.sa_family;
	tcp_fd = socket(family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (tcp_fd < 0) {
		pr_error("Failed to create socket: %s", strerror(errno));
		return -errno;
	}

#ifdef SO_REUSEADDR
	ret = 1;
	setsockopt(tcp_fd, SOL_SOCKET, SO_REUSEADDR, &ret, sizeof(ret));
#endif

	if (family == AF_INET6)
		len = sizeof(ctx->cfg.bind_addr.in6);
	else
		len = sizeof(ctx->cfg.bind_addr.in4);

	ret = bind(tcp_fd, &ctx->cfg.bind_addr.sa, len);
	if (ret) {
		ret = -errno;
		pr_error("Failed to bind socket: %s", strerror(-ret));
		goto out;
	}

	ret = listen(tcp_fd, ctx->cfg.backlog);
	if (ret) {
		ret = -errno;
		pr_error("Failed to listen on socket: %s", strerror(-ret));
		goto out;
	}

	pr_info("Listening on %s...", sockaddr_to_str(&ctx->cfg.bind_addr));
	ctx->tcp_fd = tcp_fd;
	return 0;

out:
	close(tcp_fd);
	return ret;
}

static void free_socket(struct server_ctx *ctx)
{
	if (ctx->tcp_fd >= 0)
		close(ctx->tcp_fd);
}

static void init_client_ep(struct client_endp *ep)
{
	ep->fd = -1;
	ep->len = 0;
	ep->cap = 0;
	ep->buf = NULL;
	memset(&ep->addr, 0, sizeof(ep->addr));
}

static void init_client_state(struct client_state *c)
{
	init_client_ep(&c->client_ep);
	init_client_ep(&c->target_ep);
	c->spd = NULL;
	c->socks5 = NULL;
	c->rate_limit_flags = 0;
	c->target_connected = false;
	c->is_used = false;
}

static struct client_state *alloc_client_state(void)
{
	struct client_state *c;

	c = calloc(1, sizeof(*c));
	if (!c)
		return NULL;

	init_client_state(c);
	return c;
}

static void reset_client_ep(struct client_endp *ep, bool preserve_buf,
			    size_t max_preserve)
{
	if (ep->fd >= 0) {
		close(ep->fd);
		ep->fd = -1;
	}

	if (ep->buf) {
		if (preserve_buf && ep->cap <= max_preserve) {
			ep->len = 0;
		} else {
			free(ep->buf);
			ep->buf = NULL;
			ep->len = 0;
			ep->cap = 0;
		}
	} else {
		ep->len = 0;
		ep->cap = 0;
	}

	memset(&ep->addr, 0, sizeof(ep->addr));
}

static struct socks5_data *alloc_socks5_data(void)
{
	struct socks5_data *sd;

	sd = malloc(sizeof(*sd));
	if (!sd)
		return NULL;

	sd->len = 0;
	sd->cap = 2048;
	sd->state = SOCKS5_STATE_INIT;
	sd->buf = malloc(sd->cap);
	if (!sd->buf) {
		free(sd);
		return NULL;
	}

	return sd;
}

static void free_socks5_data(struct socks5_data *sd)
{
	if (!sd)
		return;

	if (sd->buf)
		free(sd->buf);

	free(sd);
}

static void reset_client_state(struct client_state *c, bool preserve_buf,
			       size_t max_preserve)
{
	/*
	 * The caller must already put c->spd.
	 */
	assert(!c->spd);

	/*
	 * The caller must only pass a client state that is used.
	 */
	assert(c->is_used);

	reset_client_ep(&c->client_ep, preserve_buf, max_preserve);
	reset_client_ep(&c->target_ep, preserve_buf, max_preserve);

	if (c->socks5) {
		free_socks5_data(c->socks5);
		c->socks5 = NULL;
	}

	c->spd = NULL;
	c->rate_limit_flags = 0;
	c->target_connected = false;
	c->is_used = false;
}

static int upsize_clients(struct server_wrk *w)
{
	struct client_state **new_arr;
	size_t old_len;
	size_t new_len;
	uint32_t i;
	int ret = 0;

	pthread_mutex_lock(&w->cl_stack.lock);
	old_len = w->client_arr_size;
	new_len = (old_len + 1) * 2;
	new_arr = realloc(w->clients, new_len * sizeof(*new_arr));
	if (!new_arr) {
		ret = -ENOMEM;
		goto out;
	}

	w->clients = new_arr;
	w->client_arr_size = new_len;
	ret = __upsize_stack_u32(&w->cl_stack, w->client_arr_size);
	if (ret)
		goto out;

	for (i = old_len; i < new_len; i++) {
		struct client_state *c = alloc_client_state();
		if (!c) {
			ret = -ENOMEM;
			goto out;
		}

		c->idx = i;
		w->clients[i] = c;

		ret = __push_stack_u32(&w->cl_stack, i);
		assert(!ret);
		(void)ret;
	}

	pr_infov("upsize_clients: old_size=%zu; new_size=%zu (thread=%u)", old_len, new_len, w->idx);
out:
	pthread_mutex_unlock(&w->cl_stack.lock);
	return ret;
}

static int init_clients(struct server_wrk *w)
{
	struct client_state **clients;
	uint32_t i;
	int ret;

	ret = init_client_stack(w);
	if (ret)
		return ret;

	w->client_arr_size = NR_INIT_CLIENT_ARR;
	clients = calloc(w->client_arr_size, sizeof(*clients));
	if (!clients) {
		free_client_stack(w);
		return -ENOMEM;
	}

	for (i = 0; i < w->client_arr_size; i++) {
		struct client_state *c = alloc_client_state();
		if (!c) {
			while (i--)
				free(clients[i]);
			free(clients);
			return -ENOMEM;
		}

		c->idx = i;
		clients[i] = c;
	}

	w->clients = clients;
	return 0;
}

static void put_client_slot_no_epoll(struct server_wrk *w, struct client_state *c);

static void close_all_clients(struct server_wrk *w)
{
	uint32_t i;

	for (i = 0; i < w->client_arr_size; i++) {
		struct client_state *c = w->clients[i];

		if (c->is_used) {
			put_client_slot_no_epoll(w, c);
			assert(!c->is_used);
			assert(c->client_ep.fd < 0);
			assert(c->target_ep.fd < 0);
			assert(!c->client_ep.buf);
			assert(!c->target_ep.buf);
		} else {
			assert(c->client_ep.fd < 0);
			assert(c->target_ep.fd < 0);

			if (c->target_ep.buf) {
				free(c->target_ep.buf);
				c->target_ep.buf = NULL;
			}

			if (c->client_ep.buf) {
				free(c->client_ep.buf);
				c->client_ep.buf = NULL;
			}
		}
	}
}

static void free_clients(struct server_wrk *w)
{
	uint32_t i;

	if (!w->clients)
		return;

	close_all_clients(w);
	for (i = 0; i < w->client_arr_size; i++) {
		struct client_state *c = w->clients[i];

		if (c) {
			free(c);
			w->clients[i] = NULL;
		}
	}

	free(w->clients);
	w->clients = NULL;
	free_client_stack(w);
}

static int handle_epoll_ctl_err(const char *op, int ret, int epl_fd, int fd)
{
	pr_error("Failed to %s FD %d in epoll (%d): %s", op, fd, epl_fd, strerror(ret));
	assert(0);
	return -ret;
}

static int epoll_add(int ep_fd, int fd, uint32_t events, union epoll_data data)
{
	struct epoll_event ev = { .events = events, .data = data };
	int ret = 0;

	if (epoll_ctl(ep_fd, EPOLL_CTL_ADD, fd, &ev))
		ret = handle_epoll_ctl_err("add", errno, ep_fd, fd);

	return ret;
}

static int epoll_del(int ep_fd, int fd)
{
	int ret = 0;

	if (epoll_ctl(ep_fd, EPOLL_CTL_DEL, fd, NULL))
		ret = handle_epoll_ctl_err("del", errno, ep_fd, fd);

	return ret;
}

static int epoll_mod(int ep_fd, int fd, uint32_t events, union epoll_data data)
{
	struct epoll_event ev = { .events = events, .data = data };
	int ret = 0;

	if (epoll_ctl(ep_fd, EPOLL_CTL_MOD, fd, &ev))
		ret = handle_epoll_ctl_err("mod", errno, ep_fd, fd);

	return ret;
}

static int set_fd_nonblock(int fd)
{
	int flags, ret;

	flags = fcntl(fd, F_GETFL);
	if (flags < 0) {
		ret = -errno;
		pr_error("Failed to get FD flags: %s", strerror(-ret));
		return ret;
	}

	flags |= O_NONBLOCK;
	ret = fcntl(fd, F_SETFL, flags);
	if (ret) {
		ret = -errno;
		pr_error("Failed to set FD flags: %s", strerror(-ret));
		return ret;
	}

	return 0;
}

static int init_epoll(struct server_wrk *w)
{
	int ep_fd, ev_fd, ret;
	union epoll_data data;

	ep_fd = epoll_create(16);
	if (ep_fd < 0) {
		ret = -errno;
		pr_error("Failed to create epoll FD: %s", strerror(-ret));
		return ret;
	}

	ev_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
	if (ev_fd < 0) {
		ret = -errno;
		pr_error("Failed to create event FD: %s", strerror(-ret));
		close(ep_fd);
		return ret;
	}

	ret = set_fd_nonblock(ev_fd);
	if (ret) {
		close(ev_fd);
		close(ep_fd);
		return ret;
	}

	w->ep_fd = ep_fd;
	w->ev_fd = ev_fd;

	data.u64 = EPL_EV_EVENTFD;
	ret = epoll_add(ep_fd, ev_fd, EPOLLIN, data);
	if (ret) {
		close(ev_fd);
		close(ep_fd);
		w->ev_fd = -1;
		w->ep_fd = -1;
		return ret;
	}

	w->ep_timeout = 5000;
	return 0;
}

static void free_epoll(struct server_wrk *w)
{
	if (w->ep_fd >= 0)
		close(w->ep_fd);

	if (w->ev_fd >= 0)
		close(w->ev_fd);
}

static int init_timer(struct server_wrk *w)
{
	union epoll_data data;
	int ret;

	if (!w->ctx->need_timer) {
		w->timer_fd = -1;
		return 0;
	}

	ret = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
	if (ret < 0) {
		ret = -errno;
		pr_error("Failed to create timer FD: %s", strerror(-ret));
		return ret;
	}

	w->timer_fd = ret;
	data.u64 = EPL_EV_TIMERFD;
	ret = epoll_add(w->ep_fd, ret, EPOLLIN, data);
	if (ret)
		return ret;

	memset(&w->next_timer_fire, 0, sizeof(w->next_timer_fire));
	w->nr_zero_limited = 0;
	return 0;
}

static void free_timer(struct server_wrk *w)
{
	if (w->timer_fd >= 0) {
		close(w->timer_fd);
		w->timer_fd = -1;
	}
}

static void *worker_entry(void *arg);

static int init_worker(struct server_wrk *w, bool create_thread)
{
	int ret;

	w->timer_fd = -1;

	ret = init_clients(w);
	if (ret)
		return ret;

	ret = init_epoll(w);
	if (ret) {
		free_clients(w);
		return ret;
	}

	ret = init_timer(w);
	if (ret) {
		free_epoll(w);
		free_clients(w);
		return ret;
	}

	ret = pthread_mutex_init(&w->epass_mutex, NULL);
	if (ret) {
		free_timer(w);
		free_epoll(w);
		free_clients(w);
		return -ret;
	}

	if (create_thread) {
		ret = pthread_create(&w->thread, NULL, &worker_entry, w);
		if (ret) {
			pr_error("Failed to create worker thread %u: %s", w->idx, strerror(ret));
			ret = -ret;
			goto out_err;
		}
	} else {
		/*
		 * Add the main TCP socket which accepts new connections to the
		 * epoll instance in the main thread.
		 */
		union epoll_data data;

		data.u64 = EPL_EV_TCP_ACCEPT;
		ret = epoll_add(w->ep_fd, w->ctx->tcp_fd, EPOLLIN, data);
		if (ret)
			goto out_err;
	}

	return 0;

out_err:
	pthread_mutex_destroy(&w->epass_mutex);
	free_clients(w);
	free_epoll(w);
	free_timer(w);
	return ret;
}

static int send_event_fd(struct server_wrk *w)
{
	uint64_t val = 1;
	int ret;

	ret = write(w->ev_fd, &val, sizeof(val));
	if (ret != sizeof(val)) {
		ret = errno;
		if (ret == EAGAIN)
			return 0;

		pr_error("Failed to write to event FD: %s (thread %u)", strerror(ret), w->idx);
		return -ret;
	}

	return 0;
}

static int consume_event_fd(struct server_wrk *w)
{
	uint64_t val;
	int ret;

	ret = read(w->ev_fd, &val, sizeof(val));
	if (ret != sizeof(val)) {
		ret = errno;
		if (ret == EAGAIN)
			return 0;

		pr_error("Failed to read from event FD: %s (thread %u)", strerror(ret), w->idx);
		return -ret;
	}

	return 0;
}

static void free_worker(struct server_wrk *w)
{
	if (w->ctx && w->idx != 0) {
		w->ctx->should_stop = true;
		send_event_fd(w);
		pr_info("Joining worker thread %u...", w->idx);
		pthread_join(w->thread, NULL);
		pr_info("Worker thread %u joined", w->idx);
	}

	free_clients(w);
	free_epoll(w);
	free_timer(w);
	pthread_mutex_destroy(&w->epass_mutex);
}

static int init_workers(struct server_ctx *ctx)
{
	int ret = 0;
	uint32_t i;

	if (ctx->cfg.nr_workers < 1)
		ctx->cfg.nr_workers = 1;

	ctx->workers = calloc(ctx->cfg.nr_workers, sizeof(*ctx->workers));
	if (!ctx->workers)
		return -ENOMEM;

	for (i = 0; i < ctx->cfg.nr_workers; i++) {
		struct server_wrk *w = &ctx->workers[i];
		bool create_thread = (i > 0);
		int ret;

		w->idx = i;
		w->ctx = ctx;
		ret = init_worker(w, create_thread);
		if (ret) {
			pr_error("Failed to initialize worker %u: %s", i, strerror(-ret));
			goto out_err;
		}
	}

	return 0;

out_err:
	while (i--)
		free_worker(&ctx->workers[i]);

	free(ctx->workers);
	ctx->workers = NULL;
	return ret;
}

static void free_workers(struct server_ctx *ctx)
{
	uint32_t i;

	if (!ctx->workers)
		return;

	for (i = 0; i < ctx->cfg.nr_workers; i++)
		free_worker(&ctx->workers[i]);

	free(ctx->workers);
	ctx->workers = NULL;
}

static int init_ctx(struct server_ctx *ctx)
{
	struct server_cfg *cfg = &ctx->cfg;
	int ret;

	if ((cfg->up_limit && cfg->up_interval) || (cfg->down_limit && cfg->down_interval))
		ctx->need_timer = true;
	else
		ctx->need_timer = false;

	g_verbose = ctx->cfg.verbose;
	try_increase_rlimit_nofile();
	ret = install_signal_handlers(ctx);
	if (ret)
		return ret;

	ret = init_socket(ctx);
	if (ret)
		return ret;

	ret = init_spd_map(ctx);
	if (ret) {
		free_socket(ctx);
		return ret;
	}

	ret = pthread_mutex_init(&ctx->accept_mutex, NULL);
	if (ret) {
		free_spd_map(ctx);
		free_socket(ctx);
		return -ret;
	}

	pr_infov("up_limit=%lu; up_interval=%lu; down_limit=%lu; down_interval=%lu",
		 cfg->up_limit,
		 cfg->up_interval,
		 cfg->down_limit,
		 cfg->down_interval);

	ret = init_workers(ctx);
	if (ret) {
		pthread_mutex_destroy(&ctx->accept_mutex);
		free_spd_map(ctx);
		free_socket(ctx);
		return ret;
	}

	return 0;
}

static void free_ctx(struct server_ctx *ctx)
{
	free_workers(ctx);
	pthread_mutex_destroy(&ctx->accept_mutex);
	free_spd_map(ctx);
	free_socket(ctx);
}

static inline void get_ip_ptr(const struct sockaddr_in46 *addr, const void **ptr,
			      size_t *len)
{
	if (addr->sa.sa_family == AF_INET) {
		*ptr = &addr->in4.sin_addr;
		*len = sizeof(addr->in4.sin_addr);
	} else {
		*ptr = &addr->in6.sin6_addr;
		*len = sizeof(addr->in6.sin6_addr);
	}
}

/*
 * MUST HOLD: map->lock when calling this function.
 */
static int get_bucket_index(struct ip_spd_map *map,
			    const struct sockaddr_in46 *key, uint32_t *idx)
{
	struct ht_data *data;
	const void *tkey;
	size_t tkey_len;
	int ret;

	get_ip_ptr(key, &tkey, &tkey_len);
	ret = ht_lookup(&map->ht, tkey, tkey_len, &data);
	if (ret)
		return ret;

	*idx = data->u32;
	return 0;
}

/*
 * MUST HOLD: map->lock when calling this function.
 */
static int set_bucket_index(struct ip_spd_map *map,
			    const struct sockaddr_in46 *key,
			    uint32_t idx)
{
	struct ht_data data;
	const void *tkey;
	size_t tkey_len;
	int ret;

	get_ip_ptr(key, &tkey, &tkey_len);
	data.u32 = idx;
	ret = ht_insert(&map->ht, tkey, tkey_len, &data);
	if (ret)
		return ret;

	return 0;
}

static void init_ip_spd_bucket(struct ip_spd_bucket *b)
{
	memset(b, 0, sizeof(*b));
}

static uint64_t get_time_us(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000 + (uint64_t)ts.tv_nsec / 1000;
}

static void us_to_timespec(uint64_t ns, struct timespec *ts)
{
	ts->tv_sec = ns / 1000000000;
	ts->tv_nsec = ns % 1000000000;
}

static void ts_add_us(struct timespec *ts, uint64_t us)
{
	ts->tv_sec += us / 1000000;
	ts->tv_nsec += (us % 1000000) * 1000;
	if (ts->tv_nsec >= 1000000000) {
		ts->tv_sec++;
		ts->tv_nsec -= 1000000000;
	}
}

static struct ip_spd_bucket *get_ip_spd_bucket(struct server_ctx *ctx,
					       struct ip_spd_map *map,
					       const struct sockaddr_in46 *addr)
{
	struct ip_spd_bucket *b;
	uint32_t idx;

	if (!map->bucket_arr)
		return NULL;

	pthread_mutex_lock(&map->lock);
	if (!get_bucket_index(map, addr, &idx)) {
		b = map->bucket_arr[idx];
		b->nr_conns++;
		pthread_mutex_unlock(&map->lock);
		return b;
	}

	if (map->len == map->cap) {
		size_t new_cap = map->cap + (map->cap / 2) + 1;
		struct ip_spd_bucket **new_arr;

		new_arr = realloc(map->bucket_arr, new_cap * sizeof(*new_arr));
		if (!new_arr) {
			pthread_mutex_unlock(&map->lock);
			return NULL;
		}

		map->bucket_arr = new_arr;
		map->cap = new_cap;
	}

	b = calloc(1, sizeof(*b));
	if (!b) {
		pthread_mutex_unlock(&map->lock);
		return NULL;
	}

	init_ip_spd_bucket(b);
	map->bucket_arr[map->len] = b;
	if (set_bucket_index(map, addr, map->len)) {
		free(b);
		b = NULL;
	} else {
		struct server_cfg *cfg = &ctx->cfg;
		uint64_t bonus_init_bytes = 0;
		uint64_t now = get_time_us();

		map->len++;
		b->nr_conns = 1;
		b->wrk_idx = -1;
		b->dn_tkn.fill_intv = cfg->down_interval * 1000;
		b->up_tkn.fill_intv = cfg->up_interval * 1000;
		b->dn_tkn.max = cfg->down_limit;
		b->up_tkn.max = cfg->up_limit;
		b->dn_tkn.last_fill = now;
		b->up_tkn.last_fill = now;
		b->dn_tkn.tkn = b->dn_tkn.max + bonus_init_bytes;
		b->up_tkn.tkn = b->up_tkn.max + bonus_init_bytes;
	}

	pthread_mutex_unlock(&map->lock);
	return b;
}

static void put_ip_spd_bucket(struct ip_spd_map *map, struct sockaddr_in46 *addr)
{
	struct ip_spd_bucket *b;
	uint32_t idx;
	uint16_t n;

	assert(map->bucket_arr);
	pthread_mutex_lock(&map->lock);
	if (get_bucket_index(map, addr, &idx)) {
		pthread_mutex_unlock(&map->lock);
		pr_error("Failed to put bucket index for %s", sockaddr_to_str(addr));
		return;
	}

	b = map->bucket_arr[idx];
	n = atomic_fetch_sub(&b->nr_conns, 1u);
	if (n == 1) {
		const void *key;
		size_t key_len;

		get_ip_ptr(addr, &key, &key_len);
		ht_remove(&map->ht, key, key_len);
		map->bucket_arr[idx] = NULL;
		free(b);
	}
	pthread_mutex_unlock(&map->lock);
}

static int get_client_slot(struct server_wrk *w, struct client_state **c)
{
	struct client_state *t;
	uint32_t idx;
	int ret;

	ret = pop_stack_u32(&w->cl_stack, &idx);
	if (ret) {
		ret = upsize_clients(w);
		if (ret)
			return ret;

		ret = pop_stack_u32(&w->cl_stack, &idx);
		if (ret)
			return ret;
	}

	t = w->clients[idx];
	if (!t) {
		push_stack_u32(&w->cl_stack, idx);
		return -ENOMEM;
	}

	assert(!t->is_used);
	assert(!t->spd);
	assert(!t->socks5);
	assert(t->client_ep.fd < 0);
	assert(t->client_ep.len == 0);
	assert(t->target_ep.fd < 0);
	assert(t->target_ep.len == 0);

	t->is_used = true;
	*c = t;
	atomic_fetch_add(&w->nr_online_clients, 1u);
	return 0;
}

static void __put_client_slot(struct server_wrk *w, struct client_state *c,
			      bool epl_del, bool preserve_buf)
{
	bool hess = false;
	int ret;

	if (epl_del) {
		pthread_mutex_lock(&w->epass_mutex);
		if (c->client_ep.fd >= 0) {
			ret = epoll_del(w->ep_fd, c->client_ep.fd);
			if (ret) {
				pr_error("client_ep epoll_del error: %s -> %s (ep_fd=%d; fd=%d)",
					sockaddr_to_str(&c->client_ep.addr),
					sockaddr_to_str(&c->target_ep.addr),
					w->ep_fd,
					c->client_ep.fd);
			}
			hess = true;
		}

		if (c->target_ep.fd >= 0) {
			ret = epoll_del(w->ep_fd, c->target_ep.fd);
			if (ret) {
				pr_error("target_ep epoll_del error: %s -> %s (ep_fd=%d; fd=%d)",
					sockaddr_to_str(&c->client_ep.addr),
					sockaddr_to_str(&c->target_ep.addr),
					w->ep_fd,
					c->target_ep.fd);
			}
			hess = true;
		}
		pthread_mutex_unlock(&w->epass_mutex);
	}

	if (hess) {
		pthread_mutex_lock(&w->ctx->accept_mutex);
		if (w->ctx->accept_stopped) {
			union epoll_data data;

			data.u64 = EPL_EV_TCP_ACCEPT;
			pr_info("Re-enabling accept() (thread %u)", w->idx);
			ret = epoll_add(w->ep_fd, w->ctx->tcp_fd, EPOLLIN, data);
			assert(!ret);

			w->ctx->accept_stopped = false;
			send_event_fd(&w->ctx->workers[0]);
		}
		pthread_mutex_unlock(&w->ctx->accept_mutex);
	}

	if (c->spd) {
		put_ip_spd_bucket(&w->ctx->spd_map, &c->client_ep.addr);
		c->spd = NULL;
	}

	if (c->client_ep.fd >= 0) {
		pr_infov("pcls: %s -> %s (fd=%d; tfd=%d; thread=%u)",
			 sockaddr_to_str(&c->client_ep.addr),
			 sockaddr_to_str(&c->target_ep.addr),
			 c->client_ep.fd,
			 c->target_ep.fd,
			 w->idx);
	}

	reset_client_state(c, preserve_buf, NR_INIT_RECV_BUF_BYTES);
	push_stack_u32(&w->cl_stack, c->idx);
	atomic_fetch_sub(&w->nr_online_clients, 1u);
	w->handle_events_should_stop = hess;
	(void)ret;
}

static void put_client_slot(struct server_wrk *w, struct client_state *c)
{
	__put_client_slot(w, c, true, true);
}

static void put_client_slot_no_epoll(struct server_wrk *w, struct client_state *c)
{
	__put_client_slot(w, c, false, false);
}

static struct server_wrk *pick_worker_for_new_conn(struct server_ctx *ctx,
						   struct ip_spd_bucket *b)
{
	uint32_t i, min, idx = 0;

	if (b) {
		pthread_mutex_lock(&ctx->spd_map.lock);
		if (b->wrk_idx >= 0) {
			pthread_mutex_unlock(&ctx->spd_map.lock);
			return &ctx->workers[b->wrk_idx];
		}
	}

	min = atomic_load(&ctx->workers[0].nr_online_clients);
	for (i = 1; i < ctx->cfg.nr_workers; i++) {
		uint32_t nr;

		nr = atomic_load(&ctx->workers[i].nr_online_clients);
		if (nr < 5) {
			idx = i;
			break;
		}

		if (nr < min) {
			min = nr;
			idx = i;
		}
	}

	if (b) {
		b->wrk_idx = idx;
		pthread_mutex_unlock(&ctx->spd_map.lock);
	}

	return &ctx->workers[idx];
}

static int get_target_addr(struct server_wrk *w, struct client_state *c,
			   struct sockaddr_in46 *addr)
{
	struct sockaddr_in46 *cfg_addr = &w->ctx->cfg.target_addr;
	socklen_t len;
	sa_family_t f;
	int ret;

	/*
	 * If the destination is 0.0.0.0 or [::], get the original
	 * destination address from the client using getsockopt().
	 */
	if (cfg_addr->sa.sa_family == AF_INET) {
		if (cfg_addr->in4.sin_addr.s_addr != INADDR_ANY) {
			*addr = *cfg_addr;
			return 0;
		}
	} else if (cfg_addr->sa.sa_family == AF_INET6) {
		if (!IN6_IS_ADDR_UNSPECIFIED(&cfg_addr->in6.sin6_addr)) {
			*addr = *cfg_addr;
			return 0;
		}
	}

	f = w->ctx->cfg.bind_addr.sa.sa_family;
	if (f == AF_INET6 && !IN6_IS_ADDR_V4MAPPED(&c->client_ep.addr.in6.sin6_addr)) {
		len = sizeof(addr->in6);
		ret = getsockopt(c->client_ep.fd, SOL_IPV6, IP6T_SO_ORIGINAL_DST, &addr->in6, &len);
		if (ret) {
			ret = -errno;
			pr_error("getsockopt(SOL_IPV6, IP6T_SO_ORIGINAL_DST): %s", strerror(-ret));
		}

		return ret;
	}

	len = sizeof(addr->in4);
	ret = getsockopt(c->client_ep.fd, SOL_IP, SO_ORIGINAL_DST, &addr->in4, &len);
	if (ret) {
		ret = -errno;
		pr_error("getsockopt(SOL_IP, SO_ORIGINAL_DST): %s", strerror(-ret));
	}
	return ret;
}

static inline void set_epoll_data(union epoll_data *data, struct client_state *c,
				  uint64_t ev_mask)
{
	data->u64 = 0;
	data->ptr = c;
	data->u64 |= ev_mask;
}

static int get_target_addr_socks5(struct client_state *c, struct sockaddr_in46 *addr)
{
	struct socks5_data *sd = c->socks5;

	assert(sd);
	assert(sd->state == SOCKS5_STATE_REQ);

	if (sd->atyp == SOCKS5_ATYP_IPV4) {
		addr->sa.sa_family = AF_INET;
		addr->in4.sin_port = sd->port;
		memcpy(&addr->in4.sin_addr, sd->ipv4, sizeof(addr->in4.sin_addr));
	} else if (sd->atyp == SOCKS5_ATYP_IPV6) {
		addr->sa.sa_family = AF_INET6;
		addr->in6.sin6_port = sd->port;
		memcpy(&addr->in6.sin6_addr, sd->ipv6, sizeof(addr->in6.sin6_addr));
	} else {
		pr_errorv("Invalid SOCKS5 ATYP: %u", sd->atyp);
		return -EINVAL;
	}

	return 0;
}

static int prepare_target_connect(struct server_wrk *w, struct client_state *c,
				  bool for_socks5)
{
	struct sockaddr_in46 taddr;
	union epoll_data data;
	socklen_t len;
	int fd, ret;

	memset(&taddr, 0, sizeof(taddr));
	if (for_socks5)
		ret = get_target_addr_socks5(c, &taddr);
	else
		ret = get_target_addr(w, c, &taddr);

	if (ret)
		return ret;

	if (taddr.sa.sa_family == AF_INET6)
		len = sizeof(taddr.in6);
	else
		len = sizeof(taddr.in4);

	fd = socket(taddr.sa.sa_family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (fd < 0) {
		ret = errno;
		pr_error("Failed to create target socket: %s", strerror(ret));
		return -ret;
	}

	if (w->ctx->cfg.out_mark) {
		uint32_t mark = w->ctx->cfg.out_mark;

		ret = setsockopt(fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark));
		if (ret) {
			ret = errno;
			pr_error("Failed to set SO_MARK on target socket: %s", strerror(ret));
			close(fd);
			return -ret;
		}
	}

	c->target_ep.fd = fd;
	c->target_ep.addr = taddr;

	pr_infov("ncon: %s -> %s (fd=%d; tfd=%d; thread=%u)",
		 sockaddr_to_str(&c->client_ep.addr),
		 sockaddr_to_str(&c->target_ep.addr),
		 c->client_ep.fd,
		 c->target_ep.fd,
		 w->idx);


#ifdef TCP_NODELAY
	ret = 1;
	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &ret, sizeof(ret));
#endif

	ret = connect(fd, &taddr.sa, len);
	if (ret) {
		ret = errno;
		if (ret != EINPROGRESS) {
			pr_error("Failed to connect to target %s: %s", sockaddr_to_str(&taddr), strerror(ret));
			close(fd);
			return -ret;
		}
	}

	pthread_mutex_lock(&w->epass_mutex);
	c->target_ep.ep_mask = EPOLLOUT;
	if (for_socks5)
		set_epoll_data(&data, c, EPL_EV_TCP_TARGET_SOCKS5_CONN);
	else
		set_epoll_data(&data, c, EPL_EV_TCP_TARGET_CONN);

	ret = epoll_add(w->ep_fd, c->target_ep.fd, c->target_ep.ep_mask, data);
	if (ret)
		goto out_epoll_err;

	if (!for_socks5) {
		c->client_ep.ep_mask = EPOLLIN;
		set_epoll_data(&data, c, EPL_EV_TCP_CLIENT_DATA);
		ret = epoll_add(w->ep_fd, c->client_ep.fd, c->client_ep.ep_mask, data);
		if (ret)
			goto out_epoll_err;

		send_event_fd(w);
	}
	pthread_mutex_unlock(&w->epass_mutex);
	atomic_fetch_add(&w->nr_online_clients, 1u);
	return 0;

out_epoll_err:
	pthread_mutex_unlock(&w->epass_mutex);
	close(c->target_ep.fd);
	c->target_ep.fd = -1;
	return ret;
}

static int prepare_socks5_handshake(struct server_wrk *w, struct client_state *c)
{
	union epoll_data data;
	int ret;

	c->socks5 = alloc_socks5_data();
	if (!c->socks5) {
		pr_error("Failed to allocate SOCKS5 data");
		return -ENOMEM;
	}

	c->client_ep.ep_mask = EPOLLIN;
	set_epoll_data(&data, c, EPL_EV_TCP_CLIENT_SOCKS5);
	pthread_mutex_lock(&w->epass_mutex);
	ret = epoll_add(w->ep_fd, c->client_ep.fd, c->client_ep.ep_mask, data);
	if (!ret)
		send_event_fd(w);
	pthread_mutex_unlock(&w->epass_mutex);
	return ret;
}

/*
 * @fd: The ownership is taken by give_client_fd_to_a_worker().
 */
static int give_client_fd_to_a_worker(struct server_ctx *ctx, int fd,
				      const struct sockaddr_in46 *addr)
{
	struct ip_spd_bucket *b;
	struct client_state *c;
	struct server_wrk *w;
	int r;

	b = get_ip_spd_bucket(ctx, &ctx->spd_map, addr);
	w = pick_worker_for_new_conn(ctx, b);
	r = get_client_slot(w, &c);
	if (r) {
		close(fd);
		pr_error("get_client_slot(): %s", strerror(-r));
		return -ENOMEM;
	}

	if (b)
		c->spd = b;

	c->client_ep.fd = fd;
	c->client_ep.addr = *addr;
	if (ctx->cfg.as_socks5)
		r = prepare_socks5_handshake(w, c);
	else
		r = prepare_target_connect(w, c, false);

	if (r) {
		put_client_slot_no_epoll(w, c);
		return r;
	}

	return 0;
}

static int handle_accept_error(int err, struct server_wrk *w)
{
	if (err == EAGAIN || err == EINTR)
		return 0;

	if (err == EMFILE || err == ENFILE) {
		pr_error("accept(): (%d) Too many open files, stop accepting...", err);
		pr_info("accept() will be re-enabled when a client disconnects (thread %u)", w->idx);
		pthread_mutex_lock(&w->ctx->accept_mutex);
		w->ctx->accept_stopped = true;
		pthread_mutex_unlock(&w->ctx->accept_mutex);
		return epoll_del(w->ep_fd, w->ctx->tcp_fd);
	}

	pr_error("accept() failed: %s", strerror(err));
	return -err;
}

static int set_optional_sockopt(int fd)
{
	int p;

	/*
	 * Set TCP_NODELAY.
	 */
	p = 1;
	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &p, sizeof(p));

	return 0;
}

static int handle_event_accept(struct server_wrk *w)
{
	static const uint32_t NR_MAX_ACCEPT_CYCLE = 4;
	struct server_ctx *ctx = w->ctx;
	struct sockaddr_in46 addr;
	uint32_t counter = 0;
	socklen_t len;
	int ret;

do_accept:
	memset(&addr, 0, sizeof(addr));
	if (ctx->cfg.bind_addr.sa.sa_family == AF_INET6)
		len = sizeof(addr.in6);
	else
		len = sizeof(addr.in4);

	ret = accept4(ctx->tcp_fd, &addr.sa, &len, SOCK_NONBLOCK | SOCK_CLOEXEC);
	if (unlikely(ret < 0))
		return handle_accept_error(errno, w);

	set_optional_sockopt(ret);
	if (unlikely(len > sizeof(addr))) {
		pr_error("accept() returned invalid address length: %u", len);
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

static int resize_buffer_if_needed(struct client_endp *ep)
{
	size_t new_cap;
	char *new_buf;

	if (ep->len < ep->cap)
		return 0;

	if (ep->cap == 0)
		new_cap = NR_INIT_RECV_BUF_BYTES;
	else
		new_cap = (ep->cap * 2u) + 1u;

	new_cap = MIN(new_cap, NR_MAX_RECV_BUF_BYTES);
	if (new_cap <= NR_MAX_RECV_BUF_BYTES) {
		new_buf = realloc(ep->buf, new_cap);
		if (!new_buf) {
			if (ep->cap > 0)
				return -ENOBUFS;

			pr_error("Failed to realloc receive buffer: %s", strerror(ENOMEM));
			return -ENOMEM;
		}

		ep->buf = new_buf;
		ep->cap = new_cap;
	}

	return 0;
}

static ssize_t do_ep_recv(struct client_endp *ep)
{
	ssize_t ret;
	size_t len;
	char *buf;

	ret = resize_buffer_if_needed(ep);
	if (ret)
		return ret;

	assert(ep->len <= ep->cap);
	assert(ep->buf);

	len = ep->cap - ep->len;
	buf = ep->buf + ep->len;
	if (len == 0)
		return -ENOBUFS;

	ret = recv(ep->fd, buf, len, MSG_DONTWAIT);
	if (ret < 0) {
		ret = -errno;
		if (ret == -EAGAIN || ret == -EINTR)
			return -EAGAIN;

		return ret;
	}

	if (ret == 0)
		return -ECONNRESET;

	ep->len += (size_t)ret;
	return 0;
}

static ssize_t do_ep_send(struct client_endp *src, struct client_endp *dst,
			  size_t max_send)
{
	size_t len = MIN(src->len, max_send);
	char *buf = src->buf;
	ssize_t ret;
	size_t uret;

	if (!len)
		return 0;

	ret = send(dst->fd, buf, len, MSG_DONTWAIT);
	if (ret < 0) {
		ret = -errno;
		if (ret == -EAGAIN || ret == -EINTR)
			return -EAGAIN;

		return ret;
	}

	if (ret == 0)
		return -ECONNRESET;

	uret = (size_t)ret;
	src->len -= uret;

	if (src->len > 0)
		memmove(src->buf, src->buf + uret, src->len);

	return ret;
}

static int apply_ep_mask(struct server_wrk *w, struct client_state *c,
			 struct client_endp *ep)
{
	union epoll_data data;

	if (&c->target_ep == ep)
		set_epoll_data(&data, c, (c->target_connected) ? EPL_EV_TCP_TARGET_DATA : EPL_EV_TCP_TARGET_CONN);
	else
		set_epoll_data(&data, c, EPL_EV_TCP_CLIENT_DATA);

	return epoll_mod(w->ep_fd, ep->fd, ep->ep_mask, data);
}

enum stream_dir {
	UP_DIR,
	DN_DIR
};

static size_t get_max_send_size(struct client_state *c, enum stream_dir dir)
{
	uint64_t cur, now = 0, delta = 0, to_fill = 0;
	struct ip_spd_bucket *b = c->spd;
	struct spd_tkn *tkn;

	if (!b)
		return (size_t)~0ull;

	if (dir == UP_DIR)
		tkn = &b->up_tkn;
	else
		tkn = &b->dn_tkn;

	if (!tkn->max || !tkn->fill_intv)
		return (size_t)~0ull;

	cur = tkn->tkn;
	if (cur < tkn->max) {
		now = get_time_us();
		delta = now - tkn->last_fill;

		to_fill = (delta * tkn->max) / tkn->fill_intv;
		if (to_fill >= spd_min_fill) {
			cur += to_fill;
			if (cur > tkn->max)
				cur = tkn->max;

			tkn->last_fill = now;
			tkn->tkn = cur;
		}
	}

	return cur / b->nr_conns;
}

static void consume_token(struct client_state *c, enum stream_dir dir,
			  size_t size)
{
	struct ip_spd_bucket *b = c->spd;
	struct spd_tkn *tkn;

	if (!b)
		return;

	if (dir == UP_DIR)
		tkn = &b->up_tkn;
	else
		tkn = &b->dn_tkn;

	tkn->tkn -= size;
}

static int timespec_cmp(const struct timespec *a, const struct timespec *b)
{
	if (a->tv_sec < b->tv_sec)
		return -1;
	if (a->tv_sec > b->tv_sec)
		return 1;

	if (a->tv_nsec < b->tv_nsec)
		return -1;
	if (a->tv_nsec > b->tv_nsec)
		return 1;

	return 0;
}

static int timespec_non_zero(const struct timespec *ts)
{
	return ts->tv_sec | ts->tv_nsec;
}

static int arm_timer(struct server_wrk *w, uint64_t delta_us)
{
	struct timespec *next = &w->next_timer_fire;
	struct timespec now, next_intv;
	struct itimerspec its;
	int ret;

	ret = clock_gettime(CLOCK_MONOTONIC, &now);
	if (ret) {
		ret = -errno;
		pr_error("Failed to get current time: %s", strerror(-ret));
		return ret;
	}

	ts_add_us(&now, delta_us);

	/*
	 * If next_timer_fire is smaller than @now, skip arming the timer.
	 */
	if (timespec_non_zero(next) && timespec_cmp(next, &now) < 0)
		return 0;

	us_to_timespec(delta_us, &next_intv);

	w->next_timer_fire = now;
	w->next_intv = next_intv;
	its.it_value = now;
	its.it_interval = next_intv;
	ret = timerfd_settime(w->timer_fd, TFD_TIMER_ABSTIME, &its, NULL);
	if (ret) {
		ret = -errno;
		pr_error("Failed to arm timer: %s", strerror(-ret));
	}

	return ret;
}

static int disarm_timer(struct server_wrk *w)
{
	struct itimerspec its;
	int ret;

	memset(&its, 0, sizeof(its));
	memset(&w->next_timer_fire, 0, sizeof(w->next_timer_fire));
	ret = timerfd_settime(w->timer_fd, 0, &its, NULL);
	if (ret) {
		ret = -errno;
		pr_error("Failed to disarm timer: %s", strerror(-ret));
	}

	return ret;
}

static int do_rate_limit(struct server_wrk *w, struct client_state *c,
			 enum stream_dir dir)
{
	struct ip_spd_bucket *b = c->spd;
	struct client_endp *ep;
	struct spd_tkn *tkn;
	uint64_t delta_us;
	int ret;

	assert(b);
	if (dir == UP_DIR) {
		if (c->rate_limit_flags & RTF_UP_RATE_LIMITED)
			return 0;

		ep = &c->target_ep;
		tkn = &b->up_tkn;
		c->rate_limit_flags |= RTF_UP_RATE_LIMITED;
	} else {
		if (c->rate_limit_flags & RTF_DN_RATE_LIMITED)
			return 0;

		ep = &c->client_ep;
		tkn = &b->dn_tkn;
		c->rate_limit_flags |= RTF_DN_RATE_LIMITED;
	}

	delta_us = (spd_min_fill * tkn->fill_intv) / tkn->max;
	if (!delta_us)
		return 0;

	ep->ep_mask &= ~EPOLLOUT;
	ret = apply_ep_mask(w, c, ep);
	if (ret)
		return ret;

	return arm_timer(w, delta_us);
}

static ssize_t do_pipe_epoll_in(struct server_wrk *w, struct client_state *c,
				struct client_endp *src, struct client_endp *dst)
{
	__unused struct sockaddr_in46 *psrc = (src == &c->client_ep) ? &c->client_ep.addr : &c->target_ep.addr;
	__unused struct sockaddr_in46 *pdst = (dst == &c->client_ep) ? &c->client_ep.addr : &c->target_ep.addr;
	__unused const char *src_name = (src == &c->client_ep) ? "Client" : "Target";
	__unused const char *dst_name = (dst == &c->client_ep) ? "Client" : "Target";
	enum stream_dir dir = (src == &c->client_ep) ? UP_DIR : DN_DIR;
	size_t max_send_size = get_max_send_size(c, dir);
	ssize_t sock_ret;
	int err;

	sock_ret = do_ep_recv(src);
	if (sock_ret < 0) {
		if (sock_ret == -EAGAIN)
			return 0;

		if (sock_ret != -ENOBUFS)
			return sock_ret;

		/*
		 * The receive buffer is full. Disable EPOLLIN on the source
		 * endpoint. Also, enable EPOLLOUT on the destination endpoint
		 * to drain the buffer.
		 */
		pr_vl_dbg(3, "Disabling EPOLLIN on src=%s (fd=%d; psrc=%s; pdst=%s; thread=%u)",
			  src_name,
			  src->fd,
			  sockaddr_to_str(psrc),
			  sockaddr_to_str(pdst),
			  w->idx);

		assert(src->len > 0);
		src->ep_mask &= ~EPOLLIN;
		err = apply_ep_mask(w, c, src);
		if (err)
			return (ssize_t)err;

		sock_ret = 0;
		goto enable_out_dst;
	}

	if (dst->ep_mask & EPOLLOUT)
		return 0;
	if (dst == &c->target_ep && !c->target_connected)
		goto enable_out_dst;
	if (dir == UP_DIR && (c->rate_limit_flags & RTF_UP_RATE_LIMITED))
		return 0;
	if (dir == DN_DIR && (c->rate_limit_flags & RTF_DN_RATE_LIMITED))
		return 0;
	if (!max_send_size)
		return do_rate_limit(w, c, dir);

	sock_ret = do_ep_send(src, dst, max_send_size);
	if (sock_ret < 0 && sock_ret != -EAGAIN) {
		pr_vl_dbg(3, "po: send() to %s (fd=%d; psrc=%s; pdst=%s; thread=%u): %s",
			  dst_name,
			  dst->fd,
			  sockaddr_to_str(psrc),
			  sockaddr_to_str(pdst),
			  w->idx,
			  strerror((int)-sock_ret));

		return sock_ret;
	}

	if (sock_ret > 0)
		consume_token(c, dir, (size_t)sock_ret);

enable_out_dst:
	if (src->len > 0) {
		if (dir == UP_DIR && (c->rate_limit_flags & RTF_UP_RATE_LIMITED))
			return 0;
		if (dir == DN_DIR && (c->rate_limit_flags & RTF_DN_RATE_LIMITED))
			return 0;

		pr_vl_dbg(3, "Enabling  EPOLLOUT on dst=%s (fd=%d; psrc=%s; pdst=%s; thread=%u)",
			  dst_name,
			  dst->fd,
			  sockaddr_to_str(psrc),
			  sockaddr_to_str(pdst),
			  w->idx);

		dst->ep_mask |= EPOLLOUT;
		err = apply_ep_mask(w, c, dst);
		if (err)
			return (ssize_t)err;
	}

	if (sock_ret == -EAGAIN)
		sock_ret = 0;

	return sock_ret;
}

static ssize_t do_pipe_epoll_out(struct server_wrk *w, struct client_state *c,
				 struct client_endp *src, struct client_endp *dst)
{
	__unused struct sockaddr_in46 *psrc = (src == &c->client_ep) ? &c->client_ep.addr : &c->target_ep.addr;
	__unused struct sockaddr_in46 *pdst = (dst == &c->client_ep) ? &c->client_ep.addr : &c->target_ep.addr;
	__unused const char *src_name = (src == &c->client_ep) ? "Client" : "Target";
	__unused const char *dst_name = (dst == &c->client_ep) ? "Client" : "Target";
	enum stream_dir dir = (src == &c->client_ep) ? UP_DIR : DN_DIR;
	size_t max_send_size = get_max_send_size(c, dir);
	size_t remain_bsize;
	ssize_t sock_ret;
	int err;

	if (!max_send_size)
		return do_rate_limit(w, c, dir);

	sock_ret = do_ep_send(src, dst, max_send_size);
	if (sock_ret < 0 && sock_ret != -EAGAIN) {
		pr_vl_dbg(3, "po: send() to %s (fd=%d; psrc=%s; pdst=%s; thread=%u): %s",
			  dst_name,
			  dst->fd,
			  sockaddr_to_str(psrc),
			  sockaddr_to_str(pdst),
			  w->idx,
			  strerror((int)-sock_ret));
		return sock_ret;
	}

	if (sock_ret > 0)
		consume_token(c, dir, (size_t)sock_ret);

	if (src->len == 0) {
		pr_vl_dbg(3, "Disabling EPOLLOUT on dst=%s (fd=%d; psrc=%s; pdst=%s; thread=%u)",
			  dst_name,
			  dst->fd,
			  sockaddr_to_str(psrc),
			  sockaddr_to_str(pdst),
			  w->idx);

		dst->ep_mask &= ~EPOLLOUT;
		err = apply_ep_mask(w, c, dst);
		if (err)
			return err;
	}

	remain_bsize = src->cap - src->len;
	if (remain_bsize > 0 && !(src->ep_mask & EPOLLIN)) {
		pr_vl_dbg(3, "Enabling  EPOLLIN on src=%s (fd=%d; psrc=%s; pdst=%s; thread=%u)",
			  src_name,
			  src->fd,
			  sockaddr_to_str(psrc),
			  sockaddr_to_str(pdst),
			  w->idx);
		src->ep_mask |= EPOLLIN;
		err = apply_ep_mask(w, c, src);
		if (err)
			return (ssize_t)err;
	}

	if (sock_ret == -EAGAIN)
		sock_ret = 0;

	return sock_ret;
}

static int handle_event_client_data(struct server_wrk *w, struct epoll_event *ev)
{
	struct client_state *c = GET_EPL_DT(ev->data.u64);
	uint32_t events = ev->events;
	int ret;

	if (unlikely(events & (EPOLLERR | EPOLLHUP))) {
		pr_errorv("rhup: Client socket hit EPOLLERR|EPOLLHUP: %s -> %s (thread %u)", sockaddr_to_str(&c->client_ep.addr), sockaddr_to_str(&c->target_ep.addr), w->idx);
		return -ECONNRESET;
	}

	if (events & EPOLLIN) {
		ret = do_pipe_epoll_in(w, c, &c->client_ep, &c->target_ep);
		if (ret < 0)
			return ret;
	}

	if (events & EPOLLOUT) {
		ret = do_pipe_epoll_out(w, c, &c->target_ep, &c->client_ep);
		if (ret < 0)
			return ret;
	}

	return 0;
}

static int handle_event_target_data(struct server_wrk *w, struct epoll_event *ev)
{
	struct client_state *c = GET_EPL_DT(ev->data.u64);
	uint32_t events = ev->events;
	int ret;

	if (unlikely(events & (EPOLLERR | EPOLLHUP))) {
		pr_errorv("thup: Target socket hit EPOLLERR|EPOLLHUP: %s -> %s (thread %u)", sockaddr_to_str(&c->client_ep.addr), sockaddr_to_str(&c->target_ep.addr), w->idx);
		return -ECONNRESET;
	}

	if (events & EPOLLIN) {
		ret = do_pipe_epoll_in(w, c, &c->target_ep, &c->client_ep);
		if (ret < 0)
			return ret;
	}

	if (events & EPOLLOUT) {
		ret = do_pipe_epoll_out(w, c, &c->client_ep, &c->target_ep);
		if (ret < 0)
			return ret;
	}

	return 0;
}

/*
 *
 *   The server evaluates the request, and returns a reply formed as follows:
 *
 *        +----+-----+-------+------+----------+----------+
 *        |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
 *        +----+-----+-------+------+----------+----------+
 *        | 1  |  1  | X'00' |  1   | Variable |    2     |
 *        +----+-----+-------+------+----------+----------+
 *
 *     Where:
 *
 *          o  VER    protocol version: X'05'
 *          o  REP    Reply field:
 *             o  X'00' succeeded
 *             o  X'01' general SOCKS server failure
 *             o  X'02' connection not allowed by ruleset
 *             o  X'03' Network unreachable
 *             o  X'04' Host unreachable
 *             o  X'05' Connection refused
 *             o  X'06' TTL expired
 *             o  X'07' Command not supported
 *             o  X'08' Address type not supported
 *             o  X'09' to X'FF' unassigned
 *          o  RSV    RESERVED
 *          o  ATYP   address type of following address
 *             o  IP V4 address: X'01'
 *             o  DOMAINNAME: X'03'
 *             o  IP V6 address: X'04'
 *          o  BND.ADDR       server bound address
 *          o  BND.PORT       server bound port in network octet order
 *
 *   Fields marked RESERVED (RSV) must be set to X'00'.
 */
static int respond_socks5_request(struct server_wrk *w, struct client_state *c, int err)
{
	uint8_t buf[1 + 1 + 1 + 1 + 16 + 2];
	struct socks5_data *sd = c->socks5;
	union epoll_data data;
	size_t len = 0;
	ssize_t ret;

	buf[0] = 0x05; /* VER */
	len++;

	/* REP */
	len++;
	switch (err) {
	case 0:
		/* Succeeded. */
		buf[1] = 0x00;
		break;
	case EPERM:
	case EACCES:
		/* Connection not allowed by ruleset. */
		buf[1] = 0x02;
		break;
	case ENETUNREACH:
		/* Network unreachable. */
		buf[1] = 0x03;
		break;
	case EHOSTUNREACH:
		/* Host unreachable. */
		buf[1] = 0x04;
		break;
	case ECONNREFUSED:
		/* Connection refused. */
		buf[1] = 0x05;
		break;
	default:
		/* General SOCKS server failure. */
		buf[1] = 0x01;
		break;
	}

	buf[2] = 0x00; /* RSV */
	len++;

	buf[3] = sd->atyp; /* ATYP */
	len++;

	switch (sd->atyp) {
	case SOCKS5_ATYP_IPV4:
		memcpy(buf + 4, sd->ipv4, 4);
		memcpy(buf + 8, &sd->port, 2);
		len += 6;
		break;
	case SOCKS5_ATYP_IPV6:
		memcpy(buf + 4, sd->ipv6, 16);
		memcpy(buf + 20, &sd->port, 2);
		len += 18;
		break;
	default:
		pr_errorv("Invalid SOCKS5 ATYP: %u", sd->atyp);
		return -EINVAL;
	}

	ret = send(c->client_ep.fd, buf, len, MSG_DONTWAIT);
	if ((size_t)ret != len) {
		pr_errorv("Failed to send SOCKS5 response: %s: send(): %zd", strerror(errno), ret);
		return -ECONNRESET;
	}

	if (err)
		return -err;

	free_socks5_data(sd);
	c->socks5 = NULL;

	pthread_mutex_lock(&w->epass_mutex);
	c->client_ep.ep_mask = EPOLLIN;
	set_epoll_data(&data, c, EPL_EV_TCP_CLIENT_DATA);
	ret = epoll_mod(w->ep_fd, c->client_ep.fd, c->client_ep.ep_mask, data);
	if (ret)
		goto out;

	c->target_ep.ep_mask = EPOLLIN;
	set_epoll_data(&data, c, EPL_EV_TCP_TARGET_DATA);
	ret = epoll_mod(w->ep_fd, c->target_ep.fd, c->target_ep.ep_mask, data);
	if (ret)
		goto out;
	
	send_event_fd(w);
out:
	pthread_mutex_unlock(&w->epass_mutex);
	return ret;
}

static int handle_event_target_conn(struct server_wrk *w, struct epoll_event *ev)
{
	struct client_state *c = GET_EPL_DT(ev->data.u64);
	uint32_t events = ev->events;
	socklen_t len;
	int ret, tmp;

	tmp = 0;
	len = sizeof(tmp);
	ret = getsockopt(c->target_ep.fd, SOL_SOCKET, SO_ERROR, &tmp, &len);
	if (unlikely(tmp || !(events & EPOLLOUT))) {
		if (tmp < 0)
			tmp = -tmp;
		pr_error("Connect error: %s: %s", sockaddr_to_str(&c->target_ep.addr), strerror(tmp));

		if (c->socks5) {
			ret = respond_socks5_request(w, c, tmp);
			if (ret)
				return ret;
		}
		return -ECONNRESET;
	}

	if (c->socks5) {
		ret = respond_socks5_request(w, c, 0);
	} else {
		pthread_mutex_lock(&w->epass_mutex);
		c->target_connected = true;
		c->target_ep.ep_mask |= EPOLLIN;
		ret = apply_ep_mask(w, c, &c->target_ep);
		if (ret) {
			pthread_mutex_unlock(&w->epass_mutex);
			return ret;
		}

		if (!(c->client_ep.ep_mask & EPOLLIN)) {
			c->client_ep.ep_mask |= EPOLLIN;
			ret = apply_ep_mask(w, c, &c->client_ep);
			if (ret) {
				pthread_mutex_unlock(&w->epass_mutex);
				return ret;
			}
		}
		pthread_mutex_unlock(&w->epass_mutex);
	}

	pr_infov("conn: %s -> %s (fd=%d; tfd=%d; thread=%u)",
		 sockaddr_to_str(&c->client_ep.addr),
		 sockaddr_to_str(&c->target_ep.addr),
		 c->client_ep.fd,
		 c->target_ep.fd,
		 w->idx);

	return ret;
}

static int timespec_add(struct timespec *a, const struct timespec *b)
{
	a->tv_sec += b->tv_sec;
	a->tv_nsec += b->tv_nsec;
	if (a->tv_nsec >= 1000000000) {
		a->tv_sec++;
		a->tv_nsec -= 1000000000;
	}

	return 0;
}

static int handle_event_timer(struct server_wrk *w)
{
	struct client_state *c;
	size_t nr_limited = 0;
	int ret = 0;
	uint32_t i;

	assert(w->ctx->need_timer);

	timespec_add(&w->next_timer_fire, &w->next_intv);
	pthread_mutex_lock(&w->cl_stack.lock);
	for (i = 0; i < w->client_arr_size; i++) {
		c = w->clients[i];
		if (!c || !c->is_used)
			continue;

		if (c->rate_limit_flags & RTF_UP_RATE_LIMITED) {
			nr_limited++;
			if (get_max_send_size(c, UP_DIR)) {
				c->target_ep.ep_mask |= EPOLLOUT;
				c->rate_limit_flags &= ~RTF_UP_RATE_LIMITED;
				ret = apply_ep_mask(w, c, &c->target_ep);
				if (ret)
					break;
			}
		}

		if (c->rate_limit_flags & RTF_DN_RATE_LIMITED) {
			nr_limited++;
			if (get_max_send_size(c, DN_DIR)) {
				c->client_ep.ep_mask |= EPOLLOUT;
				c->rate_limit_flags &= ~RTF_DN_RATE_LIMITED;
				ret = apply_ep_mask(w, c, &c->client_ep);
				if (ret)
					break;
			}
		}
	}
	pthread_mutex_unlock(&w->cl_stack.lock);

	if (nr_limited == 0) {
		if (++w->nr_zero_limited > 1024)
			ret = disarm_timer(w);
	} else {
		w->nr_zero_limited = 0;
	}

	return ret;
}

static int send_socks5_auth_method(struct client_state *c)
{
	char buf[2] = { 0x05, c->socks5->auth_method };
	ssize_t ret;

	errno = 0;
	ret = send(c->client_ep.fd, buf, sizeof(buf), MSG_DONTWAIT);
	if (ret != sizeof(buf)) {
		/*
		 * Don't bother checking for EAGAIN or EINTR here.
		 * Just drop the client if we can't just send 2 bytes.
		 */
		pr_errorv("Failed to send SOCKS5 authentication method: %s: send(): %zd", strerror(errno), ret);
		return -ECONNRESET;
	}

	return 0;
}

static int evaluate_socks5_init(struct server_wrk *w, struct client_state *c)
{
	uint8_t nr_methods, *methods, expected_method;
	struct socks5_data *sd = c->socks5;
	size_t len = sd->len, expected_len;
	char *buf = sd->buf;

	if (len < 2)
		return -EAGAIN;

	if (buf[0] != 0x05) {
		pr_errorv("Invalid SOCKS5 version: %u", buf[0]);
		return -EINVAL;
	}

	nr_methods = buf[1];
	expected_len = (size_t)(nr_methods + 2);
	if (len < expected_len) {
		/*
		 * We have not received all methods yet.
		 * Wait for more data.
		 */
		return -EAGAIN;
	}

	if (len > expected_len) {
		pr_errorv("Invalid SOCKS5 method negotiation message length: %zu", len);
		return -EINVAL;
	}

	assert(len == expected_len);

	if (w->ctx->cfg.socks5_user && w->ctx->cfg.socks5_pass)
		expected_method = SOCKS5_AUTH_USERPASS;
	else
		expected_method = SOCKS5_AUTH_NONE;

	methods = (uint8_t *)(buf + 2);
	sd->len = 0;

	if (memchr(methods, expected_method, nr_methods)) {
		if (expected_method == SOCKS5_AUTH_USERPASS)
			sd->state = SOCKS5_STATE_AUTH;
		else
			sd->state = SOCKS5_STATE_REQ;

		sd->auth_method = expected_method;
		return send_socks5_auth_method(c);
	} else {
		pr_errorv("Unsupported SOCKS5 authentication method: %u", expected_method);
		sd->auth_method = SOCKS5_AUTH_NOACCEPT;
		send_socks5_auth_method(c);
		return -EINVAL;
	}
}

static int send_socks5_auth_res(struct client_state *c, int code)
{
	uint8_t buf[2] = { 0x01, code };
	ssize_t ret;

	errno = 0;
	ret = send(c->client_ep.fd, buf, sizeof(buf), MSG_DONTWAIT);
	if (ret == sizeof(buf))
		return 0;

	pr_errorv("Failed to send SOCKS5 invalid authentication response: %s: send(): %zd", strerror(errno), ret);
	return -EIO;
}

/*
 *   This begins with the client producing a Username/Password request:
 *
 *           +----+------+----------+------+----------+
 *           |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
 *           +----+------+----------+------+----------+
 *           | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
 *           +----+------+----------+------+----------+
 *
 *   The VER field contains the current version of the subnegotiation,
 *   which is X'01'. The ULEN field contains the length of the UNAME field
 *   that follows. The UNAME field contains the username as known to the
 *   source operating system. The PLEN field contains the length of the
 *   PASSWD field that follows. The PASSWD field contains the password
 *   association with the given UNAME.
 *
 *   The server verifies the supplied UNAME and PASSWD, and sends the
 *   following response:
 *
 *                        +----+--------+
 *                        |VER | STATUS |
 *                        +----+--------+
 *                        | 1  |   1    |
 *                        +----+--------+
 *
 *   A STATUS field of X'00' indicates success. If the server returns a
 *   `failure' (STATUS value other than X'00') status, it MUST close the
 *   connection.
 */
static int evaluate_socks5_auth(struct server_wrk *w, struct client_state *c)
{
	const char *suname = w->ctx->cfg.socks5_user;
	const char *spasswd = w->ctx->cfg.socks5_pass;
	size_t suname_len, spasswd_len;

	struct socks5_data *sd = c->socks5;
	size_t len = sd->len, expected_len;
	uint8_t *buf = (uint8_t *)sd->buf;
	uint8_t ulen, plen, *uname, *passwd;

	assert(suname);
	assert(spasswd);

	if (len < 2)
		return -EAGAIN;

	if (buf[0] != 0x01) {
		pr_errorv("Invalid SOCKS5 authentication version: %u", buf[0]);
		return -EINVAL;
	}

	ulen = buf[1];
	expected_len = 2 + ulen; /* VER + ULEN + UNAME */
	if (len < expected_len)
		return -EAGAIN;

	expected_len += 1; /* PLEN */
	if (len < expected_len)
		return -EAGAIN;

	plen = buf[2 + ulen];
	expected_len += plen; /* PASSWD */
	if (len < expected_len)
		return -EAGAIN;

	if (len > expected_len) {
		pr_errorv("Invalid SOCKS5 authentication message length: %zu", len);
		return -EINVAL;
	}

	uname = buf + 2;
	passwd = buf + 3 + ulen;
	suname_len = strlen(suname);
	spasswd_len = strlen(spasswd);

	if (ulen != suname_len || memcmp(uname, suname, suname_len)) {
		pr_errorv("Invalid SOCKS5 username: %.*s", ulen, uname);
		send_socks5_auth_res(c, 1);
		return -EPERM;
	}

	if (plen != spasswd_len || memcmp(passwd, spasswd, spasswd_len)) {
		pr_errorv("Invalid SOCKS5 password: %.*s", plen, passwd);
		send_socks5_auth_res(c, 2);
		return -EPERM;
	}

	sd->state = SOCKS5_STATE_REQ;
	sd->len = 0;
	return send_socks5_auth_res(c, 0);
}

/*
 *   The SOCKS request is formed as follows:
 *
 *        +----+-----+-------+------+----------+----------+
 *        |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
 *        +----+-----+-------+------+----------+----------+
 *        | 1  |  1  | X'00' |  1   | Variable |    2     |
 *        +----+-----+-------+------+----------+----------+
 *
 *     Where:
 *
 *          o  VER    protocol version: X'05'
 *          o  CMD
 *             o  CONNECT X'01'
 *             o  BIND X'02'
 *             o  UDP ASSOCIATE X'03'
 *          o  RSV    RESERVED
 *          o  ATYP   address type of following address
 *             o  IP V4 address: X'01'
 *             o  DOMAINNAME: X'03'
 *             o  IP V6 address: X'04'
 *          o  DST.ADDR       desired destination address
 *          o  DST.PORT desired destination port in network octet
 *             order
 *
 *   The SOCKS server will typically evaluate the request based on source
 *   and destination addresses, and return one or more reply messages, as
 *   appropriate for the request type.
 */
static int evaluate_socks5_req(struct server_wrk *w, struct client_state *c)
{
	struct socks5_data *sd = c->socks5;
	size_t len = sd->len, expected_len = 4;
	uint8_t *buf = (uint8_t *)sd->buf;

	if (buf[0] != 0x05) {
		pr_errorv("Invalid SOCKS5 version: %u", buf[0]);
		return -EINVAL;
	}

	if (len < expected_len)
		return -EAGAIN;

	if (buf[1] != 0x01) {
		/*
		 * Currently, we only support CONNECT command.
		 */
		pr_errorv("Unsupported SOCKS5 command: %u", buf[1]);
		return -EINVAL;
	}

	if (buf[2] != 0x00) {
		pr_errorv("Invalid SOCKS5 reserved byte: %u", buf[2]);
		return -EINVAL;
	}

	switch (buf[3]) {
	case SOCKS5_ATYP_IPV4:
		expected_len += 4 + 2;
		break;
	case SOCKS5_ATYP_DOMAIN:
		expected_len += 1;
		break;
	case SOCKS5_ATYP_IPV6:
		expected_len += 16 + 2;
		break;
	default:
		pr_errorv("Invalid SOCKS5 address type: %u", buf[3]);
		return -EINVAL;
	}

	if (len < expected_len)
		return -EAGAIN;

	if (len > expected_len) {
		pr_errorv("Invalid SOCKS5 request message length: %zu", len);
		return -EINVAL;
	}

	switch (buf[3]) {
	case SOCKS5_ATYP_IPV4:
		sd->atyp = SOCKS5_ATYP_IPV4;
		memcpy(&sd->ipv4, buf + 4, 4);
		memcpy(&sd->port, buf + 8, 2);
		break;
	case SOCKS5_ATYP_DOMAIN:
		/*
		 * To be implemented.
		 */
		return -ENOSYS;
	case SOCKS5_ATYP_IPV6:
		sd->atyp = SOCKS5_ATYP_IPV6;
		memcpy(&sd->ipv6, buf + 4, 16);
		memcpy(&sd->port, buf + 20, 2);
		break;
	}

	sd->len = 0;
	return prepare_target_connect(w, c, true);
}

static int evaluate_socks5_data(struct server_wrk *w, struct client_state *c)
{
	switch (c->socks5->state) {
	case SOCKS5_STATE_INIT:
		return evaluate_socks5_init(w, c);
	case SOCKS5_STATE_AUTH:
		return evaluate_socks5_auth(w, c);
	case SOCKS5_STATE_REQ:
		return evaluate_socks5_req(w, c);
	default:
		pr_error("Unknown SOCKS5 state: %u", c->socks5->state);
		assert(0);
		return -EINVAL;
	}
}

static int handle_event_client_socks5_in(struct server_wrk *w, struct client_state *c)
{
	struct socks5_data *sd = c->socks5;
	ssize_t ret;
	size_t len;
	char *buf;

	buf = sd->buf + sd->len;
	len = sd->cap - sd->len;
	if (len == 0)
		return -ENOBUFS;

	ret = recv(c->client_ep.fd, buf, len, MSG_DONTWAIT);
	if (ret < 0) {
		ret = -errno;
		if (ret == -EAGAIN || ret == -EINTR)
			return 0;

		return ret;
	}

	if (ret == 0)
		return -ECONNRESET;

	sd->len += (size_t)ret;

	ret = evaluate_socks5_data(w, c);
	if (ret == -EAGAIN)
		ret = 0;

	return ret;
}

static int handle_event_client_socks5(struct server_wrk *w, struct epoll_event *ev)
{
	struct client_state *c = GET_EPL_DT(ev->data.u64);
	uint32_t events = ev->events;
	int ret;

	if (unlikely(events & (EPOLLERR | EPOLLHUP))) {
		pr_errorv("shup: Client socket hit EPOLLERR|EPOLLHUP: %s -> %s (thread %u)", sockaddr_to_str(&c->client_ep.addr), sockaddr_to_str(&c->target_ep.addr), w->idx);
		return -ECONNRESET;
	}

	assert(!(events & EPOLLOUT));

	if (events & EPOLLIN) {
		ret = handle_event_client_socks5_in(w, c);
		if (ret)
			return ret;
	}

	return 0;
}

static int handle_event(struct server_wrk *w, struct epoll_event *ev,
			bool *has_event_timer, bool *has_event_accept)
{
	uint64_t evt = GET_EPL_EV(ev->data.u64);
	int ret = 0;

	switch (evt) {
	case EPL_EV_EVENTFD:
		ret = consume_event_fd(w);
		break;
	case EPL_EV_TCP_ACCEPT:
		*has_event_accept = true;
		break;
	case EPL_EV_TCP_CLIENT_DATA:
		if (!w->handle_events_should_stop)
			ret = handle_event_client_data(w, ev);
		break;
	case EPL_EV_TCP_TARGET_DATA:
		if (!w->handle_events_should_stop)
			ret = handle_event_target_data(w, ev);
		break;
	case EPL_EV_TCP_TARGET_CONN:
	case EPL_EV_TCP_TARGET_SOCKS5_CONN:
		if (!w->handle_events_should_stop)
			ret = handle_event_target_conn(w, ev);
		break;
	case EPL_EV_TIMERFD:
		*has_event_timer = true;
		break;
	case EPL_EV_TCP_CLIENT_SOCKS5:
		if (!w->handle_events_should_stop)
			ret = handle_event_client_socks5(w, ev);
		break;
	default:
		pr_error("Unknown event type: %lu (thread %u)", evt, w->idx);
		return -EINVAL;
	}

	if (ret < 0) {
		switch (evt) {
		case EPL_EV_TCP_TARGET_CONN:
		case EPL_EV_TCP_TARGET_SOCKS5_CONN:
		case EPL_EV_TCP_CLIENT_DATA:
		case EPL_EV_TCP_TARGET_DATA:
			put_client_slot(w, GET_EPL_DT(ev->data.u64));
			ret = 0;
			break;
		default:
			break;
		}
	}

	return 0;
}

static int handle_events(struct server_wrk *w, int nr_events)
{
	/*
	 * Accept and timer are low priority. They are handled after all
	 * other client events are processed.
	 */
	bool has_event_timer = false;
	bool has_event_accept = false;
	int ret = 0;
	int i;

	for (i = 0; i < nr_events; i++) {
		struct epoll_event *ev = &w->events[i];

		ret = handle_event(w, ev, &has_event_timer, &has_event_accept);
		if (ret < 0)
			break;
	}

	if (has_event_timer) {
		ret = handle_event_timer(w);
		if (ret)
			return ret;
	}

	if (has_event_accept) {
		ret = handle_event_accept(w);
		if (ret)
			return ret;
	}

	return ret;
}

static int poll_events(struct server_wrk *w)
{
	struct epoll_event *ev = w->events;
	int ret;

	w->handle_events_should_stop = false;
	ret = epoll_wait(w->ep_fd, ev, NR_EPOLL_EVENTS, w->ep_timeout);
	if (unlikely(ret < 0)) {
		ret = -errno;
		if (ret == -EINTR)
			return 0;

		pr_error("epoll_wait() failed: %s (thread %u)", strerror(-ret), w->idx);
		return ret;
	}

	return ret;
}

static void *worker_entry(void *arg)
{
	struct server_wrk *w = arg;
	struct server_ctx *ctx = w->ctx;
	int ret = 0;
	void *ptr;

	while (!ctx->should_stop) {
		ret = poll_events(w);
		if (ret < 0)
			break;

		ret = handle_events(w, ret);
		if (ret < 0)
			break;
	}

	ptr = (void *)(intptr_t)ret;
	return ptr;
}

static int run_ctx(struct server_ctx *ctx)
{
	intptr_t ret;
	void *tmp;

	tmp = worker_entry(&ctx->workers[0]);
	ret = (intptr_t)tmp;

	return (int)ret;
}

int main(int argc, char *argv[])
{
	struct server_ctx ctx;
	int ret;

	memset(&ctx, 0, sizeof(ctx));
	ret = parse_args(argc, argv, &ctx.cfg);
	if (ret)
		return ret;

	ret = init_ctx(&ctx);
	if (ret)
		return ret;

	ret = run_ctx(&ctx);
	free_ctx(&ctx);
	return ret;
}
