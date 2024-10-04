// SPDX-License-Identifier: GPL-2.0-only

#include <proxmasterd/http.h>

struct pm_http_net_ctx_arr {
	size_t				nr_ctx;
	uint8_t				*type_arr;
	struct pm_http_net_ctx		*ctx_arr;
};

struct pm_http_ctx {
	struct pm_http_net_ctx_arr	net_ctx_arr;
};

struct pm_http_client {
	uint8_t				method;
	bool				use_ssl;
	bool				keep_alive;
	struct pm_http_hdr		hdr;
	struct pm_buf			*recv_buf;
	struct pm_buf			*send_buf;
	void				*nclient;
};

int pm_http_hdr_add(struct pm_http_hdr *hdr, const char *key, const char *val)
{
	struct pm_http_hdr_pair *pair;
	size_t new_nr_pairs;

	new_nr_pairs = hdr->nr_pairs + 1;
	pair = realloc(hdr->pairs, new_nr_pairs * sizeof(*pair));
	if (!pair)
		return -ENOMEM;

	hdr->pairs = pair;
	pair = &hdr->pairs[hdr->nr_pairs];
	pair->key = strdup(key);
	if (!pair->key)
		return -ENOMEM;

	pair->val = strdup(val);
	if (!pair->val) {
		free(pair->key);
		return -ENOMEM;
	}

	pair->key_len = strlen(key);
	pair->val_len = strlen(val);
	hdr->nr_pairs = new_nr_pairs;
	return 0;
}

static void pm_http_hdr_destroy(struct pm_http_hdr *hdr)
{
	size_t i;

	if (!hdr->nr_pairs)
		return;

	for (i = 0; i < hdr->nr_pairs; i++) {
		struct pm_http_hdr_pair *pair = &hdr->pairs[i];

		free(pair->key);
		free(pair->val);
	}

	free(hdr->pairs);
	memset(hdr, 0, sizeof(*hdr));
}

int pm_http_ctx_init(pm_http_ctx_t **ctx_p)
{
	pm_http_ctx_t *ctx;

	ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
		return -1;

	*ctx_p = ctx;
	return 0;
}

int pm_http_ctx_easy_init(pm_http_ctx_t **ctx_p, const struct pm_http_easy_arg *arg)
{
	struct pm_http_net_ctx net_ctx;
	pm_http_ctx_t *ctx;
	int ret;

	if (!arg->use_plain && !arg->use_ssl)
		return -EINVAL;

	ret = pm_http_ctx_init(&ctx);
	if (ret)
		return ret;

	if (arg->use_plain) {
		struct pm_net_tcp_arg parg;

		memset(&parg, 0, sizeof(parg));
		parg.bind_addr.v6.sin6_addr = in6addr_any;
		parg.bind_addr.v6.sin6_port = htons(arg->plain_port);
		parg.bind_addr.v6.sin6_family = AF_INET6;

		parg.client_init_cap = 8192;
		parg.nr_workers = 4;
		parg.sock_backlog = 2048;
		ret = pm_net_tcp_ctx_init(&net_ctx.plain, &parg);
		if (ret) {
			pm_http_ctx_destroy(ctx);
			return ret;
		}

		ret = pm_http_ctx_add_net_ctx(ctx, &net_ctx, PM_HTTP_NET_CTX_PLAIN);
		if (ret) {
			pm_http_ctx_destroy(ctx);
			pm_net_tcp_ctx_destroy(net_ctx.plain);
			return ret;
		}
	}

	if (arg->use_ssl) {
		struct pm_net_tcp_ssl_arg sarg;
		struct pm_net_tcp_arg *parg = &sarg.net_arg;

		memset(&sarg, 0, sizeof(sarg));
		parg->bind_addr.v6.sin6_addr = in6addr_any;
		parg->bind_addr.v6.sin6_port = htons(arg->ssl_port);
		parg->bind_addr.v6.sin6_family = AF_INET6;

		parg->client_init_cap = 8192;
		parg->nr_workers = 4;
		parg->sock_backlog = 2048;

		strncpy(sarg.cert_file, arg->cert_file, sizeof(sarg.cert_file) - 1);
		strncpy(sarg.key_file, arg->key_file, sizeof(sarg.key_file) - 1);
		ret = pm_net_tcp_ssl_ctx_init(&net_ctx.ssl, &sarg);
		if (ret) {
			pm_http_ctx_destroy(ctx);
			return ret;
		}

		ret = pm_http_ctx_add_net_ctx(ctx, &net_ctx, PM_HTTP_NET_CTX_SSL);
		if (ret) {
			pm_http_ctx_destroy(ctx);
			pm_net_tcp_ssl_ctx_destroy(net_ctx.ssl);
			return ret;
		}
	}

	*ctx_p = ctx;
	return 0;
}

int pm_http_ctx_add_net_ctx(pm_http_ctx_t *ctx, pm_http_net_ctx_t *net_ctx, uint8_t type)
{
	struct pm_http_net_ctx_arr *net_ctx_arr;
	struct pm_http_net_ctx *new_ctx_arr;
	uint8_t *new_type_arr;
	size_t new_nr_ctx;

	net_ctx_arr = &ctx->net_ctx_arr;
	new_nr_ctx = net_ctx_arr->nr_ctx + 1;

	new_ctx_arr = realloc(net_ctx_arr->ctx_arr, new_nr_ctx * sizeof(*new_ctx_arr));
	if (!new_ctx_arr)
		return -ENOMEM;

	new_type_arr = realloc(net_ctx_arr->type_arr, new_nr_ctx * sizeof(*new_type_arr));
	if (!new_type_arr) {
		net_ctx_arr->ctx_arr = new_ctx_arr;
		return -ENOMEM;
	}

	net_ctx_arr->ctx_arr = new_ctx_arr;
	net_ctx_arr->type_arr = new_type_arr;
	net_ctx_arr->ctx_arr[net_ctx_arr->nr_ctx] = *net_ctx;
	net_ctx_arr->type_arr[net_ctx_arr->nr_ctx] = type;
	net_ctx_arr->nr_ctx = new_nr_ctx;
	return 0;
}

static void __pm_http_ctx_run(pm_http_ctx_t *ctx, pm_net_tcp_ctx_t *nctx);
static void __pm_http_ctx_run_ssl(pm_http_ctx_t *ctx, pm_net_tcp_ssl_ctx_t *nctx);

void pm_http_ctx_run(pm_http_ctx_t *ctx)
{
	struct pm_http_net_ctx_arr *net_ctx_arr;
	size_t i;

	net_ctx_arr = &ctx->net_ctx_arr;
	for (i = 0; i < net_ctx_arr->nr_ctx; i++) {
		struct pm_http_net_ctx *net_ctx = &net_ctx_arr->ctx_arr[i];
		uint8_t type = net_ctx_arr->type_arr[i];

		if (type == PM_HTTP_NET_CTX_PLAIN)
			__pm_http_ctx_run(ctx, net_ctx->plain);
		else
			__pm_http_ctx_run_ssl(ctx, net_ctx->ssl);
	}
}

void pm_http_ctx_wait(pm_http_ctx_t *ctx)
{
	struct pm_http_net_ctx_arr *net_ctx_arr;
	size_t i;

	net_ctx_arr = &ctx->net_ctx_arr;
	for (i = 0; i < net_ctx_arr->nr_ctx; i++) {
		struct pm_http_net_ctx *net_ctx = &net_ctx_arr->ctx_arr[i];
		uint8_t type = net_ctx_arr->type_arr[i];

		if (type == PM_HTTP_NET_CTX_PLAIN)
			pm_net_tcp_ctx_wait(net_ctx->plain);
		else
			pm_net_tcp_ssl_ctx_wait(net_ctx->ssl);
	}
}

void pm_http_ctx_stop(pm_http_ctx_t *ctx)
{
	struct pm_http_net_ctx_arr *net_ctx_arr;
	size_t i;

	net_ctx_arr = &ctx->net_ctx_arr;
	for (i = 0; i < net_ctx_arr->nr_ctx; i++) {
		struct pm_http_net_ctx *net_ctx = &net_ctx_arr->ctx_arr[i];
		uint8_t type = net_ctx_arr->type_arr[i];

		if (type == PM_HTTP_NET_CTX_PLAIN)
			pm_net_tcp_ctx_stop(net_ctx->plain);
		else
			pm_net_tcp_ssl_ctx_stop(net_ctx->ssl);
	}
}

void pm_http_ctx_destroy(pm_http_ctx_t *ctx_p)
{
	struct pm_http_net_ctx_arr *net_ctx_arr;
	size_t i;

	net_ctx_arr = &ctx_p->net_ctx_arr;
	for (i = 0; i < net_ctx_arr->nr_ctx; i++) {
		struct pm_http_net_ctx *net_ctx = &net_ctx_arr->ctx_arr[i];
		uint8_t type = net_ctx_arr->type_arr[i];

		if (type == PM_HTTP_NET_CTX_PLAIN)
			pm_net_tcp_ctx_destroy(net_ctx->plain);
		else
			pm_net_tcp_ssl_ctx_destroy(net_ctx->ssl);
	}

	free(net_ctx_arr->ctx_arr);
	free(net_ctx_arr->type_arr);
	free(ctx_p);
	memset(ctx_p, 0, sizeof(*ctx_p));
}

static struct pm_http_client *pm_http_alloc_client(void)
{
	return calloc(1, sizeof(struct pm_http_client));
}

static void pm_http_client_close(struct pm_http_client *hc)
{
	if (hc->use_ssl)
		pm_net_tcp_ssl_client_user_close(hc->nclient);
	else
		pm_net_tcp_client_user_close(hc->nclient);
}

static const char http_res[] = "HTTP/1.0 200 OK\r\n"
	"Content-Type: text/plain\r\n"
	"Content-Length: 13\r\n"
	"Connection: keep-alive\r\n"
	"\r\n"
	"Hello World!\n";

static int pm_http_handle_recv(struct pm_http_client *hc)
{
	// struct pm_buf *recv_buf = hc->recv_buf;
	struct pm_buf *send_buf = hc->send_buf;

	memcpy(send_buf->buf, http_res, sizeof(http_res));
	send_buf->len = sizeof(http_res) - 1;
	return 0;
}

static int pm_http_handle_close(struct pm_http_client *hc)
{
	pm_http_hdr_destroy(&hc->hdr);
	free(hc);
	return 0;
}

static int pm_http_close_cb(pm_net_tcp_client_t *c)
{
	return pm_http_handle_close(pm_net_tcp_client_get_udata(c));
}

static int pm_http_recv_cb(pm_net_tcp_client_t *c)
{
	return pm_http_handle_recv(pm_net_tcp_client_get_udata(c));
}

static int pm_https_close_cb(pm_net_tcp_ssl_client_t *c)
{
	return pm_http_handle_close(pm_net_tcp_ssl_client_get_udata(c));
}

static int pm_https_recv_cb(pm_net_tcp_ssl_client_t *c)
{
	return pm_http_handle_recv(pm_net_tcp_ssl_client_get_udata(c));
}

static int pm_http_accept_cb(pm_net_tcp_ctx_t *ctx, pm_net_tcp_client_t *c)
{
	struct pm_http_client *hc = pm_http_alloc_client();
	if (!c)
		return -ENOMEM;

	hc->recv_buf = pm_net_tcp_client_get_recv_buf(c);
	hc->send_buf = pm_net_tcp_client_get_send_buf(c);
	hc->nclient = c;
	pm_net_tcp_client_set_udata(c, hc);
	pm_net_tcp_client_set_recv_cb(c, &pm_http_recv_cb);
	pm_net_tcp_client_set_close_cb(c, &pm_http_close_cb);
	(void)ctx;
	return 0;
}

static int pm_https_accept_cb(pm_net_tcp_ssl_ctx_t *ctx, pm_net_tcp_ssl_client_t *c)
{
	struct pm_http_client *hc = pm_http_alloc_client();
	if (!hc)
		return -ENOMEM;

	hc->use_ssl = true;
	hc->recv_buf = pm_net_tcp_ssl_client_get_recv_buf(c);
	hc->send_buf = pm_net_tcp_ssl_client_get_send_buf(c);
	hc->nclient = c;
	pm_net_tcp_ssl_client_set_udata(c, hc);
	pm_net_tcp_ssl_client_set_recv_cb(c, &pm_https_recv_cb);
	pm_net_tcp_ssl_client_set_close_cb(c, &pm_https_close_cb);
	(void)ctx;
	return 0;
}

static void __pm_http_ctx_run(pm_http_ctx_t *ctx, pm_net_tcp_ctx_t *nctx)
{
	pm_net_tcp_ctx_set_udata(nctx, ctx);
	pm_net_tcp_ctx_set_accept_cb(nctx, &pm_http_accept_cb);
	pm_net_tcp_ctx_run(nctx);
}

static void __pm_http_ctx_run_ssl(pm_http_ctx_t *ctx, pm_net_tcp_ssl_ctx_t *nctx)
{
	pm_net_tcp_ssl_ctx_set_udata(nctx, ctx);
	pm_net_tcp_ssl_ctx_set_accept_cb(nctx, &pm_https_accept_cb);
	pm_net_tcp_ssl_ctx_run(nctx);
}
