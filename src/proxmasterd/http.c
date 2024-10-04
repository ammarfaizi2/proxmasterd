// SPDX-License-Identifier: GPL-2.0-only

#include <proxmasterd/http.h>
#include <ctype.h>
#include <assert.h>

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

	struct pm_http_str		uri;
	struct pm_http_str		qs;
	struct pm_http_str		ver;

	struct pm_http_hdr		hdr;
	struct pm_buf			*recv_buf;
	struct pm_buf			*send_buf;
	void				*nclient;
};

static int pm_http_str_append(struct pm_http_str *str, const char *s, size_t len)
{
	char *p;

	p = realloc(str->str, str->len + len + 1);
	if (!p)
		return -ENOMEM;

	memcpy(p + str->len, s, len);
	p[str->len + len] = '\0';
	str->str = p;
	str->len += len;
	return 0;
}

static void pm_http_str_free(struct pm_http_str *str)
{
	if (!str->str)
		return;

	free(str->str);
	str->str = NULL;
	str->len = 0;
}

static int pm_http_strdup(struct pm_http_str *str, const char *s, size_t len)
{
	char *p;

	pm_http_str_free(str);
	p = malloc(len + 1);
	if (!p)
		return -ENOMEM;

	memcpy(p, s, len);
	p[len] = '\0';
	str->str = p;
	str->len = len;
	return 0;
}

static char *strtolower(char *str)
{
	char *p;

	for (p = str; *p; p++)
		*p = tolower(*p);
	return str;
}

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

	pair->key = strtolower(pair->key);
	pair->key_len = strlen(key);
	pair->val_len = strlen(val);
	hdr->nr_pairs = new_nr_pairs;
	return 0;
}

int pm_http_hdr_get(struct pm_http_hdr *hdr, const char *key, char **val)
{
	size_t i;

	for (i = 0; i < hdr->nr_pairs; i++) {
		struct pm_http_hdr_pair *pair = &hdr->pairs[i];

		if (!strcmp(pair->key, key)) {
			*val = pair->val;
			return 0;
		}
	}

	return -ENOENT;
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

static int parse_http_hdr(struct pm_http_client *hc)
{
	char *method, *uri, *qs, *ver, *p, *q, *dcrlf, c;
	char *to_null[2];

	struct pm_buf *rbuf = hc->recv_buf;
	size_t len = rbuf->len;
	size_t eaten_len;

	if (len < 6)
		return -EAGAIN;

	p = rbuf->buf;
	method = p;
	while (*p != ' ') {
		c = *p;
		if (c < 'A' || c > 'Z')
			return -EINVAL;
		if (p - method >= 8)
			return -EINVAL;
		p++;
		len--;
		if (!len)
			return -EAGAIN;
	}
	to_null[0] = p;
	p++;
	len--;
	if (!len)
		return -EAGAIN;

	dcrlf = memmem(p, len, "\r\n\r\n", 4);
	if (!dcrlf)
		return -EAGAIN;

	if (!strncmp(method, "GET", 3))
		hc->method = PM_HTTP_METHOD_GET;
	else if (!strncmp(method, "POST", 4))
		hc->method = PM_HTTP_METHOD_POST;
	else if (!strncmp(method, "PUT", 3))
		hc->method = PM_HTTP_METHOD_PUT;
	else if (!strncmp(method, "DELETE", 6))
		hc->method = PM_HTTP_METHOD_DELETE;
	else if (!strncmp(method, "HEAD", 4))
		hc->method = PM_HTTP_METHOD_HEAD;
	else if (!strncmp(method, "OPTIONS", 7))
		hc->method = PM_HTTP_METHOD_OPTIONS;
	else if (!strncmp(method, "TRACE", 5))
		hc->method = PM_HTTP_METHOD_TRACE;
	else if (!strncmp(method, "CONNECT", 7))
		hc->method = PM_HTTP_METHOD_CONNECT;
	else if (!strncmp(method, "PATCH", 5))
		hc->method = PM_HTTP_METHOD_PATCH;
	else
		return -EINVAL;

	uri = p;
	if (*p != '/')
		return -EINVAL;

	while (*p != ' ') {
		c = *p;
		if (c < 32 || c > 126)
			return -EINVAL;
		p++;
		len--;
		if (!len)
			return -EAGAIN;
	}
	to_null[1] = p;
	p++;
	len--;
	if (!len)
		return -EAGAIN;

	qs = strchr(uri, '?');
	if (qs) {
		*qs = '\0';
		qs++;
	}

	ver = p;
	if (strncmp(ver, "HTTP/1.0", 8) && strncmp(ver, "HTTP/1.1", 8))
		return -EINVAL;
	p += 8;
	len -= 8;
	if (!len) {
		/*
		 * Must not run out of buffer here, as we have already
		 * checked for "\r\n\r\n" above.
		 */
		return -EINVAL;
	}
	if (memcmp(p, "\r\n", 2))
		return -EINVAL;
	*p = '\0';

	p += 2;
	len -= 2;
	if (!len) {
		/*
		 * Must not run out of buffer here, as we have already
		 * checked for "\r\n\r\n" above.
		 */
		return -EINVAL;
	}

	to_null[0][0] = '\0';
	to_null[1][0] = '\0';

	if (pm_http_strdup(&hc->uri, uri, strlen(uri)))
		return -ENOMEM;

	if (qs && pm_http_strdup(&hc->qs, qs, strlen(qs)))
		return -ENOMEM;

	if (pm_http_strdup(&hc->ver, ver, strlen(ver)))
		return -ENOMEM;

	do {
		char *key, *val;

		q = strstr(p, ": ");
		if (!q)
			return -EINVAL;

		key = p;
		*q = '\0';
		p = q + 2;
		len -= (size_t) (p - key);

		q = strstr(p, "\r\n");
		if (!q)
			return -EINVAL;
		val = p;
		*q = '\0';

		if (pm_http_hdr_add(&hc->hdr, key, val))
			return -ENOMEM;

		p = q + 2;
		len -= 2;
		if (len < 2)
			return -EINVAL;
		if (!memcmp(p, "\r\n", 2)) {
			p += 2;
			len -= 2;
			break;
		}
	} while (q < dcrlf);


	eaten_len = (size_t) (p - rbuf->buf);
	assert(eaten_len <= rbuf->len);
	if (eaten_len < rbuf->len) {
		memmove(rbuf->buf, p, rbuf->len - eaten_len);
		rbuf->len -= eaten_len;
	} else {
		rbuf->len = 0;
	}

	return 0;
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

static const char res_test[] =
"HTTP/1.0 200 OK\r\n"
"Server: proxmasterd/0.0.1\r\n"
"Content-Type: text/plain; charset=UTF-8\r\n"
"Content-Length: 13\r\n"
"Connection: keep-alive\r\n"
"\r\n"
"Hello World!\n";

static int pm_http_handle_recv(struct pm_http_client *hc)
{
	struct pm_buf *rbuf = hc->recv_buf;
	int ret;

	if (rbuf->len == rbuf->cap) {
		if (pm_buf_resize(rbuf, rbuf->cap + 1))
			return -ENOMEM;
	}
	rbuf->buf[rbuf->len] = '\0';

	ret = parse_http_hdr(hc);
	if (ret < 0) {
		if (ret != -EAGAIN || hc->recv_buf->len >= 8192)
			pm_http_client_close(hc);
		return ret;
	}

	return pm_buf_append(hc->send_buf, res_test, sizeof(res_test) - 1);
}

static int pm_http_handle_close(struct pm_http_client *hc)
{
	pm_http_hdr_destroy(&hc->hdr);
	pm_http_str_free(&hc->uri);
	pm_http_str_free(&hc->qs);
	pm_http_str_free(&hc->ver);
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
