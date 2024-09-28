// SPDX-License-Identifier: GPL-2.0-only

#include <proxmasterd/net_tcp_ssl.h>
#include <stdio.h>
#include <assert.h>


struct pm_net_tcp_ssl_ctx {
	SSL_CTX				*ssl_ctx;
	struct pm_net_tcp_ctx		*net_ctx;
	struct pm_net_tcp_ssl_arg	arg;
	pm_net_tcp_ssl_accept_cb_t	accept_cb;
};

struct pm_net_tcp_ssl_client {
	SSL				*ssl;
	BIO				*rbio;
	BIO				*wbio;
	struct pm_net_tcp_ssl_ctx	*ssl_ctx;
	struct pm_buf			recv_buf;
	struct pm_buf			send_buf;
	pm_net_tcp_ssl_recv_cb_t	recv_cb;
	pm_net_tcp_ssl_send_cb_t	send_cb;
	pm_net_tcp_ssl_close_cb_t	close_cb;
	bool				has_accepted;
};

static int do_bio_read(pm_net_tcp_client_t *c, struct pm_net_tcp_ssl_client *ssl_c)
{
	struct pm_buf *tcp_sbuf = pm_net_tcp_client_get_send_buf(c);
	size_t len;
	char *buf;
	int ret;

	if (BIO_ctrl_pending(ssl_c->wbio) == 0)
		return -EAGAIN;

	len = tcp_sbuf->cap - tcp_sbuf->len;
	if (!len) {
		if (pm_buf_resize(tcp_sbuf, (tcp_sbuf->cap + 1) * 2))
			return -ENOMEM;
		len = tcp_sbuf->cap - tcp_sbuf->len;
	}

	buf = tcp_sbuf->buf + tcp_sbuf->len;
	ret = BIO_read(ssl_c->wbio, buf, len);
	if (ret <= 0)
		return -EIO;

	tcp_sbuf->len += (size_t)ret;
	return 0;
}

static int do_bio_write(pm_net_tcp_client_t *c, struct pm_net_tcp_ssl_client *ssl_c)
{
	struct pm_buf *tcp_rbuf = pm_net_tcp_client_get_recv_buf(c);
	size_t uret;
	int ret;

	if (tcp_rbuf->len == 0)
		return -EAGAIN;

	ret = BIO_write(ssl_c->rbio, tcp_rbuf->buf, tcp_rbuf->len);
	if (ret <= 0)
		return -EIO;

	uret = (size_t)ret;
	if (uret > tcp_rbuf->len)
		return -EINVAL;

	if (uret < tcp_rbuf->len) {
		memmove(tcp_rbuf->buf, tcp_rbuf->buf + uret, tcp_rbuf->len - uret);
		tcp_rbuf->len -= uret;
	} else {
		tcp_rbuf->len = 0;
	}

	return 0;
}

static int handle_ssl_error(pm_net_tcp_client_t *c,
			    struct pm_net_tcp_ssl_client *ssl_c,
			    int ret)
{
	switch (SSL_get_error(ssl_c->ssl, ret)) {
	case SSL_ERROR_WANT_READ:
		return do_bio_read(c, ssl_c);
	case SSL_ERROR_WANT_WRITE:
		return do_bio_write(c, ssl_c);
	default:
		return -EIO;
	}
}

static int pm_net_tcp_ssl_client_do_accept(pm_net_tcp_client_t *c,
					   struct pm_net_tcp_ssl_client *ssl_c)
{
	int ret = SSL_accept(ssl_c->ssl);
	if (ret != 1)
		return handle_ssl_error(c, ssl_c, ret);

	if (ssl_c->recv_cb)
		return ssl_c->recv_cb(ssl_c);

	return 0;
}

static int pm_net_tcp_ssl_do_recv(pm_net_tcp_client_t *c,
				  struct pm_net_tcp_ssl_client *ssl_c)
{
	struct pm_buf *ssl_rbuf = &ssl_c->recv_buf;
	size_t uret, len;
	char *buf;
	int ret;

	len = ssl_rbuf->cap - ssl_rbuf->len;
	if (len < 2) {
		if (pm_buf_resize(ssl_rbuf, (ssl_rbuf->cap + 1) * 2))
			return -ENOMEM;
		len = ssl_rbuf->cap - ssl_rbuf->len;
	}

	buf = ssl_rbuf->buf + ssl_rbuf->len;
	ret = SSL_read(ssl_c->ssl, buf, len - 1);
	if (ret <= 0)
		return handle_ssl_error(c, ssl_c, ret);

	uret = (size_t)ret;
	if (uret > len - 1)
		return -EINVAL;

	ssl_rbuf->len += uret;
	ssl_rbuf->buf[ssl_rbuf->len] = '\0';

	if (ssl_c->recv_cb)
		ret = ssl_c->recv_cb(ssl_c);

	if (ret == -EAGAIN)
		ret = 0;

	return ret;
}

static int pm_net_tcp_ssl_do_send(pm_net_tcp_client_t *c,
				  struct pm_net_tcp_ssl_client *ssl_c)
{
	struct pm_buf *ssl_sbuf = &ssl_c->send_buf;
	size_t uret, len;
	char *buf;
	int ret;

	if (ssl_c->send_cb) {
		ret = ssl_c->send_cb(ssl_c);
		if (ret < 0 && ret != -EAGAIN)
			return ret;
	}

	len = ssl_sbuf->len;
	if (!len)
		return -EAGAIN;

	buf = ssl_sbuf->buf;
	ret = SSL_write(ssl_c->ssl, buf, len);
	if (ret <= 0)
		return handle_ssl_error(c, ssl_c, ret);

	uret = (size_t)ret;
	if (uret > len)
		return -EINVAL;

	if (uret < len) {
		memmove(ssl_sbuf->buf, ssl_sbuf->buf + uret, len - uret);
		ssl_sbuf->len -= uret;
	} else {
		ssl_sbuf->len = 0;
	}

	return 0;
}

static int pm_net_tcp_ssl_client_recv_cb(pm_net_tcp_client_t *c)
{
	struct pm_net_tcp_ssl_client *ssl_c = pm_net_tcp_client_get_udata(c);
	int ret;

	while (1) {
		ret = do_bio_write(c, ssl_c);
		if (ret)
			return ret;

		if (!ssl_c->has_accepted) {
			ret = pm_net_tcp_ssl_client_do_accept(c, ssl_c);
			if (!ret)
				return ret;
			ssl_c->has_accepted = true;
		}

		ret = pm_net_tcp_ssl_do_recv(c, ssl_c);
		if (ret)
			return ret;
	}
}

static int pm_net_tcp_ssl_client_send_cb(pm_net_tcp_client_t *c)
{
	struct pm_net_tcp_ssl_client *ssl_c = pm_net_tcp_client_get_udata(c);
	int ret;

	while (1) {
		ret = pm_net_tcp_ssl_do_send(c, ssl_c);
		if (ret)
			return ret;

		ret = do_bio_read(c, ssl_c);
		if (ret)
			return ret;
	}
}

static int pm_net_tcp_ssl_client_close_cb(pm_net_tcp_client_t *c)
{
	pm_net_tcp_ssl_client_t *ssl_c = pm_net_tcp_client_get_udata(c);

	pm_buf_destroy(&ssl_c->recv_buf);
	pm_buf_destroy(&ssl_c->send_buf);
	SSL_free(ssl_c->ssl);
	free(ssl_c);
	return 0;
}

static int pm_net_ssl_accept_cb(pm_net_tcp_ctx_t *ctx, pm_net_tcp_client_t *c)
{
	pm_net_tcp_ssl_ctx_t *ssl_ctx = pm_net_tcp_ctx_get_udata(ctx);
	pm_net_tcp_ssl_client_t *ssl_c;

	ssl_c = calloc(1, sizeof(*ssl_c));
	if (!ssl_c)
		return -ENOMEM;
	ssl_c->ssl = SSL_new(ssl_ctx->ssl_ctx);
	if (!ssl_c->ssl)
		goto out_ssl_c;
	ssl_c->rbio = BIO_new(BIO_s_mem());
	if (!ssl_c->rbio)
		goto out_ssl;
	ssl_c->wbio = BIO_new(BIO_s_mem());
	if (!ssl_c->wbio)
		goto out_rbio;
	if (pm_buf_init(&ssl_c->recv_buf, 2048))
		goto out_wbio;
	if (pm_buf_init(&ssl_c->send_buf, 2048))
		goto out_recv_buf;

	ssl_c->ssl_ctx = ssl_ctx;
	SSL_set_bio(ssl_c->ssl, ssl_c->rbio, ssl_c->wbio);
	SSL_set_accept_state(ssl_c->ssl);

	pm_net_tcp_client_set_udata(c, ssl_c);
	pm_net_tcp_client_set_recv_cb(c, &pm_net_tcp_ssl_client_recv_cb);
	pm_net_tcp_client_set_send_cb(c, &pm_net_tcp_ssl_client_send_cb);
	pm_net_tcp_client_set_close_cb(c, &pm_net_tcp_ssl_client_close_cb);
	return 0;

out_recv_buf:
	pm_buf_destroy(&ssl_c->recv_buf);
out_wbio:
	BIO_free(ssl_c->wbio);
out_rbio:
	BIO_free(ssl_c->rbio);
out_ssl:
	SSL_free(ssl_c->ssl);
out_ssl_c:
	free(ssl_c);
	return -ENOMEM;
}

static void set_default_arg(struct pm_net_tcp_ssl_arg *arg)
{
	memset(arg, 0, sizeof(*arg));
	arg->net_arg.nr_workers = 1;
	arg->net_arg.client_init_cap = 1024;
	arg->net_arg.sock_backlog = 1024;
}

int pm_net_tcp_ssl_ctx_init(pm_net_tcp_ssl_ctx_t **ctx_p, const struct pm_net_tcp_ssl_arg *arg)
{
	pm_net_tcp_ssl_ctx_t *ctx;
	int ret;

	ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
		return -ENOMEM;

	if (arg)
		ctx->arg = *arg;
	else
		set_default_arg(&ctx->arg);

	SSL_library_init();
	SSL_load_error_strings();
	ctx->ssl_ctx = SSL_CTX_new(TLS_server_method());
	if (!ctx->ssl_ctx) {
		ret = -ENOMEM;
		goto out_ctx;
	}

	ret = SSL_CTX_use_certificate_file(ctx->ssl_ctx, ctx->arg.cert_file, SSL_FILETYPE_PEM);
	if (ret <= 0) {
		ret = -EINVAL;
		goto out_ssl_ctx;
	}

	ret = SSL_CTX_use_PrivateKey_file(ctx->ssl_ctx, ctx->arg.key_file, SSL_FILETYPE_PEM);
	if (ret <= 0) {
		ret = -EINVAL;
		goto out_ssl_ctx;
	}

	ret = pm_net_tcp_ctx_init(&ctx->net_ctx, &ctx->arg.net_arg);
	if (ret)
		goto out_ssl_ctx;

	pm_net_tcp_ctx_set_udata(ctx->net_ctx, ctx);
	pm_net_tcp_ctx_set_accept_cb(ctx->net_ctx, &pm_net_ssl_accept_cb);
	*ctx_p = ctx;
	return 0;

out_ssl_ctx:
	SSL_CTX_free(ctx->ssl_ctx);
out_ctx:
	free(ctx);
	return ret;
}

void pm_net_tcp_ssl_ctx_run(pm_net_tcp_ssl_ctx_t *ctx)
{
	pm_net_tcp_ctx_run(ctx->net_ctx);
}

void pm_net_tcp_ssl_ctx_wait(pm_net_tcp_ssl_ctx_t *ctx)
{
	pm_net_tcp_ctx_wait(ctx->net_ctx);
}

void pm_net_tcp_ssl_ctx_stop(pm_net_tcp_ssl_ctx_t *ctx)
{
	pm_net_tcp_ctx_stop(ctx->net_ctx);
}

void pm_net_tcp_ssl_ctx_destroy(pm_net_tcp_ssl_ctx_t *ctx)
{
	pm_net_tcp_ctx_destroy(ctx->net_ctx);
	SSL_CTX_free(ctx->ssl_ctx);
	free(ctx);
}
