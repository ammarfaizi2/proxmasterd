// SPDX-License-Identifier: GPL-2.0-only

#include <proxmasterd/net_ssl.h>
#include <stdio.h>
#include <assert.h>

struct pm_net_ssl_client {
	SSL		*ssl;
	BIO		*rbio;
	BIO		*wbio;
	struct pm_buf	recv_buf;
	struct pm_buf	send_buf;
};

static int pm_net_ssl_client_prep_send(struct pm_net_client *c)
{
	struct pm_net_ssl_client *ssl_c = pm_net_client_get_udata(c);
	struct pm_buf *sbuf = &c->send_buf;
	size_t len;
	char *buf;
	int ret;

	len = sbuf->cap - sbuf->len;
	if (!len) {
		if (pm_buf_resize(sbuf, (sbuf->cap + 1) * 2))
			return -ENOMEM;
		len = sbuf->cap - sbuf->len;
	}

	buf = sbuf->buf + sbuf->len;
	ret = BIO_read(ssl_c->wbio, buf, len);
	if (ret <= 0)
		return -EIO;

	sbuf->len += (size_t)ret;
	return 0;
}

static int recv_cb(struct pm_net_client *c)
{
	struct pm_net_ssl_client *ssl_c = pm_net_client_get_udata(c);
	struct pm_buf *b = &c->recv_buf;
	size_t uret, len;
	char *buf;
	int ret;

	len = b->cap - b->len;
	if (len < 2) {
		if (pm_buf_resize(b, (b->cap + 1) * 2))
			return -ENOMEM;
		len = b->cap - b->len;
	}

	buf = b->buf + b->len;
	ret = SSL_read(ssl_c->ssl, buf, len - 1);
	if (ret <= 0) {
		switch (SSL_get_error(ssl_c->ssl, ret)) {
		case SSL_ERROR_WANT_READ:
			return pm_net_ssl_client_prep_send(c);
		case SSL_ERROR_WANT_WRITE:
			return -EAGAIN;
		default:
			return -EINVAL;
		}
	}

	uret = (size_t)ret;
	if (uret > len)
		return -EINVAL;

	b->len += uret;
	b->buf[b->len] = '\0';
	return 0;
}

static int pm_net_ssl_client_recv_cb(struct pm_net_client *c, ssize_t recv_ret)
{
	struct pm_net_ssl_client *ssl_c = pm_net_client_get_udata(c);
	struct pm_buf *b = &c->recv_buf;
	size_t uret;
	int ret;

	assert(recv_ret > 0);

do_write:
	ret = BIO_write(ssl_c->rbio, b->buf, b->len);
	if (ret <= 0)
		return -EINVAL;

	uret = (size_t)ret;
	if (uret > b->len)
		return -EINVAL;

	if (uret < b->len) {
		memmove(b->buf, b->buf + uret, b->len - uret);
		b->len -= uret;
	} else {
		b->len = 0;
	}

	ret = recv_cb(c);
	if (ret == -EAGAIN && b->len)
		goto do_write;

	return ret;
}

static int pm_net_ssl_client_send_cb(struct pm_net_client *c, ssize_t send_ret)
{
	(void)c;
	(void)send_ret;
	return 0;
}

static int pm_net_ssl_client_close_cb(struct pm_net_client *c)
{
	struct pm_net_ssl_client *ssl_c = pm_net_client_get_udata(c);

	pm_buf_destroy(&ssl_c->recv_buf);
	pm_buf_destroy(&ssl_c->send_buf);
	SSL_free(ssl_c->ssl);
	free(ssl_c);
	return 0;
}

static int pm_net_ssl_accept_cb(struct pm_net_ctx *ctx, struct pm_net_client *c)
{
	struct pm_net_ssl_ctx *ssl_ctx = pm_net_ctx_get_udata(ctx);
	struct pm_net_ssl_client *ssl_c;
	BIO *rbio, *wbio;
	SSL *ssl;

	ssl_c = malloc(sizeof(*ssl_c));
	if (!ssl_c)
		return -ENOMEM;

	rbio = BIO_new(BIO_s_mem());
	if (!rbio)
		goto out;

	wbio = BIO_new(BIO_s_mem());
	if (!wbio)
		goto out_rbio;

	ssl = SSL_new(ssl_ctx->ssl_ctx);
	if (!ssl)
		goto out_wbio;

	if (pm_buf_init(&ssl_c->recv_buf, 4096))
		goto out_ssl;

	if (pm_buf_init(&ssl_c->send_buf, 4096))
		goto out_recv_buf;

	SSL_set_bio(ssl, rbio, wbio);
	SSL_set_accept_state(ssl);

	ssl_c->ssl = ssl;
	ssl_c->rbio = rbio;
	ssl_c->wbio = wbio;

	pm_net_client_set_udata(c, ssl_c);
	pm_net_client_set_recv_cb(c, &pm_net_ssl_client_recv_cb);
	pm_net_client_set_send_cb(c, &pm_net_ssl_client_send_cb);
	pm_net_client_set_close_cb(c, &pm_net_ssl_client_close_cb);
	return 0;

out_recv_buf:
	pm_buf_destroy(&ssl_c->recv_buf);
out_ssl:
	SSL_free(ssl);
out_wbio:
	BIO_free(wbio);
out_rbio:
	BIO_free(rbio);
out:
	free(ssl_c);
	return -ENOMEM;
}

int pm_net_ssl_ctx_init(struct pm_net_ssl_ctx *ctx, const struct pm_net_ssl_ctx_arg *arg)
{
	const char *cert = arg->cert_file;
	const char *key = arg->key_file;
	const SSL_METHOD *method;
	SSL_CTX *ssl_ctx;
	int err;

	SSL_library_init();
	SSL_load_error_strings();
	method = TLS_server_method();
	ssl_ctx = SSL_CTX_new(method);
	if (!ssl_ctx)
		return -ENOMEM;

	if (SSL_CTX_use_certificate_file(ssl_ctx, cert, SSL_FILETYPE_PEM) <= 0) {
		SSL_CTX_free(ssl_ctx);
		return -EINVAL;
	}

	if (SSL_CTX_use_PrivateKey_file(ssl_ctx, key, SSL_FILETYPE_PEM) <= 0) {
		SSL_CTX_free(ssl_ctx);
		return -EINVAL;
	}

	err = pm_net_ctx_init(&ctx->net_ctx, &arg->net_ctx_arg);
	if (err) {
		SSL_CTX_free(ssl_ctx);
		return err;
	}

	pm_net_ctx_set_udata(&ctx->net_ctx, ctx);
	pm_net_ctx_set_accept_cb(&ctx->net_ctx, &pm_net_ssl_accept_cb);
	ctx->ssl_ctx = ssl_ctx;
	return 0;
}

void pm_net_ssl_ctx_run(struct pm_net_ssl_ctx *ctx)
{
	pm_net_ctx_run(&ctx->net_ctx);
}

void pm_net_ssl_ctx_wait(struct pm_net_ssl_ctx *ctx)
{
	pm_net_ctx_wait(&ctx->net_ctx);
}

void pm_net_ssl_ctx_stop(struct pm_net_ssl_ctx *ctx)
{
	pm_net_ctx_stop(&ctx->net_ctx);
}

void pm_net_ssl_ctx_destroy(struct pm_net_ssl_ctx *ctx)
{
	pm_net_ctx_destroy(&ctx->net_ctx);
	SSL_CTX_free(ctx->ssl_ctx);
}
