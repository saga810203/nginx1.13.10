/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef struct ngx_http2_proxy_rewrite_s ngx_http2_proxy_rewrite_t;

typedef ngx_int_t (*ngx_http2_proxy_rewrite_pt)(ngx_http_request_t *r, ngx_table_elt_t *h, size_t prefix, size_t len, ngx_http2_proxy_rewrite_t *pr);

struct ngx_http2_proxy_rewrite_s {
	ngx_http2_proxy_rewrite_pt handler;

	union {
		ngx_http_complex_value_t complex;
	} pattern;

	ngx_http_complex_value_t replacement;
};



typedef struct {
	ngx_array_t *flushes;
	ngx_array_t *lengths;
	ngx_array_t *values;
	ngx_hash_t hash;
} ngx_http2_proxy_headers_t;

typedef struct {
	ngx_http2_upstream_srv_conf_t *srv_conf;

	ngx_array_t *body_flushes;
	ngx_array_t *body_lengths;
	ngx_array_t *body_values;
	ngx_str_t body_source;

	ngx_http2_proxy_headers_t headers;

	ngx_array_t *headers_source;

	ngx_array_t *proxy_lengths;
	ngx_array_t *proxy_values;


	ngx_array_t *cookie_domains;
	ngx_array_t *cookie_paths;


	ngx_str_t location;
	ngx_str_t url;


	ngx_uint_t headers_hash_max_size;
	ngx_uint_t headers_hash_bucket_size;
} ngx_http2_proxy_loc_conf_t;

typedef struct {

	ngx_http_status_t status;
	ngx_http_chunked_t chunked;
	off_t internal_body_length;

	ngx_chain_t *free;
	ngx_chain_t *busy;

	unsigned head :1;
	unsigned internal_chunked :1;
	unsigned header_sent :1;
} ngx_http2_proxy_ctx_t;

static ngx_int_t ngx_http2_proxy_eval(ngx_http_request_t *r, ngx_http2_proxy_ctx_t *ctx, ngx_http2_proxy_loc_conf_t *plcf);

static ngx_int_t ngx_http2_proxy_create_request(ngx_http_request_t *r);
static ngx_int_t ngx_http2_proxy_reinit_request(ngx_http_request_t *r);
static ngx_int_t ngx_http2_proxy_body_output_filter(void *data, ngx_chain_t *in);
static ngx_int_t ngx_http2_proxy_process_status_line(ngx_http_request_t *r);
static ngx_int_t ngx_http2_proxy_process_header(ngx_http_request_t *r);
static ngx_int_t ngx_http2_proxy_input_filter_init(void *data);
static ngx_int_t ngx_http2_proxy_copy_filter(ngx_event_pipe_t *p, ngx_buf_t *buf);
static ngx_int_t ngx_http2_proxy_chunked_filter(ngx_event_pipe_t *p, ngx_buf_t *buf);
static ngx_int_t ngx_http2_proxy_non_buffered_copy_filter(void *data, ssize_t bytes);
static ngx_int_t ngx_http2_proxy_non_buffered_chunked_filter(void *data, ssize_t bytes);
static void ngx_http2_proxy_abort_request(ngx_http_request_t *r);
static void ngx_http2_proxy_finalize_request(ngx_http_request_t *r, ngx_int_t rc);

static ngx_int_t ngx_http2_proxy_host_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http2_proxy_port_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t
ngx_http2_proxy_add_x_forwarded_for_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t
ngx_http2_proxy_internal_body_length_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http2_proxy_internal_chunked_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http2_proxy_rewrite_redirect(ngx_http_request_t *r, ngx_table_elt_t *h, size_t prefix);
static ngx_int_t ngx_http2_proxy_rewrite_cookie(ngx_http_request_t *r, ngx_table_elt_t *h);
static ngx_int_t ngx_http2_proxy_rewrite_cookie_value(ngx_http_request_t *r, ngx_table_elt_t *h, u_char *value, ngx_array_t *rewrites);
static ngx_int_t ngx_http2_proxy_rewrite(ngx_http_request_t *r, ngx_table_elt_t *h, size_t prefix, size_t len, ngx_str_t *replacement);


static void *ngx_http2_proxy_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http2_proxy_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_http2_proxy_init_headers(ngx_conf_t *cf, ngx_http2_proxy_loc_conf_t *conf, ngx_http2_proxy_headers_t *headers,
        ngx_keyval_t *default_headers);

static char *ngx_http2_proxy_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http2_proxy_redirect(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http2_proxy_cookie_domain(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http2_proxy_cookie_path(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http2_proxy_store(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


static char *ngx_http2_proxy_lowat_check(ngx_conf_t *cf, void *post, void *data);

static ngx_int_t ngx_http2_proxy_rewrite_regex(ngx_conf_t *cf, ngx_http2_proxy_rewrite_t *pr, ngx_str_t *regex, ngx_uint_t caseless);




//static ngx_conf_post_t ngx_http2_proxy_lowat_post = { ngx_http2_proxy_lowat_check };

static ngx_conf_bitmask_t ngx_http2_proxy_next_upstream_masks[] = {
		{ ngx_string("error"), NGX_HTTP_UPSTREAM_FT_ERROR },
		{ ngx_string("timeout"),NGX_HTTP_UPSTREAM_FT_TIMEOUT },
		{ ngx_string("invalid_header"), NGX_HTTP_UPSTREAM_FT_INVALID_HEADER },
		{ ngx_string("non_idempotent"), NGX_HTTP_UPSTREAM_FT_NON_IDEMPOTENT },
		{ ngx_string("http_500"), NGX_HTTP_UPSTREAM_FT_HTTP_500 },
		{ ngx_string("http_502"), NGX_HTTP_UPSTREAM_FT_HTTP_502 },
		{ ngx_string("http_503"), NGX_HTTP_UPSTREAM_FT_HTTP_503 },
		{ ngx_string("http_504"), NGX_HTTP_UPSTREAM_FT_HTTP_504 },
		{ ngx_string("http_403"), NGX_HTTP_UPSTREAM_FT_HTTP_403 },
		{ ngx_string("http_404"), NGX_HTTP_UPSTREAM_FT_HTTP_404 },
		{ ngx_string("http_429"), NGX_HTTP_UPSTREAM_FT_HTTP_429 },
		{ ngx_string("updating"), NGX_HTTP_UPSTREAM_FT_UPDATING },
		{ ngx_string("off"), NGX_HTTP_UPSTREAM_FT_OFF },
		{ ngx_null_string, 0 }
};



ngx_module_t ngx_http2_proxy_module;

static ngx_command_t ngx_http2_proxy_commands[] = {

	{ ngx_string("http2_proxy_pass"),
	NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ngx_http2_proxy_pass,
	NGX_HTTP_LOC_CONF_OFFSET, 0,
	NULL },



	{ ngx_string("proxy_cookie_domain"),
	NGX_HTTP_LOC_CONF | NGX_CONF_TAKE12, ngx_http2_proxy_cookie_domain,
	NGX_HTTP_LOC_CONF_OFFSET, 0,
	NULL },

	{ ngx_string("proxy_cookie_path"),
	NGX_HTTP_LOC_CONF | NGX_CONF_TAKE12, ngx_http2_proxy_cookie_path,
	NGX_HTTP_LOC_CONF_OFFSET, 0,
	NULL },


	{ ngx_string("proxy_set_header"),
	NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE2, ngx_conf_set_keyval_slot,
	NGX_HTTP_LOC_CONF_OFFSET, offsetof(ngx_http2_proxy_loc_conf_t, headers_source),
	NULL },

	{ ngx_string("proxy_headers_hash_max_size"),
	NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ngx_conf_set_num_slot,
	NGX_HTTP_LOC_CONF_OFFSET, offsetof(ngx_http2_proxy_loc_conf_t, headers_hash_max_size),
	NULL },

	{ ngx_string("proxy_headers_hash_bucket_size"),
	NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ngx_conf_set_num_slot,
	NGX_HTTP_LOC_CONF_OFFSET, offsetof(ngx_http2_proxy_loc_conf_t, headers_hash_bucket_size),
	NULL },

	{ ngx_string("proxy_set_body"),
	NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ngx_conf_set_str_slot,
	NGX_HTTP_LOC_CONF_OFFSET, offsetof(ngx_http2_proxy_loc_conf_t, body_source),
	NULL },

	ngx_null_command };

static ngx_http_module_t ngx_http2_proxy_module_ctx = {
		NULL, /* preconfiguration */
		NULL, /* postconfiguration */
		NULL, /* create main configuration */
		NULL, /* init main configuration */
		NULL, /* create server configuration */
		NULL, /* merge server configuration */
		ngx_http2_proxy_create_loc_conf, /* create location configuration */
		ngx_http2_proxy_merge_loc_conf /* merge location configuration */
};

ngx_module_t ngx_http2_proxy_module = {
		NGX_MODULE_V1,
		&ngx_http2_proxy_module_ctx, /* module context */
		ngx_http2_proxy_commands, /* module directives */
		NGX_HTTP_MODULE, /* module type */
		NULL, /* init master */
		NULL, /* init module */
		NULL, /* init process */
		NULL, /* init thread */
		NULL, /* exit thread */
		NULL, /* exit process */
		NULL, /* exit master */
		NGX_MODULE_V1_PADDING };




static ngx_str_t ngx_http2_proxy_hide_headers[] = {
	ngx_string("Date"),
	ngx_string("Server"),
	ngx_string("X-Pad"),
	ngx_string("X-Accel-Expires"),
	ngx_string("X-Accel-Redirect"),
	ngx_string("X-Accel-Limit-Rate"),
	ngx_string("X-Accel-Buffering"),
	ngx_string("X-Accel-Charset"),
	ngx_null_string
};



static ngx_int_t ngx_http2_proxy_handler(ngx_http_request_t *r) {
	ngx_int_t rc;
	ngx_http2_stream_t  *stream;
	ngx_http2_proxy_loc_conf_t *plcf;

	if((r->method != NGX_HTTP_GET) &&   (r->method != NGX_HTTP_POST) &&(r->method != NGX_HTTP_PUT) &&(r->method != NGX_HTTP_DELETE)){
		return NGX_HTTP_NOT_ALLOWED;
	}


	if (ngx_http2_upstream_create(r) != NGX_OK) {
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	plcf = ngx_http_get_module_loc_conf(r, ngx_http2_proxy_module);

	stream =(ngx_http2_stream_t*) r->upstream;




	u->create_request = ngx_http2_proxy_create_request;
	u->reinit_request = ngx_http2_proxy_reinit_request;
	u->process_header = ngx_http2_proxy_process_status_line;
	u->abort_request = ngx_http2_proxy_abort_request;
	u->finalize_request = ngx_http2_proxy_finalize_request;
	r->state = 0;

	if (plcf->redirects) {
		u->rewrite_redirect = ngx_http2_proxy_rewrite_redirect;
	}

	if (plcf->cookie_domains || plcf->cookie_paths) {
		u->rewrite_cookie = ngx_http2_proxy_rewrite_cookie;
	}

	u->buffering = plcf->upstream.buffering;

	u->pipe = ngx_pcalloc(r->pool, sizeof(ngx_event_pipe_t));
	if (u->pipe == NULL) {
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	u->pipe->input_filter = ngx_http2_proxy_copy_filter;
	u->pipe->input_ctx = r;

	u->input_filter_init = ngx_http2_proxy_input_filter_init;
	u->input_filter = ngx_http2_proxy_non_buffered_copy_filter;
	u->input_filter_ctx = r;

	u->accel = 1;

	if (!plcf->upstream.request_buffering && plcf->body_values == NULL && plcf->upstream.pass_request_body
	        && (!r->headers_in.chunked || plcf->http_version == NGX_HTTP_VERSION_11)) {
		r->request_body_no_buffering = 1;
	}

	rc = ngx_http_read_client_request_body(r, ngx_http_upstream_init);

	if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
		return rc;
	}

	return NGX_DONE;
}




static ngx_int_t ngx_http2_proxy_create_request(ngx_http_request_t *r) {
	size_t len, uri_len, loc_len, body_len, key_len, val_len;
	uintptr_t escape;
	ngx_buf_t *b;
	ngx_str_t method;
	ngx_uint_t i, unparsed_uri;
	ngx_chain_t *cl, *body;
	ngx_list_part_t *part;
	ngx_table_elt_t *header;
	ngx_http_upstream_t *u;
	ngx_http2_proxy_ctx_t *ctx;
	ngx_http_script_code_pt code;
	ngx_http2_proxy_headers_t *headers;
	ngx_http_script_engine_t e, le;
	ngx_http2_proxy_loc_conf_t *plcf;
	ngx_http_script_len_code_pt lcode;

	u = r->upstream;

	plcf = ngx_http_get_module_loc_conf(r, ngx_http2_proxy_module);


	headers = &plcf->headers;

	if (u->method.len) {
		/* HEAD was changed to GET to cache response */
		method = u->method;

	} else if (plcf->method) {
		if (ngx_http_complex_value(r, plcf->method, &method) != NGX_OK) {
			return NGX_ERROR;
		}

	} else {
		method = r->method_name;
	}

	ctx = ngx_http_get_module_ctx(r, ngx_http2_proxy_module);

	if (method.len == 4 && ngx_strncasecmp(method.data, (u_char *) "HEAD", 4) == 0) {
		ctx->head = 1;
	}

	len = method.len + 1 + sizeof(ngx_http2_proxy_version) - 1 + sizeof(CRLF) - 1;

	escape = 0;
	loc_len = 0;
	unparsed_uri = 0;

	if (plcf->proxy_lengths && ctx->vars.uri.len) {
		uri_len = ctx->vars.uri.len;

	} else if (ctx->vars.uri.len == 0 && r->valid_unparsed_uri) {
		unparsed_uri = 1;
		uri_len = r->unparsed_uri.len;

	} else {
		loc_len = (r->valid_location && ctx->vars.uri.len) ? plcf->location.len : 0;

		if (r->quoted_uri || r->space_in_uri || r->internal) {
			escape = 2 * ngx_escape_uri(NULL, r->uri.data + loc_len, r->uri.len - loc_len, NGX_ESCAPE_URI);
		}

		uri_len = ctx->vars.uri.len + r->uri.len - loc_len + escape + sizeof("?") - 1 + r->args.len;
	}

	if (uri_len == 0) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "zero length URI to proxy");
		return NGX_ERROR;
	}

	len += uri_len;

	ngx_memzero(&le, sizeof(ngx_http_script_engine_t));

	ngx_http_script_flush_no_cacheable_variables(r, plcf->body_flushes);
	ngx_http_script_flush_no_cacheable_variables(r, headers->flushes);

	if (plcf->body_lengths) {
		le.ip = plcf->body_lengths->elts;
		le.request = r;
		le.flushed = 1;
		body_len = 0;

		while (*(uintptr_t *) le.ip) {
			lcode = *(ngx_http_script_len_code_pt *) le.ip;
			body_len += lcode(&le);
		}

		ctx->internal_body_length = body_len;
		len += body_len;

	} else if (r->headers_in.chunked && r->reading_body) {
		ctx->internal_body_length = -1;
		ctx->internal_chunked = 1;

	} else {
		ctx->internal_body_length = r->headers_in.content_length_n;
	}

	le.ip = headers->lengths->elts;
	le.request = r;
	le.flushed = 1;

	while (*(uintptr_t *) le.ip) {

		lcode = *(ngx_http_script_len_code_pt *) le.ip;
		key_len = lcode(&le);

		for (val_len = 0; *(uintptr_t *) le.ip; val_len += lcode(&le)) {
			lcode = *(ngx_http_script_len_code_pt *) le.ip;
		}
		le.ip += sizeof(uintptr_t);

		if (val_len == 0) {
			continue;
		}

		len += key_len + sizeof(": ") - 1 + val_len + sizeof(CRLF) - 1;
	}

	if (plcf->upstream.pass_request_headers) {
		part = &r->headers_in.headers.part;
		header = part->elts;

		for (i = 0; /* void */; i++) {

			if (i >= part->nelts) {
				if (part->next == NULL) {
					break;
				}

				part = part->next;
				header = part->elts;
				i = 0;
			}

			if (ngx_hash_find(&headers->hash, header[i].hash, header[i].lowcase_key, header[i].key.len)) {
				continue;
			}

			len += header[i].key.len + sizeof(": ") - 1 + header[i].value.len + sizeof(CRLF) - 1;
		}
	}

	b = ngx_create_temp_buf(r->pool, len);
	if (b == NULL) {
		return NGX_ERROR;
	}

	cl = ngx_alloc_chain_link(r->pool);
	if (cl == NULL) {
		return NGX_ERROR;
	}

	cl->buf = b;

	/* the request line */

	b->last = ngx_copy(b->last, method.data, method.len);
	*b->last++ = ' ';

	u->uri.data = b->last;

	if (plcf->proxy_lengths && ctx->vars.uri.len) {
		b->last = ngx_copy(b->last, ctx->vars.uri.data, ctx->vars.uri.len);

	} else if (unparsed_uri) {
		b->last = ngx_copy(b->last, r->unparsed_uri.data, r->unparsed_uri.len);

	} else {
		if (r->valid_location) {
			b->last = ngx_copy(b->last, ctx->vars.uri.data, ctx->vars.uri.len);
		}

		if (escape) {
			ngx_escape_uri(b->last, r->uri.data + loc_len, r->uri.len - loc_len, NGX_ESCAPE_URI);
			b->last += r->uri.len - loc_len + escape;

		} else {
			b->last = ngx_copy(b->last, r->uri.data + loc_len,
					r->uri.len - loc_len);
		}

		if (r->args.len > 0) {
			*b->last++ = '?';
			b->last = ngx_copy(b->last, r->args.data, r->args.len);
		}
	}

	u->uri.len = b->last - u->uri.data;

	if (plcf->http_version == NGX_HTTP_VERSION_11) {
		b->last = ngx_cpymem(b->last, ngx_http2_proxy_version_11, sizeof(ngx_http2_proxy_version_11) - 1);

	} else {
		b->last = ngx_cpymem(b->last, ngx_http2_proxy_version, sizeof(ngx_http2_proxy_version) - 1);
	}

	ngx_memzero(&e, sizeof(ngx_http_script_engine_t));

	e.ip = headers->values->elts;
	e.pos = b->last;
	e.request = r;
	e.flushed = 1;

	le.ip = headers->lengths->elts;

	while (*(uintptr_t *) le.ip) {

		lcode = *(ngx_http_script_len_code_pt *) le.ip;
		(void) lcode(&le);

		for (val_len = 0; *(uintptr_t *) le.ip; val_len += lcode(&le)) {
			lcode = *(ngx_http_script_len_code_pt *) le.ip;
		}
		le.ip += sizeof(uintptr_t);

		if (val_len == 0) {
			e.skip = 1;

			while (*(uintptr_t *) e.ip) {
				code = *(ngx_http_script_code_pt *) e.ip;
				code((ngx_http_script_engine_t *) &e);
			}
			e.ip += sizeof(uintptr_t);

			e.skip = 0;

			continue;
		}

		code = *(ngx_http_script_code_pt *) e.ip;
		code((ngx_http_script_engine_t *) &e);

		*e.pos++ = ':';
		*e.pos++ = ' ';

		while (*(uintptr_t *) e.ip) {
			code = *(ngx_http_script_code_pt *) e.ip;
			code((ngx_http_script_engine_t *) &e);
		}
		e.ip += sizeof(uintptr_t);

		*e.pos++ = CR;
		*e.pos++ = LF;
	}

	b->last = e.pos;

	if (plcf->upstream.pass_request_headers) {
		part = &r->headers_in.headers.part;
		header = part->elts;

		for (i = 0; /* void */; i++) {

			if (i >= part->nelts) {
				if (part->next == NULL) {
					break;
				}

				part = part->next;
				header = part->elts;
				i = 0;
			}

			if (ngx_hash_find(&headers->hash, header[i].hash, header[i].lowcase_key, header[i].key.len)) {
				continue;
			}

			b->last = ngx_copy(b->last, header[i].key.data, header[i].key.len);

			*b->last++ = ':';
			*b->last++ = ' ';

			b->last = ngx_copy(b->last, header[i].value.data,
					header[i].value.len);

			*b->last++ = CR;
			*b->last++ = LF;

			ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
					"http proxy header: \"%V: %V\"",
					&header[i].key, &header[i].value);
		}
	}

	/* add "\r\n" at the header end */
	*b->last++ = CR;
	*b->last++ = LF;

	if (plcf->body_values) {
		e.ip = plcf->body_values->elts;
		e.pos = b->last;
		e.skip = 0;

		while (*(uintptr_t *) e.ip) {
			code = *(ngx_http_script_code_pt *) e.ip;
			code((ngx_http_script_engine_t *) &e);
		}

		b->last = e.pos;
	}

	ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
			"http proxy header:%N\"%*s\"",
			(size_t) (b->last - b->pos), b->pos);

	if (r->request_body_no_buffering) {

		u->request_bufs = cl;

		if (ctx->internal_chunked) {
			u->output.output_filter = ngx_http2_proxy_body_output_filter;
			u->output.filter_ctx = r;
		}

	} else if (plcf->body_values == NULL && plcf->upstream.pass_request_body) {

		body = u->request_bufs;
		u->request_bufs = cl;

		while (body) {
			b = ngx_alloc_buf(r->pool);
			if (b == NULL) {
				return NGX_ERROR;
			}

			ngx_memcpy(b, body->buf, sizeof(ngx_buf_t));

			cl->next = ngx_alloc_chain_link(r->pool);
			if (cl->next == NULL) {
				return NGX_ERROR;
			}

			cl = cl->next;
			cl->buf = b;

			body = body->next;
		}

	} else {
		u->request_bufs = cl;
	}

	b->flush = 1;
	cl->next = NULL;

	return NGX_OK;
}

static ngx_int_t ngx_http2_proxy_reinit_request(ngx_http_request_t *r) {
	ngx_http2_proxy_ctx_t *ctx;

	ctx = ngx_http_get_module_ctx(r, ngx_http2_proxy_module);

	if (ctx == NULL) {
		return NGX_OK;
	}

	ctx->status.code = 0;
	ctx->status.count = 0;
	ctx->status.start = NULL;
	ctx->status.end = NULL;
	ctx->chunked.state = 0;

	r->upstream->process_header = ngx_http2_proxy_process_status_line;
	r->upstream->pipe->input_filter = ngx_http2_proxy_copy_filter;
	r->upstream->input_filter = ngx_http2_proxy_non_buffered_copy_filter;
	r->state = 0;

	return NGX_OK;
}

static ngx_int_t ngx_http2_proxy_body_output_filter(void *data, ngx_chain_t *in) {
	ngx_http_request_t *r = data;

	off_t size;
	u_char *chunk;
	ngx_int_t rc;
	ngx_buf_t *b;
	ngx_chain_t *out, *cl, *tl, **ll, **fl;
	ngx_http2_proxy_ctx_t *ctx;

	ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
			"proxy output filter");

	ctx = ngx_http_get_module_ctx(r, ngx_http2_proxy_module);

	if (in == NULL) {
		out = in;
		goto out;
	}

	out = NULL;
	ll = &out;

	if (!ctx->header_sent) {
		/* first buffer contains headers, pass it unmodified */

		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
				"proxy output header");

		ctx->header_sent = 1;

		tl = ngx_alloc_chain_link(r->pool);
		if (tl == NULL) {
			return NGX_ERROR;
		}

		tl->buf = in->buf;
		*ll = tl;
		ll = &tl->next;

		in = in->next;

		if (in == NULL) {
			tl->next = NULL;
			goto out;
		}
	}

	size = 0;
	cl = in;
	fl = ll;

	for (;;) {
		ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
				"proxy output chunk: %O", ngx_buf_size(cl->buf));

		size += ngx_buf_size(cl->buf);

		if (cl->buf->flush || cl->buf->sync || ngx_buf_in_memory(cl->buf) || cl->buf->in_file) {
			tl = ngx_alloc_chain_link(r->pool);
			if (tl == NULL) {
				return NGX_ERROR;
			}

			tl->buf = cl->buf;
			*ll = tl;
			ll = &tl->next;
		}

		if (cl->next == NULL) {
			break;
		}

		cl = cl->next;
	}

	if (size) {
		tl = ngx_chain_get_free_buf(r->pool, &ctx->free);
		if (tl == NULL) {
			return NGX_ERROR;
		}

		b = tl->buf;
		chunk = b->start;

		if (chunk == NULL) {
			/* the "0000000000000000" is 64-bit hexadecimal string */

			chunk = ngx_palloc(r->pool, sizeof("0000000000000000" CRLF) - 1);
			if (chunk == NULL) {
				return NGX_ERROR;
			}

			b->start = chunk;
			b->end = chunk + sizeof("0000000000000000" CRLF) - 1;
		}

		b->tag = (ngx_buf_tag_t) &ngx_http2_proxy_body_output_filter;
		b->memory = 0;
		b->temporary = 1;
		b->pos = chunk;
		b->last = ngx_sprintf(chunk, "%xO" CRLF, size);

		tl->next = *fl;
		*fl = tl;
	}

	if (cl->buf->last_buf) {
		tl = ngx_chain_get_free_buf(r->pool, &ctx->free);
		if (tl == NULL) {
			return NGX_ERROR;
		}

		b = tl->buf;

		b->tag = (ngx_buf_tag_t) &ngx_http2_proxy_body_output_filter;
		b->temporary = 0;
		b->memory = 1;
		b->last_buf = 1;
		b->pos = (u_char *) CRLF "0" CRLF CRLF;
		b->last = b->pos + 7;

		cl->buf->last_buf = 0;

		*ll = tl;

		if (size == 0) {
			b->pos += 2;
		}

	} else if (size > 0) {
		tl = ngx_chain_get_free_buf(r->pool, &ctx->free);
		if (tl == NULL) {
			return NGX_ERROR;
		}

		b = tl->buf;

		b->tag = (ngx_buf_tag_t) &ngx_http2_proxy_body_output_filter;
		b->temporary = 0;
		b->memory = 1;
		b->pos = (u_char *) CRLF;
		b->last = b->pos + 2;

		*ll = tl;

	} else {
		*ll = NULL;
	}

	out:

	rc = ngx_chain_writer(&r->upstream->writer, out);

	ngx_chain_update_chains(r->pool, &ctx->free, &ctx->busy, &out, (ngx_buf_tag_t) &ngx_http2_proxy_body_output_filter);

	return rc;
}

static ngx_int_t ngx_http2_proxy_process_status_line(ngx_http_request_t *r) {
	size_t len;
	ngx_int_t rc;
	ngx_http_upstream_t *u;
	ngx_http2_proxy_ctx_t *ctx;

	ctx = ngx_http_get_module_ctx(r, ngx_http2_proxy_module);

	if (ctx == NULL) {
		return NGX_ERROR;
	}

	u = r->upstream;

	rc = ngx_http_parse_status_line(r, &u->buffer, &ctx->status);

	if (rc == NGX_AGAIN) {
		return rc;
	}

	if (rc == NGX_ERROR) {

#if (NGX_HTTP_CACHE)

		if (r->cache) {
			r->http_version = NGX_HTTP_VERSION_9;
			return NGX_OK;
		}

#endif

		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "upstream sent no valid HTTP/1.0 header");

#if 0
		if (u->accel) {
			return NGX_HTTP_UPSTREAM_INVALID_HEADER;
		}
#endif

		r->http_version = NGX_HTTP_VERSION_9;
		u->state->status = NGX_HTTP_OK;
		u->headers_in.connection_close = 1;

		return NGX_OK;
	}

	if (u->state && u->state->status == 0) {
		u->state->status = ctx->status.code;
	}

	u->headers_in.status_n = ctx->status.code;

	len = ctx->status.end - ctx->status.start;
	u->headers_in.status_line.len = len;

	u->headers_in.status_line.data = ngx_pnalloc(r->pool, len);
	if (u->headers_in.status_line.data == NULL) {
		return NGX_ERROR;
	}

	ngx_memcpy(u->headers_in.status_line.data, ctx->status.start, len);

	ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
			"http proxy status %ui \"%V\"",
			u->headers_in.status_n, &u->headers_in.status_line);

	if (ctx->status.http_version < NGX_HTTP_VERSION_11) {
		u->headers_in.connection_close = 1;
	}

	u->process_header = ngx_http2_proxy_process_header;

	return ngx_http2_proxy_process_header(r);
}

static ngx_int_t ngx_http2_proxy_process_header(ngx_http_request_t *r) {
	ngx_int_t rc;
	ngx_table_elt_t *h;
	ngx_http_upstream_t *u;
	ngx_http2_proxy_ctx_t *ctx;
	ngx_http_upstream_header_t *hh;
	ngx_http_upstream_main_conf_t *umcf;

	umcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);

	for (;;) {

		rc = ngx_http_parse_header_line(r, &r->upstream->buffer, 1);

		if (rc == NGX_OK) {

			/* a header line has been parsed successfully */

			h = ngx_list_push(&r->upstream->headers_in.headers);
			if (h == NULL) {
				return NGX_ERROR;
			}

			h->hash = r->header_hash;

			h->key.len = r->header_name_end - r->header_name_start;
			h->value.len = r->header_end - r->header_start;

			h->key.data = ngx_pnalloc(r->pool, h->key.len + 1 + h->value.len + 1 + h->key.len);
			if (h->key.data == NULL) {
				h->hash = 0;
				return NGX_ERROR;
			}

			h->value.data = h->key.data + h->key.len + 1;
			h->lowcase_key = h->key.data + h->key.len + 1 + h->value.len + 1;

			ngx_memcpy(h->key.data, r->header_name_start, h->key.len);
			h->key.data[h->key.len] = '\0';
			ngx_memcpy(h->value.data, r->header_start, h->value.len);
			h->value.data[h->value.len] = '\0';

			if (h->key.len == r->lowcase_index) {
				ngx_memcpy(h->lowcase_key, r->lowcase_header, h->key.len);

			} else {
				ngx_strlow(h->lowcase_key, h->key.data, h->key.len);
			}

			hh = ngx_hash_find(&umcf->headers_in_hash, h->hash, h->lowcase_key, h->key.len);

			if (hh && hh->handler(r, h, hh->offset) != NGX_OK) {
				return NGX_ERROR;
			}

			ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
					"http proxy header: \"%V: %V\"",
					&h->key, &h->value);

			continue;
		}

		if (rc == NGX_HTTP_PARSE_HEADER_DONE) {

			/* a whole header has been parsed successfully */

			ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
					"http proxy header done");

			/*
			 * if no "Server" and "Date" in header line,
			 * then add the special empty headers
			 */

			if (r->upstream->headers_in.server == NULL) {
				h = ngx_list_push(&r->upstream->headers_in.headers);
				if (h == NULL) {
					return NGX_ERROR;
				}

				h->hash = ngx_hash(ngx_hash(ngx_hash(ngx_hash( ngx_hash('s', 'e'), 'r'), 'v'), 'e'), 'r');

				ngx_str_set(&h->key, "Server");
				ngx_str_null(&h->value);
				h->lowcase_key = (u_char *) "server";
			}

			if (r->upstream->headers_in.date == NULL) {
				h = ngx_list_push(&r->upstream->headers_in.headers);
				if (h == NULL) {
					return NGX_ERROR;
				}

				h->hash = ngx_hash(ngx_hash(ngx_hash('d', 'a'), 't'), 'e');

				ngx_str_set(&h->key, "Date");
				ngx_str_null(&h->value);
				h->lowcase_key = (u_char *) "date";
			}

			/* clear content length if response is chunked */

			u = r->upstream;

			if (u->headers_in.chunked) {
				u->headers_in.content_length_n = -1;
			}

			/*
			 * set u->keepalive if response has no body; this allows to keep
			 * connections alive in case of r->header_only or X-Accel-Redirect
			 */

			ctx = ngx_http_get_module_ctx(r, ngx_http2_proxy_module);

			if (u->headers_in.status_n == NGX_HTTP_NO_CONTENT || u->headers_in.status_n == NGX_HTTP_NOT_MODIFIED || ctx->head
			        || (!u->headers_in.chunked && u->headers_in.content_length_n == 0)) {
				u->keepalive = !u->headers_in.connection_close;
			}

			if (u->headers_in.status_n == NGX_HTTP_SWITCHING_PROTOCOLS) {
				u->keepalive = 0;

				if (r->headers_in.upgrade) {
					u->upgrade = 1;
				}
			}

			return NGX_OK;
		}

		if (rc == NGX_AGAIN) {
			return NGX_AGAIN;
		}

		/* there was error while a header line parsing */

		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "upstream sent invalid header");

		return NGX_HTTP_UPSTREAM_INVALID_HEADER;
	}
}

static ngx_int_t ngx_http2_proxy_input_filter_init(void *data) {
	ngx_http_request_t *r = data;
	ngx_http_upstream_t *u;
	ngx_http2_proxy_ctx_t *ctx;

	u = r->upstream;
	ctx = ngx_http_get_module_ctx(r, ngx_http2_proxy_module);

	if (ctx == NULL) {
		return NGX_ERROR;
	}

	ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
			"http proxy filter init s:%ui h:%d c:%d l:%O",
			u->headers_in.status_n, ctx->head, u->headers_in.chunked,
			u->headers_in.content_length_n);

	/* as per RFC2616, 4.4 Message Length */

	if (u->headers_in.status_n == NGX_HTTP_NO_CONTENT || u->headers_in.status_n == NGX_HTTP_NOT_MODIFIED || ctx->head) {
		/* 1xx, 204, and 304 and replies to HEAD requests */
		/* no 1xx since we don't send Expect and Upgrade */

		u->pipe->length = 0;
		u->length = 0;
		u->keepalive = !u->headers_in.connection_close;

	} else if (u->headers_in.chunked) {
		/* chunked */

		u->pipe->input_filter = ngx_http2_proxy_chunked_filter;
		u->pipe->length = 3; /* "0" LF LF */

		u->input_filter = ngx_http2_proxy_non_buffered_chunked_filter;
		u->length = 1;

	} else if (u->headers_in.content_length_n == 0) {
		/* empty body: special case as filter won't be called */

		u->pipe->length = 0;
		u->length = 0;
		u->keepalive = !u->headers_in.connection_close;

	} else {
		/* content length or connection close */

		u->pipe->length = u->headers_in.content_length_n;
		u->length = u->headers_in.content_length_n;
	}

	return NGX_OK;
}

static ngx_int_t ngx_http2_proxy_copy_filter(ngx_event_pipe_t *p, ngx_buf_t *buf) {
	ngx_buf_t *b;
	ngx_chain_t *cl;
	ngx_http_request_t *r;

	if (buf->pos == buf->last) {
		return NGX_OK;
	}

	cl = ngx_chain_get_free_buf(p->pool, &p->free);
	if (cl == NULL) {
		return NGX_ERROR;
	}

	b = cl->buf;

	ngx_memcpy(b, buf, sizeof(ngx_buf_t));
	b->shadow = buf;
	b->tag = p->tag;
	b->last_shadow = 1;
	b->recycled = 1;
	buf->shadow = b;

	ngx_log_debug1(NGX_LOG_DEBUG_EVENT, p->log, 0, "input buf #%d", b->num);

	if (p->in) {
		*p->last_in = cl;
	} else {
		p->in = cl;
	}
	p->last_in = &cl->next;

	if (p->length == -1) {
		return NGX_OK;
	}

	p->length -= b->last - b->pos;

	if (p->length == 0) {
		r = p->input_ctx;
		p->upstream_done = 1;
		r->upstream->keepalive = !r->upstream->headers_in.connection_close;

	} else if (p->length < 0) {
		r = p->input_ctx;
		p->upstream_done = 1;

		ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "upstream sent more data than specified in "
				"\"Content-Length\" header");
	}

	return NGX_OK;
}

static ngx_int_t ngx_http2_proxy_chunked_filter(ngx_event_pipe_t *p, ngx_buf_t *buf) {
	ngx_int_t rc;
	ngx_buf_t *b, **prev;
	ngx_chain_t *cl;
	ngx_http_request_t *r;
	ngx_http2_proxy_ctx_t *ctx;

	if (buf->pos == buf->last) {
		return NGX_OK;
	}

	r = p->input_ctx;
	ctx = ngx_http_get_module_ctx(r, ngx_http2_proxy_module);

	if (ctx == NULL) {
		return NGX_ERROR;
	}

	b = NULL;
	prev = &buf->shadow;

	for (;;) {

		rc = ngx_http_parse_chunked(r, buf, &ctx->chunked);

		if (rc == NGX_OK) {

			/* a chunk has been parsed successfully */

			cl = ngx_chain_get_free_buf(p->pool, &p->free);
			if (cl == NULL) {
				return NGX_ERROR;
			}

			b = cl->buf;

			ngx_memzero(b, sizeof(ngx_buf_t));

			b->pos = buf->pos;
			b->start = buf->start;
			b->end = buf->end;
			b->tag = p->tag;
			b->temporary = 1;
			b->recycled = 1;

			*prev = b;
			prev = &b->shadow;

			if (p->in) {
				*p->last_in = cl;
			} else {
				p->in = cl;
			}
			p->last_in = &cl->next;

			/* STUB */b->num = buf->num;

			ngx_log_debug2(NGX_LOG_DEBUG_EVENT, p->log, 0,
					"input buf #%d %p", b->num, b->pos);

			if (buf->last - buf->pos >= ctx->chunked.size) {

				buf->pos += (size_t) ctx->chunked.size;
				b->last = buf->pos;
				ctx->chunked.size = 0;

				continue;
			}

			ctx->chunked.size -= buf->last - buf->pos;
			buf->pos = buf->last;
			b->last = buf->last;

			continue;
		}

		if (rc == NGX_DONE) {

			/* a whole response has been parsed successfully */

			p->upstream_done = 1;
			r->upstream->keepalive = !r->upstream->headers_in.connection_close;

			break;
		}

		if (rc == NGX_AGAIN) {

			/* set p->length, minimal amount of data we want to see */

			p->length = ctx->chunked.length;

			break;
		}

		/* invalid response */

		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "upstream sent invalid chunked response");

		return NGX_ERROR;
	}

	ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
			"http proxy chunked state %ui, length %O",
			ctx->chunked.state, p->length);

	if (b) {
		b->shadow = buf;
		b->last_shadow = 1;

		ngx_log_debug2(NGX_LOG_DEBUG_EVENT, p->log, 0,
				"input buf %p %z", b->pos, b->last - b->pos);

		return NGX_OK;
	}

	/* there is no data record in the buf, add it to free chain */

	if (ngx_event_pipe_add_free_buf(p, buf) != NGX_OK) {
		return NGX_ERROR;
	}

	return NGX_OK;
}

static ngx_int_t ngx_http2_proxy_non_buffered_copy_filter(void *data, ssize_t bytes) {
	ngx_http_request_t *r = data;

	ngx_buf_t *b;
	ngx_chain_t *cl, **ll;
	ngx_http_upstream_t *u;

	u = r->upstream;

	for (cl = u->out_bufs, ll = &u->out_bufs; cl; cl = cl->next) {
		ll = &cl->next;
	}

	cl = ngx_chain_get_free_buf(r->pool, &u->free_bufs);
	if (cl == NULL) {
		return NGX_ERROR;
	}

	*ll = cl;

	cl->buf->flush = 1;
	cl->buf->memory = 1;

	b = &u->buffer;

	cl->buf->pos = b->last;
	b->last += bytes;
	cl->buf->last = b->last;
	cl->buf->tag = u->output.tag;

	if (u->length == -1) {
		return NGX_OK;
	}

	u->length -= bytes;

	if (u->length == 0) {
		u->keepalive = !u->headers_in.connection_close;
	}

	return NGX_OK;
}

static ngx_int_t ngx_http2_proxy_non_buffered_chunked_filter(void *data, ssize_t bytes) {
	ngx_http_request_t *r = data;

	ngx_int_t rc;
	ngx_buf_t *b, *buf;
	ngx_chain_t *cl, **ll;
	ngx_http_upstream_t *u;
	ngx_http2_proxy_ctx_t *ctx;

	ctx = ngx_http_get_module_ctx(r, ngx_http2_proxy_module);

	if (ctx == NULL) {
		return NGX_ERROR;
	}

	u = r->upstream;
	buf = &u->buffer;

	buf->pos = buf->last;
	buf->last += bytes;

	for (cl = u->out_bufs, ll = &u->out_bufs; cl; cl = cl->next) {
		ll = &cl->next;
	}

	for (;;) {

		rc = ngx_http_parse_chunked(r, buf, &ctx->chunked);

		if (rc == NGX_OK) {

			/* a chunk has been parsed successfully */

			cl = ngx_chain_get_free_buf(r->pool, &u->free_bufs);
			if (cl == NULL) {
				return NGX_ERROR;
			}

			*ll = cl;
			ll = &cl->next;

			b = cl->buf;

			b->flush = 1;
			b->memory = 1;

			b->pos = buf->pos;
			b->tag = u->output.tag;

			if (buf->last - buf->pos >= ctx->chunked.size) {
				buf->pos += (size_t) ctx->chunked.size;
				b->last = buf->pos;
				ctx->chunked.size = 0;

			} else {
				ctx->chunked.size -= buf->last - buf->pos;
				buf->pos = buf->last;
				b->last = buf->last;
			}

			ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
					"http proxy out buf %p %z",
					b->pos, b->last - b->pos);

			continue;
		}

		if (rc == NGX_DONE) {

			/* a whole response has been parsed successfully */

			u->keepalive = !u->headers_in.connection_close;
			u->length = 0;

			break;
		}

		if (rc == NGX_AGAIN) {
			break;
		}

		/* invalid response */

		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "upstream sent invalid chunked response");

		return NGX_ERROR;
	}

	return NGX_OK;
}

static void ngx_http2_proxy_abort_request(ngx_http_request_t *r) {
	ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
			"abort http proxy request");

	return;
}

static void ngx_http2_proxy_finalize_request(ngx_http_request_t *r, ngx_int_t rc) {
	ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
			"finalize http proxy request");

	return;
}

static ngx_int_t ngx_http2_proxy_host_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
	ngx_http2_proxy_ctx_t *ctx;

	ctx = ngx_http_get_module_ctx(r, ngx_http2_proxy_module);

	if (ctx == NULL) {
		v->not_found = 1;
		return NGX_OK;
	}

	v->len = ctx->vars.host_header.len;
	v->valid = 1;
	v->no_cacheable = 0;
	v->not_found = 0;
	v->data = ctx->vars.host_header.data;

	return NGX_OK;
}

static ngx_int_t ngx_http2_proxy_port_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
	ngx_http2_proxy_ctx_t *ctx;

	ctx = ngx_http_get_module_ctx(r, ngx_http2_proxy_module);

	if (ctx == NULL) {
		v->not_found = 1;
		return NGX_OK;
	}

	v->len = ctx->vars.port.len;
	v->valid = 1;
	v->no_cacheable = 0;
	v->not_found = 0;
	v->data = ctx->vars.port.data;

	return NGX_OK;
}

static ngx_int_t ngx_http2_proxy_add_x_forwarded_for_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
	size_t len;
	u_char *p;
	ngx_uint_t i, n;
	ngx_table_elt_t **h;

	v->valid = 1;
	v->no_cacheable = 0;
	v->not_found = 0;

	n = r->headers_in.x_forwarded_for.nelts;
	h = r->headers_in.x_forwarded_for.elts;

	len = 0;

	for (i = 0; i < n; i++) {
		len += h[i]->value.len + sizeof(", ") - 1;
	}

	if (len == 0) {
		v->len = r->connection->addr_text.len;
		v->data = r->connection->addr_text.data;
		return NGX_OK;
	}

	len += r->connection->addr_text.len;

	p = ngx_pnalloc(r->pool, len);
	if (p == NULL) {
		return NGX_ERROR;
	}

	v->len = len;
	v->data = p;

	for (i = 0; i < n; i++) {
		p = ngx_copy(p, h[i]->value.data, h[i]->value.len);
		*p++ = ',';
		*p++ = ' ';
	}

	ngx_memcpy(p, r->connection->addr_text.data, r->connection->addr_text.len);

	return NGX_OK;
}

static ngx_int_t ngx_http2_proxy_internal_body_length_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
	ngx_http2_proxy_ctx_t *ctx;

	ctx = ngx_http_get_module_ctx(r, ngx_http2_proxy_module);

	if (ctx == NULL || ctx->internal_body_length < 0) {
		v->not_found = 1;
		return NGX_OK;
	}

	v->valid = 1;
	v->no_cacheable = 0;
	v->not_found = 0;

	v->data = ngx_pnalloc(r->pool, NGX_OFF_T_LEN);

	if (v->data == NULL) {
		return NGX_ERROR;
	}

	v->len = ngx_sprintf(v->data, "%O", ctx->internal_body_length) - v->data;

	return NGX_OK;
}

static ngx_int_t ngx_http2_proxy_internal_chunked_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
	ngx_http2_proxy_ctx_t *ctx;

	ctx = ngx_http_get_module_ctx(r, ngx_http2_proxy_module);

	if (ctx == NULL || !ctx->internal_chunked) {
		v->not_found = 1;
		return NGX_OK;
	}

	v->valid = 1;
	v->no_cacheable = 0;
	v->not_found = 0;

	v->data = (u_char *) "chunked";
	v->len = sizeof("chunked") - 1;

	return NGX_OK;
}

static ngx_int_t ngx_http2_proxy_rewrite_redirect(ngx_http_request_t *r, ngx_table_elt_t *h, size_t prefix) {
	size_t len;
	ngx_int_t rc;
	ngx_uint_t i;
	ngx_http2_proxy_rewrite_t *pr;
	ngx_http2_proxy_loc_conf_t *plcf;

	plcf = ngx_http_get_module_loc_conf(r, ngx_http2_proxy_module);

	pr = plcf->redirects->elts;

	if (pr == NULL) {
		return NGX_DECLINED;
	}

	len = h->value.len - prefix;

	for (i = 0; i < plcf->redirects->nelts; i++) {
		rc = pr[i].handler(r, h, prefix, len, &pr[i]);

		if (rc != NGX_DECLINED) {
			return rc;
		}
	}

	return NGX_DECLINED;
}

static ngx_int_t ngx_http2_proxy_rewrite_cookie(ngx_http_request_t *r, ngx_table_elt_t *h) {
	size_t prefix;
	u_char *p;
	ngx_int_t rc, rv;
	ngx_http2_proxy_loc_conf_t *plcf;

	p = (u_char *) ngx_strchr(h->value.data, ';');
	if (p == NULL) {
		return NGX_DECLINED;
	}

	prefix = p + 1 - h->value.data;

	rv = NGX_DECLINED;

	plcf = ngx_http_get_module_loc_conf(r, ngx_http2_proxy_module);

	if (plcf->cookie_domains) {
		p = ngx_strcasestrn(h->value.data + prefix, "domain=", 7 - 1);

		if (p) {
			rc = ngx_http2_proxy_rewrite_cookie_value(r, h, p + 7, plcf->cookie_domains);
			if (rc == NGX_ERROR) {
				return NGX_ERROR;
			}

			if (rc != NGX_DECLINED) {
				rv = rc;
			}
		}
	}

	if (plcf->cookie_paths) {
		p = ngx_strcasestrn(h->value.data + prefix, "path=", 5 - 1);

		if (p) {
			rc = ngx_http2_proxy_rewrite_cookie_value(r, h, p + 5, plcf->cookie_paths);
			if (rc == NGX_ERROR) {
				return NGX_ERROR;
			}

			if (rc != NGX_DECLINED) {
				rv = rc;
			}
		}
	}

	return rv;
}

static ngx_int_t ngx_http2_proxy_rewrite_cookie_value(ngx_http_request_t *r, ngx_table_elt_t *h, u_char *value, ngx_array_t *rewrites) {
	size_t len, prefix;
	u_char *p;
	ngx_int_t rc;
	ngx_uint_t i;
	ngx_http2_proxy_rewrite_t *pr;

	prefix = value - h->value.data;

	p = (u_char *) ngx_strchr(value, ';');

	len = p ? (size_t) (p - value) : (h->value.len - prefix);

	pr = rewrites->elts;

	for (i = 0; i < rewrites->nelts; i++) {
		rc = pr[i].handler(r, h, prefix, len, &pr[i]);

		if (rc != NGX_DECLINED) {
			return rc;
		}
	}

	return NGX_DECLINED;
}

static ngx_int_t ngx_http2_proxy_rewrite_complex_handler(ngx_http_request_t *r, ngx_table_elt_t *h, size_t prefix, size_t len, ngx_http2_proxy_rewrite_t *pr) {
	ngx_str_t pattern, replacement;

	if (ngx_http_complex_value(r, &pr->pattern.complex, &pattern) != NGX_OK) {
		return NGX_ERROR;
	}

	if (pattern.len > len || ngx_rstrncmp(h->value.data + prefix, pattern.data, pattern.len) != 0) {
		return NGX_DECLINED;
	}

	if (ngx_http_complex_value(r, &pr->replacement, &replacement) != NGX_OK) {
		return NGX_ERROR;
	}

	return ngx_http2_proxy_rewrite(r, h, prefix, pattern.len, &replacement);
}

#if (NGX_PCRE)

static ngx_int_t ngx_http2_proxy_rewrite_regex_handler(ngx_http_request_t *r, ngx_table_elt_t *h, size_t prefix, size_t len, ngx_http2_proxy_rewrite_t *pr) {
	ngx_str_t pattern, replacement;

	pattern.len = len;
	pattern.data = h->value.data + prefix;

	if (ngx_http_regex_exec(r, pr->pattern.regex, &pattern) != NGX_OK) {
		return NGX_DECLINED;
	}

	if (ngx_http_complex_value(r, &pr->replacement, &replacement) != NGX_OK) {
		return NGX_ERROR;
	}

	if (prefix == 0 && h->value.len == len) {
		h->value = replacement;
		return NGX_OK;
	}

	return ngx_http2_proxy_rewrite(r, h, prefix, len, &replacement);
}

#endif

static ngx_int_t ngx_http2_proxy_rewrite_domain_handler(ngx_http_request_t *r, ngx_table_elt_t *h, size_t prefix, size_t len, ngx_http2_proxy_rewrite_t *pr) {
	u_char *p;
	ngx_str_t pattern, replacement;

	if (ngx_http_complex_value(r, &pr->pattern.complex, &pattern) != NGX_OK) {
		return NGX_ERROR;
	}

	p = h->value.data + prefix;

	if (p[0] == '.') {
		p++;
		prefix++;
		len--;
	}

	if (pattern.len != len || ngx_rstrncasecmp(pattern.data, p, len) != 0) {
		return NGX_DECLINED;
	}

	if (ngx_http_complex_value(r, &pr->replacement, &replacement) != NGX_OK) {
		return NGX_ERROR;
	}

	return ngx_http2_proxy_rewrite(r, h, prefix, len, &replacement);
}

static ngx_int_t ngx_http2_proxy_rewrite(ngx_http_request_t *r, ngx_table_elt_t *h, size_t prefix, size_t len, ngx_str_t *replacement) {
	u_char *p, *data;
	size_t new_len;

	new_len = replacement->len + h->value.len - len;

	if (replacement->len > len) {

		data = ngx_pnalloc(r->pool, new_len + 1);
		if (data == NULL) {
			return NGX_ERROR;
		}

		p = ngx_copy(data, h->value.data, prefix);
		p = ngx_copy(p, replacement->data, replacement->len);

		ngx_memcpy(p, h->value.data + prefix + len, h->value.len - len - prefix + 1);

		h->value.data = data;

	} else {
		p = ngx_copy(h->value.data + prefix, replacement->data,
				replacement->len);

		ngx_memmove(p, h->value.data + prefix + len, h->value.len - len - prefix + 1);
	}

	h->value.len = new_len;

	return NGX_OK;
}





static void *
ngx_http2_proxy_create_loc_conf(ngx_conf_t *cf) {
	ngx_http2_proxy_loc_conf_t *conf;

	conf = ngx_pcalloc(cf->pool, sizeof(ngx_http2_proxy_loc_conf_t));
	if (conf == NULL) {
		return NULL;
	}
	conf->redirect = NGX_CONF_UNSET;
	conf->upstream.change_buffering = 1;

	conf->cookie_domains = NGX_CONF_UNSET_PTR;
	conf->cookie_paths = NGX_CONF_UNSET_PTR;



	conf->headers_hash_max_size = NGX_CONF_UNSET_UINT;
	conf->headers_hash_bucket_size = NGX_CONF_UNSET_UINT;



	return conf;
}

static char *
ngx_http2_proxy_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
	ngx_http2_proxy_loc_conf_t *prev = parent;
	ngx_http2_proxy_loc_conf_t *conf = child;

	u_char *p;
	size_t size;
	ngx_int_t rc;
	ngx_hash_init_t hash;
	ngx_http_core_loc_conf_t *clcf;
	ngx_http2_proxy_rewrite_t *pr;
	ngx_http_script_compile_t sc;




	ngx_conf_merge_uint_value(conf->upstream.store_access, prev->upstream.store_access, 0600);

	ngx_conf_merge_uint_value(conf->upstream.next_upstream_tries, prev->upstream.next_upstream_tries, 0);

	ngx_conf_merge_value(conf->upstream.buffering, prev->upstream.buffering, 1);

	ngx_conf_merge_value(conf->upstream.request_buffering, prev->upstream.request_buffering, 1);

	ngx_conf_merge_value(conf->upstream.ignore_client_abort, prev->upstream.ignore_client_abort, 0);

	ngx_conf_merge_value(conf->upstream.force_ranges, prev->upstream.force_ranges, 0);

	ngx_conf_merge_ptr_value(conf->upstream.local, prev->upstream.local, NULL);

	ngx_conf_merge_msec_value(conf->upstream.connect_timeout, prev->upstream.connect_timeout, 60000);

	ngx_conf_merge_msec_value(conf->upstream.send_timeout, prev->upstream.send_timeout, 60000);

	ngx_conf_merge_msec_value(conf->upstream.read_timeout, prev->upstream.read_timeout, 60000);

	ngx_conf_merge_msec_value(conf->upstream.next_upstream_timeout, prev->upstream.next_upstream_timeout, 0);

	ngx_conf_merge_size_value(conf->upstream.send_lowat, prev->upstream.send_lowat, 0);

	ngx_conf_merge_size_value(conf->upstream.buffer_size, prev->upstream.buffer_size, (size_t ) ngx_pagesize);

	ngx_conf_merge_size_value(conf->upstream.limit_rate, prev->upstream.limit_rate, 0);

	ngx_conf_merge_bufs_value(conf->upstream.bufs, prev->upstream.bufs, 8, ngx_pagesize);

	if (conf->upstream.bufs.num < 2) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "there must be at least 2 \"proxy_buffers\"");
		return NGX_CONF_ERROR ;
	}

	size = conf->upstream.buffer_size;
	if (size < conf->upstream.bufs.size) {
		size = conf->upstream.bufs.size;
	}

	ngx_conf_merge_size_value(conf->upstream.busy_buffers_size_conf, prev->upstream.busy_buffers_size_conf, NGX_CONF_UNSET_SIZE);

	if (conf->upstream.busy_buffers_size_conf == NGX_CONF_UNSET_SIZE) {
		conf->upstream.busy_buffers_size = 2 * size;
	} else {
		conf->upstream.busy_buffers_size = conf->upstream.busy_buffers_size_conf;
	}

	if (conf->upstream.busy_buffers_size < size) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"proxy_busy_buffers_size\" must be equal to or greater than "
				"the maximum of the value of \"proxy_buffer_size\" and "
				"one of the \"proxy_buffers\"");

		return NGX_CONF_ERROR ;
	}

	if (conf->upstream.busy_buffers_size > (conf->upstream.bufs.num - 1) * conf->upstream.bufs.size) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"proxy_busy_buffers_size\" must be less than "
				"the size of all \"proxy_buffers\" minus one buffer");

		return NGX_CONF_ERROR ;
	}

	ngx_conf_merge_size_value(conf->upstream.temp_file_write_size_conf, prev->upstream.temp_file_write_size_conf, NGX_CONF_UNSET_SIZE);

	if (conf->upstream.temp_file_write_size_conf == NGX_CONF_UNSET_SIZE) {
		conf->upstream.temp_file_write_size = 2 * size;
	} else {
		conf->upstream.temp_file_write_size = conf->upstream.temp_file_write_size_conf;
	}

	if (conf->upstream.temp_file_write_size < size) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"proxy_temp_file_write_size\" must be equal to or greater "
				"than the maximum of the value of \"proxy_buffer_size\" and "
				"one of the \"proxy_buffers\"");

		return NGX_CONF_ERROR ;
	}

	ngx_conf_merge_size_value(conf->upstream.max_temp_file_size_conf, prev->upstream.max_temp_file_size_conf, NGX_CONF_UNSET_SIZE);

	if (conf->upstream.max_temp_file_size_conf == NGX_CONF_UNSET_SIZE) {
		conf->upstream.max_temp_file_size = 1024 * 1024 * 1024;
	} else {
		conf->upstream.max_temp_file_size = conf->upstream.max_temp_file_size_conf;
	}

	if (conf->upstream.max_temp_file_size != 0 && conf->upstream.max_temp_file_size < size) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"proxy_max_temp_file_size\" must be equal to zero to disable "
				"temporary files usage or must be equal to or greater than "
				"the maximum of the value of \"proxy_buffer_size\" and "
				"one of the \"proxy_buffers\"");

		return NGX_CONF_ERROR ;
	}

	ngx_conf_merge_bitmask_value(conf->upstream.ignore_headers, prev->upstream.ignore_headers, NGX_CONF_BITMASK_SET);

	ngx_conf_merge_bitmask_value(conf->upstream.next_upstream, prev->upstream.next_upstream,
	        (NGX_CONF_BITMASK_SET |NGX_HTTP_UPSTREAM_FT_ERROR |NGX_HTTP_UPSTREAM_FT_TIMEOUT));

	if (conf->upstream.next_upstream & NGX_HTTP_UPSTREAM_FT_OFF) {
		conf->upstream.next_upstream = NGX_CONF_BITMASK_SET | NGX_HTTP_UPSTREAM_FT_OFF;
	}

	if (ngx_conf_merge_path_value(cf, &conf->upstream.temp_path, prev->upstream.temp_path, &ngx_http2_proxy_temp_path) != NGX_OK) {
		return NGX_CONF_ERROR ;
	}


	ngx_conf_merge_value(conf->upstream.pass_request_headers, prev->upstream.pass_request_headers, 1);
	ngx_conf_merge_value(conf->upstream.pass_request_body, prev->upstream.pass_request_body, 1);

	ngx_conf_merge_value(conf->upstream.intercept_errors, prev->upstream.intercept_errors, 0);



	ngx_conf_merge_value(conf->redirect, prev->redirect, 1);

	if (conf->redirect) {

		if (conf->redirects == NULL) {
			conf->redirects = prev->redirects;
		}

		if (conf->redirects == NULL && conf->url.data) {

			conf->redirects = ngx_array_create(cf->pool, 1, sizeof(ngx_http2_proxy_rewrite_t));
			if (conf->redirects == NULL) {
				return NGX_CONF_ERROR ;
			}

			pr = ngx_array_push(conf->redirects);
			if (pr == NULL) {
				return NGX_CONF_ERROR ;
			}

			ngx_memzero(&pr->pattern.complex, sizeof(ngx_http_complex_value_t));

			ngx_memzero(&pr->replacement, sizeof(ngx_http_complex_value_t));

			pr->handler = ngx_http2_proxy_rewrite_complex_handler;

			if (conf->vars.uri.len) {
				pr->pattern.complex.value = conf->url;
				pr->replacement.value = conf->location;

			} else {
				pr->pattern.complex.value.len = conf->url.len + sizeof("/") - 1;

				p = ngx_pnalloc(cf->pool, pr->pattern.complex.value.len);
				if (p == NULL) {
					return NGX_CONF_ERROR ;
				}

				pr->pattern.complex.value.data = p;

				p = ngx_cpymem(p, conf->url.data, conf->url.len);
				*p = '/';

				ngx_str_set(&pr->replacement.value, "/");
			}
		}
	}

	ngx_conf_merge_ptr_value(conf->cookie_domains, prev->cookie_domains, NULL);

	ngx_conf_merge_ptr_value(conf->cookie_paths, prev->cookie_paths, NULL);

	ngx_conf_merge_uint_value(conf->http_version, prev->http_version, NGX_HTTP_VERSION_10);

	ngx_conf_merge_uint_value(conf->headers_hash_max_size, prev->headers_hash_max_size, 512);

	ngx_conf_merge_uint_value(conf->headers_hash_bucket_size, prev->headers_hash_bucket_size, 64);

	conf->headers_hash_bucket_size = ngx_align(conf->headers_hash_bucket_size, ngx_cacheline_size);

	hash.max_size = conf->headers_hash_max_size;
	hash.bucket_size = conf->headers_hash_bucket_size;
	hash.name = "proxy_headers_hash";

	if (ngx_http_upstream_hide_headers_hash(cf, &conf->upstream, &prev->upstream, ngx_http2_proxy_hide_headers, &hash) != NGX_OK) {
		return NGX_CONF_ERROR ;
	}

	clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

	if (clcf->noname && conf->upstream.upstream == NULL && conf->proxy_lengths == NULL) {
		conf->upstream.upstream = prev->upstream.upstream;
		conf->location = prev->location;
		conf->vars = prev->vars;

		conf->proxy_lengths = prev->proxy_lengths;
		conf->proxy_values = prev->proxy_values;

#if (NGX_HTTP_SSL)
		conf->upstream.ssl = prev->upstream.ssl;
#endif
	}

	if (clcf->lmt_excpt && clcf->handler == NULL && (conf->upstream.upstream || conf->proxy_lengths)) {
		clcf->handler = ngx_http2_proxy_handler;
	}

	if (conf->body_source.data == NULL) {
		conf->body_flushes = prev->body_flushes;
		conf->body_source = prev->body_source;
		conf->body_lengths = prev->body_lengths;
		conf->body_values = prev->body_values;
	}

	if (conf->body_source.data && conf->body_lengths == NULL) {

		ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));

		sc.cf = cf;
		sc.source = &conf->body_source;
		sc.flushes = &conf->body_flushes;
		sc.lengths = &conf->body_lengths;
		sc.values = &conf->body_values;
		sc.complete_lengths = 1;
		sc.complete_values = 1;

		if (ngx_http_script_compile(&sc) != NGX_OK) {
			return NGX_CONF_ERROR ;
		}
	}

	if (conf->headers_source == NULL) {
		conf->headers = prev->headers;

		conf->headers_source = prev->headers_source;
	}

	rc = ngx_http2_proxy_init_headers(cf, conf, &conf->headers, ngx_http2_proxy_headers);
	if (rc != NGX_OK) {
		return NGX_CONF_ERROR ;
	}


	/*
	 * special handling to preserve conf->headers in the "http" section
	 * to inherit it to all servers
	 */

	if (prev->headers.hash.buckets == NULL && conf->headers_source == prev->headers_source) {
		prev->headers = conf->headers;
#if (NGX_HTTP_CACHE)
		prev->headers_cache = conf->headers_cache;
#endif
	}

	return NGX_CONF_OK;
}

static ngx_int_t ngx_http2_proxy_init_headers(ngx_conf_t *cf, ngx_http2_proxy_loc_conf_t *conf, ngx_http2_proxy_headers_t *headers,
        ngx_keyval_t *default_headers) {
	u_char *p;
	size_t size;
	uintptr_t *code;
	ngx_uint_t i;
	ngx_array_t headers_names, headers_merged;
	ngx_keyval_t *src, *s, *h;
	ngx_hash_key_t *hk;
	ngx_hash_init_t hash;
	ngx_http_script_compile_t sc;
	ngx_http_script_copy_code_t *copy;

	if (headers->hash.buckets) {
		return NGX_OK;
	}

	if (ngx_array_init(&headers_names, cf->temp_pool, 4, sizeof(ngx_hash_key_t)) != NGX_OK) {
		return NGX_ERROR;
	}

	if (ngx_array_init(&headers_merged, cf->temp_pool, 4, sizeof(ngx_keyval_t)) != NGX_OK) {
		return NGX_ERROR;
	}

	headers->lengths = ngx_array_create(cf->pool, 64, 1);
	if (headers->lengths == NULL) {
		return NGX_ERROR;
	}

	headers->values = ngx_array_create(cf->pool, 512, 1);
	if (headers->values == NULL) {
		return NGX_ERROR;
	}

	if (conf->headers_source) {

		src = conf->headers_source->elts;
		for (i = 0; i < conf->headers_source->nelts; i++) {

			s = ngx_array_push(&headers_merged);
			if (s == NULL) {
				return NGX_ERROR;
			}

			*s = src[i];
		}
	}

	h = default_headers;

	while (h->key.len) {

		src = headers_merged.elts;
		for (i = 0; i < headers_merged.nelts; i++) {
			if (ngx_strcasecmp(h->key.data, src[i].key.data) == 0) {
				goto next;
			}
		}

		s = ngx_array_push(&headers_merged);
		if (s == NULL) {
			return NGX_ERROR;
		}

		*s = *h;

		next:

		h++;
	}

	src = headers_merged.elts;
	for (i = 0; i < headers_merged.nelts; i++) {

		hk = ngx_array_push(&headers_names);
		if (hk == NULL) {
			return NGX_ERROR;
		}

		hk->key = src[i].key;
		hk->key_hash = ngx_hash_key_lc(src[i].key.data, src[i].key.len);
		hk->value = (void *) 1;

		if (src[i].value.len == 0) {
			continue;
		}

		copy = ngx_array_push_n(headers->lengths, sizeof(ngx_http_script_copy_code_t));
		if (copy == NULL) {
			return NGX_ERROR;
		}

		copy->code = (ngx_http_script_code_pt) ngx_http_script_copy_len_code;
		copy->len = src[i].key.len;

		size = (sizeof(ngx_http_script_copy_code_t) + src[i].key.len + sizeof(uintptr_t) - 1) & ~(sizeof(uintptr_t) - 1);

		copy = ngx_array_push_n(headers->values, size);
		if (copy == NULL) {
			return NGX_ERROR;
		}

		copy->code = ngx_http_script_copy_code;
		copy->len = src[i].key.len;

		p = (u_char *) copy + sizeof(ngx_http_script_copy_code_t);
		ngx_memcpy(p, src[i].key.data, src[i].key.len);

		ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));

		sc.cf = cf;
		sc.source = &src[i].value;
		sc.flushes = &headers->flushes;
		sc.lengths = &headers->lengths;
		sc.values = &headers->values;

		if (ngx_http_script_compile(&sc) != NGX_OK) {
			return NGX_ERROR;
		}

		code = ngx_array_push_n(headers->lengths, sizeof(uintptr_t));
		if (code == NULL) {
			return NGX_ERROR;
		}

		*code = (uintptr_t) NULL;

		code = ngx_array_push_n(headers->values, sizeof(uintptr_t));
		if (code == NULL) {
			return NGX_ERROR;
		}

		*code = (uintptr_t) NULL;
	}

	code = ngx_array_push_n(headers->lengths, sizeof(uintptr_t));
	if (code == NULL) {
		return NGX_ERROR;
	}

	*code = (uintptr_t) NULL;

	hash.hash = &headers->hash;
	hash.key = ngx_hash_key_lc;
	hash.max_size = conf->headers_hash_max_size;
	hash.bucket_size = conf->headers_hash_bucket_size;
	hash.name = "proxy_headers_hash";
	hash.pool = cf->pool;
	hash.temp_pool = NULL;

	return ngx_hash_init(&hash, headers_names.elts, headers_names.nelts);
}

static char *
ngx_http2_proxy_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
	ngx_http2_proxy_loc_conf_t *plcf = conf;
	ngx_str_t *value, *url;
	ngx_http_core_loc_conf_t *clcf;

	u_char* p;
	size_t srv_name_len;


	if (plcf->srv_conf) {
		return "is duplicate";
	}

	clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

	clcf->handler = ngx_http2_proxy_handler;

	if (clcf->name.data[clcf->name.len - 1] == '/') {
		clcf->auto_redirect = 1;
	}

	value = cf->args->elts;

	url = &value[1];

	p = ngx_ngx_strlchr(url->data,url->data+url->len,'/');
	if(!p){
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid URL ");
		return NGX_CONF_ERROR ;
	}
	srv_name_len = p - url->data;
	if(!srv_name_len){
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid URL ");
		return NGX_CONF_ERROR ;
	}

	plcf->srv_conf = ngx_http2_upstream_get_srv_conf(cf,url->data,srv_name_len);
	if(!plcf->srv_conf){
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid URL error server_name");
				return NGX_CONF_ERROR ;
	}
	plcf->location = clcf->name;
	url->data+=srv_name_len;
	url->len-=srv_name_len;

	plcf->url = *url;

	return NGX_CONF_OK;
}

static char *
ngx_http2_proxy_redirect(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
	ngx_http2_proxy_loc_conf_t *plcf = conf;

	u_char *p;
	ngx_str_t *value;
	ngx_http2_proxy_rewrite_t *pr;
	ngx_http_compile_complex_value_t ccv;

	if (plcf->redirect == 0) {
		return NGX_CONF_OK;
	}

	plcf->redirect = 1;

	value = cf->args->elts;

	if (cf->args->nelts == 2) {
		if (ngx_strcmp(value[1].data, "off") == 0) {
			plcf->redirect = 0;
			plcf->redirects = NULL;
			return NGX_CONF_OK;
		}

		if (ngx_strcmp(value[1].data, "false") == 0) {
			ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "invalid parameter \"false\", use \"off\" instead");
			plcf->redirect = 0;
			plcf->redirects = NULL;
			return NGX_CONF_OK;
		}

		if (ngx_strcmp(value[1].data, "default") != 0) {
			ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid parameter \"%V\"", &value[1]);
			return NGX_CONF_ERROR ;
		}
	}

	if (plcf->redirects == NULL) {
		plcf->redirects = ngx_array_create(cf->pool, 1, sizeof(ngx_http2_proxy_rewrite_t));
		if (plcf->redirects == NULL) {
			return NGX_CONF_ERROR ;
		}
	}

	pr = ngx_array_push(plcf->redirects);
	if (pr == NULL) {
		return NGX_CONF_ERROR ;
	}

	if (ngx_strcmp(value[1].data, "default") == 0) {
		if (plcf->proxy_lengths) {
			ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"proxy_redirect default\" cannot be used "
					"with \"proxy_pass\" directive with variables");
			return NGX_CONF_ERROR ;
		}

		if (plcf->url.data == NULL) {
			ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"proxy_redirect default\" should be placed "
					"after the \"proxy_pass\" directive");
			return NGX_CONF_ERROR ;
		}

		pr->handler = ngx_http2_proxy_rewrite_complex_handler;

		ngx_memzero(&pr->pattern.complex, sizeof(ngx_http_complex_value_t));

		ngx_memzero(&pr->replacement, sizeof(ngx_http_complex_value_t));

		if (plcf->vars.uri.len) {
			pr->pattern.complex.value = plcf->url;
			pr->replacement.value = plcf->location;

		} else {
			pr->pattern.complex.value.len = plcf->url.len + sizeof("/") - 1;

			p = ngx_pnalloc(cf->pool, pr->pattern.complex.value.len);
			if (p == NULL) {
				return NGX_CONF_ERROR ;
			}

			pr->pattern.complex.value.data = p;

			p = ngx_cpymem(p, plcf->url.data, plcf->url.len);
			*p = '/';

			ngx_str_set(&pr->replacement.value, "/");
		}

		return NGX_CONF_OK;
	}

	if (value[1].data[0] == '~') {
		value[1].len--;
		value[1].data++;

		if (value[1].data[0] == '*') {
			value[1].len--;
			value[1].data++;

			if (ngx_http2_proxy_rewrite_regex(cf, pr, &value[1], 1) != NGX_OK) {
				return NGX_CONF_ERROR ;
			}

		} else {
			if (ngx_http2_proxy_rewrite_regex(cf, pr, &value[1], 0) != NGX_OK) {
				return NGX_CONF_ERROR ;
			}
		}

	} else {

		ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

		ccv.cf = cf;
		ccv.value = &value[1];
		ccv.complex_value = &pr->pattern.complex;

		if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
			return NGX_CONF_ERROR ;
		}

		pr->handler = ngx_http2_proxy_rewrite_complex_handler;
	}

	ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

	ccv.cf = cf;
	ccv.value = &value[2];
	ccv.complex_value = &pr->replacement;

	if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
		return NGX_CONF_ERROR ;
	}

	return NGX_CONF_OK;
}

static char *
ngx_http2_proxy_cookie_domain(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
	ngx_http2_proxy_loc_conf_t *plcf = conf;

	ngx_str_t *value;
	ngx_http2_proxy_rewrite_t *pr;
	ngx_http_compile_complex_value_t ccv;

	if (plcf->cookie_domains == NULL) {
		return NGX_CONF_OK;
	}

	value = cf->args->elts;

	if (cf->args->nelts == 2) {

		if (ngx_strcmp(value[1].data, "off") == 0) {
			plcf->cookie_domains = NULL;
			return NGX_CONF_OK;
		}

		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid parameter \"%V\"", &value[1]);
		return NGX_CONF_ERROR ;
	}

	if (plcf->cookie_domains == NGX_CONF_UNSET_PTR) {
		plcf->cookie_domains = ngx_array_create(cf->pool, 1, sizeof(ngx_http2_proxy_rewrite_t));
		if (plcf->cookie_domains == NULL) {
			return NGX_CONF_ERROR ;
		}
	}

	pr = ngx_array_push(plcf->cookie_domains);
	if (pr == NULL) {
		return NGX_CONF_ERROR ;
	}

	if (value[1].data[0] == '.') {
		value[1].len--;
		value[1].data++;
	}

	ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

	ccv.cf = cf;
	ccv.value = &value[1];
	ccv.complex_value = &pr->pattern.complex;

	if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
		return NGX_CONF_ERROR ;
	}

	pr->handler = ngx_http2_proxy_rewrite_domain_handler;

	if (value[2].data[0] == '.') {
		value[2].len--;
		value[2].data++;
	}

	ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

	ccv.cf = cf;
	ccv.value = &value[2];
	ccv.complex_value = &pr->replacement;

	if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
		return NGX_CONF_ERROR ;
	}

	return NGX_CONF_OK;
}

static char *
ngx_http2_proxy_cookie_path(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
	ngx_http2_proxy_loc_conf_t *plcf = conf;

	ngx_str_t *value;
	ngx_http2_proxy_rewrite_t *pr;
	ngx_http_compile_complex_value_t ccv;

	if (plcf->cookie_paths == NULL) {
		return NGX_CONF_OK;
	}

	value = cf->args->elts;

	if (cf->args->nelts == 2) {

		if (ngx_strcmp(value[1].data, "off") == 0) {
			plcf->cookie_paths = NULL;
			return NGX_CONF_OK;
		}

		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid parameter \"%V\"", &value[1]);
		return NGX_CONF_ERROR ;
	}

	if (plcf->cookie_paths == NGX_CONF_UNSET_PTR) {
		plcf->cookie_paths = ngx_array_create(cf->pool, 1, sizeof(ngx_http2_proxy_rewrite_t));
		if (plcf->cookie_paths == NULL) {
			return NGX_CONF_ERROR ;
		}
	}

	pr = ngx_array_push(plcf->cookie_paths);
	if (pr == NULL) {
		return NGX_CONF_ERROR ;
	}

	ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

	ccv.cf = cf;
	ccv.value = &value[1];
	ccv.complex_value = &pr->pattern.complex;

	if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
		return NGX_CONF_ERROR ;
	}

	pr->handler = ngx_http2_proxy_rewrite_complex_handler;


	ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

	ccv.cf = cf;
	ccv.value = &value[2];
	ccv.complex_value = &pr->replacement;

	if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
		return NGX_CONF_ERROR ;
	}

	return NGX_CONF_OK;
}

