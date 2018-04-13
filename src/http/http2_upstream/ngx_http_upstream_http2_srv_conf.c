/*
 * ngx_http_upstream_http2_srv_conf.c
 *
 *  Created on: Apr 10, 2018
 *      Author: root
 */
#include <ngx_http_upstream_http2.h>

static void noop_log_wirter(ngx_log_t *log, ngx_uint_t level, u_char *buf, size_t len) {
}

static ngx_log_t noop_log = {
/*ngx_uint_t           log_level;*/
0,
/*ngx_open_file_t     *file;*/
NULL,
/* ngx_atomic_uint_t    connection;*/
0,

/*time_t               disk_full_time;*/
0,
/* ngx_log_handler_pt   handler;*/
NULL,
/*void *data;*/
NULL,
/*ngx_log_writer_pt writer;*/
noop_log_wirter,
/*void *wdata;*/
NULL,

/*
 * we declare "action" as "char *" because the actions are usually
 * the static strings and in the "u_char *" case we have to override
 * their types all the time
 */
/*char *action;*/
NULL,

/*ngx_log_t *next;*/
NULL };

static char *
ngx_http_upstream_http2_conn(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
	ngx_http_upstream_srv_conf_t *uscf;

	ngx_int_t n;
	ngx_uint_t i;
	ngx_str_t *value;
	ngx_str_t * log_file_name;

	ngx_http_upstream_http2_srv_conf_t *kcf = conf;

	if (kcf->first_uri.len) {
		return "is duplicate";
	}

	/* read options */

	log_file_name = ngx_pcalloc(cf->pool, sizeof(ngx_str_t));
	if (log_file_name == NULL) {
		return "alloc mem error";
	}
	log_file_name->len = 3;
	log_file_name->data = "off";

	value = cf->args->elts;

	if (value[1].data[0] != '/') {
		return "invalid http2 first uri";
	}

	kcf->log = &noop_log;
	kcf->pool_size = 8192;
//	kcf->rcvbuf = 8192;
	kcf->first_uri = value[1];

	for (i = 2; i < cf->args->nelts; i++) {

		if (ngx_strncmp(value[i].data, "rcvbuf=", 7) == 0) {
			n = ngx_atoi(&value[i].data[7], value[i].len - 7);

			if (n == NGX_ERROR || n == 0) {
				goto invalid;
			}
			if (n > 4096) {
				kcf->rcvbuf = n;
			}
			continue;
		}

		if (ngx_strncmp(value[i].data, "conn_pool_size=", 15) == 0) {
			n = ngx_atoi(&value[i].data[15], value[i].len - 15);

			if (n == NGX_ERROR || n == 0) {
				goto invalid;
			}
			if (n > 4096) {
				kcf->pool_size = n;
			}
			continue;
		}

		if (ngx_strncmp(value[i].data, "max_conns=", 10) == 0) {
			n = ngx_atoi(&value[i].data[10], value[i].len - 10);

			if (n == NGX_ERROR || n == 0) {
				goto invalid;
			}
			if (n > 128) {
				kcf->max_conns = n;
			}
			continue;
		}

		if (ngx_strncmp(value[i].data, "logs=", 5) == 0) {
			if (value[i].len > 5) {
				log_file_name->len = value[i].len - 5;
				log_file_name->data = &value[i].data[5];
			}
			if (ngx_http_upstream_http2_config_log(cf, kcf, log_file_name)) {
				goto invalid;
			};
			continue;
		}

		goto invalid;
	}

	kcf->pool = ngx_create_pool(kcf->pool_size, cf->log);
	if (kcf->pool == NULL) {
		return "create http2 upstream pool error";
	}

	uscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_module);

	kcf->original_init_upstream = uscf->peer.init_upstream ? uscf->peer.init_upstream : ngx_http_upstream_init_round_robin;

	uscf->peer.init_upstream = ngx_http_upstream_init_http2;

	return NGX_CONF_OK;
	invalid:

	ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid parameter \"%V\"", &value[i]);

	return NGX_CONF_ERROR ;
}

static char *
ngx_http_upstream_http2_indexed_header(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
	ngx_http_upstream_http2_srv_conf_t *kcf = conf;

	ngx_str_t *value;
	value = cf->args->elts;
	if (kcf->idx_of_dyn_headers == sizeof(kcf->indexed_headers) / sizeof(ngx_http_v2_header_t)) {
		return "too many indexed header";
	}

	/* read options */

	value = cf->args->elts;

	kcf->indexed_headers[kcf->idx_of_dyn_headers].name = value[1];
	kcf->indexed_headers[kcf->idx_of_dyn_headers].value = value[2];
	++kcf->idx_of_dyn_headers;
	return NGX_CONF_OK;
}

char *ngx_http_upstream_http2_buffer_size(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
	ngx_int_t n;
	ngx_str_t * value = cf->args->elts;
	ngx_http_upstream_http2_srv_conf_t *kcf = conf;
	n = ngx_atoi(value[1].data, value[1].len);
	if (n == NGX_ERROR || n == 0) {
		return "invalid paramter http2_buffer_size";
	}
	if (n > 8192) {
		kcf->buffer_size = n;
	}
	return NGX_CONF_OK;
}
char *ngx_http_upstream_http2_buffer_count(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
	ngx_int_t n;
	ngx_str_t * value = cf->args->elts;
	ngx_http_upstream_http2_srv_conf_t *kcf = conf;
	n = ngx_atoi(value[1].data, value[1].len);
	if (n == NGX_ERROR || n == 0) {
		return "invalid paramter http2_buffer_count";
	}
	if (n > 1024) {
		kcf->buffer_count = n;
	}
	return NGX_CONF_OK;
}
char* ngx_http_upstream_http2_sid_mask(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
	ngx_int_t n;
	ngx_int_t mask;
	ngx_str_t * value = cf->args->elts;
	ngx_http_upstream_http2_srv_conf_t *kcf = conf;
	n = ngx_atoi(value[1].data, value[1].len);
	if (n == NGX_ERROR || n == 0) {
		return "invalid paramter http2_sid_mask";
	}
	if (n > 8) {

		mask = n - 1;

		if (n == 0 || (n & mask)) {
			return "invalid paramter http2_sid_mask:must be a power of two";
		}

		kcf->sid_mask = mask;

	}
	return NGX_CONF_OK;
}
char* ngx_http_upstream_http2_conn_pool_size(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
	ngx_int_t n;
	ngx_int_t mask;
	ngx_str_t * value = cf->args->elts;
	ngx_http_upstream_http2_srv_conf_t *kcf = conf;
	n = ngx_atoi(value[1].data, value[1].len);
	if (n == NGX_ERROR || n == 0) {
		return "invalid paramter http2_conn_pool_size";
	}
	if(n > 8192) {
		kcf->http2_connection_pool_size = n;
	}
	return NGX_CONF_OK;
}

void *
ngx_http_upstream_http2_create_conf(ngx_conf_t *cf) {
	ngx_http_upstream_http2_srv_conf_t *conf;

	conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_upstream_http2_srv_conf_t));
	if (conf == NULL) {
		return NULL;
	}

	conf->buffer_size = 8192;
	conf->buffer_count = 1024 * 1024;
	conf->max_conns = 128;
	conf->sid_mask = 32;
	conf->http2_connection_pool_size = 8192;
	ngx_queue_init(&conf->need_free_frame_queue);
	/*
	 * set by ngx_pcalloc():
	 *
	 *     conf->original_init_upstream = NULL;
	 *     conf->original_init_peer = NULL;
	 *     conf->max_cached = 0;
	 */

	return conf;
}

ngx_command_t ngx_http_upstream_http2_commands[] = {
		{
				ngx_string("http2_conn"),
				NGX_HTTP_UPS_CONF | NGX_CONF_1MORE, ngx_http_upstream_http2_conn,
				NGX_HTTP_SRV_CONF_OFFSET, 0,NULL
		},
		{
				ngx_string("http2_indexed_header"),
				NGX_HTTP_UPS_CONF | NGX_CONF_TAKE2, ngx_http_upstream_http2_indexed_header,
				NGX_HTTP_SRV_CONF_OFFSET, 0,NULL
		},
		{
				ngx_string("http2_buffer_size"),
				NGX_HTTP_UPS_CONF | NGX_CONF_TAKE1, ngx_http_upstream_http2_buffer_size,
				NGX_HTTP_SRV_CONF_OFFSET, 0,NULL
		},
		{
				ngx_string("http2_buffer_count"),
				NGX_HTTP_UPS_CONF | NGX_CONF_TAKE1, ngx_http_upstream_http2_buffer_count,
				NGX_HTTP_SRV_CONF_OFFSET, 0,NULL
		},
		{
				ngx_string("http2_sid_mask"),
				NGX_HTTP_UPS_CONF | NGX_CONF_TAKE1, ngx_http_upstream_http2_sid_mask,
				NGX_HTTP_SRV_CONF_OFFSET, 0,NULL
		},
		{
				ngx_string("http2_conn_pool_size"),
				NGX_HTTP_UPS_CONF | NGX_CONF_TAKE1, ngx_http_upstream_http2_conn_pool_size,
				NGX_HTTP_SRV_CONF_OFFSET, 0,NULL
		},

		ngx_null_command
};
