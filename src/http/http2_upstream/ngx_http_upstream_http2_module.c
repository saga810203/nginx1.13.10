/*
 * ngx_http_upstream_http2_module.c
 *
 *  Created on: Apr 8, 2018
 *      Author: root
 */

/*
 * Copyright (C) Maxim Dounin
 * Copyright (C) Nginx, Inc.
 */

#include <ngx_http_upstream_http2.h>

//static ngx_log_t ngx_log;

static ngx_int_t ngx_http_upstream_get_http2_peer(ngx_peer_connection_t *pc, void *data);
static void ngx_http_upstream_free_http2_peer(ngx_peer_connection_t *pc, void *data, ngx_uint_t state);

static void ngx_http_upstream_keepalive_dummy_handler(ngx_event_t *ev);
static void ngx_http_upstream_http2_close_handler(ngx_event_t *ev);
static void ngx_http_upstream_http2_close(ngx_connection_t *c);

extern ngx_command_t ngx_http_upstream_http2_commands[];

static ngx_http_module_t ngx_http_upstream_http2_module_ctx = {
NULL, /* preconfiguration */
NULL, /* postconfiguration */

NULL, /* create main configuration */
NULL, /* init main configuration */

ngx_http_upstream_http2_create_conf, /* create server configuration */
NULL, /* merge server configuration */

NULL, /* create location configuration */
NULL /* merge location configuration */
};

ngx_module_t ngx_http_upstream_http2_module = {
NGX_MODULE_V1, &ngx_http_upstream_http2_module_ctx, /* module context */
ngx_http_upstream_http2_commands, /* module directives */
NGX_HTTP_MODULE, /* module type */
NULL, /* init master */
NULL, /* init module */
NULL, /* init process */
NULL, /* init thread */
NULL, /* exit thread */
NULL, /* exit process */
NULL, /* exit master */
NGX_MODULE_V1_PADDING };

ngx_int_t ngx_http_upstream_init_http2(ngx_conf_t *cf, ngx_http_upstream_srv_conf_t *us) {
	ngx_int_t i;
	ngx_http_upstream_http2_srv_conf_t *kcf;
	ngx_http_upstream_server_t *server;
	ngx_http2_server_t *h2server;

	ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cf->log, 0,
			"init http2 upstream");

	kcf = ngx_http_conf_upstream_srv_conf(us, ngx_http_upstream_http2_module);

	if (kcf->original_init_upstream(cf, us) != NGX_OK) {
		return NGX_ERROR;
	}

	kcf->original_init_peer = us->peer.init;

	us->peer.init = ngx_http_upstream_init_http2_peer;

	/* allocate cache items and add to free queue */

	if (us->servers && us->servers->nelts) {

		server = us->servers->elts;

		kcf->servers_size = us->servers->nelts;

		kcf->servers = ngx_pcalloc(cf->pool, sizeof(ngx_http2_server_t) * kcf->servers_size);

		if (kcf->servers == NULL) {
			return NGX_ERROR;
		}

		for (i = 0; i < kcf->servers_size; ++i) {
			h2server = &kcf->servers[i];
			ngx_memcpy(&h2server->sockaddr, server[i].addrs->sockaddr, server[i].addrs->socklen);
			h2server->socklen = server[i].addrs->socklen;
			ngx_queue_init(&h2server->connection_queue);
			ngx_queue_init(&h2server->stream_queue);
			h2server->conf = kcf;
		}
	}
	return NGX_OK;
}

static ngx_int_t ngx_http_upstream_init_http2_peer(ngx_http_request_t *r, ngx_http_upstream_srv_conf_t *us) {
	ngx_http_upstream_http2_peer_data_t *kp;
	ngx_http_upstream_http2_srv_conf_t *kcf;
	ngx_http2_stream_t* stream;
	ngx_event_t* rev;
	ngx_event_t* wev;
	ngx_connection_t * c;
	ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"init http2 peer");

	kcf = ngx_http_conf_upstream_srv_conf(us, ngx_http_upstream_http2_module);

	kp = ngx_palloc(r->pool, sizeof(ngx_http_upstream_http2_peer_data_t));
	if (kp == NULL) {
		return NGX_ERROR;
	}
	stream = ngx_http_get_module_ctx(r, ngx_http_upstream_http2_module);
	if (stream == NULL) {
		stream = ngx_http_upstream_http2_stream_create(r);
		if (stream == NULL) {
			return NGX_ERROR;
		}
		ngx_http_set_ctx(r, stream, ngx_http_upstream_http2_module);
	}
	if (kcf->original_init_peer(r, us) != NGX_OK) {
		return NGX_ERROR;
	}
	stream->request = r;
	kp->conf = kcf;
	kp->request = r;
	kp->data = r->upstream->peer.data;
	kp->original_get_peer = r->upstream->peer.get;
	kp->original_free_peer = r->upstream->peer.free;

	r->upstream->peer.data = kp;
	r->upstream->peer.get = ngx_http_upstream_get_http2_peer;
	r->upstream->peer.free = ngx_http_upstream_free_http2_peer;
	return NGX_OK;
}




 void ngx_http_upstream_http2_close_stream_in_server(ngx_http2_server_t* server){
	ngx_queue_t *streams=&server->stream_queue;
	ngx_queue_t *q;
	ngx_http2_stream_t stream;
	ngx_connection_t* c;
    for (q = ngx_queue_head(streams);
         q != ngx_queue_sentinel(streams);
         q = ngx_queue_next(q))
    {
        stream = ngx_queue_data(q, ngx_http2_stream_t, queue);
        c = &stream->connection;
        c->error = 1;
        c->read->ready = 1;
        c->write->ready=1;
        ngx_post_event(c->write, &ngx_posted_events);
    }
    ngx_queue_init(streams);
}


static ngx_int_t ngx_http_upstream_get_http2_connection(ngx_peer_connection_t *pc, ngx_http_upstream_http2_peer_data_t *kp) {
	ngx_http2_server_t* server = kp->server;
	ngx_http_upstream_http2_srv_conf_t usf = server->conf;
	ngx_http2_connection_t *h2c = NULL;
	ngx_http_request_t* request = kp->request;
	ngx_http2_stream_t *stream = ngx_http_get_module_ctx(request, ngx_http_upstream_http2_module);
	ngx_queue_t *queue;
	int i;

	/* search cache for suitable connection */

	queue = &server->connection_queue;
	if (!ngx_queue_empty(queue)) {
		queue = ngx_queue_head(queue);
		h2c = ngx_queue_data(queue, ngx_http2_connection_t, queue);
		pc->connection = &stream->connection;
		stream->h2c = h2c;
		stream->state = NGX_HTTP2_STREAM_STATE_WATTING_IN_CONNECTION;
		ngx_queue_insert_tail(&h2c->idle_streams, &stream->queue);
		stream->connection->write->accept = 1;
		stream->connection->write->ready = 1;
		return NGX_DONE;
	}
	if (server->connection) {
		ngx_http_upstream_http2_server_add_stream(server,stream);
		pc->connection = &stream->connection;
		return NGX_AGAIN;
	}

	h2c = usf->free_connections;
	if(h2c){
		usf->free_connections = h2c->data;
	}else{
		if (usf->use_conns >= usf->max_conns) {
			return NGX_BUSY;
		}
		h2c = ngx_pcalloc(usf->pool, (sizeof(ngx_http2_connection_t) + (sizeof(ngx_queue_t) * (usf->sid_mask))));
		if (h2c == NULL) {
			return NGX_ERROR;
		}
		++usf->use_conns;
	}
	ngx_http_upstream_http2_server_add_stream(server,stream);
	h2c->server = server;
	pc->connection = &stream->connection;
	server->connection = h2c;
	ngx_http_upstream_http2_connection_connect(h2c);
	return NGX_AGAIN;
}

static ngx_int_t ngx_http_upstream_get_http2_peer(ngx_peer_connection_t *pc, void *data) {
	ngx_http_upstream_http2_peer_data_t *kp = data;
	ngx_http_upstream_http2_srv_conf_t *kcf = kp->conf;
	ngx_http2_server_t* servers = kcf->servers;
	ngx_http2_server_t* server;
	ngx_uint_t servers_size = kcf->servers_size;
	ngx_int_t rc;
	ngx_uint_t i;
	u_char* cmp_char_1 = (u_char*) pc->sockaddr;
	u_char* cmp_char_2;
	socklen_t cmp_len_1 = pc->socklen;
	socklen_t cmp_len_2;
	ngx_http2_stream_t* stream;

	ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0,"get http2 peer");

	/* ask balancer */

	rc = kp->original_get_peer(pc, kp->data);

	if (rc != NGX_OK) {
		return rc;
	}

	for (i = 0; i < servers_size; ++i) {
		server = &servers[i];
		cmp_char_2 = (u_char*) &server->sockaddr;
		cmp_len_2 = server->socklen;
		if (ngx_memn2cmp(cmp_char_1, cmp_char_2, cmp_len_1, cmp_len_2) == 0) {
			kp->server = server;
			return ngx_http_upstream_get_http2_connection(pc, kp);
		}
	}

	return NGX_BUSY;
}

static void ngx_http_upstream_free_http2_peer(ngx_peer_connection_t *pc, void *data, ngx_uint_t state) {
ngx_http_upstream_keepalive_peer_data_t *kp = data;
ngx_http_upstream_keepalive_cache_t *item;

ngx_queue_t *q;
ngx_connection_t *c;
ngx_http_upstream_t *u;

ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0,
		"free keepalive peer");

/* cache valid connections */

u = kp->upstream;
c = pc->connection;

if (state & NGX_PEER_FAILED || c == NULL || c->read->eof || c->read->error || c->read->timedout || c->write->error || c->write->timedout) {
	goto invalid;
}

if (!u->keepalive) {
	goto invalid;
}

if (!u->request_body_sent) {
	goto invalid;
}

if (ngx_terminate || ngx_exiting) {
	goto invalid;
}

if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
	goto invalid;
}

ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0,
		"free keepalive peer: saving connection %p", c);

if (ngx_queue_empty(&kp->conf->free)) {

	q = ngx_queue_last(&kp->conf->cache);
	ngx_queue_remove(q);

	item = ngx_queue_data(q, ngx_http_upstream_keepalive_cache_t, queue);

	ngx_http_upstream_keepalive_close(item->connection);

} else {
	q = ngx_queue_head(&kp->conf->free);
	ngx_queue_remove(q);

	item = ngx_queue_data(q, ngx_http_upstream_keepalive_cache_t, queue);
}

ngx_queue_insert_head(&kp->conf->cache, q);

item->connection = c;

pc->connection = NULL;

if (c->read->timer_set) {
	c->read->delayed = 0;
	ngx_del_timer(c->read);
}
if (c->write->timer_set) {
	ngx_del_timer(c->write);
}

c->write->handler = ngx_http_upstream_keepalive_dummy_handler;
c->read->handler = ngx_http_upstream_keepalive_close_handler;

c->data = item;
c->idle = 1;
c->log = ngx_cycle->log;
c->read->log = ngx_cycle->log;
c->write->log = ngx_cycle->log;
c->pool->log = ngx_cycle->log;

item->socklen = pc->socklen;
ngx_memcpy(&item->sockaddr, pc->sockaddr, pc->socklen);

if (c->read->ready) {
	ngx_http_upstream_keepalive_close_handler(c->read);
}

invalid:

kp->original_free_peer(pc, kp->data, state);
}

static void ngx_http_upstream_keepalive_dummy_handler(ngx_event_t *ev) {
ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ev->log, 0,
		"keepalive dummy handler");
}

static void ngx_http_upstream_http2_close_handler(ngx_event_t *ev) {
ngx_http_upstream_keepalive_srv_conf_t *conf;
ngx_http_upstream_keepalive_cache_t *item;

int n;
char buf[1];
ngx_connection_t *c;

ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ev->log, 0,
		"keepalive close handler");

c = ev->data;

if (c->close) {
	goto close;
}

n = recv(c->fd, buf, 1, MSG_PEEK);

if (n == -1 && ngx_socket_errno == NGX_EAGAIN) {
	ev->ready = 0;

	if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
		goto close;
	}

	return;
}

close:

item = c->data;
conf = item->conf;

ngx_http_upstream_keepalive_close(c);

ngx_queue_remove(&item->queue);
ngx_queue_insert_head(&conf->free, &item->queue);
}

static void ngx_http_upstream_http2_close(ngx_connection_t *c) {

ngx_destroy_pool(c->pool);
ngx_close_connection(c);
}

ngx_int_t ngx_http_upstream_http2_config_log(ngx_conf_t *cf, ngx_http_upstream_http2_srv_conf_t *kcf, ngx_str_t* file_name) {
//	u_char *p, *name;
//	size_t nlen, plen;
//	ngx_log_t *log;

if (file_name.len == 3 && ngx_strncmp(file_name.data, "off", 3) == 0) {
	return NGX_OK;
}

//TODO:  impl

return NGX_OK;

//	log = ngx_pcalloc(cf->pool, sizeof(ngx_log_t));
//	if(log == NULL){
//		return "alloc error";
//	}
//	log->file = log->file = ngx_conf_open_file(cf->cycle, &file_name);
//	if (log->file == NULL) {
//	     return NGX_CONF_ERROR;
//	}
//
//
//	name = (u_char *) NGX_ERROR_LOG_PATH;
//
//	/*
//	 * we use ngx_strlen() here since BCC warns about
//	 * condition is always false and unreachable code
//	 */
//
//	nlen = ngx_strlen(name);
//
//	if (nlen == 0) {
//		ngx_log_file.fd = ngx_stderr;
//		return &ngx_log;
//	}
//
//	p = NULL;
//
//	if (name[0] != '/') {
//
//		if (prefix) {
//			plen = ngx_strlen(prefix);
//
//		} else {
//
//			prefix = (u_char *) NGX_PREFIX;
//			plen = ngx_strlen(prefix);
//
//		}
//
//		if (plen) {
//			name = malloc(plen + nlen + 2);
//			if (name == NULL) {
//				return NULL;
//			}
//
//			p = ngx_cpymem(name, prefix, plen);
//
//			if (!ngx_path_separator(*(p - 1))) {
//				*p++ = '/';
//			}
//
//			ngx_cpystrn(p, (u_char *) NGX_ERROR_LOG_PATH, nlen + 1);
//
//			p = name;
//		}
//	}
//
//	ngx_log_file.fd = ngx_open_file(name, NGX_FILE_APPEND,
//			NGX_FILE_CREATE_OR_OPEN, NGX_FILE_DEFAULT_ACCESS);
//
//	if (ngx_log_file.fd == NGX_INVALID_FILE) {
//		ngx_log_stderr(ngx_errno, "[alert] could not open error log file: "
//		ngx_open_file_n " \"%s\" failed", name);
//
//		ngx_log_file.fd = ngx_stderr;
//	}
//
//	if (p) {
//		ngx_free(p);
//	}
//
//	return &ngx_log;
}

//
//static char *
//ngx_http_upstream_http2_max_streams(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
//{
//    ngx_http_upstream_srv_conf_t            *uscf;
//    ngx_http_upstream_http2_srv_conf_t  *kcf = conf;
//
//    ngx_int_t    n;
//    ngx_str_t   *value;
//    value = cf->args->elts;
//
//
//    n = ngx_atoi(value[1].data, value[1].len);
//    if (n == NGX_ERROR || n == 0) {
//        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
//                           "invalid value \"%V\" in \"%V\" directive",
//                           &value[1], &cmd->name);
//        return NGX_CONF_ERROR;
//    }
//    if(n<100){
//    	n=100;
//    }
//    return NGX_CONF_OK;
//}

