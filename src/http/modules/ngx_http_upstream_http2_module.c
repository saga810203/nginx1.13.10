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

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_v2.h>

typedef struct {
//    ngx_uint_t                         max_cached;
//
//    ngx_queue_t                        cache;
//    ngx_queue_t                        free;
	ngx_pool_t *pool;

	ngx_uint_t max_streams;

	ngx_http_v2_header_t indexed_headers[16];
	size_t idx_of_dyn_headers;
	ngx_str_t first_uri;

	ngx_http_upstream_init_pt original_init_upstream;
	ngx_http_upstream_init_peer_pt original_init_peer;

	void* servers;
	ngx_uint_t servers_size;

    int                              rcvbuf;

	ngx_log_t *log;
	size_t   pool_size;

} ngx_http_upstream_http2_srv_conf_t;

typedef struct {
	ngx_http_upstream_http2_srv_conf_t *conf;

	ngx_queue_t queue;
	ngx_connection_t *connection;

	socklen_t socklen;
	ngx_sockaddr_t sockaddr;

} ngx_http_upstream_http2_server_t;

typedef struct {
	ngx_http_upstream_http2_srv_conf_t *conf;
	ngx_http_upstream_http2_server_t* server;

	ngx_http_upstream_t *upstream;

	void *data;

	ngx_event_get_peer_pt original_get_peer;
	ngx_event_free_peer_pt original_free_peer;
} ngx_http_upstream_http2_peer_data_t;

typedef struct {
	ngx_http_upstream_http2_srv_conf_t *conf;
	ngx_connection_t *connection;
	ngx_queue_t queue;

	ngx_uint_t max_streams;
	ngx_uint_t processing;

	size_t send_window;
	size_t recv_window;
	size_t init_window;

	size_t frame_size;

} ngx_http_upstream_http_v2_connection_t;

static ngx_log_t ngx_log;

static ngx_int_t ngx_http_upstream_init_http2_peer(ngx_http_request_t *r,
		ngx_http_upstream_srv_conf_t *us);
static ngx_int_t ngx_http_upstream_get_http2_peer(ngx_peer_connection_t *pc,
		void *data);
static void ngx_http_upstream_free_http2_peer(ngx_peer_connection_t *pc,
		void *data, ngx_uint_t state);

static void ngx_http_upstream_keepalive_dummy_handler(ngx_event_t *ev);
static void ngx_http_upstream_http2_close_handler(ngx_event_t *ev);
static void ngx_http_upstream_http2_close(ngx_connection_t *c);

static void *ngx_http_upstream_http2_create_conf(ngx_conf_t *cf);
static char *ngx_http_upstream_http2_conn(ngx_conf_t *cf, ngx_command_t *cmd,
		void *conf);
static char *ngx_http_upstream_http2_indexed_header(ngx_conf_t *cf,
		ngx_command_t *cmd, void *conf);

static void noop_log_wirter(ngx_log_t *log, ngx_uint_t level, u_char *buf,
		size_t len);

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
	NULL
};

static ngx_command_t ngx_http_upstream_http2_commands[] = { {
ngx_string("http2_conn"),
NGX_HTTP_UPS_CONF | NGX_CONF_1MORE, ngx_http_upstream_http2_conn,
NGX_HTTP_SRV_CONF_OFFSET, 0,
NULL }, {
ngx_string("http2_indexed_header"),
NGX_HTTP_UPS_CONF | NGX_CONF_TAKE2, ngx_http_upstream_http2_indexed_header,
NGX_HTTP_SRV_CONF_OFFSET, 0,
NULL },

ngx_null_command };

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
static void noop_log_wirter(ngx_log_t *log, ngx_uint_t level, u_char *buf,
		size_t len) {
}
static ngx_int_t ngx_http_upstream_init_http2(ngx_conf_t *cf,
		ngx_http_upstream_srv_conf_t *us) {
	ngx_uint_t i;
	ngx_http_upstream_http2_srv_conf_t *kcf;
	ngx_http_upstream_http2_server_t *cached;
	ngx_http_upstream_server_t *server;

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

		cached = ngx_pcalloc(cf->pool,
				sizeof(ngx_http_upstream_http2_server_t) * kcf->servers_size);

		if (cached == NULL) {
			return NGX_ERROR;
		}

		kcf->servers = cached;

		for (i = 0; i < kcf->servers_size; ++i) {
			ngx_memcpy(&cached[i].sockaddr, server[i].addrs->sockaddr,
					server[i].addrs->socklen);
			cached[i].socklen = server[i].addrs->socklen;
			ngx_queue_init(&cached[i].queue);
			cached[i].conf = kcf;
		}
	}

	return NGX_OK;
}

static ngx_int_t ngx_http_upstream_init_http2_peer(ngx_http_request_t *r,
		ngx_http_upstream_srv_conf_t *us) {
	ngx_http_upstream_http2_peer_data_t *kp;
	ngx_http_upstream_http2_srv_conf_t *kcf;

	ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
			"init http2 peer");

	kcf = ngx_http_conf_upstream_srv_conf(us, ngx_http_upstream_http2_module);

	kp = ngx_palloc(r->pool, sizeof(ngx_http_upstream_http2_peer_data_t));
	if (kp == NULL) {
		return NGX_ERROR;
	}

	if (kcf->original_init_peer(r, us) != NGX_OK) {
		return NGX_ERROR;
	}

	kp->conf = kcf;
	kp->upstream = r->upstream;
	kp->data = r->upstream->peer.data;
	kp->original_get_peer = r->upstream->peer.get;
	kp->original_free_peer = r->upstream->peer.free;

	r->upstream->peer.data = kp;
	r->upstream->peer.get = ngx_http_upstream_get_http2_peer;
	r->upstream->peer.free = ngx_http_upstream_free_http2_peer;
	return NGX_OK;
}

static ngx_int_t ngx_http_upstream_http2_connect(ngx_peer_connection_t *pc,ngx_http_upstream_http2_peer_data_t *kp) {
	int rc, type;
#if (NGX_HAVE_IP_BIND_ADDRESS_NO_PORT || NGX_LINUX)
	in_port_t port;
#endif
	ngx_int_t event;
	ngx_err_t err;
	ngx_uint_t level;
	ngx_socket_t s;
	ngx_event_t *rev, *wev;
	ngx_connection_t *c;
	ngx_log_t *log;
	ngx_http_upstream_http2_srv_conf_t *hsc;

	hsc = kp->conf;
	log = hsc->log;


	type = SOCK_STREAM;

	s = ngx_socket(pc->sockaddr->sa_family, SOCK_STREAM, 0);

	ngx_log_debug2(NGX_LOG_DEBUG_EVENT,log, 0, "%s socket %d",
			(type == SOCK_STREAM) ? "stream" : "dgram", s);

	if (s == (ngx_socket_t) -1) {
		ngx_log_error(NGX_LOG_ALERT, log, ngx_socket_errno,
				ngx_socket_n " failed");
		return NGX_ERROR;
	}

	c = ngx_get_connection(s, log);

	if (c == NULL) {
		if (ngx_close_socket(s) == -1) {
			ngx_log_error(NGX_LOG_ALERT,log, ngx_socket_errno,
					ngx_close_socket_n "failed");
		}
		return NGX_ERROR;
	}




	c->type = SOCK_STREAM;

	if (hsc->rcvbuf) {
		if (setsockopt(s, SOL_SOCKET, SO_RCVBUF, (const void *) &hsc->rcvbuf,
				sizeof(int)) == -1) {
			ngx_log_error(NGX_LOG_ALERT,log, ngx_socket_errno,
					"setsockopt(SO_RCVBUF) failed");
			goto failed;
		}
	}

	if (ngx_nonblocking(s) == -1) {
		ngx_log_error(NGX_LOG_ALERT, log, ngx_socket_errno,
				ngx_nonblocking_n " failed");

		goto failed;
	}


	c->recv = ngx_recv;
	c->send = ngx_send;
	c->recv_chain = ngx_recv_chain;
	c->send_chain = ngx_send_chain;
	c->sendfile = 0;
	if (pc->sockaddr->sa_family == AF_UNIX) {
		c->tcp_nopush = NGX_TCP_NOPUSH_DISABLED;
		c->tcp_nodelay = NGX_TCP_NODELAY_DISABLED;
	}

	c->log_error =NGX_ERROR_IGNORE_ECONNRESET;

	rev = c->read;
	wev = c->write;

	rev->log =log;
	wev->log =log;

	pc->connection = c;

	c->number = ngx_atomic_fetch_add(ngx_connection_counter, 1);

	if (ngx_add_conn) {
		if (ngx_add_conn(c) == NGX_ERROR) {
			goto failed;
		}
	}

	ngx_log_debug3(NGX_LOG_DEBUG_EVENT, pc->log, 0,
			"connect to %V, fd:%d #%uA", pc->name, s, c->number);

	rc = connect(s, pc->sockaddr, pc->socklen);

	if (rc == -1) {
		err = ngx_socket_errno;

		if (err != NGX_EINPROGRESS) {
			if (err == NGX_ECONNREFUSED

			/*
			 * Linux returns EAGAIN instead of ECONNREFUSED
			 * for unix sockets if listen queue is full
			 */
			|| err == NGX_EAGAIN

			|| err == NGX_ECONNRESET || err == NGX_ENETDOWN
					|| err == NGX_ENETUNREACH || err == NGX_EHOSTDOWN
					|| err == NGX_EHOSTUNREACH) {
				level = NGX_LOG_ERR;

			} else {
				level = NGX_LOG_CRIT;
			}

			ngx_log_error(level, c->log, err, "connect() to %V failed",
					pc->name);

			ngx_close_connection(c);
			pc->connection = NULL;

			return NGX_DECLINED;
		}
	}

	if (ngx_add_conn) {
		if (rc == -1) {

			/* NGX_EINPROGRESS */

			return NGX_AGAIN;
		}

		ngx_log_debug0(NGX_LOG_DEBUG_EVENT,log, 0, "connected");

		wev->ready = 1;

		return NGX_OK;
	}

	/* kqueue */

	event = NGX_CLEAR_EVENT;

	if (ngx_add_event(rev, NGX_READ_EVENT, event) != NGX_OK) {
		goto failed;
	}

	if (rc == -1) {

		/* NGX_EINPROGRESS */

		if (ngx_add_event(wev, NGX_WRITE_EVENT, event) != NGX_OK) {
			goto failed;
		}

		return NGX_AGAIN;
	}

	ngx_log_debug0(NGX_LOG_DEBUG_EVENT, pc->log, 0, "connected");

	wev->ready = 1;

	return NGX_OK;

	failed:

	ngx_close_connection(c);
	pc->connection = NULL;

	return NGX_ERROR;

}

static ngx_int_t ngx_http_upstream_get_init_http2_connection(ngx_peer_connection_t *pc,ngx_http_upstream_http2_peer_data_t *kp){
	ngx_connection_t *c;
	ngx_http_upstream_http_v2_connection_t *h2c;
		c = pc->connection;
		pc->connection = NULL;
		c->pool = ngx_create_pool(kp->conf->pool_size, kp->conf->log);
		if (c->pool == NULL) {
			ngx_close_connection(c);
			return NGX_ERROR;
		}

		h2c = ngx_pcalloc(c->pool, sizeof(ngx_http_upstream_http_v2_connection_t));
		if(NULL == h2c){
			ngx_close_connection(c);

		}


}

static ngx_int_t ngx_http_upstream_get_http2_connection(
		ngx_peer_connection_t *pc, ngx_http_upstream_http2_peer_data_t *kp) {
	ngx_http_upstream_http2_server_t* server = kp->server;
	ngx_http_upstream_http_v2_connection_t *h2c = NULL;
	ngx_http_upstream_http_v2_connection_t *item;

	ngx_connection_t *c;
	ngx_queue_t *q, *cache;

	/* search cache for suitable connection */

	cache = &server->queue;

	for (q = ngx_queue_head(cache); q != ngx_queue_sentinel(cache); q =
			ngx_queue_next(q)) {
		item = ngx_queue_data(q, ngx_http_upstream_http_v2_connection_t, queue);

		if (item->max_streams > item->processing) {
			h2c = item;
			goto found;
		}
	}

	pc->connection = NULL;
	ngx_http_upstream_http2_connect(pc,kp);
	if(pc->connection == NULL){
		return NGX_BUSY;
	}








	h2c

	found:

	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0,
			"get keepalive peer: using connection %p", c);

	c->idle = 0;
	c->sent = 0;
	c->log = pc->log;
	c->read->log = pc->log;
	c->write->log = pc->log;
	c->pool->log = pc->log;

	pc->connection = c;
	pc->cached = 1;

	return NGX_DONE;

}

static ngx_int_t ngx_http_upstream_get_http2_peer(ngx_peer_connection_t *pc,
		void *data) {
	ngx_http_upstream_http2_peer_data_t *kp = data;
	ngx_http_upstream_http2_server_t *servers;
	ngx_http_upstream_http2_server_t *server;

	ngx_int_t rc;
	ngx_uint_t i;
	ngx_queue_t *q, *cache;
	ngx_connection_t *c;
	ngx_uint_t servers_size;

	ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0,
			"get http2 peer");

	/* ask balancer */

	rc = kp->original_get_peer(pc, kp->data);

	if (rc != NGX_OK) {
		return rc;
	}

	servers = kp->conf->servers;
	servers_size = kp->conf->servers_size;
	for (i = 0; i < servers_size; ++i) {
		server = &servers[i];
		if (ngx_memn2cmp((u_char *) &server->sockaddr, (u_char *) pc->sockaddr,
				server->socklen, pc->socklen) == 0) {

			kp->server = server;
			return ngx_http_upstream_get_http2_connection(pc, kp);
		}
	}
	return NGX_BUSY;

}

static void ngx_http_upstream_free_http2_peer(ngx_peer_connection_t *pc,
		void *data, ngx_uint_t state) {
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

	if (state & NGX_PEER_FAILED || c == NULL || c->read->eof || c->read->error
			|| c->read->timedout || c->write->error || c->write->timedout) {
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

static void *
ngx_http_upstream_http2_create_conf(ngx_conf_t *cf) {
	ngx_http_upstream_http2_srv_conf_t *conf;

	conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_upstream_http2_srv_conf_t));
	if (conf == NULL) {
		return NULL;
	}

	/*
	 * set by ngx_pcalloc():
	 *
	 *     conf->original_init_upstream = NULL;
	 *     conf->original_init_peer = NULL;
	 *     conf->max_cached = 0;
	 */

	return conf;
}

ngx_int_t
ngx_http_upstream_http2_config_log(ngx_conf_t *cf,
		ngx_http_upstream_http2_srv_conf_t *kcf, ngx_str_t* file_name) {
	u_char *p, *name;
	size_t nlen, plen;
	ngx_log_t *log;


	if(file_name.len == 3 && ngx_strncmp(file_name.data, "off", 3) == 0){
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

static char *
ngx_http_upstream_http2_conn(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
	ngx_http_upstream_srv_conf_t *uscf;
	ngx_http_upstream_http2_srv_conf_t *kcf = conf;

	ngx_int_t n;
	ngx_uint_t i;
	ngx_str_t *value;
	ngx_str_t * log_file_name;

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

	kcf->max_streams = 100;
	kcf->pool_size = 8192;
//	kcf->rcvbuf = 8192;
	kcf->first_uri = value[1];

	for (i = 2; i < cf->args->nelts; i++) {

		if (ngx_strncmp(value[i].data, "max_streams=", 12) == 0) {
			n = ngx_atoi(&value[i].data[12], value[i].len - 12);

			if (n == NGX_ERROR || n == 0) {
				goto invalid;
			}
			if (n > 100) {
				kcf->max_streams = n;
			}

			continue;
		}
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

		if (ngx_strncmp(value[i].data, "logs=", 5) == 0) {
			if (value[i].len > 5) {
				log_file_name->len = value[i].len - 5;
				log_file_name->data = &value[i].data[5];
			}
			if(ngx_http_upstream_http2_config_log(cf, kcf, log_file_name)){
				goto invalid;
			};
			continue;
		}

		goto invalid;
	}

	uscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_module);

	kcf->original_init_upstream =
			uscf->peer.init_upstream ?
					uscf->peer.init_upstream :
					ngx_http_upstream_init_round_robin;

	uscf->peer.init_upstream = ngx_http_upstream_init_http2;

	return NGX_CONF_OK;
	invalid:

	ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid parameter \"%V\"",
			&value[i]);

	return NGX_CONF_ERROR ;
}

static char *
ngx_http_upstream_http2_indexed_header(ngx_conf_t *cf, ngx_command_t *cmd,
		void *conf) {
	ngx_http_upstream_srv_conf_t *uscf;
	ngx_http_upstream_http2_srv_conf_t *kcf = conf;

	ngx_str_t *value;
	value = cf->args->elts;
	if (kcf->idx_of_dyn_headers
			== sizeof(kcf->indexed_headers) / sizeof(ngx_http_v2_header_t)) {
		return "too many indexed header";
	}

	/* read options */

	value = cf->args->elts;

	kcf->indexed_headers[kcf->idx_of_dyn_headers].name = value[1];
	kcf->indexed_headers[kcf->idx_of_dyn_headers].value = value[2];
	++kcf->idx_of_dyn_headers;
	return NGX_CONF_OK;
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

