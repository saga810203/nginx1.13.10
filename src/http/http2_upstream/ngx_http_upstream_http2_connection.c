/*
 * ngx_http_upstream_http2_connection.c
 *
 *  Created on: Apr 10, 2018
 *      Author: root
 */
#include <ngx_http_upstream_http2.h>

ngx_http2_connection_t* ngx_http_upstream_http2_connection_create(ngx_http_upstream_http2_srv_conf_t *us) {
	ngx_queue_t *queue;
	int i;
	ngx_http2_connection_t *ret = ngx_pcalloc(us->pool, (sizeof(ngx_http2_connection_t) + (sizeof(ngx_queue_t) * (us->sid_mask))));
	if (ret != NULL) {
		queue = &ret->streams;
		for (i = 0; i <= us->sid_mask; ++i) {
			ngx_queue_init(queue);
			++queue;
		}

		++us->use_conns;
	}
	return ret;
}
void ngx_http_upstream_http2_connection_connect(ngx_http2_connection_t* h2c) {
	int rc, type;
	ngx_int_t event;
	ngx_err_t err;
	ngx_uint_t level;
	ngx_socket_t s;
	ngx_event_t *rev, *wev;
	ngx_connection_t *c;
	ngx_log_t *log;

	ngx_http_upstream_http2_srv_conf_t *hsc;
	ngx_http2_server_t* server = h2c->server;
	ngx_http_upstream_http2_srv_conf_t *hsc = server->conf;
	int i;
	ngx_queue_t *queue;

	log = hsc->log;

	h2c->data = NULL;

	s = ngx_socket(server->sockaddr.sockaddr.sa_family, SOCK_STREAM, 0);

	if (s == (ngx_socket_t) -1) {
		ngx_log_error(NGX_LOG_ALERT, log, ngx_socket_errno, ngx_socket_n " failed");
		goto failed;
	}

	c = ngx_get_connection(s, log);

	if (c == NULL) {
		if (ngx_close_socket(s) == -1) {
			ngx_log_error(NGX_LOG_ALERT, log, ngx_socket_errno, ngx_close_socket_n "failed");
		}
		goto failed;
	}

	c->type = SOCK_STREAM;

	if (hsc->rcvbuf) {
		if (setsockopt(s, SOL_SOCKET, SO_RCVBUF, (const void *) &hsc->rcvbuf, sizeof(int)) == -1) {
			ngx_log_error(NGX_LOG_ALERT, log, ngx_socket_errno, "setsockopt(SO_RCVBUF) failed");
			goto failed;
		}
	}

	if (ngx_nonblocking(s) == -1) {
		ngx_log_error(NGX_LOG_ALERT, log, ngx_socket_errno, ngx_nonblocking_n " failed");
		goto failed;
	}

	c->recv = ngx_recv;
	c->send = ngx_send;
	c->recv_chain = ngx_recv_chain;
	c->send_chain = ngx_send_chain;
	c->sendfile = 0;
	if (server->sockaddr.sockaddr.sa_family == AF_UNIX) {
		c->tcp_nopush = NGX_TCP_NOPUSH_DISABLED;
		c->tcp_nodelay = NGX_TCP_NODELAY_DISABLED;
	}

	c->log_error = NGX_ERROR_IGNORE_ECONNRESET;

	rev = c->read;
	wev = c->write;

	rev->log = log;
	wev->log = log;

	h2c->data = c;

	c->number = ngx_atomic_fetch_add(ngx_connection_counter, 1);
	c->data = h2c;

	if (ngx_add_conn) {
		if (ngx_add_conn(c) == NGX_ERROR) {
			goto failed;
		}
	}

	ngx_log_debug3(NGX_LOG_DEBUG_EVENT, pc->log, 0,
			"connect to %V, fd:%d #%uA", pc->name, s, c->number);

	rc = connect(s, &server->sockaddr, server->socklen);

	if (rc == -1) {
		err = ngx_socket_errno;
		if (err != NGX_EINPROGRESS) {
			if (err == NGX_ECONNREFUSED

			/*
			 * Linux returns EAGAIN instead of ECONNREFUSED
			 * for unix sockets if listen queue is full
			 */
			|| err == NGX_EAGAIN

			|| err == NGX_ECONNRESET || err == NGX_ENETDOWN || err == NGX_ENETUNREACH || err == NGX_EHOSTDOWN || err == NGX_EHOSTUNREACH) {
				level = NGX_LOG_ERR;

			} else {
				level = NGX_LOG_CRIT;
			}
			goto failed;
		}
	}

	if (ngx_add_conn) {
		if (rc == -1) {

			/* NGX_EINPROGRESS */

			goto connect_wait;
		}

		ngx_log_debug0(NGX_LOG_DEBUG_EVENT,log, 0, "connected");

		wev->ready = 1;

		goto connect_ok;
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
	}

	ngx_log_debug0(NGX_LOG_DEBUG_EVENT,log, 0, "connected");

	wev->ready = 1;

	connect_ok: ngx_http_upstream_http2_connection_init(h2c);
	wev->handler(wev);
	return;

	connect_wait: ngx_http_upstream_http2_connection_init(h2c);

	return;

	failed: if (c != NULL) {
		ngx_close_connection(c);
	}
	h2c->data = hsc->free_connections;
	hsc->free_connections = h2c;
	ngx_http_upstream_http2_close_stream_in_server(server);
	server->connection = NULL;
	return;

}

static void ngx_http_upstream_http2_block_io(ngx_event_t* ev) {
	if (ev->timedout) {
		ngx_del_timer(ev);
	}
}



static u_char ngx_http2_connection_start[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" /* connection preface */

		"\x00\x00\x12\x04\x00\x00\x00\x00\x00" /* settings frame */
		"\x00\x01\x00\x00\x10\x00" /* header table size */
		"\x00\x02\x00\x00\x00\x00" /* disable push */
		"\x00\x04\x7f\xff\xff\xff" /* initial window */

		"\x00\x00\x04\x08\x00\x00\x00\x00\x00" /* window update frame */
		"\x7f\xff\x00\x00";


static void ngx_http_upstream_http2_init_request_send_handler(ngx_event_t* wev ){
		ngx_connection_t* c = wev->data;
		ngx_http2_connection_t* h2c = c->data;
		ngx_http2_server_t *server = h2c->server;
		ngx_http_upstream_http2_srv_conf_t* scf = server->conf;
		u_char* p ,*end;
		ssize_t capacity_size;
		ssize_t rc;
		ngx_uint_t pn ,pv;




}

static void ngx_http_upstream_http2_first_read_handler(ngx_event_t* rev) {
	ngx_connection_t* c = rev->data;
	ngx_http2_connection_t* h2c = c->data;
	ngx_http2_server_t *server = h2c->server;
	ngx_http_upstream_http2_srv_conf_t* scf = server->conf;
	u_char* p ,*end;
	ssize_t capacity_size;
	ssize_t rc;
	ngx_uint_t pn ,pv;

	if (!h2c->recv.buffer) {
		h2c->recv.buffer = ngx_http2_get_frame(scf);
		if (h2c->recv.buffer) {
			h2c->recv.pos = h2c->recv.buffer;
			h2c->recv.readable_size = scf->buffer_size;
		} else {
			ngx_queue_insert_tail(&scf->need_free_frame_queue, &rev->queue);
			return;
		}
	}

	p = h2c->recv.pos + h2c->recv.len;
	rc = c->recv(c, p, h2c->recv.readable_size);
	if (rc == NGX_ERROR) {
		goto failed;
	}else if(rc == NGX_AGAIN){
		goto again;
	}else if (rc) {
		h2c->recv.len+=rc;
		h2c->recv.readable_size-=rc;
		if(h2c->recv.len>=9){
			p = h2c->recv.pos;
			ngx_http2_parse_readed_frame_head(h2c,p);
			if(h2c->recv.type!= 0x04){
				goto failed;
			}
			if(h2c->recv.payload_len % 6 != 0){
				goto failed;
			}
			if(h2c->recv.payload_len >48){
				goto failed;
			}
			if(h2c->recv.len>=(h2c->recv.payload_len+9)){
				p+=9;
				end = p+h2c->recv.payload_len;
				while(p<end){
					pn =  p[0] << 8 | p[1];
					pv =  (p[2]<<24)| (p[3]<<16)|(p[4]<<8)|(p[5]);
					p+=6;
					if(pn==0x4){
						if(pv>(((1U << 31) - 1))){
							goto failed;
						}
						h2c->init_window = pv;
						h2c->send.send_window = pv;
					}else if(pn==0x03){
						h2c->max_streams = pv;
					}
				}

				h2c->recv.len = end - h2c->recv.pos;
				h2c->recv.pos = end;

				p = h2c->send.first_frame;
				ngx_memzero(p,18);
				p[3] = NGX_HTTP2_SETTINGS_FRAME;
				p[4] = NGX_HTTP2_ACK_FLAG;
				p += 9;

				p[3]=NGX_HTTP2_HEADERS_FRAME;
				p[4]= NGX_HTTP2_END_STREAM_FLAG | NGX_HTTP2_END_HEADERS_FLAG;
				p[8]=1;
				end = &p[9];

				*end++ = 0x80 | 0x2; // :method   GET
				*end++ = 0x80 | 0x6; // :scheme   http
				if(scf->first_uri.len ==1 &&( (*(scf->first_uri.data)) =='/')){
					*end++ = 0x80 | 0x4;
				}else{
					*end++ = 0x40 | 0x4;
					if()

				}








				rev->handler = ngx_http_upstream_http2_block_io;
				c->write->handler=ngx_http_upstream_http2_init_request_send_handler;
				ngx_http_upstream_http2_init_request_send_handler(c->write);
			}
		}
		goto again;
	} else {
		goto failed;
	}
	return;

again:
	if (ngx_handle_read_event(rev, 0) != NGX_OK) {
	        goto failed;
	}
	return;
failed:
	ngx_http2_free_frame(scf, h2c->send.first_frame);
	ngx_http2_free_frame(scf, h2c->recv.buffer);
	rev->handler = ngx_http_upstream_http2_block_io;
	ngx_close_connection(c);
	h2c->data = scf->free_connections;
	scf->free_connections = h2c;
	ngx_http_upstream_http2_close_stream_in_server(server);
	server->connection = NULL;
}

static void ngx_http_upstream_http2_first_write_handler(ngx_event_t* wev) {
	ngx_connection_t* c = wev->data;
	ngx_http2_connection_t* h2c = c->data;
	ngx_http2_server_t *server = h2c->server;
	ngx_http_upstream_http2_srv_conf_t* scf = server->conf;
	u_char* p;
	ngx_uint_t flow;
	ssize_t rc;

	if (!h2c->send.first_frame) {
		h2c->send.first_frame = ngx_http2_get_frame(scf);

		if (h2c->send.first_frame) {
			p = h2c->send.pos = h2c->send.first_frame;
			h2c->send.len = sizeof(ngx_http2_connection_start);
			p = h2c->send.pos;
			ngx_memcpy(p, ngx_http2_connection_start, sizeof(ngx_http2_connection_start));
			//initial window size;
			p[47] = (u_char) ((scf->buffer_size) >> 24);
			p[48] = (u_char) ((scf->buffer_size) >> 16);
			p[49] = (u_char) ((scf->buffer_size) >> 8);
			p[50] = (u_char) scf->buffer_size;
			flow = NGX_HTTP2_MAX_FLOW_CONTROL_SIZE - scf->buffer_size;
			//window update szie
			p[60] = (u_char) flow >> 24;
			p[61] = (u_char) flow >> 16;
			p[62] = (u_char) flow >> 8;
			p[63] = (u_char) flow;
			h2c->send.send_window = NGX_HTTP2_MAX_FLOW_CONTROL_SIZE;
		} else {
			ngx_queue_insert_tail(&scf->need_free_frame_queue, &wev->queue);
			return;
		}
	}
	rc = c->send(c, h2c->send.pos, h2c->send.len);
	if (rc == NGX_ERROR) {
		goto failed;
	} else {
		if (h2c->send.len == rc) {
			wev->handler = ngx_http_upstream_http2_block_io;
			c->read->handler = ngx_http_upstream_http2_first_read_handler;
			ngx_http_upstream_http2_first_read_handler(c->read);
		} else {
			h2c->send.pos += rc;
			h2c->send.len -= rc;
			if (ngx_handle_write_event(wev, 0) != NGX_OK) {
				goto failed;
			}
		}
	}
	return;
failed:
	ngx_http2_free_frame(scf, h2c->send.first_frame);
	wev->handler = ngx_http_upstream_http2_block_io;
	ngx_close_connection(c);
	h2c->data = scf->free_connections;
	scf->free_connections = h2c;
	ngx_http_upstream_http2_close_stream_in_server(server);
	server->connection = NULL;

}
void ngx_http_upstream_http2_first_read_handler(ngx_event_t* wev) {

}
void ngx_http_upstream_http2_connection_init(ngx_http2_connection_t* h2c) {
	ngx_int_t i;
	ngx_connection_t* c = h2c->data;
	ngx_queue_t* queue = &h2c->streams;
	c->read->handler = ngx_http_upstream_http2_block_io;
	c->write->handler = ngx_http_upstream_http2_first_write_handler;
	ngx_queue_init(&h2c->queue);
	ngx_memzero(&h2c->send, sizeof(ngx_http2_connection_send_part_t));
	ngx_memzero(&h2c->recv, sizeof(ngx_http2_connection_recv_part_t));

	for (i = 0; i <= h2c->server->conf->sid_mask; ++i) {
		ngx_queue_init(queue);
		++queue;
	}
}
