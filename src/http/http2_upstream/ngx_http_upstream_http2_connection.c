/*
 * ngx_http_upstream_http2_connection.c
 *
 *  Created on: Apr 10, 2018
 *      Author: root
 */
#include <ngx_http_upstream_http2.h>

static int ngx_http_upstream_http2_read_skip_data(ngx_http2_connection_t* h2c);
static int ngx_http_upstream_http2_read_frame_head(ngx_http2_connection_t* h2c);
static int ngx_http_upstream_http2_read_setting_frame(ngx_http2_connection_t* h2c);
static int ngx_http_upstream_http2_read_ping_frame(ngx_http2_connection_t* h2c);
static int ngx_http_upstream_http2_read_window_update_frame(ngx_http2_connection_t* h2c);
static int ngx_http_upstream_http2_read_data_frame(ngx_http2_connection_t* h2c);
static int ngx_http_upstream_http2_read_headers_frame(ngx_http2_connection_t* h2c);
static int ngx_http_upstream_http2_read_priority_frame(ngx_http2_connection_t* h2c);
static int ngx_http_upstream_http2_read_rest_stream_frame(ngx_http2_connection_t* h2c);
static int ngx_http_upstream_http2_read_push_promise_frame(ngx_http2_connection_t* h2c);
static int ngx_http_upstream_http2_read_goaway_frame(ngx_http2_connection_t* h2c);
static int ngx_http_upstream_http2_read_continuation_frame(ngx_http2_connection_t* h2c);
static int ngx_http_upstream_http2_read_field_len(ngx_http2_connection_t* h2c);

//static int ngx_http_upstream_http2_read_setting_frame(ngx_http2_connection_t* h2c);
#define NGX_HTTP2_DATA_FRAME           0x0
#define NGX_HTTP2_HEADERS_FRAME        0x1
#define NGX_HTTP2_PRIORITY_FRAME       0x2
#define NGX_HTTP2_RST_STREAM_FRAME     0x3
#define NGX_HTTP2_SETTINGS_FRAME       0x4
#define NGX_HTTP2_PUSH_PROMISE_FRAME   0x5
#define NGX_HTTP2_PING_FRAME           0x6
#define NGX_HTTP2_GOAWAY_FRAME         0x7
#define NGX_HTTP2_WINDOW_UPDATE_FRAME  0x8
#define NGX_HTTP2_CONTINUATION_FRAME   0x9

typedef struct {
	ngx_uint_t len;
	ngx_http2_handler_pt handler;
} ngx_http2_frame_read_handler_config;

static ngx_http2_frame_read_handler_config ngx_http2_frame_read_handler_configs[] = {
		{ 0, ngx_http_upstream_http2_read_data_frame },
		{ 1, ngx_http_upstream_http2_read_headers_frame },
		{ NGX_HTTP2_PRIORITY_SIZE, ngx_http_upstream_http2_read_priority_frame }, { NGX_HTTP2_RST_STREAM_SIZE,
        ngx_http_upstream_http2_read_rest_stream_frame }, { 0, ngx_http_upstream_http2_read_setting_frame }, { 0,
        ngx_http_upstream_http2_read_push_promise_frame }, { NGX_HTTP2_PING_SIZE, ngx_http_upstream_http2_read_ping_frame }, { NGX_HTTP2_GOAWAY_SIZE,
        ngx_http_upstream_http2_read_goaway_frame }, { NGX_HTTP2_WINDOW_UPDATE_SIZE, ngx_http_upstream_http2_read_window_update_frame }, { 0,
        ngx_http_upstream_http2_read_continuation_frame },

};

ngx_http2_connection_t* ngx_http_upstream_http2_connection_create(ngx_http_upstream_http2_srv_conf_t *us) {
	ngx_queue_t *queue;
	int i;
	ngx_http2_connection_t *ret = ngx_pcalloc(us->pool, (sizeof(ngx_http2_connection_t) + (sizeof(ngx_queue_t) * (us->sid_mask))));
	if (ret != NULL) {
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
	if(h2c->recv.hpack.data){
			ngx_free(h2c->recv.hpack.data);
			h2c->recv.hpack.data = NULL;
	}
	h2c->data = hsc->free_connections;
	hsc->free_connections = h2c;
	ngx_http_upstream_http2_close_stream_in_server(server);
	server->connection = NULL;
	return;

}

static void ngx_http_upstream_http2_block_io(ngx_event_t* ev) {
//	if (ev->timedout) {
//		ngx_del_timer(ev);
//	}
}

static u_char ngx_http2_connection_start[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" /* connection preface */

		"\x00\x00\x12\x04\x00\x00\x00\x00\x00" /* settings frame */
		"\x00\x01\x00\x00\x00\x00" /* header table size */
		"\x00\x02\x00\x00\x00\x00" /* disable push */
		"\x00\x04\x7f\xff\xff\xff" /* initial window */

		"\x00\x00\x04\x08\x00\x00\x00\x00\x00" /* window update frame */
		"\x7f\xff\x00\x00";

static void ngx_http_upstream_http2_accecpt_streams(ngx_http2_connection_t* h2c) {
	ngx_http2_server_t *server = h2c->server;
	ngx_connection_t* c = h2c->data;
	ngx_http_upstream_http2_srv_conf_t* scf = server->conf;
	ngx_queue_t* queue, *q;
	ngx_http2_stream_t * stream;
	queue = &server->stream_queue;
	while (!ngx_queue_empty(queue)) {
		if (h2c->max_streams > h2c->processing) {
			++h2c->processing;
			q = ngx_queue_head(queue);
			ngx_queue_remove(q);
			stream = ngx_queue_data(q, ngx_http2_stream_t, queue);
			ngx_queue_insert_tail(&h2c->idle_streams, q);
			stream->h2c = h2c;
			stream->connection.fd = c->fd;
			stream->state = NGX_HTTP2_STREAM_STATE_WATTING_IN_CONNECTION;
			ngx_post_event(stream->connection->write, &ngx_posted_events);
		}
	}

	if (h2c->processing >= h2c->max_streams) {
		if (!ngx_queue_empty(queue)) {
			h2c = scf->free_connections;
			if (h2c) {
				scf->free_connections = h2c->data;
			} else {
				if (scf->use_conns >= scf->max_conns) {
					goto failed;
				}
				h2c = ngx_pcalloc(scf->pool, (sizeof(ngx_http2_connection_t) + (sizeof(ngx_queue_t) * (scf->sid_mask))));
				if (h2c == NULL) {
					goto failed;
				}
				++scf->use_conns;
				h2c->server = server;
				server->connection = h2c;
				ngx_http_upstream_http2_connection_connect(h2c);

			}
		}
	} else {
		ngx_queue_insert_tail(server->connection_queue, &h2c->queue);
	}
	return;

	failed: for (q = ngx_queue_head(queue); q != ngx_queue_sentinel(queue); q = ngx_queue_next(q)) {
		stream = ngx_queue_data(q, ngx_http2_stream_t, queue);
		stream->connection.error = 1;
		stream->connection.fd = -1;
		ngx_post_event(stream->connection->write, &ngx_posted_events);
	}
	ngx_queue_init(&server->stream_queue);

}

static void ngx_http_upstream_http2_send_queue_frame(ngx_http2_connection_t* h2c, ngx_http2_frame_t* frame) {
	u_char* p;
	ngx_connection_t* c = h2c->data;
	if (h2c->send.first_frame) {
		h2c->send.last_frame->data = frame;
		h2c->send.last_frame = frame;
	} else {
		h2c->send.first_frame = h2c->send.last_frame = frame;
		p = &frame->payload;
		h2c->send.pos = p;
		h2c->send.len = 9 + ((p[0] << 16) | (p[1] << 8) + p[2]);
		ngx_post_event(c->write, &ngx_posted_events);
	}
}
static void ngx_http_upstream_http2_send_queue_frame_ignore(ngx_http2_connection_t* h2c, ngx_http2_frame_t* frame) {
	ngx_http2_free_frame(h2c->server->conf, frame);
}
static void ngx_http_upstream_http2_send_ping_frame(ngx_http2_connection_t* h2c, ngx_http2_frame_t* frame, int ack) {
	u_char* p;
	ngx_uint_t num;
	ngx_http2_frame_t* prev, *next;
	u_char* p;
	ngx_connection_t* c = h2c->data;
	if (h2c->send.first_frame) {
		if (ack) {
			if (h2c->send.num_ping_ack) {
				num = 0;
				prev = h2c->send.first_frame;
				for (;;) {
					p = &prev->payload;
					if (p[3] == NGX_HTTP2_PING_FRAME && p[4] == NGX_HTTP2_ACK_FLAG) {
						++num;
						if (num == h2c->send.num_ping_ack) {
							frame->data = prev->data;
							prev->data = frame;
							break;
						}
					} else if (prev->data == NULL) {
						prev->data = frame;
						h2c->send.last_frame = frame;
						h2c->send.num_ping_ack = 0;
						break;
					} else {
						prev = prev.data;
					}
				}
			} else {
				prev = h2c->send.first_frame;
				for (;;) {
					p = &prev->payload;
					if ((p[3] == NGX_HTTP2_HEADERS_FRAME) || (p[3] == NGX_HTTP2_CONTINUATION_FRAME)) {
						if (p[4] & NGX_HTTP2_END_HEADERS_FLAG) {
							frame->data = prev->data;
							prev->data = frame;
							break;
						} else {
							prev = prev->data;
							//TODO check NULL == prev
						}
					} else {
						frame->data = prev->data;
						prev->data = frame;
						break;
					}
				}

			}
			if (NULL == frame->data) {
				h2c->send.last_frame = frame;
			}
			++h2c->send.num_ping_ack;
		} else {
			if (h2c->send.num_ping) {
				num = 0;
				prev = h2c->send.first_frame;
				for (;;) {
					p = &prev->payload;
					if (p[3] == NGX_HTTP2_PING_FRAME && p[4] == 0x00) {
						++num;
						if (num == h2c->send.num_ping_ack) {
							frame->data = prev->data;
							prev->data = frame;
							break;
						}
					} else if (prev->data == NULL) {
						prev->data = frame;
						h2c->send.last_frame = frame;
						h2c->send.num_ping = 0;
						break;
					} else {
						prev = prev.data;
					}
				}
			} else {
				prev = h2c->send.first_frame;
				for (;;) {
					p = &prev->payload;
					if ((p[3] == NGX_HTTP2_HEADERS_FRAME) || (p[3] == NGX_HTTP2_CONTINUATION_FRAME)) {
						if (p[4] & NGX_HTTP2_END_HEADERS_FLAG) {
							frame->data = prev->data;
							prev->data = frame;
							break;
						} else {
							prev = prev->data;
							//TODO check NULL == prev
						}
					} else {
						frame->data = prev->data;
						prev->data = frame;
						break;
					}
				}

			}
			if (NULL == frame->data) {
				h2c->send.last_frame = frame;
			}
			++h2c->send.num_ping;

		}
	} else {
		h2c->send.first_frame = h2c->send.last_frame = frame;
		p = &frame->payload;
		h2c->send.pos = p;
		h2c->send.len = 9 + NGX_HTTP2_PING_SIZE;
		ngx_post_event(c->write, &ngx_posted_events);
		if (ack) {
			++h2c->send.num_ping_ack;
		} else {
			++h2c->send.num_ping;
		}
	}
}
static void ngx_http_upstream_http2_send_ping_frame_ignore(ngx_http2_connection_t* h2c, ngx_http2_frame_t* frame, int ack) {
	ngx_http2_free_frame(h2c->server->conf, frame);
}

static void ngx_http_upstream_http2_send_header_frame(ngx_http2_connection_t* h2c, ngx_http2_frame_t* begin, ngx_http2_frame_t* end) {
	u_char* p;
	ngx_uint_t num;
	ngx_http2_frame_t* prev, *next;
	u_char* p;
	ngx_connection_t* c = h2c->data;
	if (h2c->send.first_frame) {
		h2c->send.last_frame->data = begin;
		h2c->send.last_frame = end;
	} else {
		h2c->send.first_frame = begin;
		h2c->send.last_frame = end;
		p = &begin->payload;
		h2c->send.pos = p;
		h2c->send.len = 9 + ((p[0] << 16) | (p[1] << 8) + p[2]);
		ngx_post_event(c->write, &ngx_posted_events);
	}
}
static void ngx_http_upstream_http2_send_header_frame_ignore(ngx_http2_connection_t* h2c, ngx_http2_frame_t* begin, ngx_http2_frame_t* end) {
	ngx_http_upstream_http2_srv_conf_t* scf = h2c->server->conf;

	while (begin) {
		end = begin->data;
		ngx_http2_free_frame(h2c->server->conf, begin);
		begin = end;

	}
}

static int ngx_http_upstream_http2_read_setting_params(ngx_http2_connection_t* h2c) {
	int i, j;
	ngx_uint_t pn, pv;
	u_char* p;
	ssize_t window_delta;
	ngx_http2_frame_t* frame;
	ngx_http2_stream_t* stream;
	ngx_connection_t * c;
	ngx_queue_t* queue, *q;
	int sid_mask = h2c->server->conf->sid_mask;

	frame = ngx_http2_get_frame(h2c->server->conf);
	if (frame) {
		h2c->recv.len-=h2c->recv.payload_len;
		for (i = 0; i < h2c->recv.payload_len; i += 6, h2c->recv.pos += 6) {
			p = h2c->recv.pos;
			pn = p[0] << 8 | p[1];
			pv = (p[2] << 24) | (p[3] << 16) | (p[4] << 8) | (p[5]);
			switch (pn) {
				case 0x01:
					if(pv){
						if(h2c->recv.hpack.data){
							if(ngx_http2_hpack_resize(&h2c->recv.hpack,pv)){
								ngx_http2_free_frame(h2c->server->conf,frame);
								return NGX_ERROR;
							}
						}else{
							if(ngx_http2_hpack_init(&h2c->recv.hpack,pv)){
								ngx_http2_free_frame(h2c->server->conf,frame);
								return NGX_ERROR;
							}
						}
					}else{
						if(h2c->recv.hpack.data){
							ngx_free(h2c->recv.hpack.data);
							h2c->recv.hpack.data =NULL;
							h2c->recv.hpack.rds_headers = 0;
						}
					}
					break;
				case 0x04:  //NGX_HTTP_V2_INIT_WINDOW_SIZE_SETTING
					if (pv > NGX_HTTP2_MAX_FLOW_CONTROL_SIZE) {
						return NGX_ERROR;
					}
					window_delta = pv - h2c->init_window;
					if (window_delta) {
						h2c->init_window += window_delta;
						j = 0;
						queue = &h2c->streams;
						while (j <= sid_mask) {
							for (q = ngx_queue_head(queue); q != ngx_queue_sentinel(queue); q = ngx_queue_next(q)) {
								stream = ngx_queue_data(q, ngx_http2_stream_t, queue_in_waiting);
								if (stream->state == NGX_HTTP2_STREAM_STATE_OPENED) {
									stream->send_window += window_delta;
									if ((stream->send_window == window_delta) && (window_delta > 0)) {
										ngx_post_event(stream->connection.write, &ngx_posted_events);
									}
								}

							}
							++queue;
							++j;

						}
					}
					break;

				case 0x03:  //NGX_HTTP_V2_MAX_STREAMS_SETTING
					if (pv > h2c->server->conf->max_streams) {
						pv = h2c->server->conf->max_streams;
					}
					if (h2c->max_streams) {
						if (pv > h2c->max_streams) {
							if (h2c->processing == h2c->max_streams) {
								ngx_queue_insert_tail(&h2c->server->connection_queue, &h2c->queue);
							}
							h2c->max_streams = pv;
						} else if (pv < h2c->max_streams) {
							if (pv == h2c->processing) {
								ngx_queue_remove(&h2c->queue);
							} else if (pv < h2c->processing) {
								if (h2c->processing < h2c->max_streams) {
									ngx_queue_remove(&h2c->queue);
								}
								queue = &h2c->idle_streams;
								for (q = ngx_queue_head(queue); q != ngx_queue_sentinel(queue); q = ngx_queue_next(q)) {
									ngx_queue_remove(q);
									stream = ngx_queue_data(q, ngx_http2_stream_t, queue);
									c = &stream->connection;
									c->fd = -1;
									c->error = 1;
									c->write->ready = 1;
									ngx_post_event(c->write, &ngx_posted_events);
									--h2c->processing;
									if (h2c->processing == pv) {
										break;
									}
								}
								h2c->max_streams = pv;
							}
						}
					}
					break;
				default:
					break;
			}
		}
		ngx_mem_zero(frame, sizeof(void*) + 9 + 0);
		p = &frame->payload;
		p[3] = NGX_HTTP2_SETTINGS_FRAME;
		p[4] = NGX_HTTP2_ACK_FLAG;
		h2c->send_frame(h2c, frame);
		h2c->recv.min_len = 9;
		h2c->recv.handler = ngx_http_upstream_http2_read_frame_head;
		return NGX_OK;
	} else {
		return NGX_AGAIN;
	}
}
static int ngx_http_upstream_http2_read_setting_frame(ngx_http2_connection_t* h2c) {
	if (h2c->recv.flag == NGX_HTTP2_ACK_FLAG) {
		if (h2c->recv.payload_len != 0) {
			return NGX_ERROR;
		}

	} else if (h2c->recv.payload_len % 6) {
		return NGX_ERROR;
	} else if (h2c->recv.payload_len) {
		h2c->recv.handler = ngx_http_upstream_http2_read_setting_params;
		h2c->recv.min_len = h2c->recv.payload_len;
		return NGX_OK;
	}
	h2c->recv.min_len = 9;
	h2c->recv.handler = ngx_http_upstream_http2_read_frame_head;
	return NGX_OK;

}
static int ngx_http_upstream_http2_read_ping_frame(ngx_http2_connection_t* h2c) {
	ngx_http2_frame_t * frame;
	ngx_http_upstream_http2_srv_conf_t scf = h2c->server->conf;
	u_char* p;
	if (!(h2c->recv.flag & NGX_HTTP2_ACK_FLAG)) {
		frame = ngx_http2_get_frame(scf);
		if (frame) {
			ngx_memzero(frame, sizeof(void*)+9+NGX_HTTP2_PING_SIZE);
			p = &frame->payload;
			p[2] = 0x08;
			p[3] = NGX_HTTP2_PING_FRAME;
			p[4] = NGX_HTTP2_ACK_FLAG;
			p += 9;
			ngx_memcpy(p, h2c->recv.pos, NGX_HTTP2_PING_SIZE);
			h2c->send_ping(h2c, frame, 1);
		} else {
			return NGX_AGAIN;
		}
	}
	h2c->recv.len -= NGX_HTTP2_PING_SIZE;
	h2c->recv.pos += NGX_HTTP2_PING_SIZE;
	h2c->recv.min_len = 9;
	h2c->recv.handler = ngx_http_upstream_http2_read_frame_head;
	return NGX_OK;

}
static int ngx_http_upstream_http2_read_data_frame(ngx_http2_connection_t* h2c) {
	ngx_uint_t rsize,size ;

	if(h2c->recv.len<h2c->recv.payload_len){
		h2c->recv.min_len = h2c->recv.payload_len;
		return NGX_OK;
	}
	size = h2c->


	rsize = h2c->recv.payload_len;
	if(h2c->recv.flag & NGX_HTTP2_PADDED_FLAG){
		rsize -=(1+(*h2c->recv.pos));
	}

}


static int ngx_http_upstream_http2_read_continuation_head(ngx_http2_connection_t* h2c){
	u_char* p;
	uint32_t cid;
	int32_t old_len;
	int32_t old_padding = h2c->recv.padding;
	old_len = h2c->recv.payload_len;
	if(old_padding){
		h2c->recv.padding = 0;
	}
	p = h2c->recv.pos+old_len+old_padding;
	if(p[3]!=NGX_HTTP2_CONTINUATION_FRAME){
		ngx_destroy_pool(h2c->recv.pool);
		h2c->recv.pool = NULL;
		return NGX_ERROR;
	}
	h2c->recv.payload_len += ((p[0]<<16)|(p[1]<<8)|p[2]);
	cid =  (p[5]<<24)|(p[6]<<16)|(p[7]<<8)|p[8];
	if(cid!=h2c->recv.sid){
		ngx_destroy_pool(h2c->recv.pool);
		h2c->recv.pool = NULL;
		return NGX_ERROR;
	}
	h2c->recv.flag |=p[4];

	p = h2c->recv.pos;

	h2c->recv.pos+= (9 + old_padding);
	h2c->recv.len-=(9 + old_padding);
	if(old_len){
		ngx_memmove(h2c->recv.pos,p,old_len);
	}


	h2c->recv.min_len = 0;
	h2c->recv.handler = h2c->recv.next_handler;
	return NGX_OK;
}


static int ngx_http_upstream_http2_process_field_cnt(ngx_http2_connection_t* h2c){
	u_char* p,*end;
	u_char state;
	ngx_str_t* str;
	if(h2c->recv_huff){
		p = ngx_palloc(h2c->recv.pool,h2c->recv.field_len*8/5);
		if(p){
			end = p;
			state = 0x00;
			if(ngx_http_v2_huff_decode(&state, h2c->recv.pos, h2c->recv.field_len, &end,1,NULL)){
				return NGX_ERROR;
			}
			str = h2c->recv_paser_value?&h2c->recv.c_header->value:&h2c->recv.c_header->name;
			str->len =end - p;
			str->data = p;
		}else{
			return NGX_ERROR;
		}
	}else{
		p = ngx_palloc(h2c->recv.pool,h2c->recv.field_len);
		if(p){
			ngx_memcpy(p,h2c->recv.pos,h2c->recv.field_len);
			str = h2c->recv_paser_value?&h2c->recv.c_header->value:&h2c->recv.c_header->name;
			str->len =h2c->recv.field_len;
			str->data = p;
		}else{
			return NGX_ERROR;
		}
	}
	return NGX_OK;
}

static int ngx_http_upstream_http2_read_field_cnt(ngx_http2_connection_t* h2c){
	if(h2c->recv.field_len<= h2c->recv.payload_len){
		if(h2c->recv.field_len< h2c->recv.len){
			h2c->recv.min_len = h2c->recv.field_len;
			return NGX_OK;
		}

		if(h2c->recv.field_len){
			if(ngx_http_upstream_http2_process_field_cnt(h2c)){
				goto failed;
			}
			h2c->recv.pos+=h2c->recv.field_len;
			h2c->recv.len-=h2c->recv.field_len;
			h2c->recv.payload_len-=h2c->recv.field_len;
		}else{
			if(h2c->recv_paser_value){
				h2c->recv.c_header->value.len = 0;
				h2c->recv.c_header->value.data = "";
			}else{
				h2c->recv.c_header->name.len = 0;
				h2c->recv.c_header->name.data = "";
			}
		}
		if(h2c->recv_paser_value){
			if(h2c->recv_index){
				h2c->recv_index = 0;
				if(ngx_http2_hpack_add(&h2c->recv.hpack,&h2c->recv.c_header->name,&h2c->recv.c_header->value)){
					goto failed;
				}
			}
			h2c->recv.min_len = 0;
			h2c->recv.handler = ngx_http_upstream_http2_read_headers_item;
		}else{
			h2c->recv_paser_value= 1;
			h2c->recv.min_len=1;
			h2c->recv.handler = ngx_http_upstream_http2_read_field_len;
		}

	}else{
		h2c->recv.min_len =h2c->recv.payload_len+ h2c->recv.padding+ 9;
		h2c->recv.next_handler =ngx_http_upstream_http2_read_field_cnt;
		h2c->recv.handler = ngx_http_upstream_http2_read_continuation_head;

	}
	return NGX_OK;

	failed: ngx_destroy_pool(h2c->recv.pool);
	h2c->recv.pool = NULL;
	return NGX_ERROR;
}
static int ngx_http_upstream_http2_read_field_len(ngx_http2_connection_t* h2c) {
	u_char ch;
	u_char* p;
	ngx_int_t value;
	ngx_uint_t huff, shift, octet, len;
	if (h2c->recv.payload_len) {
		if ((h2c->recv.payload_len < 4) && (!(h2c->recv.flag & NGX_HTTP2_END_HEADERS_FLAG))) {
			h2c->recv.min_len = 9 + h2c->recv.padding + h2c->recv.payload_len;
			h2c->recv.next_handler = ngx_http_upstream_http2_read_field_len;
			h2c->recv.handler = ngx_http_upstream_http2_read_continuation_head;
		} else {
			if (h2c->recv.len < 4) {
				if (h2c->recv.payload_len >= 4) {
					h2c->recv.min_len = 4;
					return NGX_OK;
				} else if (h2c->recv.len < h2c->recv.payload_len) {
					h2c->recv.min_len = h2c->recv.payload_len;
					return NGX_OK;
				}
			}
			p = h2c->recv.pos;
			h2c->recv_huff = *p >> 7;
			value = *p & 0x7F;
			++p;
			len = 1;
			if (value == 0x7F) {
				shift = 0;
				for (;;) {
					++len;
					octet = *p++;
					value += (octet & 0x7f) << shift;
					if (octet < 128) {
						if (h2c->recv.payload_len < len) {
							goto failed;
						}
						break;
					}
					shift += 7;
					if ((h2c->recv.payload_len <= len) || (len == 4)) {
						goto failed;
					}
				}
			}
			if(value > (h2c->server->conf->buffer_size - 9 /*frame head size*/-256/*max padding + 1*/)){
				// header_name or header_value too large
				return NGX_ERROR;
			}
			h2c->recv.pos+=len;
			h2c->recv.len-=len;
			h2c->recv.payload_len -=len;
			h2c->recv.field_len = value;
			h2c->recv.min_len = value <= h2c->recv.payload_len ? value : (h2c->recv.payload_len+h2c->recv.padding+9);
			h2c->recv.handler = ngx_http_upstream_http2_read_field_cnt;
		}
	} else if (h2c->recv.flag & NGX_HTTP2_END_HEADERS_FLAG) {
		goto failed;
	} else {
		h2c->recv.min_len = 9 + h2c->recv.padding;
		h2c->recv.next_handler = ngx_http_upstream_http2_read_field_len;
		h2c->recv.handler = ngx_http_upstream_http2_read_continuation_head;
	}
	return NGX_OK;

	failed: ngx_destroy_pool(h2c->recv.pool);
	h2c->recv.pool = NULL;
	return NGX_ERROR;

}

static int ngx_http_upstream_http2_read_headers_item(ngx_http2_connection_t* h2c){
    u_char      ch;
    u_char* p;
    ngx_int_t   value;
    ngx_uint_t  indexed, size_update, prefix,shift,octet,len;

    ngx_http2_header_t * header,*stream_header;
    ngx_http2_stream_t* stream;
    ngx_queue_t* queue,*q;
	if(h2c->recv.payload_len){
		if((h2c->recv.payload_len<4) && (!(h2c->recv.flag & NGX_HTTP2_END_HEADERS_FLAG))){
			h2c->recv.min_len = 9 + h2c->recv.padding + h2c->recv.payload_len;
			h2c->recv.next_handler = ngx_http_upstream_http2_read_headers_item;
			h2c->recv.handler = ngx_http_upstream_http2_read_continuation_head;
		}else{
			if(h2c->recv.len<4){
				if(h2c->recv.payload_len>=4){
					h2c->recv.min_len = 4;
					return NGX_OK;
				}else if(h2c->recv.len<h2c->recv.payload_len){
					h2c->recv.min_len = h2c->recv.payload_len;
					return NGX_OK;
				}
			}
			size_update = 0;
			indexed = 0;
			p= h2c->recv.pos;
			len = 1;
			ch = *p++;

			if (ch >= (1 << 7)) {
				/* indexed header field */
				indexed = 1;
				prefix = (1<<7) -1;

			} else if (ch >= (1 << 6)) {
				/* literal header field with incremental indexing */
				h2c->recv_index = 1;
				prefix = (1<<6) -1;

			} else if (ch >= (1 << 5)) {
				/* dynamic table size update */
				size_update = 1;
				prefix = (1<<5) -1;

			} else if (ch >= (1 << 4)) {
				/* literal header field never indexed */
				prefix = (1<<4) -1;

			} else {
				/* literal header field without indexing */
				prefix = (1<<4) -1;
			}
			value = ch & prefix;
			if (value == prefix) {
				shift = 0;
				for(;;){
					++len;
					octet = *p++;
					value += (octet & 0x7f) << shift;
					if(octet<128){
						if(h2c->recv.payload_len<len){
							goto failed;
						}
						break;
					}
					shift+=7;
					if((h2c->recv.payload_len<=len)|| (len==4)){
						goto failed;
					}
				}
			}
			h2c->recv.pos+=len;
			h2c->recv.len-=len;
			h2c->recv.payload_len-=len;

			if(indexed){
				if(ngx_http2_hpack_get_index_header(h2c,value,0)){
					goto failed;
				}
			}else if(size_update){
				if(value){
					if(ngx_http2_hpack_resize(&h2c->recv.hpack,value)){
						goto failed;
					}
				}else{
					ngx_free(h2c->recv.hpack.data);
					h2c->recv.hpack.data = NULL;
					h2c->recv.hpack.rds_headers = 0;
				}
			}else{
				h2c->recv_paser_value = 0;
				if(value){
					if(ngx_http2_hpack_get_index_header(h2c,value,1)){
						goto failed;
					}
					h2c->recv_paser_value = 1;
				}else{
					header = ngx_pcalloc(h2c->recv.pool,sizeof(ngx_http2_header_t));
					if(header){
						h2c->recv.c_header = header;
						ngx_queue_insert_tail(&h2c->recv.headers_queue,&header->queue);
					}else{
						goto failed;
					}
				}
				h2c->recv.min_len = 0 ;
				h2c->recv.handler = ngx_http_upstream_http2_read_field_len;
			}
		}
	}else if(h2c->recv.flag & NGX_HTTP2_END_HEADERS_FLAG) {
		stream = ngx_http_upstream_http2_find_stream(h2c, h2c->recv.sid);
		if(stream){
			ngx_queue_init(&stream->res_header_queue);
			queue=&h2c->recv.headers_queue;
			for (q = ngx_queue_head(queue); q != ngx_queue_sentinel(queue); q = ngx_queue_next(q)) {
				header = ngx_queue_data(q, ngx_http2_header_t, queue);
				stream_header = ngx_alloc(stream->request->pool, sizeof(ngx_http2_header_t));
				if (stream_header) {
					ngx_queue_insert_tail(&stream->res_header_queue, &stream_header->queue);
					stream_header->name.len = header->name.len;
					stream_header->value.len = header->value.len;
					if (header->cache == 'V') {
						stream_header->name.data = header->name.data;
						stream_header->value.data = header->value.data;
						continue;
					} else if (header->cache == 'N') {
						stream_header->name.data = header->name.data;
						stream_header->value.data = ngx_alloc(stream->request->pool, header->value.len);
						if (stream_header->value.data) {
							ngx_memcpy(stream_header->value.data, header->value.data, stream_header->value.len);
							continue;
						}
					} else {
						stream_header->name.data = ngx_alloc(stream->request->pool, header->name.len);
						if (stream_header->name.data) {
							ngx_memcpy(stream_header->name.data, header->name.data, stream_header->name.len);
							stream_header->value.data = ngx_alloc(stream->request->pool, header->value.len);
							if (stream_header->value.data) {
								ngx_memcpy(stream_header->value.data, header->value.data, stream_header->value.len);
								continue;
							}
						}
					}

				}
				stream->connection.fd = -1;
				stream->connection.error = 1;
				stream->read->ready = 1;
				ngx_queue_remove(&stream->queue);
				ngx_post_event(stream->connection.read,&ngx_posted_events);
				stream = NULL;
				break;

			}
			if(stream && (h2c->recv.flag & NGX_HTTP2_END_STREAM_FLAG)){
				stream->state = NGX_HTTP2_STREAM_STATE__CLOSED;
				ngx_queue_remove(&stream->queue);
				stream->connection.read->ready = 1;
				ngx_post_event(stream->connection.read,&ngx_posted_events);
			}
		}
		ngx_queue_init(&h2c->recv.headers_queue);
		ngx_destroy_pool(h2c->recv.pool);
		h2c->recv.pool = NULL;
		// copy headers to stream;  NGX_HTTP2_END_STREAMS_FLAG
		if(h2c->recv.padding){
			h2c->recv.payload_len = h2c->recv.padding;
			h2c->recv.padding = 0;
			h2c->recv.min_len = 1;
			h2c->recv.handler =ngx_http_upstream_http2_read_skip_data;
		}else{
			h2c->recv.min_len = 9;
			h2c->recv.handler = ngx_http_upstream_http2_read_frame_head;
		}
	}else{
		h2c->recv.min_len = 9 + h2c->recv.padding;
		h2c->recv.next_handler = ngx_http_upstream_http2_read_headers_item;
		h2c->recv.handler = ngx_http_upstream_http2_read_continuation_head;
	}
	return NGX_OK;

	failed:
		ngx_destroy_pool(h2c->recv.pool);
		h2c->recv.pool = NULL;
		return NGX_ERROR;

}
static int ngx_http_upstream_http2_read_headers_priority(ngx_http2_connection_t* h2c){

	//TODO: ignore priority
	h2c->recv.len-=sizeof(uint32_t)+1;
	h2c->recv.pos+=sizeof(uint32_t)+1;
	h2c->recv.payload_len-=sizeof(uint32_t)+1;
	h2c->recv.min_len = 0;
	h2c->recv.handler = ngx_http_upstream_http2_read_headers_item;
	h2c->recv.pool = ngx_create_pool(h2c->server->conf->http2_connection_pool_size,h2c->server->conf->log);
	if(!h2c->recv.pool){
		return NGX_ERROR;
	}
	return NGX_OK;
}
static int ngx_http_upstream_http2_read_headers_frame(ngx_http2_connection_t* h2c) {

	if(h2c->max_streams){
		h2c->recv_index = 0;
		h2c->recv.padding = 0;
		ngx_queue_init(&h2c->recv.headers_queue);
		h2c->recv.res_status = 0;
		if(h2c->recv.flag & NGX_HTTP2_PADDED_FLAG){
			if(h2c->recv.payload_len<1){
				return NGX_ERROR;
			}
			h2c->recv.padding = *((uint8_t*)h2c->recv.pos);
			++h2c->recv.pos;
			--h2c->recv.len;
			h2c->recv.payload_len-=(1+h2c->recv.padding);
		}
		if(h2c->recv.flag& NGX_HTTP2_PRIORITY_FLAG){
			if(h2c->recv.payload_len< (sizeof(uint32_t)+1)){
				return NGX_ERROR;
			}
			h2c->recv.min_len = sizeof(uint32_t)+1;
			h2c->recv.handler = ngx_http_upstream_http2_read_headers_priority;
		}else{
			h2c->recv.min_len = 0;
			h2c->recv.handler = ngx_http_upstream_http2_read_headers_item;
			h2c->recv.pool = ngx_create_pool(h2c->server->conf->http2_connection_pool_size,h2c->server->conf->log);
			if(!h2c->recv.pool){
				return NGX_ERROR;
			}
		}
	}else{
		h2c->recv.min_len = 1;
		h2c->recv.handler =ngx_http_upstream_http2_read_skip_data;
	}
	return NGX_OK;
}


static int ngx_http_upstream_http2_read_priority_frame(ngx_http2_connection_t* h2c) {
	if (NGX_HTTP2_PRIORITY_SIZE != h2c->recv.payload_len) {
		return NGX_ERROR;
	}
	h2c->recv.len -= NGX_HTTP2_PRIORITY_SIZE;
	h2c->recv.pos += NGX_HTTP2_PRIORITY_SIZE;
	h2c->recv.min_len = 9;
	h2c->recv.handler = ngx_http_upstream_http2_read_frame_head;
	return NGX_OK;
}
static int ngx_http_upstream_http2_read_rest_stream_frame(ngx_http2_connection_t* h2c) {
	ngx_http2_server_t *server = h2c->server;
	ngx_connection_t *c;
	ngx_http2_stream_t * stream;
	if (NGX_HTTP2_RST_STREAM_SIZE != h2c->recv.payload_len) {
		return NGX_ERROR;
	}
	if (0 == h2c->recv.sid) {
		return NGX_ERROR;
	}
	stream = ngx_http_upstream_http2_find_stream(h2c, h2c->recv.sid);

	if (stream) {
		ngx_queue_remove(&stream->queue);
		c = &stream->connection;
		c->error = 1;
		c->fd = -1;
		if (h2c->processing == h2c->max_streams) {
			ngx_queue_insert_tail(&server->connection_queue, &h2c->queue);
		}
		--h2c->processing;
		if (stream->state == NGX_HTTP2_STREAM_STATE_OPENED) {
			c->write->ready = 1;
			if (stream->waiting) {
				stream->waiting = 0;
				ngx_queue_remove(&stream->queue_in_waiting);
			}
			ngx_post_event(c->write, &ngx_posted_events);
		} else {
			c->read->ready = 1;
			ngx_post_event(c->read, &ngx_posted_events);
		}
	}
	h2c->recv.len -= NGX_HTTP2_RST_STREAM_SIZE;
	h2c->recv.pos += NGX_HTTP2_RST_STREAM_SIZE;
	h2c->recv.min_len = 9;
	h2c->recv.handler = ngx_http_upstream_http2_read_frame_head;
	return NGX_OK;
}
static int ngx_http_upstream_http2_read_push_promise_frame(ngx_http2_connection_t* h2c) {
	return NGX_ERROR;
}
static int ngx_http_upstream_http2_read_goaway_frame(ngx_http2_connection_t* h2c) {
	u_char* p;
	ngx_uint_t lsid,err_code;
	ngx_connection_t* c;
	ngx_queue_t *queue,*q;
	ngx_http2_stream_t* stream;
	int i;
	int sid_mask = h2c->server->conf->sid_mask;

	if (h2c->recv.payload_len < NGX_HTTP2_GOAWAY_SIZE) {
		return NGX_ERROR;
	}

	if (h2c->processing < h2c->max_streams) {
		ngx_queue_remove(&h2c->queue);
	}

	h2c->max_streams = 0;

	p = h2c->recv.pos;
	lsid = (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
	err_code = (p[4] << 24) | (p[5] << 16) | (p[6] << 8) | p[7];
	if (err_code)
		return NGX_ERROR;

	queue = &h2c->idle_streams;
	for (q = ngx_queue_head(queue); q != ngx_queue_sentinel(queue); q = ngx_queue_next(q)) {
		stream = ngx_queue_data(q, ngx_http2_stream_t, queue);
		ngx_queue_remove(q);
		c = &stream->connection;
		c->error = 1;
		c->fd = -1;
		c->write->ready = 1;
		--h2c->processing;
		ngx_post_event(c->write, &ngx_posted_events);
	}
	queue = &h2c->streams;
	i = 0;
	while (i <= sid_mask) {
		for (q = ngx_queue_head(queue); q != ngx_queue_sentinel(queue); q = ngx_queue_next(q)) {
			stream = ngx_queue_data(q, ngx_http2_stream_t, queue);
			if (stream->id > lsid) {
				ngx_queue_remove(q);
				c = &stream->connection;
				c->error = 1;
				c->fd = -1;
				if (((u_char) NGX_HTTP2_STREAM_STATE_OPENED) == stream->state) {
					c->write->ready = 1;
					if (stream->waiting) {
						stream->waiting = 0;
						ngx_queue_remove(&stream->queue_in_waiting);
					}
					ngx_post_event(c->write, &ngx_posted_events);
				}else{

				}
				--h2c->processing;
			}
		}
		++i;
		++queue;
	}
	h2c->recv.min_len =1;
	h2c->recv.handler = ngx_http_upstream_http2_read_skip_data;
	return NGX_OK;
}
static int ngx_http_upstream_http2_read_window_update_frame(ngx_http2_connection_t* h2c) {
	size_t window;
	ngx_http2_stream_t* stream;
	ngx_connection_t* c;
	ngx_http2_frame_t* frame;
	u_char* p;
	ngx_queue_t* queue, *q;
	if (h2c->recv.payload_len != NGX_HTTP2_WINDOW_UPDATE_SIZE) {
		return NGX_ERROR;
	}

	window = (ntohl(*(uint32_t *) (h2c->recv.pos)) & 0x7fffffff);
	if (window) {
		if (h2c->recv.sid) {
			stream = ngx_http_upstream_http2_find_stream(h2c, h2c->recv.sid);
			if (stream) {
				if (window > NGX_HTTP2_MAX_FLOW_CONTROL_SIZE - stream->send_window) {
					frame = ngx_http2_get_frame(h2c->server->conf);
					if (frame) {
						ngx_memzero(frame, sizeof(void*)+9+NGX_HTTP2_RST_STREAM_SIZE);
						p = &frame->payload;
						p[2] = NGX_HTTP2_RST_STREAM_SIZE;
						p[3] = NGX_HTTP2_RST_STREAM_FRAME;
						p[5] = h2c->recv.sid << 24;
						p[6] = h2c->recv.sid << 16;
						p[7] = h2c->recv.sid << 8;
						p[8] = h2c->recv.sid;
						p[12] = 0x01;
						h2c->send_frame(h2c, frame);
						ngx_queue_remove(&stream->queue);
						if (stream->waiting) {
							ngx_queue_remove(&stream->queue_in_waiting);
							stream->waiting = 0;
						}
						c = &stream->connection;
						c->error = 1;
						c->fd = -1;
						if (stream->state == NGX_HTTP2_STREAM_STATE_OPENED) {
							c->write->ready = 1;
							ngx_post_event(c->write, &ngx_posted_events);
						} else {
							c->read->ready = 1;
							ngx_post_event(c->read, &ngx_posted_events);
						}
					} else {
						return NGX_AGAIN;
					}
				} else if (stream->state == NGX_HTTP2_STREAM_STATE_OPENED && (0 == stream->send_window) && (!stream->waiting)) {
					c = &stream->connection;
					ngx_post_event(c->write, &ngx_posted_events);
				}
			}
		} else {
			if (window > NGX_HTTP2_MAX_FLOW_CONTROL_SIZE - h2c->send.send_window) {
				return NGX_ERROR;
			} else {
				if (h2c->send.send_window) {
					h2c->send.send_window += window;
				} else {
					h2c->send.send_window += window;
					queue = &h2c->send.flow_control_queue;
					for (q = ngx_queue_head(queue); q != ngx_queue_sentinel(queue); q = ngx_queue_next(q)) {
						ngx_queue_remove(q);
						stream = ngx_queue_data(q, ngx_http2_stream_t, queue_in_waiting);
						stream->waiting = 0;
						ngx_post_event(stream->connection.write, &ngx_posted_events);
					}
				}
			}
		}
	} else {
		if (h2c->recv.sid) {
			stream = ngx_http_upstream_http2_find_stream(h2c, h2c->recv.sid);
			if (stream) {
				frame = ngx_http2_get_frame(h2c->server->conf);
				if (frame) {
					ngx_memzero(frame, sizeof(void*)+9+NGX_HTTP2_RST_STREAM_SIZE);
					p = &frame->payload;
					p[2] = NGX_HTTP2_RST_STREAM_SIZE;
					p[3] = NGX_HTTP2_RST_STREAM_FRAME;
					p[5] = h2c->recv.sid << 24;
					p[6] = h2c->recv.sid << 16;
					p[7] = h2c->recv.sid << 8;
					p[8] = h2c->recv.sid;
					p[12] = 0x01;
					h2c->send_frame(h2c, frame);
					ngx_queue_remove(&stream->queue);
					if (stream->waiting) {
						ngx_queue_remove(&stream->queue_in_waiting);
						stream->waiting = 0;
					}
					c = &stream->connection;
					c->error = 1;
					c->fd = -1;
					if (stream->state == NGX_HTTP2_STREAM_STATE_OPENED) {
						c->write->ready = 1;
						ngx_post_event(c->write, &ngx_posted_events);
					} else {
						c->read->ready = 1;
						ngx_post_event(c->read, &ngx_posted_events);
					}

				} else {
					return NGX_AGAIN;
				}
			}
		} else {
			return NGX_ERROR;
		}
	}

	h2c->recv.len -= NGX_HTTP2_WINDOW_UPDATE_SIZE;
	h2c->recv.pos += NGX_HTTP2_WINDOW_UPDATE_SIZE;
	h2c->recv.min_len = 9;
	h2c->recv.handler = ngx_http_upstream_http2_read_frame_head;
	return NGX_OK;

}
static int ngx_http_upstream_http2_read_continuation_frame(ngx_http2_connection_t* h2c) {
	if(h2c->max_streams){
		return NGX_ERROR;
	}else{
		h2c->recv.min_len = 1;
		h2c->recv.handler = ngx_http_upstream_http2_read_skip_data;
		return NGX_OK;
	}
}
static int ngx_http_upstream_http2_read_skip_data(ngx_http2_connection_t* h2c) {
	if(h2c->recv.payload_len <= h2c->recv.len){
		h2c->recv.len-=h2c->recv.payload_len;
		h2c->recv.pos +=h2c->recv.payload_len;
		h2c->recv.min_len = 9;
		h2c->recv.handler = ngx_http_upstream_http2_read_frame_head;
	}else{
		h2c->recv.payload_len -=h2c->recv.len;
		h2c->recv.pos = h2c->recv.buffer;
		h2c->recv.readable_size = h2c->server->conf->buffer_size;
		h2c->recv.len=0;
	}
	return NGX_OK;
}

static int ngx_http_upstream_http2_read_frame_head(ngx_http2_connection_t* h2c) {
	ngx_http2_frame_read_handler_config hc;
	u_char* p = h2c->recv.pos;
	ngx_http2_parse_readed_frame_head(h2c, p);

	if (h2c->recv.type > ngx_http2_frame_read_handler_configs.len) {
		return NGX_ERROR;
	}

	h2c->recv.pos += 9;
	h2c->recv.len -= 9;

	hc = ngx_http2_frame_read_handler_configs[h2c->recv.type];
	h2c->recv.min_len = hc.len;
	h2c->recv.handler = hc.handler;
	return NGX_OK;
}

static void ngx_http_updateam_Http2_read_error(ngx_http2_connection_t* h2c) {
	ngx_http2_server_t *server = h2c->server;
	ngx_connection_t *c;
	ngx_http_upstream_http2_srv_conf_t* scf = server->conf;
	ngx_queue_t* queue, *q;
	ngx_http2_stream_t * stream;
	ngx_http2_frame_t* frame, *prev;
	u_char* p;

	int i;
	h2c->recv_error = 1;
	if (h2c->processing < h2c->max_streams) {
		ngx_queue_remove(&h2c->queue);
	}
	h2c->max_streams = 0;
	c->read->handler = ngx_http_upstream_http2_block_io;
	if (h2c->send_error) {
		queue = &h2c->streams;
		i = 0;
		while (i <= scf->sid_mask) {
			for (q = ngx_queue_head(queue); q != ngx_queue_sentinel(queue); q = ngx_queue_next(q)) {
				ngx_queue_remove(q);
				stream = ngx_queue_data(q, ngx_http2_stream_t, queue);
				c = &stream->connection;
				c->error = 1;
				c->fd = -1;
				c->read->ready = 1;
				--h2c->processing;
				ngx_post_event(c->read, &ngx_posted_events);
			}
			++i;
			++queue;
		}
		if (h2c->recv.buffer) {
			ngx_http2_free_frame(h2c->recv.buffer);
			h2c->recv.buffer = NULL;
		}
		ngx_close_connection(c);
		if(h2c->recv.hpack.data){
				ngx_free(h2c->recv.hpack.data);
				h2c->recv.hpack.data = NULL;
		}
		h2c->data = scf->free_connections;
		scf->free_connections = h2c;
	} else if (h2c->send_goaway) {
		if (h2c->recv.buffer) {
			ngx_http2_free_frame(h2c->recv.buffer);
			h2c->recv.buffer = NULL;
		}
	} else {
		queue = &h2c->idle_streams;
		for (q = ngx_queue_head(queue); q != ngx_queue_sentinel(queue); q = ngx_queue_next(q)) {
			stream = ngx_queue_data(q, ngx_http2_stream_t, queue);
			ngx_queue_remove(q);
			c = &stream->connection;
			c->fd = -1;
			c->error = 1;
			c->write->ready = 1;
			--h2c->processing;
			ngx_post_event(c->write, &ngx_posted_events);
		}
		queue = &h2c->streams;
		i = 0;
		while (i <= scf->sid_mask) {
			for (q = ngx_queue_head(queue); q != ngx_queue_sentinel(queue); q = ngx_queue_next(q)) {
				ngx_queue_remove(q);
				stream = ngx_queue_data(q, ngx_http2_stream_t, queue);
				c = &stream->connection;
				c->fd = -2;
				c->error = 1;
				if (((u_char) NGX_HTTP2_STREAM_STATE_LOCAL_CLOSED) == stream->state) {
					c->read->ready = 1;
					ngx_post_event(c->read, &ngx_posted_events);
				} else {
					if (stream->waiting) {
						stream->waiting = 0;
						ngx_queue_remove(&stream->queue_in_waiting);
					}
					c->write->ready = 1;
					ngx_post_event(c->write, &ngx_posted_events);
				}
				--h2c->processing;
			}
			++i;
			++queue;
		}
		frame = h2c->send.first_frame;
		if (frame) {
			while (frame) {
				prev = frame;
				frame = prev->data;
				p = &prev->payload;
				if (((p[3] != NGX_HTTP2_HEADERS_FRAME) && (p[3] != NGX_HTTP2_CONTINUATION_FRAME)) || (p[4] & NGX_HTTP2_END_HEADERS_FLAG)) {
					break;
				}
			}
			prev->data = h2c->send.last_frame = h2c->recv.buffer;
			while (frame) {
				prev = frame->data;
				ngx_http2_free_frame(scf, frame);
				frame = prev;
			}
		} else {
			h2c->send.first_frame = h2c->send.last_frame = h2c->recv.buffer;
		}
		frame = h2c->recv.buffer;
		ngx_memzero(frame, 17 + sizeof(void*));
		p = &frame->payload;
		p[2] = 0x08;
		p[3] = NGX_HTTP2_GOAWAY_FRAME;
		p[16] = 0x01;
		h2c->send_goaway = 1;
		h2c->send_frame(h2c, frame);
		h2c->recv.buffer = NULL;
	}
}

static void ngx_http_updateam_Http2_write_error(ngx_http2_connection_t* h2c) {
	ngx_http2_server_t *server = h2c->server;
	ngx_connection_t *c = h2c->data;
	ngx_http_upstream_http2_srv_conf_t* scf = server->conf;
	ngx_queue_t* queue, *q;
	ngx_http2_stream_t * stream;
	ngx_http2_frame_t* frame, *next;

	int i;
	h2c->send_frame = ngx_http_upstream_http2_send_queue_frame_ignore;
	h2c->send_ping = ngx_http_upstream_http2_send_ping_frame_ignore;
	h2c->send_headers = ngx_http_upstream_http2_send_header_frame_ignore;
	h2c->send_error = 1;
	if (h2c->processing < h2c->max_streams) {
		ngx_queue_remove(&h2c->queue);
	}
	h2c->max_streams = 0;
	c->write->handler = ngx_http_upstream_http2_block_io;
	if (h2c->recv_error) {
		ngx_close_connection(c);
		if(h2c->recv.hpack.data){
				ngx_free(h2c->recv.hpack.data);
				h2c->recv.hpack.data = NULL;
			}
		h2c->data = scf->free_connections;
		scf->free_connections = h2c;
	} else {
		queue = &h2c->idle_streams;
		for (q = ngx_queue_head(queue); q != ngx_queue_sentinel(queue); q = ngx_queue_next(q)) {
			stream = ngx_queue_data(q, ngx_http2_stream_t, queue);
			ngx_queue_remove(q);
			c = &stream->connection;
			c->error = 1;
			c->fd = -1;
			c->write->ready = 1;
			--h2c->processing;
			ngx_post_event(c->write, &ngx_posted_events);
		}
		queue = &h2c->streams;
		i = 0;
		while (i <= scf->sid_mask) {
			for (q = ngx_queue_head(queue); q != ngx_queue_sentinel(queue); q = ngx_queue_next(q)) {
				ngx_queue_remove(q);
				stream = ngx_queue_data(q, ngx_http2_stream_t, queue);
				c = &stream->connection;
				c->error = 1;
				if (((u_char) NGX_HTTP2_STREAM_STATE_OPENED) == stream->state) {
					c->write->ready = 1;
					c->fd = -1;
					if (stream->waiting) {
						stream->waiting = 0;
						ngx_queue_remove(&stream->queue_in_waiting);
					}
					ngx_post_event(c->write, &ngx_posted_events);
				}
				--h2c->processing;
			}
			++i;
			++queue;
		}
		c = h2c->data;
		ngx_post_event(c->read, &ngx_posted_events);
	}
	frame = h2c->send.first_frame;
	while (frame) {
		next = frame->data;
		ngx_http2_free(frame);
		frame = next;
	}
}

static void ngx_http_upstream_http2_frame_read_handler(ngx_event_t* rev) {
	ngx_connection_t* c = rev->data;
	ngx_http2_connection_t* h2c = c->data;
	ngx_http2_server_t *server = h2c->server;
	ngx_http_upstream_http2_srv_conf_t* scf = server->conf;
	u_char* p, *end;
	ngx_uint_t mlen, len;
	ngx_http2_handler_pt handler;
	ssize_t rc;

	mlen = h2c->recv.min_len;
	len = h2c->recv.len;
	handler = h2c->recv.handler;
	for (;;) {
		if (len >= mlen) {
			rc = handler(h2c);
			if (rc == NGX_AGAIN) {
				ngx_http2_post_need_buffer_event(scf, rev);
				break;
			} else if (rc == NGX_ERROR) {
				ngx_http_updateam_Http2_read_error(h2c);
				return;
			} else if (rc == NGX_DONE) {
				return;
			}
			mlen = h2c->recv.min_len;
			len = h2c->recv.len;
			handler = h2c->recv.handler;
		} else {
			if (h2c->recv.readable_size < mlen) {
				ngx_memcpy(h2c->recv.buffer, h2c->recv.pos, len);
				h2c->recv.readable_size += (h2c->recv.pos - h2c->recv.buffer);
				h2c->recv.pos = h2c->recv.buffer;
			}
			rc = c->recv(c, h2c->recv.pos + len, h2c->recv.readable_size);
			if (rc == NGX_ERROR) {
				ngx_http_updateam_Http2_read_error(h2c);
				return;
			} else if (rc == NGX_AGAIN) {
				return;
			} else if (rc) {
				h2c->recv.len += rc;
				len = h2c->recv.len;
				h2c->recv.readable_size -= rc;
			} else {
				ngx_http_updateam_Http2_read_error(h2c);
				return;
			}
		}
	}
}

static u_char ngx_http2_last_goaway[] = "\x00\x00\x08\x07\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

static void ngx_http_upstream_http2_gracefuly_close(ngx_event_t* wev) {
	ngx_connection_t* c = wev->data;
	ngx_http2_connection_t* h2c = c->data;
	ngx_http2_server_t *server = h2c->server;
	ngx_http_upstream_http2_srv_conf_t* scf = server->conf;
	ssize_t rc;

	wev->handler = ngx_http_upstream_http2_gracefuly_close;
	if (!h2c->send.pos) {
		h2c->send.pos = &ngx_http2_last_goaway[0];
		h2c->send.len = sizeof(ngx_http2_last_goaway);
	}

	rc = c->send(c, h2c->send.pos, h2c->send.len);
	if (rc == NGX_ERROR) {
		goto h2c_free;
	} else if (rc == NGX_AGAIN) {
		return;
	} else {
		if (h2c->send.len == rc) {
			goto h2c_free;
		} else {
			h2c->send.pos += rc;
			h2c->send.len -= rc;
			return;
		}
	}

	h2c_free:

	c->write->handler = ngx_http_upstream_http2_block_io;
	c->read->handler = ngx_http_upstream_http2_block_io;

	if (h2c->recv.buffer) {
		ngx_http2_free_frame(h2c->recv.buffer);
		h2c->recv.buffer = NULL;
	}
	ngx_close_connection(c);
	if(h2c->recv.hpack.data){
			ngx_free(h2c->recv.hpack.data);
			h2c->recv.hpack.data = NULL;
		}
	h2c->data = scf->free_connections;
	scf->free_connections = h2c;

}

static void ngx_http_upstream_http2_frame_write_handler(ngx_event_t* wev) {
	ngx_connection_t* c = wev->data;
	ngx_http2_connection_t* h2c = c->data;
	ngx_http2_server_t *server = h2c->server;
	ngx_http_upstream_http2_srv_conf_t* scf = server->conf;
	u_char* p, *end;
	ssize_t rc;
	ngx_http2_stream_t* stream;
	ngx_uint_t pn, pv;
	ngx_http2_frame_t * frame = h2c->send.first_frame;
	if (frame != NULL) {
		for (;;) {
			rc = c->send(c, h2c->send.pos, h2c->send.len);
			if (rc == NGX_ERROR) {
				ngx_http_updateam_Http2_write_error(h2c);
				return;
			} else if (rc == NGX_AGAIN) {
				return;
			} else {
				if (h2c->send.len == rc) {
					p = &frame->payload;
					if (p[3] == NGX_HTTP2_PING_FRAME) {
						if (p[4] & NGX_HTTP2_ACK_FLAG) {
							--h2c->send.num_ping_ack;
						} else {
							--h2c->send.num_ping;
						}
					} else if (p[3] == NGX_HTTP2_DATA_FRAME && (!(p[4] & NGX_HTTP2_END_STREAM_FLAG))) {
						stream = ngx_http_upstream_http2_find_stream(h2c, (p[5] << 24) | (p[5] << 16) | (p[5] << 8) | p[5]);
						if (stream && (stream->send_window > 0) && (!stream->waiting)) {
							ngx_post_event(&stream->connection.write, &ngx_posted_events);
						}
					}

					frame = frame->data;
					if (frame) {
						ngx_http2_free_frame(h2c->send.first_frame);
						h2c->send.first_frame = frame;
						p = &frame->payload;
						h2c->send.pos = p;
						h2c->send.len = 9 + ((p[0] << 16) | (p[1] << 8) + p[2]);
					} else {
						break;
					}
				} else {
					h2c->send.pos += rc;
					h2c->send.len -= rc;
					return;
				}
			}
		}
		h2c->send.first_frame = h2c->send.last_frame = NULL;
	}
	if (h2c->send_goaway) {
		c->write->handler = ngx_http_upstream_http2_block_io;
		ngx_close_connection(c);
		if(h2c->recv.hpack.data){
				ngx_free(h2c->recv.hpack.data);
				h2c->recv.hpack.data = NULL;
			}
		h2c->data = scf->free_connections;
		scf->free_connections = h2c;
		return;
	}
	if (h2c->processing) {
		return;
	}
	if (h2c->max_streams == 0) {
		h2c->send_frame = ngx_http_upstream_http2_send_queue_frame_ignore;
		h2c->send_ping = ngx_http_upstream_http2_send_ping_frame_ignore;
		h2c->send_headers = ngx_http_upstream_http2_send_header_frame_ignore;
		h2c->send_goaway = 1;
		ngx_http_upstream_http2_gracefuly_close(wev);
	} else {
		//TODO idle_timeout
	}
}

static void ngx_http_upstream_http2_first_read_handler(ngx_event_t* rev) {
	ngx_connection_t* c = rev->data;
	ngx_http2_connection_t* h2c = c->data;
	ngx_http2_server_t *server = h2c->server;
	ngx_http_upstream_http2_srv_conf_t* scf = server->conf;
	u_char* p, *end;
	ssize_t capacity_size;
	ssize_t rc;
	ngx_uint_t pn, pv;
	ngx_http2_frame_t * frame;

	if (!h2c->recv.buffer) {
		h2c->recv.buffer = ngx_http2_get_frame(scf);
		if (h2c->recv.buffer) {
			h2c->recv.pos = h2c->recv.buffer;
			h2c->recv.readable_size = scf->buffer_size;
		} else {
			ngx_http2_post_need_buffer_event(scf, rev);
			return;
		}
	}
	p = h2c->recv.pos + h2c->recv.len;
	rc = c->recv(c, p, h2c->recv.readable_size);
	if (rc == NGX_ERROR) {
		goto failed;
	} else if (rc == NGX_AGAIN) {
		return;
	} else if (rc) {
		h2c->recv.len += rc;
		h2c->recv.readable_size -= rc;
		if (h2c->recv.len >= 9) {
			p = h2c->recv.pos;
			ngx_http2_parse_readed_frame_head(h2c, p);
			if (h2c->recv.type != 0x04) {
				goto failed;
			}
			if (h2c->recv.payload_len % 6 != 0) {
				goto failed;
			}
			if (h2c->recv.payload_len > 48) {
				goto failed;
			}
			if (h2c->recv.len >= (h2c->recv.payload_len + 9)) {
				p += 9;
				end = p + h2c->recv.payload_len;
				while (p < end) {
					pn = p[0] << 8 | p[1];
					pv = (p[2] << 24) | (p[3] << 16) | (p[4] << 8) | (p[5]);
					p += 6;
					if (pn == 0x4) {
						if (pv > (((1U << 31) - 1))) {
							goto failed;
						}
						h2c->init_window = pv;
						h2c->send.send_window = pv;
					} else if (pn == 0x03) {
						h2c->max_streams = pv > scf->max_streams ? scf->max_streams : pv;
					} else if (pn == 0x01) {
						if(pv>0){
							if(ngx_http2_hpack_init(&h2c->recv.hpack,pv)){
								goto failed;
							}
						}
					}
				}

				h2c->recv.len = end - h2c->recv.pos;
				h2c->recv.pos = end;

				ngx_memzero(h2c->send.first_frame, 9 + sizeof(void*));

				h2c->send.last_frame = h2c->send.first_frame;

				p = &h2c->send.first_frame->payload;
				p[3] = NGX_HTTP2_SETTINGS_FRAME;
				p[4] = NGX_HTTP2_ACK_FLAG;

				h2c->next_sid = 1;
				h2c->processing = 0;
				server->connection = NULL;

				ngx_http_upstream_http2_accecpt_streams(h2c);
				rev->handler = ngx_http_upstream_http2_frame_read_handler;
				h2c->recv.min_len = 9;
				h2c->recv.handler = ngx_http_upstream_http2_read_frame_head;
				c->write->handler = ngx_http_upstream_http2_frame_write_handler;
				ngx_post_event(c->write, &ngx_posted_events);
				ngx_http_upstream_http2_frame_read_handler(rev);
			}
		}
	} else {
		goto failed;
	}
	return;

	failed: ngx_http2_free_frame(scf, h2c->send.first_frame);
	ngx_http2_free_frame(scf, h2c->recv.buffer);
	rev->handler = ngx_http_upstream_http2_block_io;
	if(h2c->recv.hpack.data){
		ngx_free(h2c->recv.hpack.data);
		h2c->recv.hpack.data = NULL;
	}
	ngx_close_connection(c);
	if(h2c->recv.hpack.data){
			ngx_free(h2c->recv.hpack.data);
			h2c->recv.hpack.data = NULL;
		}
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
			ngx_http2_post_need_buffer_event(scf, wev);
			return;
		}
	}
	rc = c->send(c, h2c->send.pos, h2c->send.len);
	if (rc == NGX_ERROR) {
		ngx_http2_free_frame(scf, h2c->send.first_frame);
		wev->handler = ngx_http_upstream_http2_block_io;
		ngx_close_connection(c);
		h2c->data = scf->free_connections;
		scf->free_connections = h2c;
		ngx_http_upstream_http2_close_stream_in_server(server);
		server->connection = NULL;
	} else if (rc == NGX_AGAIN) {
		return;
	} else if (h2c->send.len == rc) {
		wev->handler = ngx_http_upstream_http2_block_io;
		c->read->handler = ngx_http_upstream_http2_first_read_handler;
		ngx_http_upstream_http2_first_read_handler(c->read);
	} else if (rc) {
		h2c->send.pos += rc;
		h2c->send.len -= rc;
	}
}

void ngx_http_upstream_http2_connection_init(ngx_http2_connection_t* h2c) {
	ngx_int_t i;
	ngx_connection_t* c = h2c->data;
	ngx_queue_t* queue = &h2c->streams;
	h2c->processing = 0;
	h2c->max_streams = h2c->server->conf->max_streams;
	h2c->headers_table_size = 4096;
	c->read->handler = ngx_http_upstream_http2_block_io;
	c->write->handler = ngx_http_upstream_http2_first_write_handler;
	ngx_queue_init(&h2c->queue);
	ngx_memzero(&h2c->send, sizeof(ngx_http2_connection_send_part_t));
	ngx_memzero(&h2c->recv, sizeof(ngx_http2_connection_recv_part_t));
	h2c->recv_error = 0;
	h2c->recv_goaway = 0;
	h2c->send_error = 0;
	h2c->send_goaway = 0;
	h2c-> recv_index=0;
	h2c->recv_paser_value=0;
	queue = &h2c->streams;
	for (i = 0; i <= h2c->server->conf->sid_mask; ++i) {
		ngx_queue_init(queue);
		++queue;
	}
	queue = h2c->idle_streams;
	ngx_queue_init(queue);
	queue = &h2c->send.flow_control_queue;
	ngx_queue_init(queue);
	h2c->send_frame = ngx_http_upstream_http2_send_queue_frame;
	h2c->send_ping = ngx_http_upstream_http2_send_ping_frame;
	h2c->send_headers = ngx_http_upstream_http2_send_header_frame;
}
