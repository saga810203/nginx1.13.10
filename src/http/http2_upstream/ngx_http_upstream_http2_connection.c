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
		stream->connection->error = 1;
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
		h2c->send.len = 9 + ((p[0] << 16) | (p[1] << 8) + p[2]);
		ngx_post_event(c->write, &ngx_posted_events);
		if (ack) {
			++h2c->send.num_ping_ack;
		} else {
			++h2c->send.num_ping;
		}
	}
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

static int ngx_http_upstream_http2_read_frame_head(ngx_http2_connection_t* h2c) {

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
				c->error = 1;
				if (((u_char) NGX_HTTP2_STREAM_STATE_LOCAL_CLOSED) == stream->state) {
					c->read->ready = 1;
					ngx_post_event(c->read, &ngx_posted_events);
				} else {
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
		ngx_http_upstream_http2_send_queue_frame(h2c, frame);
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

	h2c->send_error = 1;
	if (h2c->processing < h2c->max_streams) {
		ngx_queue_remove(&h2c->queue);
	}
	h2c->max_streams = 0;
	c->write->handler = ngx_http_upstream_http2_block_io;
	if (h2c->recv_error) {
		ngx_close_connection(c);
		h2c->data = scf->free_connections;
		scf->free_connections = h2c;
	} else {
		queue = &h2c->idle_streams;
		for (q = ngx_queue_head(queue); q != ngx_queue_sentinel(queue); q = ngx_queue_next(q)) {
			stream = ngx_queue_data(q, ngx_http2_stream_t, queue);
			ngx_queue_remove(q);
			c = &stream->connection;
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
				c->error = 1;
				if (((u_char) NGX_HTTP2_STREAM_STATE_OPENED) == stream->state) {
					c->write->ready = 1;
					ngx_post_event(c->write, &ngx_posted_events);
				}
				--h2c->processing;
			}
			++i;
			++queue;
		}
		if(!c->read->accept){
			ngx_post_event(c->read, &ngx_posted_events);
		}
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
				if(!c->read->accept){
					c->read->accept = 1;
					ngx_queue_insert_tail(&scf->need_free_frame_queue, &rev->queue);
				}
				break;
			} else if (rc == NGX_ERROR) {
				goto failed;
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
				goto failed;
			} else if (rc == NGX_AGAIN) {
				goto again;
			} else if (rc) {
				h2c->recv.len += rc;
				len = h2c->recv.len;
				h2c->recv.readable_size -= rc;
			} else {
				goto failed;
			}
		}
	}
	return;
	again: if (ngx_handle_read_event(rev, 0) != NGX_OK) {
		goto failed;
	}
	return;
	failed: ngx_http_updateam_Http2_read_error(h2c);
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
		if (ngx_handle_write_event(wev, 0) != NGX_OK) {
			goto h2c_free;
		}
		return;
	} else {
		if (h2c->send.len == rc) {
			goto h2c_free;
		} else {
			h2c->send.pos += rc;
			h2c->send.len -= rc;
			if (ngx_handle_write_event(wev, 0) != NGX_OK) {
				goto h2c_free;

			}
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
	ngx_uint_t pn, pv;
	ngx_http2_frame_t * frame = h2c->send.first_frame;
	if (frame != NULL) {
		for (;;) {
			rc = c->send(c, h2c->send.pos, h2c->send.len);
			if (rc == NGX_ERROR) {
				ngx_http_updateam_Http2_write_error(h2c);
				return;
			} else if (rc == NGX_AGAIN) {
				if (ngx_handle_write_event(wev, 0) != NGX_OK) {
					ngx_http_updateam_Http2_write_error(h2c);
				}
				return;
			} else {
				if (h2c->send.len == rc) {
					frame = frame->data;
					if (frame) {
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
					if (ngx_handle_write_event(wev, 0) != NGX_OK) {
						ngx_http_updateam_Http2_write_error(h2c);

					}
					return;
				}
			}
		}
		h2c->send.first_frame = h2c->send.last_frame = NULL;
	}
	if (h2c->send_goaway) {
		c->write->handler = ngx_http_upstream_http2_block_io;
		ngx_close_connection(c);
		h2c->data = scf->free_connections;
		scf->free_connections = h2c;
		return;
	}
	if (h2c->processing) {
		return;
	}
	if (h2c->max_streams == 0) {
		h2c->send_goaway = 1;
		ngx_http_upstream_http2_gracefuly_close(wev);
	}else{
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
			rev->accept = 1;
			ngx_queue_insert_tail(&scf->need_free_frame_queue, &rev->queue);
			return;
		}
	}

	p = h2c->recv.pos + h2c->recv.len;
	rc = c->recv(c, p, h2c->recv.readable_size);
	if (rc == NGX_ERROR) {
		goto failed;
	} else if (rc == NGX_AGAIN) {
		goto again;
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
						;
					}
				}

				h2c->recv.len = end - h2c->recv.pos;
				h2c->recv.pos = end;

				ngx_memzero(h2c->send.first_frame, 9 + sizeof(void*));

				h2c->send.last_frame = h2c->send.first_frame;

				p = &h2c->send.first_frame;
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
		goto again;
	} else {
		goto failed;
	}
	return;

	again: if (ngx_handle_read_event(rev, 0) != NGX_OK) {
		goto failed;
	}
	return;
	failed: ngx_http2_free_frame(scf, h2c->send.first_frame);
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
			wev->accept=1;
			ngx_queue_insert_tail(&scf->need_free_frame_queue, &wev->queue);
			return;
		}
	}
	rc = c->send(c, h2c->send.pos, h2c->send.len);
	if (rc == NGX_ERROR) {
		goto failed;
	}
	if (rc == NGX_AGAIN) {
		if (ngx_handle_write_event(wev, 0) != NGX_OK) {
			goto failed;
		}
		return;
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
	failed: ngx_http2_free_frame(scf, h2c->send.first_frame);
	wev->handler = ngx_http_upstream_http2_block_io;
	ngx_close_connection(c);
	h2c->data = scf->free_connections;
	scf->free_connections = h2c;
	ngx_http_upstream_http2_close_stream_in_server(server);
	server->connection = NULL;

}

void ngx_http_upstream_http2_connection_init(ngx_http2_connection_t* h2c) {
	ngx_int_t i;
	ngx_connection_t* c = h2c->data;
	ngx_queue_t* queue = &h2c->streams;
	h2c->processing = 0;
	h2c->max_streams = h2c->server->conf->max_streams;
	c->read->handler = ngx_http_upstream_http2_block_io;
	c->write->handler = ngx_http_upstream_http2_first_write_handler;
	ngx_queue_init(&h2c->queue);
	ngx_memzero(&h2c->send, sizeof(ngx_http2_connection_send_part_t));
	ngx_memzero(&h2c->recv, sizeof(ngx_http2_connection_recv_part_t));
	h2c->recv_error = 0;
	h2c->recv_goaway = 0;
	h2c->send_error = 0;
	h2c->send_goaway = 0;
	queue = &h2c->streams;
	for (i = 0; i <= h2c->server->conf->sid_mask; ++i) {
		ngx_queue_init(queue);
		++queue;
	}
	queue = h2c->idle_streams;
	ngx_queue_init(queue);
	queue = &h2c->send.flow_control_queue;
	ngx_queue_init(queue);
}
