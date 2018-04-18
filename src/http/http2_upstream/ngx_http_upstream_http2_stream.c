/*
 * ngx_http_upstream_http2_stream.c
 *
 *  Created on: Apr 10, 2018
 *      Author: root
 */

#include <ngx_http_upstream_http2.h>

ssize_t ngx_http2_io_error(ngx_connection_t* c, u_char* buf, size_t size) {
	return NGX_ERROR;
}
ssize_t ngx_http2_read_again(ngx_connection_t* c, u_char* buf, size_t size) {
	ngx_event_t * rev = c->read;
	rev->ready = 0;
	return NGX_AGAIN;
}
ssize_t ngx_http2_send_again(ngx_connection_t* c, u_char* buf, size_t size) {
	ngx_event_t * rev = c->write;
	rev->ready = 0;
	return NGX_AGAIN;
}

ssize_t ngx_http2_stream_recv(ngx_connection_t* c, u_char* buf, size_t size) {
	ngx_http2_stream_t *stream = c->data;
	size_t len;
	if (c->error) {
		return NGX_ERROR;
	} else if (stream->recv_buffer == NULL) {
		return 0;
	}
	len = stream->recv_last - stream->recv_pos;
	if (len) {
		if (size < len) {
			ngx_memcpy(buf, stream->recv_pos, size);
			stream->recv_pos += size;
			return size;
		} else {
			ngx_memcpy(buf, stream->recv_pos, len);
			stream->recv_pos = stream->recv_last = stream->recv_buffer;
			c->read->ready = 0;
			return len;

		}
	}
	return NGX_AGAIN;

}
ssize_t ngx_http2_stream_send(ngx_connection_t* c, u_char* buf, size_t size) {
	ngx_http2_stream_t *stream = c->data;
	size_t len;

	if (c->error) {
		return NGX_ERROR;
	} else if (stream->send_buffer == NULL) {
		return size;
	}

	len = stream->send_last - stream->send_pos;
	if (len) {
		if (len < size) {
			ngx_memcpy(stream->send_pos, buf, len);
			stream->send_pos = stream->send_last;
			//append

			return len;
		}

	}

	return NGX_AGAIN;

}

ngx_http2_stream_t* ngx_http_upstream_http2_stream_create(ngx_http_request_t* request) {
	ngx_event_t* rev;
	ngx_event_t* wev;
	ngx_connection_t* c;

	ngx_http2_stream_t* stream = ngx_pcalloc(request->pool, sizeof(ngx_http2_stream_t));
	if (stream) {
		rev = &stream->read;
		wev = &stream->write;
		c = &stream->connection;
		c->data = stream;
		rev->data = c;
		rev->ready = 0;
		wev->data = c;
		wev->ready = 0;
		rev->active = 1;
		rev->active = 1;
		c->read = rev;
		c->write = wev;
		c->recv = ngx_http2_stream_recv;
		c->send = ngx_http2_stream_send;
		c->sndlowat = 1;
		stream->send_buffer = stream->send_pos = stream->send_last = stream->recv_buffer = stream->recv_pos = stream->recv_last = stream;
	}

	return stream;

}

void ngx_http_upstream_http2_server_add_stream(ngx_http2_server_t* server, ngx_http2_stream_t* stream) {
	ngx_connection_t* c = &stream->connection;
	ngx_event_t* rev = c->read;
	ngx_event_t* wev = c->write;
	c->error = 0;
	c->recv = ngx_http2_read_again;
	c->send = ngx_http2_send_again;
	stream->state = NGX_HTTP2_STREAM_STATE_WATTING_IN_SERVER;
	ngx_queue_insert_tail(&server->stream_queue, &stream->queue);
}
