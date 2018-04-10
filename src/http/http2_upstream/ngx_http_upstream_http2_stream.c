/*
 * ngx_http_upstream_http2_stream.c
 *
 *  Created on: Apr 10, 2018
 *      Author: root
 */

#include <ngx_http_upstream_http2.h>

 void ngx_http_upstream_http2_server_add_stream(ngx_http2_server_t* server,ngx_http2_stream_t* stream){

	 ngx_queue_insert_tail(&server->stream_queue, &stream->queue);

	 //TODO
 }
