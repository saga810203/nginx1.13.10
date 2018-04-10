/*
 * ngx_http_upstream_http2.h
 *
 *  Created on: Apr 9, 2018
 *      Author: root
 */

#ifndef _NGX_HTTP_UPSTREAM_HTTP2_H_INCLUDE_
#define _NGX_HTTP_UPSTREAM_HTTP2_H_INCLUDE_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_v2.h>





typedef struct ngx_http_upstream_http2_srv_conf_s ngx_http_upstream_http2_srv_conf_t;
typedef struct ngx_http2_server_s ngx_http2_server_t;
typedef struct ngx_http_upstream_http2_peer_data_s ngx_http_upstream_http2_peer_data_t;

typedef struct ngx_http2_connection_s ngx_http2_connection_t;
typedef struct ngx_http2_stream_s ngx_http2_stream_t;


struct ngx_http_upstream_http2_srv_conf_s {

	ngx_pool_t *pool;

	ngx_http_v2_header_t indexed_headers[16];
	size_t idx_of_dyn_headers;
	ngx_str_t first_uri;

	ngx_http_upstream_init_pt original_init_upstream;
	ngx_http_upstream_init_peer_pt original_init_peer;

	ngx_http2_server_t* servers;
	int servers_size;

	int rcvbuf;



	int max_conns;

	int use_conns;
	int sid_mask;
	int http2_connection_pool_size;

	ngx_queue_t free_connections;

	ngx_log_t *log;
	int pool_size;
	int buffer_size;
	int buffer_count;
	int buffer_alloc_count;
	void *buffer;
	ngx_queue_t buffer_queue;
};

struct ngx_http2_server_s {
	ngx_http_upstream_http2_srv_conf_t *conf;
	ngx_queue_t connection_queue;
	ngx_http2_connection_t *connection;
	socklen_t socklen;
	ngx_sockaddr_t sockaddr;

	ngx_queue_t stream_queue;
};

struct ngx_http_upstream_http2_peer_data_s {
	ngx_http_upstream_http2_srv_conf_t* conf;
	ngx_http2_server_t* server;
	ngx_http_request_t *request;
	void *data;
	ngx_event_get_peer_pt original_get_peer;
	ngx_event_free_peer_pt original_free_peer;
};

struct ngx_http2_connection_s {
	ngx_connection_t connection;
    ngx_event_t      read;
    ngx_event_t      write;
	ngx_http2_server_t *server;

	ngx_queue_t queue;

	ngx_uint_t max_streams;

	ngx_uint_t processing;

	size_t send_window;

	size_t recv_window;

	size_t init_window;

	size_t frame_size;


	ngx_pool_t *pool;




	/*last element*/

	ngx_queue_t streams;
};
struct ngx_http2_stream_s{
	ngx_connection_t connection;
	ngx_http2_connection_t * h2c;
	ngx_http_request_t*  request;
	ngx_event_t read;
	ngx_event_t write;
	ngx_uint_t id;

	ngx_queue_t     queue_in_connection;

    ssize_t                          send_window;
	size_t                           recv_window;

	ngx_buf_t                       *preread;

	ngx_http_v2_out_frame_t         *free_frames;
	ngx_chain_t                     *free_frame_headers;
	ngx_chain_t                     *free_bufs;

	ngx_queue_t                      queue;
	/*
	 *   0   in server wait  connect;
	 *
	 * */
	unsigned char					state;

	ngx_array_t                     *cookies;

	    ngx_pool_t                      *pool;

	    unsigned                         waiting:1;
	    unsigned                         blocked:1;
	    unsigned                         exhausted:1;
	    unsigned                         in_closed:1;
	    unsigned                         out_closed:1;
	    unsigned                         rst_sent:1;
	    unsigned                         no_flow_control:1;
	    unsigned                         skip_data:1;
};




#define ngx_http_upstream_http2_connection_free(c)  ngx_queue_insert_head(&(c)->server->conf->free_connections,&(c)->queue);

 ngx_int_t ngx_http_upstream_init_http2_peer(ngx_http_request_t *r, ngx_http_upstream_srv_conf_t *us);
 ngx_int_t ngx_http_upstream_get_http2_peer(ngx_peer_connection_t *pc, void *data);
 void ngx_http_upstream_free_http2_peer(ngx_peer_connection_t *pc, void *data, ngx_uint_t state);

 void *ngx_http_upstream_http2_create_conf(ngx_conf_t *cf);

 ngx_http2_stream_t* ngx_http_upstream_http2_stream_create(ngx_http_request_t* request);

 ngx_http2_connection_t* ngx_http_upstream_http2_connection_create(ngx_http_upstream_http2_srv_conf_t *us);


 ngx_int_t ngx_http_upstream_http2_connection_connect(ngx_http2_connection_t* c);
 void ngx_http_upstream_http2_connection_add_stream(ngx_http2_stream_t* stream);
 void ngx_http_upstream_http2_server_add_stream(ngx_http2_server_t* server,ngx_http2_stream_t* stream);


#endif /* _NGX_HTTP_UPSTREAM_HTTP2_H_INCLUDE_ */
