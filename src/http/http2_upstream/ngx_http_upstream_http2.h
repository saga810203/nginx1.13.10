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

#define NGX_HTTP2_MAX_FLOW_CONTROL_SIZE  2147483647U
#define NGX_HTTP2_HALF_FLOW_CONTROL_SIZE 1073741673U


#define NGX_HTTP2_SETTINGS_ACK_SIZE            0
#define NGX_HTTP2_RST_STREAM_SIZE              4
#define NGX_HTTP2_PRIORITY_SIZE                5
#define NGX_HTTP2_PING_SIZE                    8
#define NGX_HTTP2_GOAWAY_SIZE                  8
#define NGX_HTTP2_WINDOW_UPDATE_SIZE           4

#define NGX_HTTP2_NO_FLAG              0x00
#define NGX_HTTP2_ACK_FLAG             0x01
#define NGX_HTTP2_END_STREAM_FLAG      0x01
#define NGX_HTTP2_END_HEADERS_FLAG     0x04
#define NGX_HTTP2_PADDED_FLAG          0x08
#define NGX_HTTP2_PRIORITY_FLAG        0x20

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


#define NGX_HTTP2_STREAM_STATE_WATTING_IN_SERVER   0x00
#define NGX_HTTP2_STREAM_STATE_WATTING_IN_CONNECTION   0x01
#define NGX_HTTP2_STREAM_STATE_OPENED   0x02
#define NGX_HTTP2_STREAM_STATE_LOCAL_CLOSED   0x03
#define NGX_HTTP2_STREAM_STATE__CLOSED   0x04


typedef struct ngx_http_upstream_http2_srv_conf_s ngx_http_upstream_http2_srv_conf_t;
typedef struct ngx_http2_server_s ngx_http2_server_t;
typedef struct ngx_http_upstream_http2_peer_data_s ngx_http_upstream_http2_peer_data_t;

typedef struct ngx_http2_connection_send_part_s ngx_http2_connection_send_part_t;
typedef struct ngx_http2_connection_recv_part_s ngx_http2_connection_recv_part_t;
typedef struct ngx_http2_connection_s ngx_http2_connection_t;
typedef struct ngx_http2_stream_s ngx_http2_stream_t;
typedef struct ngx_http2_frame_s ngx_http2_frame_t;
typedef struct ngx_http2_hpack_s ngx_http2_hpack_t;


typedef int (*ngx_http2_handler_pt) (ngx_http2_connection_t *h2c);

typedef void (*ngx_http2_send_frame)(ngx_http2_connection_t* h2c, ngx_http2_frame_t* frame);
typedef void (*ngx_http2_send_ping)(ngx_http2_connection_t* h2c, ngx_http2_frame_t* frame,int ack);
typedef void (*ngx_http2_send_header)(ngx_http2_connection_t* h2c, ngx_http2_frame_t* begin,ngx_http2_frame_t* end);







typedef struct {
	ngx_queue_t queue;
    ngx_str_t                        name;
    ngx_str_t                        value;
} ngx_http2_header_t;

struct ngx_http_upstream_http2_srv_conf_s {

	ngx_pool_t *pool;

	ngx_http2_header_t indexed_headers[16];
	size_t idx_of_dyn_headers;
	ngx_str_t first_uri;

	ngx_http_upstream_init_pt original_init_upstream;
	ngx_http_upstream_init_peer_pt original_init_peer;

	ngx_http2_server_t* servers;
	int servers_size;
	ngx_uint_t max_streams;

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
	ngx_http2_frame_t *free_frames;
	ngx_queue_t need_free_frame_queue;
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

struct ngx_http2_frame_s {
	void* data;
	u_char payload;
};

#define ngx_http2_parse_readed_frame_head(h2c,p) (h2c)->recv.payload_len = ((p)[0]<< 16) | ((p)[1]<<8)|((p)[2]); \
		(h2c)->recv.type = (p[3]);\
		(h2c)->recv.flag = (p[4]);\
		(h2c)->recv.sid =((p)[5]<< 24) | ((p)[6]<< 16) | ((7)[1]<<8)|((p)[8]);


struct ngx_http2_hpack_s{
		uint32_t  size;
		uint32_t  capacity;
		u_char*   data;
		u_char*   next;


		u_char**   index;
		uint32_t  rds_headers;
		uint32_t  bytes_headers;
};


struct ngx_http2_connection_recv_part_s {
		ngx_uint_t sid;
		ngx_uint_t payload_len;
		u_char type;
		u_char flag;

		uint8_t padding;

		ngx_uint_t  min_len;
		ngx_http2_handler_pt handler;

		size_t recv_window;
		u_char* buffer;
		u_char* pos;
		ngx_uint_t len;
		ngx_uint_t readable_size;

		ngx_http2_hpack_t hpack;
		ngx_queue_t headers_queue;
		ngx_http2_header_t* c_header;
		uint32_t res_status;
		ngx_pool_t* pool;
};
struct ngx_http2_connection_send_part_s {
	size_t send_window;
	u_char* pos;
	ngx_uint_t len;

	ngx_http2_frame_t* first_frame;
	ngx_http2_frame_t* last_frame;


	ngx_queue_t flow_control_queue;

	ngx_uint_t num_ping;
	ngx_uint_t num_ping_ack;


};
struct ngx_http2_connection_s {
	void* data;
	ngx_http2_server_t *server;
	ngx_queue_t queue;
	ngx_uint_t max_streams;
	ngx_uint_t processing;

	size_t headers_table_size;

	size_t init_window;

	size_t frame_size;

	ngx_pool_t *pool;

	ngx_uint_t next_sid;

	ngx_http2_connection_recv_part_t recv;
	ngx_http2_connection_send_part_t send;
	unsigned recv_error :1;
	unsigned recv_goaway :1;
	unsigned send_error :1;
	unsigned send_goaway :1;
	unsigned recv_index:1;
	unsigned recv_paser_value:1;





	ngx_queue_t idle_streams;

	ngx_http2_send_frame send_frame;
	ngx_http2_send_ping send_ping;
	ngx_http2_send_ping send_headers;



	/*last element*/

	ngx_queue_t streams;
};
struct ngx_http2_stream_s {
	ngx_connection_t connection;
	ngx_http2_connection_t * h2c;
	ngx_http_request_t* request;
	ngx_event_t read;
	ngx_event_t write;
	ngx_uint_t id;

	ngx_queue_t queue_in_waiting;

	ssize_t send_window;
	size_t recv_window;

	ngx_buf_t *preread;

	ngx_http_v2_out_frame_t *free_frames;
	ngx_chain_t *free_frame_headers;
	ngx_chain_t *free_bufs;

	ngx_queue_t queue;
	/*
	 *   0   in server wait  connect;
	 *
	 * */
	unsigned char state;    //0: waiting in server    1: waiting in connection  2:open  3  local close    4 close

	u_char* recv_buffer;
	u_char* recv_pos;
	u_char* recv_last;

	u_char* send_buffer;
	u_char* send_pos;
	u_char* send_last;

	ngx_array_t *cookies;

	ngx_pool_t *pool;

	unsigned waiting :1;
	unsigned blocked :1;
	unsigned exhausted :1;
	unsigned in_closed :1;
	unsigned out_closed :1;
	unsigned rst_sent :1;
	unsigned no_flow_control :1;
	unsigned skip_data :1;
};

ngx_int_t ngx_http_upstream_init_http2_peer(ngx_http_request_t *r, ngx_http_upstream_srv_conf_t *us);
ngx_int_t ngx_http_upstream_get_http2_peer(ngx_peer_connection_t *pc, void *data);
void ngx_http_upstream_free_http2_peer(ngx_peer_connection_t *pc, void *data, ngx_uint_t state);

void *ngx_http_upstream_http2_create_conf(ngx_conf_t *cf);

ngx_http2_stream_t* ngx_http_upstream_http2_stream_create(ngx_http_request_t* request);

ngx_http2_connection_t* ngx_http_upstream_http2_connection_create(ngx_http_upstream_http2_srv_conf_t *us);

void ngx_http_upstream_http2_close_stream_in_server(ngx_http2_server_t* server);
void ngx_http_upstream_http2_connection_connect(ngx_http2_connection_t* c);

void ngx_http_upstream_http2_connection_init(ngx_http2_connection_t* c);

void ngx_http_upstream_http2_connection_add_stream(ngx_http2_stream_t* stream);
void ngx_http_upstream_http2_server_add_stream(ngx_http2_server_t* server, ngx_http2_stream_t* stream);

ssize_t ngx_http2_stream_recv(ngx_connection_t* c, u_char* buf, size_t size);
ssize_t ngx_http2_stream_send(ngx_connection_t* c, u_char* buf, size_t size);

int32_t ngx_http2_hpack_init(ngx_http2_hpack_t* hpack,uint32_t size);
int32_t ngx_http2_hpack_add(ngx_http2_hpack_t* hpack,ngx_str_t* name,ngx_str_t* value);



int32_t ngx_http2_hpack_resize(ngx_http2_hpack_t* hpack,uint32_t new_size);
int32_t ngx_http2_hpack_get_index_header(ngx_http2_connection_t* h2c,int32_t idx,int32_t nameonly);


static ngx_inline ngx_http2_frame_t* ngx_http2_get_frame(ngx_http_upstream_http2_srv_conf_t* scf) {
	ngx_http2_frame_t* frame = scf->free_frames;
	if (frame) {
		scf->free_frames = frame->data;
	} else {
		if (scf->buffer_alloc_count == scf->buffer_count) {
			return NULL;
		}
		frame = ngx_pcalloc(scf->pool, scf->buffer_size);
		if (frame) {
			++scf->buffer_alloc_count;
		}
	}
	return frame;
}

static ngx_inline void ngx_http2_post_need_buffer_events(ngx_http_upstream_http2_srv_conf_t* scf,ngx_event_t* event){
	if(event->posted){
		ngx_queue_remove(&event->queue);
	}else{
		event->posted = 1;
	}
	event->active = 0;
	ngx_queue_insert_tail(&scf->need_free_frame_queue,&event->queue);
}

static ngx_inline void ngx_http2_free_frame(ngx_http_upstream_http2_srv_conf_t* scf, ngx_http2_frame_t* frame) {
	ngx_queue_t *queue = &scf->need_free_frame_queue;
	ngx_event_t* event;
	frame->data = scf->free_frames;
	scf->free_frames = frame;
	if (!ngx_queue_empty(queue)) {
		queue = ngx_queue_head(queue);
		event = ngx_queue_data(queue, ngx_event_t, queue);
		ngx_queue_remove(queue);
		event->active = 1;
		event->posted= 0;
		event->handler(event);
        //ngx_queue_insert_tail(&ngx_posted_events, &event->queue);
	}
}

static ngx_inline ngx_http2_stream_t* ngx_http_upstream_http2_find_stream(ngx_http2_connection_t* h2c,ngx_uint_t id){
	ngx_http2_stream_t* stream;
	ngx_queue_t* queue,*q;
	queue =&h2c->streams;
	queue = &queue[(id>>1) & h2c->server->conf->sid_mask];
	for (q = ngx_queue_head(queue); q != ngx_queue_sentinel(queue); q = ngx_queue_next(q)) {
		stream = ngx_queue_data(q,ngx_http2_stream_t,queue);
		if(stream->id == id){
			return stream;
		}
	}
	return NULL;
}
static ngx_inline void ngx_http_upstream_http2_stream_move_with_sid(ngx_http2_stream_t* stream){
	ngx_http2_connection_t* h2c = stream->h2c;
	ngx_queue_t* queue,*q;
	q = &stream->queue;
	ngx_queue_remove(q);
	queue =&h2c->streams;
	queue = &queue[(stream->id>>1) & h2c->server->conf->sid_mask];
	ngx_queue_insert_tail(queue,q);
}

#endif /* _NGX_HTTP_UPSTREAM_HTTP2_H_INCLUDE_ */
