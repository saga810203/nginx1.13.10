/*
 * ngx_http2_head.h
 *
 *  Created on: May 9, 2018
 *      Author: root
 */

#ifndef SINCLUDE_NGX_HTTP2_HEAD_H_
#define SINCLUDE_NGX_HTTP2_HEAD_H_
#define NGX_HTTP2_NO_ERROR                     0x0
#define NGX_HTTP2_PROTOCOL_ERROR               0x1
#define NGX_HTTP2_INTERNAL_ERROR               0x2
#define NGX_HTTP2_FLOW_CTRL_ERROR              0x3
#define NGX_HTTP2_SETTINGS_TIMEOUT             0x4
#define NGX_HTTP2_STREAM_CLOSED                0x5
#define NGX_HTTP2_SIZE_ERROR                   0x6
#define NGX_HTTP2_REFUSED_STREAM               0x7
#define NGX_HTTP2_CANCEL                       0x8
#define NGX_HTTP2_COMP_ERROR                   0x9
#define NGX_HTTP2_CONNECT_ERROR                0xa
#define NGX_HTTP2_ENHANCE_YOUR_CALM            0xb
#define NGX_HTTP2_INADEQUATE_SECURITY          0xc
#define NGX_HTTP2_HTTP_1_1_REQUIRED            0xd

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

#define NGX_HTTP2_STREAM_STATE_WATTING_WITHOUT_SERVER   0x00
#define NGX_HTTP2_STREAM_STATE_WATTING_IN_SERVER   0x01
#define NGX_HTTP2_STREAM_STATE_WATTING_IN_CONNECTION   0x02
#define NGX_HTTP2_STREAM_STATE_OPENED   0x04
#define NGX_HTTP2_STREAM_STATE_LOCAL_CLOSED   0x08
#define NGX_HTTP2_STREAM_STATE__CLOSED   0x10

typedef struct ngx_http2_upstream_s ngx_http2_stream_t;
typedef struct ngx_http2_upstream_main_conf_s ngx_http2_upstream_main_conf_t;
typedef struct ngx_http2_upstream_srv_conf_s ngx_http2_upstream_srv_conf_t;
typedef struct ngx_http2_upstream_server_s ngx_http2_server_t;
typedef struct ngx_http2_connection_send_part_s ngx_http2_connection_send_part_t;
typedef struct ngx_http2_connection_recv_part_s ngx_http2_connection_recv_part_t;
typedef struct ngx_http2_connection_s ngx_http2_connection_t;
typedef struct ngx_http2_stream_s ngx_http2_stream_t;
typedef struct ngx_http2_frame_s ngx_http2_frame_t;
typedef struct ngx_http2_hpack_s ngx_http2_hpack_t;


typedef int (*ngx_http2_read_handler_pt) (ngx_http2_connection_t *h2c);

typedef void (*ngx_http2_send_frame)(ngx_http2_connection_t* h2c, ngx_http2_frame_t* frame);
typedef void (*ngx_http2_send_ping)(ngx_http2_connection_t* h2c, ngx_http2_frame_t* frame,int ack);
typedef void (*ngx_http2_send_header)(ngx_http2_connection_t* h2c, ngx_http2_frame_t* begin,ngx_http2_frame_t* end);




typedef void (*ngx_http2_upstream_choose_server)(ngx_http_request_t* request,ngx_http2_upstream_srv_conf_t *scf);
typedef struct {
	ngx_uint_t len;
	ngx_http2_handler_pt handler;
} ngx_http2_frame_read_handler_config;



struct ngx_http2_upstream_server_s{
	ngx_http2_upstream_srv_conf_t    *scf;
    ngx_str_t                        name;
    ngx_addr_t                      *addrs;
    ngx_uint_t                       naddrs;
    ngx_uint_t                       weight;
    ngx_uint_t                       max_conns;
    ngx_uint_t                       max_fails;
    time_t                           fail_timeout;
    ngx_msec_t                       slow_start;
    ngx_uint_t                       down;

    ngx_uint_t                       use_conns;


    ngx_queue_t connection_queue;
    ngx_http2_connection_t *connection;
   	ngx_queue_t stream_queue;

    unsigned                         backup:1;
    NGX_COMPAT_BEGIN(6)
    NGX_COMPAT_END
} ;

struct ngx_http2_upstream_srv_conf_s {
	ngx_pool_t			*pool;
	ngx_log_t 	*log;

    void                              **srv_conf;
    ngx_array_t                       *servers;  /* ngx_http2_upstream_server_t */
    ngx_str_t                         host;
    ngx_http2_upstream_choose_server  choose_server;


    int recvbuf;
    ngx_addr_t*      local;
    unsigned            log_error:3;


    ngx_uint_t max_streams;
    int sid_mask;
    ngx_http2_connection_t* free_connections;
  	uint32_t buffer_size;
  	uint32_t buffer_count;
  	uint32_t buffer_alloc_count;
  	uint32_t header_pool_size;

    ngx_http2_frame_t *free_frames;
    ngx_queue_t need_free_frame_queue;
};


typedef struct ngx_http2_upstream_main_conf_s {
    ngx_hash_t                       headers_in_hash;
    ngx_array_t                      upstreams;

} ngx_http2_upstream_main_conf_t;

struct ngx_http2_upstream_s {
    ngx_http_upstream_handler_pt     read_event_handler;
    ngx_http_upstream_handler_pt     write_event_handler;


    ngx_chain_t                     *request_bufs;

    ngx_output_chain_ctx_t           output;
    ngx_chain_writer_ctx_t           writer;

    ngx_http_upstream_conf_t        *conf;
    ngx_http2_upstream_srv_conf_t    *upstream;


    ngx_http_upstream_headers_in_t   headers_in;

    ngx_http_upstream_resolved_t    *resolved;

    ngx_buf_t                        from_client;

    ngx_buf_t                        buffer;
    off_t                            length;

    ngx_chain_t                     *out_bufs;
    ngx_chain_t                     *busy_bufs;
    ngx_chain_t                     *free_bufs;

    ngx_int_t                      (*input_filter_init)(void *data);
    ngx_int_t                      (*input_filter)(void *data, ssize_t bytes);
    void                            *input_filter_ctx;


    ngx_int_t                      (*create_request)(ngx_http_request_t *r);
    ngx_int_t                      (*reinit_request)(ngx_http_request_t *r);
    ngx_int_t                      (*process_header)(ngx_http_request_t *r);
    void                           (*abort_request)(ngx_http_request_t *r);
    void                           (*finalize_request)(ngx_http_request_t *r,
                                         ngx_int_t rc);
    ngx_int_t                      (*rewrite_redirect)(ngx_http_request_t *r,
                                         ngx_table_elt_t *h, size_t prefix);
    ngx_int_t                      (*rewrite_cookie)(ngx_http_request_t *r,
                                         ngx_table_elt_t *h);

    ngx_msec_t                       timeout;


    ngx_str_t                        method;
    ngx_str_t                        schema;
    ngx_str_t                        uri;

#if (NGX_HTTP_SSL || NGX_COMPAT)
    ngx_str_t                        ssl_name;
#endif


    unsigned                         store:1;
    unsigned                         cacheable:1;
    unsigned                         accel:1;
    unsigned                         ssl:1;


    unsigned                         buffering:1;


    unsigned                         request_sent:1;
    unsigned                         request_body_sent:1;
    unsigned                         request_body_blocked:1;
    unsigned                         header_sent:1;



    ngx_str_t						 *host;

    ngx_http2_upstream_srv_conf_t* srv_conf;



    ngx_http2_server_t* server;
	ngx_http2_connection_t * h2c;
	ngx_http_request_t* request;
	ngx_event_t         event;
	ngx_uint_t id;

		ngx_queue_t queue_in_waiting;

		ssize_t send_window;
		size_t recv_window;

		ngx_buf_t *preread;



		ngx_queue_t queue;

		ngx_queue_t res_headers_queue;

		/*
		 *   0   in server wait  connect;
		 *
		 * */
		unsigned char state;    //0 waitting with find server  1: waiting in server    2: waiting in connection  4:open  8  local close    16 close

		unsigned waiting :1;

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
		ngx_http2_read_handler_pt handler;
		ngx_http2_read_handler_pt next_handler;


		size_t recv_window;
		u_char* buffer;
		u_char* pos;
		ngx_uint_t len;
		ngx_uint_t readable_size;

		ngx_http2_hpack_t hpack;
		ngx_queue_t headers_queue;
		ngx_http2_header_t* c_header;

		int32_t  field_len;


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
	unsigned recv_huff:1;





	ngx_queue_t idle_streams;

	ngx_http2_send_frame send_frame;
	ngx_http2_send_ping send_ping;
	ngx_http2_send_ping send_headers;



	/*last element*/

	ngx_queue_t streams;
};





ngx_http2_upstream_srv_conf_t* ngx_http2_upstream_get_srv_conf(ngx_conf_t *cf, u_char* name, size_t name_len);

ngx_int_t ngx_http2_upstream_create(ngx_http_request_t *r);



#endif /* SINCLUDE_NGX_HTTP2_HEAD_H_ */
