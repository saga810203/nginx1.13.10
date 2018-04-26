#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


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



static void ngx_http2_upstream_stream_write_header_event(ngx_event_t* ev);
static void ngx_http2_upstream_stream_write_data_event(ngx_event_t* ev);
static void ngx_http2_upstream_stream_read_header_event(ngx_event_t* ev);
static void ngx_http2_upstream_stream_read_data_event(ngx_event_t* ev);

static int ngx_http2_upstream_read_skip_data(ngx_http2_connection_t* h2c);
static int ngx_http2_upstream_read_frame_head(ngx_http2_connection_t* h2c);
static int ngx_http2_upstream_read_setting_frame(ngx_http2_connection_t* h2c);
static int ngx_http2_upstream_read_ping_frame(ngx_http2_connection_t* h2c);
static int ngx_http2_upstream_read_window_update_frame(ngx_http2_connection_t* h2c);
static int ngx_http2_upstream_read_data_frame(ngx_http2_connection_t* h2c);
static int ngx_http2_upstream_read_headers_frame(ngx_http2_connection_t* h2c);
static int ngx_http2_upstream_read_priority_frame(ngx_http2_connection_t* h2c);
static int ngx_http2_upstream_read_rest_stream_frame(ngx_http2_connection_t* h2c);
static int ngx_http2_upstream_read_push_promise_frame(ngx_http2_connection_t* h2c);
static int ngx_http2_upstream_read_goaway_frame(ngx_http2_connection_t* h2c);
static int ngx_http2_upstream_read_continuation_frame(ngx_http2_connection_t* h2c);
static int ngx_http2_upstream_read_field_len(ngx_http2_connection_t* h2c);
static int ngx_http2_upstream_read_headers_item(ngx_http2_connection_t* h2c);




static void ngx_http2_upstream_init_request(ngx_http_request_t *r);
static void ngx_http2_upstream_resolve_handler(ngx_resolver_ctx_t *ctx);
static void ngx_http2_upstream_rd_check_broken_connection(ngx_http_request_t *r);
static void ngx_http2_upstream_wr_check_broken_connection(ngx_http_request_t *r);
static void ngx_http2_upstream_check_broken_connection(ngx_http_request_t *r,
		ngx_event_t *ev);
static void ngx_http2_upstream_connect(ngx_http2_stream_t *r);
static ngx_int_t ngx_http2_upstream_reinit(ngx_http_request_t *r,
		ngx_http2_stream_t *u);
static void ngx_http2_upstream_send_request(ngx_http_request_t *r,
		ngx_http2_stream_t *u, ngx_uint_t do_write);
static ngx_int_t ngx_http2_upstream_send_request_body(ngx_http_request_t *r,
		ngx_http2_stream_t *u, ngx_uint_t do_write);
static void ngx_http2_upstream_send_request_handler(ngx_http_request_t *r,
		ngx_http2_stream_t *u);
static void ngx_http2_upstream_read_request_handler(ngx_http_request_t *r);
static void ngx_http2_upstream_process_header(ngx_http_request_t *r,
		ngx_http2_stream_t *u);
static ngx_int_t ngx_http2_stream_test_next(ngx_http_request_t *r,
		ngx_http2_stream_t *u);
static ngx_int_t ngx_http2_upstream_intercept_errors(ngx_http_request_t *r,
		ngx_http2_stream_t *u);
static ngx_int_t ngx_http2_stream_test_connect(ngx_connection_t *c);
static ngx_int_t ngx_http2_upstream_process_headers(ngx_http_request_t *r,
		ngx_http2_stream_t *u);
static ngx_int_t ngx_http2_upstream_process_trailers(ngx_http_request_t *r,
		ngx_http2_stream_t *u);
static void ngx_http2_upstream_send_response(ngx_http_request_t *r,
		ngx_http2_stream_t *u);
static void ngx_http2_upstream_upgrade(ngx_http_request_t *r,
		ngx_http2_stream_t *u);
static void ngx_http2_upstream_upgraded_read_downstream(ngx_http_request_t *r);
static void ngx_http2_upstream_upgraded_write_downstream(ngx_http_request_t *r);
static void ngx_http2_upstream_upgraded_read_upstream(ngx_http_request_t *r,
		ngx_http2_stream_t *u);
static void ngx_http2_upstream_upgraded_write_upstream(ngx_http_request_t *r,
		ngx_http2_stream_t *u);
static void ngx_http2_upstream_process_upgraded(ngx_http_request_t *r,
		ngx_uint_t from_upstream, ngx_uint_t do_write);
static void
ngx_http2_upstream_process_non_buffered_downstream(ngx_http_request_t *r);
static void
ngx_http2_upstream_process_non_buffered_upstream(ngx_http_request_t *r,
		ngx_http2_stream_t *u);
static void
ngx_http2_upstream_process_non_buffered_request(ngx_http_request_t *r,
		ngx_uint_t do_write);
static ngx_int_t ngx_http2_upstream_non_buffered_filter_init(void *data);
static ngx_int_t ngx_http2_upstream_non_buffered_filter(void *data,
		ssize_t bytes);

static ngx_int_t ngx_http2_upstream_output_filter(void *data, ngx_chain_t *chain);
static void ngx_http2_upstream_process_downstream(ngx_http_request_t *r);
static void ngx_http2_upstream_process_upstream(ngx_http_request_t *r,
		ngx_http2_stream_t *u);
static void ngx_http2_upstream_process_request(ngx_http_request_t *r,
		ngx_http2_stream_t *u);
static void ngx_http2_upstream_store(ngx_http_request_t *r,
		ngx_http2_stream_t *u);
static void ngx_http2_upstream_dummy_handler(ngx_http_request_t *r,
		ngx_http2_stream_t *u);
static void ngx_http2_upstream_next(ngx_http_request_t *r,
		ngx_http2_stream_t *u, ngx_uint_t ft_type);
static void ngx_http2_upstream_finalize_stream(ngx_http2_stream_t *u, ngx_int_t rc);

static ngx_int_t ngx_http2_upstream_process_header_line(ngx_http_request_t *r,
		ngx_table_elt_t *h, ngx_uint_t offset);
static ngx_int_t ngx_http2_upstream_process_content_length(ngx_http_request_t *r,
		ngx_table_elt_t *h, ngx_uint_t offset);
static ngx_int_t ngx_http2_upstream_process_last_modified(ngx_http_request_t *r,
		ngx_table_elt_t *h, ngx_uint_t offset);
static ngx_int_t ngx_http2_upstream_process_set_cookie(ngx_http_request_t *r,
		ngx_table_elt_t *h, ngx_uint_t offset);
static ngx_int_t
ngx_http2_upstream_process_cache_control(ngx_http_request_t *r,
		ngx_table_elt_t *h, ngx_uint_t offset);
static ngx_int_t ngx_http2_upstream_ignore_header_line(ngx_http_request_t *r,
		ngx_table_elt_t *h, ngx_uint_t offset);
static ngx_int_t ngx_http2_upstream_process_expires(ngx_http_request_t *r,
		ngx_table_elt_t *h, ngx_uint_t offset);
static ngx_int_t ngx_http2_upstream_process_accel_expires(ngx_http_request_t *r,
		ngx_table_elt_t *h, ngx_uint_t offset);
static ngx_int_t ngx_http2_upstream_process_limit_rate(ngx_http_request_t *r,
		ngx_table_elt_t *h, ngx_uint_t offset);
static ngx_int_t ngx_http2_upstream_process_buffering(ngx_http_request_t *r,
		ngx_table_elt_t *h, ngx_uint_t offset);
static ngx_int_t ngx_http2_upstream_process_charset(ngx_http_request_t *r,
		ngx_table_elt_t *h, ngx_uint_t offset);
static ngx_int_t ngx_http2_upstream_process_connection(ngx_http_request_t *r,
		ngx_table_elt_t *h, ngx_uint_t offset);
static ngx_int_t
ngx_http2_upstream_process_transfer_encoding(ngx_http_request_t *r,
		ngx_table_elt_t *h, ngx_uint_t offset);
static ngx_int_t ngx_http2_upstream_process_vary(ngx_http_request_t *r,
		ngx_table_elt_t *h, ngx_uint_t offset);
static ngx_int_t ngx_http2_upstream_copy_header_line(ngx_http_request_t *r,
		ngx_table_elt_t *h, ngx_uint_t offset);
static ngx_int_t
ngx_http2_upstream_copy_multi_header_lines(ngx_http_request_t *r,
		ngx_table_elt_t *h, ngx_uint_t offset);
static ngx_int_t ngx_http2_upstream_copy_content_type(ngx_http_request_t *r,
		ngx_table_elt_t *h, ngx_uint_t offset);
static ngx_int_t ngx_http2_upstream_copy_last_modified(ngx_http_request_t *r,
		ngx_table_elt_t *h, ngx_uint_t offset);
static ngx_int_t ngx_http2_upstream_rewrite_location(ngx_http_request_t *r,
		ngx_table_elt_t *h, ngx_uint_t offset);
static ngx_int_t ngx_http2_upstream_rewrite_refresh(ngx_http_request_t *r,
		ngx_table_elt_t *h, ngx_uint_t offset);
static ngx_int_t ngx_http2_upstream_rewrite_set_cookie(ngx_http_request_t *r,
		ngx_table_elt_t *h, ngx_uint_t offset);
static ngx_int_t ngx_http2_upstream_copy_allow_ranges(ngx_http_request_t *r,
		ngx_table_elt_t *h, ngx_uint_t offset);

#if (NGX_HTTP_GZIP)
static ngx_int_t ngx_http2_upstream_copy_content_encoding(ngx_http_request_t *r,
		ngx_table_elt_t *h, ngx_uint_t offset);
#endif

static ngx_int_t ngx_http2_upstream_add_variables(ngx_conf_t *cf);
static ngx_int_t ngx_http2_upstream_addr_variable(ngx_http_request_t *r,
		ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http2_upstream_status_variable(ngx_http_request_t *r,
		ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http2_upstream_response_time_variable(ngx_http_request_t *r,
		ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http2_upstream_response_length_variable(
		ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http2_upstream_header_variable(ngx_http_request_t *r,
		ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http2_stream_trailer_variable(ngx_http_request_t *r,
		ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http2_upstream_cookie_variable(ngx_http_request_t *r,
		ngx_http_variable_value_t *v, uintptr_t data);

static char *ngx_http2_upstream(ngx_conf_t *cf, ngx_command_t *cmd, void *dummy);
static char *ngx_http2_upstream_server(ngx_conf_t *cf, ngx_command_t *cmd,
		void *conf);

static char* ngx_http2_upstream_buffer_size(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static char* ngx_http2_upstream_buffer_count(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char* ngx_http2_upstream_sid_mask(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char* ngx_http2_upstream_header_pool_size(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char*ngx_http2_upstream_max_streams(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_int_t ngx_http2_upstream_set_local(ngx_http_request_t *r,
		ngx_http2_stream_t *u, ngx_http2_upstream_local_t *local);

static void *ngx_http2_upstream_create_main_conf(ngx_conf_t *cf);
static char *ngx_http2_upstream_init_main_conf(ngx_conf_t *cf, void *conf);

#if (NGX_HTTP_SSL)
static void ngx_http2_upstream_ssl_init_connection(ngx_http_request_t *,
		ngx_http2_stream_t *u, ngx_connection_t *c);
static void ngx_http2_upstream_ssl_handshake_handler(ngx_connection_t *c);
static void ngx_http2_upstream_ssl_handshake(ngx_http_request_t *,
		ngx_http2_stream_t *u, ngx_connection_t *c);
static ngx_int_t ngx_http2_upstream_ssl_name(ngx_http_request_t *r,
		ngx_http2_stream_t *u, ngx_connection_t *c);
#endif



int32_t ngx_http2_hpack_init(ngx_http2_hpack_t* hpack,uint32_t size);
int32_t ngx_http2_hpack_add(ngx_http2_hpack_t* hpack,ngx_str_t* name,ngx_str_t* value);



int32_t ngx_http2_hpack_resize(ngx_http2_hpack_t* hpack,uint32_t new_size);
int32_t ngx_http2_hpack_get_index_header(ngx_http2_connection_t* h2c,int32_t idx,int32_t nameonly);















static ngx_http2_upstream_header_t ngx_http2_upstream_headers_in[] = {

{ ngx_string("Status"), ngx_http2_upstream_process_header_line, offsetof(
		ngx_http2_upstream_headers_in_t, status),
		ngx_http2_upstream_copy_header_line, 0, 0 },

{ ngx_string("Content-Type"), ngx_http2_upstream_process_header_line, offsetof(
		ngx_http2_upstream_headers_in_t, content_type),
		ngx_http2_upstream_copy_content_type, 0, 1 },

{ ngx_string("Content-Length"), ngx_http2_upstream_process_content_length, 0,
		ngx_http2_upstream_ignore_header_line, 0, 0 },

{ ngx_string("Date"), ngx_http2_upstream_process_header_line, offsetof(
		ngx_http2_upstream_headers_in_t, date),
		ngx_http2_upstream_copy_header_line, offsetof(ngx_http_headers_out_t,
				date), 0 },

{ ngx_string("Last-Modified"), ngx_http2_upstream_process_last_modified, 0,
		ngx_http2_upstream_copy_last_modified, 0, 0 },

{ ngx_string("ETag"), ngx_http2_upstream_process_header_line, offsetof(
		ngx_http2_upstream_headers_in_t, etag),
		ngx_http2_upstream_copy_header_line, offsetof(ngx_http_headers_out_t,
				etag), 0 },

{ ngx_string("Server"), ngx_http2_upstream_process_header_line, offsetof(
		ngx_http2_upstream_headers_in_t, server),
		ngx_http2_upstream_copy_header_line, offsetof(ngx_http_headers_out_t,
				server), 0 },

{ ngx_string("WWW-Authenticate"), ngx_http2_upstream_process_header_line,
		offsetof(ngx_http2_upstream_headers_in_t, www_authenticate),
		ngx_http2_upstream_copy_header_line, 0, 0 },

{ ngx_string("Location"), ngx_http2_upstream_process_header_line, offsetof(
		ngx_http2_upstream_headers_in_t, location),
		ngx_http2_upstream_rewrite_location, 0, 0 },

{ ngx_string("Refresh"), ngx_http2_upstream_ignore_header_line, 0,
		ngx_http2_upstream_rewrite_refresh, 0, 0 },

{ ngx_string("Set-Cookie"), ngx_http2_upstream_process_set_cookie, offsetof(
		ngx_http2_upstream_headers_in_t, cookies),
		ngx_http2_upstream_rewrite_set_cookie, 0, 1 },

{ ngx_string("Content-Disposition"), ngx_http2_upstream_ignore_header_line, 0,
		ngx_http2_upstream_copy_header_line, 0, 1 },

{ ngx_string("Cache-Control"), ngx_http2_upstream_process_cache_control, 0,
		ngx_http2_upstream_copy_multi_header_lines, offsetof(
				ngx_http_headers_out_t, cache_control), 1 },

{ ngx_string("Expires"), ngx_http2_upstream_process_expires, 0,
		ngx_http2_upstream_copy_header_line, offsetof(ngx_http_headers_out_t,
				expires), 1 },

{ ngx_string("Accept-Ranges"), ngx_http2_upstream_process_header_line, offsetof(
		ngx_http2_upstream_headers_in_t, accept_ranges),
		ngx_http2_upstream_copy_allow_ranges, offsetof(ngx_http_headers_out_t,
				accept_ranges), 1 },

{ ngx_string("Content-Range"), ngx_http2_upstream_ignore_header_line, 0,
		ngx_http2_upstream_copy_header_line, offsetof(ngx_http_headers_out_t,
				content_range), 0 },

{ ngx_string("Connection"), ngx_http2_upstream_process_connection, 0,
		ngx_http2_upstream_ignore_header_line, 0, 0 },

{ ngx_string("Keep-Alive"), ngx_http2_upstream_ignore_header_line, 0,
		ngx_http2_upstream_ignore_header_line, 0, 0 },

{ ngx_string("Vary"), ngx_http2_upstream_process_vary, 0,
		ngx_http2_upstream_copy_header_line, 0, 0 },

{ ngx_string("Link"), ngx_http2_upstream_ignore_header_line, 0,
		ngx_http2_upstream_copy_multi_header_lines, offsetof(
				ngx_http_headers_out_t, link), 0 },

{ ngx_string("X-Accel-Expires"), ngx_http2_upstream_process_accel_expires, 0,
		ngx_http2_upstream_copy_header_line, 0, 0 },

{ ngx_string("X-Accel-Redirect"), ngx_http2_upstream_process_header_line,
		offsetof(ngx_http2_upstream_headers_in_t, x_accel_redirect),
		ngx_http2_upstream_copy_header_line, 0, 0 },

{ ngx_string("X-Accel-Limit-Rate"), ngx_http2_upstream_process_limit_rate, 0,
		ngx_http2_upstream_copy_header_line, 0, 0 },

{ ngx_string("X-Accel-Buffering"), ngx_http2_upstream_process_buffering, 0,
		ngx_http2_upstream_copy_header_line, 0, 0 },

{ ngx_string("X-Accel-Charset"), ngx_http2_upstream_process_charset, 0,
		ngx_http2_upstream_copy_header_line, 0, 0 },

{ ngx_string("Transfer-Encoding"), ngx_http2_upstream_process_transfer_encoding,
		0, ngx_http2_upstream_ignore_header_line, 0, 0 },

#if (NGX_HTTP_GZIP)
		{ ngx_string("Content-Encoding"), ngx_http2_upstream_process_header_line,
				offsetof(ngx_http2_upstream_headers_in_t, content_encoding),
				ngx_http2_upstream_copy_content_encoding, 0, 0 },
#endif

		{ ngx_null_string, NULL, 0, NULL, 0, 0 } };

static ngx_command_t ngx_http2_upstream_commands[] = {

{ ngx_string("http2_upstream"),
NGX_HTTP_MAIN_CONF | NGX_CONF_BLOCK | NGX_CONF_TAKE1, ngx_http2_upstream, 0, 0,
NULL },

{ ngx_string("http2_server"),
NGX_HTTP_UPS_CONF | NGX_CONF_1MORE, ngx_http2_upstream_server,
NGX_HTTP_SRV_CONF_OFFSET, 0,
NULL },
{
		ngx_string("http2_buffer_size"),
		NGX_HTTP_UPS_CONF | NGX_CONF_TAKE1, ngx_http2_upstream_buffer_size,
		NGX_HTTP_SRV_CONF_OFFSET, 0,NULL
},
{
		ngx_string("http2_buffer_count"),
		NGX_HTTP_UPS_CONF | NGX_CONF_TAKE1, ngx_http2_upstream_buffer_count,
		NGX_HTTP_SRV_CONF_OFFSET, 0,NULL
},
{
		ngx_string("http2_sid_mask"),
		NGX_HTTP_UPS_CONF | NGX_CONF_TAKE1, ngx_http2_upstream_sid_mask,
		NGX_HTTP_SRV_CONF_OFFSET, 0,NULL
},
{
		ngx_string("http2_header_pool_size"),
		NGX_HTTP_UPS_CONF | NGX_CONF_TAKE1, ngx_http2_upstream_headerif()_pool_size,
		NGX_HTTP_SRV_CONF_OFFSET, 0,NULL
},
{
		ngx_string("http2_max_stream"),
		NGX_HTTP_UPS_CONF | NGX_CONF_TAKE1, ngx_http2_upstream_max_streams,
		NGX_HTTP_SRV_CONF_OFFSET, 0,NULL
},

ngx_null_command };

static ngx_http_module_t ngx_http2_upstream_module_ctx = {
		ngx_http2_upstream_add_variables, /* preconfiguration */
		NULL, /* postconfiguration */

		ngx_http2_upstream_create_main_conf, /* create main configuration */
		ngx_http2_upstream_init_main_conf, /* init main configuration */

		NULL, /* create server configuration */
		NULL, /* merge server configuration */

		NULL, /* create location configuration */
		NULL /* merge location configuration */
};

ngx_module_t ngx_http2_upstream_module = {
NGX_MODULE_V1, &ngx_http2_upstream_module_ctx, /* module context */
ngx_http2_upstream_commands, /* module directives */
NGX_HTTP_MODULE, /* module type */
NULL, /* init master */
NULL, /* init module */
NULL, /* init process */
NULL, /* init thread */
NULL, /* exit thread */
NULL, /* exit process */
NULL, /* exit master */
NGX_MODULE_V1_PADDING };

static ngx_http_variable_t ngx_http2_upstream_vars[] = {

{ ngx_string("http2_upstream_addr"), NULL, ngx_http2_upstream_addr_variable, 0,
NGX_HTTP_VAR_NOCACHEABLE, 0 },

{ ngx_string("http2_upstream_status"), NULL, ngx_http2_upstream_status_variable, 0,
NGX_HTTP_VAR_NOCACHEABLE, 0 },

{ ngx_string("http2_upstream_connect_time"), NULL,
		ngx_http2_upstream_response_time_variable, 2,
		NGX_HTTP_VAR_NOCACHEABLE, 0 },

{ ngx_string("http2_upstream_header_time"), NULL,
		ngx_http2_upstream_response_time_variable, 1,
		NGX_HTTP_VAR_NOCACHEABLE, 0 },

{ ngx_string("http2_upstream_response_time"), NULL,
		ngx_http2_upstream_response_time_variable, 0,
		NGX_HTTP_VAR_NOCACHEABLE, 0 },

{ ngx_string("http2_upstream_response_length"), NULL,
		ngx_http2_upstream_response_length_variable, 0,
		NGX_HTTP_VAR_NOCACHEABLE, 0 },

{ ngx_string("http2_upstream_bytes_received"), NULL,
		ngx_http2_upstream_response_length_variable, 1,
		NGX_HTTP_VAR_NOCACHEABLE, 0 },



		{ ngx_string("http2_upstream_http_"), NULL, ngx_http2_upstream_header_variable,
				0, NGX_HTTP_VAR_NOCACHEABLE | NGX_HTTP_VAR_PREFIX, 0 },

		{ ngx_string("http2_upstream_trailer_"), NULL,
				ngx_http2_stream_trailer_variable, 0, NGX_HTTP_VAR_NOCACHEABLE
						| NGX_HTTP_VAR_PREFIX, 0 },

		{ ngx_string("http2_upstream_cookie_"), NULL,
				ngx_http2_upstream_cookie_variable, 0, NGX_HTTP_VAR_NOCACHEABLE
						| NGX_HTTP_VAR_PREFIX, 0 },

		ngx_http_null_variable };

static ngx_http2_upstream_next_t ngx_http2_upstream_next_errors[] = { { 500,
		ngx_http2_upstream_FT_HTTP_500 }, { 502, ngx_http2_upstream_FT_HTTP_502 },
		{ 503, ngx_http2_upstream_FT_HTTP_503 }, { 504,
				ngx_http2_upstream_FT_HTTP_504 }, { 403,
				ngx_http2_upstream_FT_HTTP_403 }, { 404,
				ngx_http2_upstream_FT_HTTP_404 }, { 429,
				ngx_http2_upstream_FT_HTTP_429 }, { 0, 0 } };

ngx_conf_bitmask_t ngx_http2_upstream_cache_method_mask[] = {
		{ ngx_string("GET"), NGX_HTTP_GET },
		{ ngx_string("HEAD"), NGX_HTTP_HEAD }, { ngx_string("POST"),
				NGX_HTTP_POST }, { ngx_null_string, 0 } };

ngx_conf_bitmask_t ngx_http2_upstream_ignore_headers_masks[] = { {
		ngx_string("X-Accel-Redirect"), ngx_http2_upstream_IGN_XA_REDIRECT }, {
		ngx_string("X-Accel-Expires"), ngx_http2_upstream_IGN_XA_EXPIRES }, {
		ngx_string("X-Accel-Limit-Rate"), ngx_http2_upstream_IGN_XA_LIMIT_RATE },
		{ ngx_string("X-Accel-Buffering"), ngx_http2_upstream_IGN_XA_BUFFERING },
		{ ngx_string("X-Accel-Charset"), ngx_http2_upstream_IGN_XA_CHARSET }, {
				ngx_string("Expires"), ngx_http2_upstream_IGN_EXPIRES },
		{ ngx_string("Cache-Control"), ngx_http2_upstream_IGN_CACHE_CONTROL }, {
				ngx_string("Set-Cookie"), ngx_http2_upstream_IGN_SET_COOKIE }, {
				ngx_string("Vary"), ngx_http2_upstream_IGN_VARY }, {
				ngx_null_string, 0 } };




static ngx_http2_frame_read_handler_config ngx_http2_frame_read_handler_configs[] = {
		{ 0, 												ngx_http2_upstream_read_data_frame },
		{ 1, 												ngx_http2_upstream_read_headers_frame },
		{ NGX_HTTP2_PRIORITY_SIZE, 							ngx_http2_upstream_read_priority_frame },
		{ NGX_HTTP2_RST_STREAM_SIZE,						ngx_http2_upstream_read_rest_stream_frame },
		{ 0, 												ngx_http2_upstream_read_setting_frame },
		{ 0,										        ngx_http2_upstream_read_push_promise_frame },
		{ NGX_HTTP2_PING_SIZE, 								ngx_http2_upstream_read_ping_frame },
		{ NGX_HTTP2_GOAWAY_SIZE,					        ngx_http2_upstream_read_goaway_frame },
		{ NGX_HTTP2_WINDOW_UPDATE_SIZE, 					ngx_http2_upstream_read_window_update_frame },
		{ 0,										        ngx_http2_upstream_read_continuation_frame },

};


extern ngx_http_v2_header_t ngx_http_v2_static_table[];



 int32_t ngx_http2_hpack_init(ngx_http2_hpack_t* hpack,uint32_t size){
	uint32_t capacity = 4096;
	u_char* data;


	while(capacity < size){
		capacity+=4096;
	}

	data = ngx_calloc(capacity,NULL);
	if(data){
		hpack->data = data;
		hpack->next = data;
		hpack->index= (u_char**)(((uint64_t)hpack->data)  + ((uint64_t)hpack->capacity));
		hpack->capacity = capacity;
		hpack->size = size;
	}else{
		return -1;
	}
	return  0;
}

int32_t ngx_http2_hpack_remove(ngx_http2_hpack_t* hpack,uint32_t size){
	u_char* b_index;
	u_char** index;
	uint32_t real_size;
	uint32_t f_len;
	uint32_t num;
	int i;

	if(size  >  hpack->size) {
		return -1;
	}
	num=0;
	real_size = 0;
	b_index = hpack->data;
	while(real_size < size){

		f_len = *((uint32_t*)b_index);
		real_size+=f_len;
		b_index+=(sizeof(uint32_t)+f_len);


		f_len = *((uint32_t*)b_index);
		real_size+=f_len;
		b_index+=(sizeof(uint32_t)+f_len);

		real_size+=32;
		++num;
	}
	hpack->bytes_headers-=real_size;
	hpack->rds_headers -=num;
	if(hpack->rds_headers){
		ngx_memmove(hpack->data,b_index, hpack->bytes_headers - (32 - (sizeof(uint32_t) * 2))) ;
		hpack->next = hpack->data + hpack->bytes_headers - (32 - (sizeof(uint32_t) * 2));
		i = 0 ;
		b_index = hpack->data;

		hpack->index = (u_char**)(((uint64_t)hpack->data)  + ((uint64_t)hpack->capacity) - (sizeof(void*) * hpack->rds_headers));

		index =(u_char**) hpack->index;
		if(hpack->rds_headers){
			i=0;
			index[i++] = b_index;
			do{
				f_len = *((uint32_t*)b_index);
				b_index+=(sizeof(uint32_t)+f_len);
				f_len = *((uint32_t*)b_index);
				b_index+=(sizeof(uint32_t)+f_len);
				index[i++] = b_index;
			}while(i< hpack->rds_headers);
		}
	}else{
		hpack->next = hpack->data;

	}
	return 0;
}

int32_t ngx_http2_hpack_add(ngx_http2_hpack_t* hpack,ngx_str_t* name,ngx_str_t* value){
	uint32_t size = name->len + value->data+32;
	u_char* p,*n;
	if(size> hpack->size){
		return -1;
	}
	if((hpack->size - hpack->bytes_headers) < size){
		ngx_http2_hpack_remove(hpack,size);
	}
	p = n = hpack->next;
	*((uint32_t*)p) = (uint32_t)name->len;
	p+=sizeof(uint32_t);
	ngx_memcpy(p,name->data,name->len);
	p+=name->len;
	*((uint32_t*)p) = (uint32_t)value->len;
	p+=sizeof(uint32_t);
	ngx_memcpy(p,value->data,value->len);
	hpack->next = p + value->len;


	hpack->bytes_headers+=size;

	p = (char*)hpack->index;
	p -=sizeof(void*);
	if(hpack->rds_headers){
		ngx_memmove(p,hpack->index,sizeof(void*)* hpack->rds_headers);
	}
	hpack->index = (u_char**)p;
	hpack->index[hpack->rds_headers++] = n;
	return 0;
}

int32_t ngx_http2_hpack_index_name(ngx_http2_connection_t* h2c,uint32_t idx){
	uint32_t len;
	u_char* data,*p;
	ngx_http2_hpack_t* hpack = &h2c->recv.hpack;
	if(idx>=hpack->rds_headers){
		return -1;
	}

	p =hpack->index[idx];

	len = *((uint32_t*)p);

	h2c->recv.c_header->name.len = len;
	data = ngx_pcalloc(h2c->recv.pool,len);
	if(data){
		ngx_memcpy(data,p+sizeof(uint32_t),len);
		h2c->recv.c_header->name.data=data;
		return 0;
	}else{
		return -1;
	}
}
int32_t ngx_http2_hpack_index_header(ngx_http2_connection_t* h2c,uint32_t idx){
	uint32_t len;
	u_char* data,*p;
	ngx_http2_hpack_t* hpack = &h2c->recv.hpack;
	if(idx>=hpack->rds_headers){
		return -1;
	}
	p =hpack->index[idx];

	len = *((uint32_t*)p);

	h2c->recv.c_header->name.len = len;
	data = ngx_pcalloc(h2c->recv.pool,len);
	if(data){
		ngx_memcpy(data,p+sizeof(uint32_t),len);
		h2c->recv.c_header->name.data=data;
	}else{
		return -1;
	}
	p+=(sizeof(uint32_t)+len);
	len = *((uint32_t*)p);

	h2c->recv.c_header->value.len = len;
	data = ngx_pcalloc(h2c->recv.pool,len);
	if(data){
		ngx_memcpy(data,p+sizeof(uint32_t),len);
		h2c->recv.c_header->value.data=data;
		return 0;
	}else{
		return -1;
	}
}

int32_t ngx_http2_hpack_resize(ngx_http2_hpack_t* hpack,uint32_t new_size){
	uint32_t new_capacity;

	int64_t delta;

	u_char* new_data;

	u_char** new_index;

	u_char** idx;
	int i ;

	new_capacity = 4096;
	while(new_capacity < new_size){
		new_capacity+=4096;
	}

	if(new_size > hpack->size){
		if(new_size <= hpack->capacity){
			hpack->size = new_size;
		}else{
			new_data = ngx_calloc(new_capacity,NULL);
			if(new_data){
				ngx_memcpy(new_data,hpack->data,hpack->size);
				delta = ((int64_t)new_data) -((int64_t)hpack->data);
				new_index = new_data  + new_capacity - (sizeof(void*) * hpack->rds_headers);

				for(i=0;i< hpack->rds_headers;++i){
					new_index[i] = hpack->index[i]+delta;
				}
				ngx_free(hpack->data);
				hpack->data = new_data;
				hpack->capacity = new_capacity;
				hpack->index = new_index;
				hpack->next +=delta;
				hpack->size = new_size;
				return 0;
			}else{
				return -1;
			}
		}
	}else if(new_size<hpack->size){
		if(hpack->bytes_headers>new_size){
			ngx_http2_hpack_remove(hpack->bytes_headers- new_size);
		}
		hpack->size = new_size;
		return 0;
	}
	return 0;

}

int32_t ngx_http2_hpack_get_index_header(ngx_http2_connection_t* h2c,int32_t idx,int32_t nameonly){
	ngx_http_v2_header_t* sheader;
	ngx_str_t* value;

	ngx_http2_header_t* header;

	header = ngx_pcalloc(h2c->recv.pool,sizeof(ngx_http2_header_t));
	if(header){
		ngx_queue_insert_tail(&h2c->recv.headers_queue,&header->queue);
		h2c->recv.c_header = header;
		if(idx){
			--idx;
			if(idx< 61){
				sheader = &ngx_http_v2_static_table[idx];
				header->name.len = sheader->name.len;
				header->name.data = sheader->name.data;
				header->cache = 'N';
				if(!nameonly){
					header->value.len = sheader->value.len;
					header->value.data = sheader->value.data;
					header->cache ='V';
				}
				return NGX_OK;
			}else{
				idx-=61;
				return nameonly?ngx_http2_hpack_index_name(h2c,idx):ngx_http2_hpack_index_header(h2c,idx);
			}
		}
	}
	return NGX_ERROR;
}







static void ngx_http2_upstream_block_event(ngx_event_t * ev){}
static ngx_inline ngx_http2_frame_t* ngx_http2_get_frame(ngx_http2_upstream_srv_conf_t* scf) {
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
static ngx_inline void ngx_http2_free_frame(ngx_http_upstream_http2_srv_conf_t* scf, ngx_http2_frame_t* frame) {
	ngx_queue_t *queue = &scf->need_free_frame_queue;
	ngx_event_t* event;
	frame->data = scf->free_frames;
	scf->free_frames = frame;
	if (!ngx_queue_empty(queue)) {
		queue = ngx_queue_head(queue);
		event = ngx_queue_data(queue, ngx_event_t, queue);
		ngx_queue_remove(queue);
//		event->active = 1;
		event->posted= 0;
		event->handler(event);
        //ngx_queue_insert_tail(&ngx_posted_events, &event->queue);
	}
}
static ngx_inline void ngx_http2_post_need_buffer_events(ngx_http_upstream_http2_srv_conf_t* scf,ngx_event_t* event){
	if(!event->posted){
		event->posted = 1;
		ngx_queue_insert_tail(&scf->need_free_frame_queue,&event->queue);
	}
}
static ngx_inline ngx_http2_stream_t* ngx_http_upstream_http2_find_stream(ngx_http2_connection_t* h2c,ngx_uint_t id){
	ngx_http2_stream_t* stream;
	ngx_queue_t* queue,*q;
	queue =&h2c->streams;
	queue = &queue[(id>>1) & h2c->server->scf->sid_mask];
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
	queue = &queue[(stream->id>>1) & h2c->server->scf->sid_mask];
	ngx_queue_insert_tail(queue,q);
}

static void ngx_http2_upstream_send_queue_frame(ngx_http2_connection_t* h2c, ngx_http2_frame_t* frame) {
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
static void ngx_http2_upstream_send_queue_frame_ignore(ngx_http2_connection_t* h2c, ngx_http2_frame_t* frame) {
	ngx_http2_free_frame(h2c->server->scf, frame);
}
static void ngx_http2_upstream_send_ping_frame(ngx_http2_connection_t* h2c, ngx_http2_frame_t* frame, int ack) {
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
static void ngx_http2_upstream_send_ping_frame_ignore(ngx_http2_connection_t* h2c, ngx_http2_frame_t* frame, int ack) {
	ngx_http2_free_frame(h2c->server->scf, frame);
}

static void ngx_http2_upstream_send_header_frame(ngx_http2_connection_t* h2c, ngx_http2_frame_t* begin, ngx_http2_frame_t* end) {
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
static void ngx_http2_upstream_send_header_frame_ignore(ngx_http2_connection_t* h2c, ngx_http2_frame_t* begin, ngx_http2_frame_t* end) {
	ngx_http_upstream_http2_srv_conf_t* scf = h2c->server->scf;
	while (begin) {
		end = begin->data;
		ngx_http2_free_frame(scf, begin);
		begin = end;
	}
}
void ngx_http2_upstream_close_stream_in_server(ngx_http2_server_t* server){
	ngx_queue_t *streams=&server->stream_queue;
	ngx_queue_t *q;
	ngx_http2_stream_t stream;
	ngx_connection_t* c;
   for (q = ngx_queue_head(streams);
        q != ngx_queue_sentinel(streams);
        q = ngx_queue_next(q))
   {
       stream = ngx_queue_data(q, ngx_http2_stream_t, queue);

       stream->event.error = 1;
       ngx_post_event(&stream->event,&ngx_posted_events);
   }
   ngx_queue_init(streams);
}
static void ngx_http2_upstream_accecpt_streams(ngx_http2_server_t* server) {
	ngx_http2_connection_t *h2c = server->connection;
	ngx_http_upstream_http2_srv_conf_t* scf = server->scf;
	ngx_queue_t* queue, *q;
	ngx_http2_stream_t * stream;
	ngx_int_t rc;
	queue = &server->stream_queue;
	if(server->connection){
		while ((!ngx_queue_empty(queue)) && (h2c->max_streams > h2c->processing)) {
				++h2c->processing;
				q = ngx_queue_head(queue);
				ngx_queue_remove(q);
				stream = ngx_queue_data(q, ngx_http2_stream_t, queue);
				stream->state = NGX_HTTP2_STREAM_STATE_WATTING_IN_CONNECTION;
				ngx_queue_insert_tail(&h2c->idle_streams, q);
				stream->h2c = h2c;
				ngx_post_event(&stream->event, &ngx_posted_events);
		}
		server->connection = NULL;
		if(h2c->processing< h2c->max_streams){
			ngx_queue_insert_tail(&server->connection_queue, &h2c->queue);
			return;
		}
	}
	while(!(ngx_queue_empty(queue))){
		q = ngx_queue_head(queue);
		stream = ngx_queue_data(q, ngx_http2_stream_t, queue);
		if(ngx_queue_empty(&server->connection_queue)){
			h2c = ngx_queue_data((ngx_queue_head(&server->connection_queue)),ngx_http2_connection_t,queue);
			ngx_queue_remove(q);
			ngx_queue_insert_tail(&h2c->idle_streams, q);
			stream->h2c = h2c;
			ngx_post_event(&stream->event, &ngx_posted_events);
			++h2c->processing;
			if(h2c->processing >= h2c->max_streams){
				ngx_queue_remove(&h2c->queue);
			}
		}else{
			break;
		}
	}
	if(ngx_queue_empty(queue)){
		return;
	}
	if (server->use_conns >= server->max_conns) {
		ngx_http2_upstream_close_stream_in_server(server);
		return;
	}
	h2c = scf->free_connections;
	if (h2c) {
		scf->free_connections = h2c->data;
	} else {
		h2c = ngx_pcalloc(scf->pool, (sizeof(ngx_http2_connection_t) + (sizeof(ngx_queue_t) * (scf->sid_mask))));
		if (h2c == NULL) {
			ngx_http2_upstream_close_stream_in_server(server);
			return;
		}
		++scf->use_conns;
		h2c->server = server;
		server->connection = h2c;
		rc = ngx_http2_upstream_connect_to_server(server);
		if(rc == NGX_ERROR){
			--server->use_conns;
			server->connection->data = server->scf->free_connections;
			server->scf->free_connections = server->connection;
			server->connection = NULL;
			ngx_queue_remove(&stream->queue);
			stream->event.error = 1;
			stream->state = NGX_HTTP2_STREAM_STATE_WATTING_WITHOUT_SERVER;
			ngx_post_event(&stream->event,&ngx_posted_events);
		}else {
			//TODO init ssl;
			((ngx_connection_t*) server->connection->data)->data = server->connection;
			ngx_http2_upstream_http2_connection_init(server->connection);
			if(rc == NGX_OK){
				ngx_http2_upstream_first_write_handler(((ngx_connection_t*) server->connection->data)->write);
			}
		}
	}
}















static int ngx_http2_upstream_read_setting_params(ngx_http2_connection_t* h2c) {
	int i, j;
	ngx_uint_t pn, pv;
	u_char* p;
	ssize_t window_delta;
	ngx_http2_frame_t* frame;
	ngx_http2_stream_t* stream;
	ngx_connection_t * c;
	ngx_queue_t* queue, *q;
	int sid_mask = h2c->server->scf->sid_mask;

	frame = ngx_http2_get_frame(h2c->server->scf);
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
								ngx_http2_free_frame(h2c->server->scf,frame);
								return NGX_ERROR;
							}
						}else{
							if(ngx_http2_hpack_init(&h2c->recv.hpack,pv)){
								ngx_http2_free_frame(h2c->server->scf,frame);
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
								stream = ngx_queue_data(q, ngx_http2_stream_t, queue);
								stream->send_window+=window_delta;
								if ((stream->state == NGX_HTTP2_STREAM_STATE_OPENED) ) {
									stream->send_window += window_delta;
									if ((stream->send_window == window_delta) && (window_delta > 0)) {
										ngx_post_event(&stream->event, &ngx_posted_events);
									}
								}

							}
							++queue;
							++j;
						}
					}
					break;

				case 0x03:  //NGX_HTTP_V2_MAX_STREAMS_SETTING
					if (pv > h2c->server->scf->max_streams) {
						pv = h2c->server->scf->max_streams;
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
								while(!(ngx_queue_empty(queue))){
									q = ngx_queue_tail(queue);
									ngx_queue_remove(q);
									stream = ngx_queue_data(q, ngx_http2_stream_t, queue);
									if(stream->event.posted){
										ngx_queue_remove(&stream->event.queue);
										stream->event.posted = 0;
									}
									stream->state=NGX_HTTP2_STREAM_STATE_WATTING_WITHOUT_SERVER;
									ngx_queue_insert_tail(&h2c->server->stream_queue,&stream->queue);
									--h2c->processing;
									if (h2c->processing == pv) {
										break;
									}
								}
								if(h2c->server->connection ==NULL &&(!ngx_queue_empty(&h2c->server->stream_queue))){
									ngx_http2_upstream_accecpt_streams(h2c->server);
								}


							}
							h2c->max_streams = pv;
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
		h2c->recv.handler = ngx_http2_upstream_read_frame_head;
		return NGX_OK;
	} else {
		return NGX_AGAIN;
	}
}
static int ngx_http2_upstream_read_setting_frame(ngx_http2_connection_t* h2c) {
	if (h2c->recv.flag == NGX_HTTP2_ACK_FLAG) {
		if (h2c->recv.payload_len != 0) {
			return NGX_ERROR;
		}

	} else if (h2c->recv.payload_len % 6) {
		return NGX_ERROR;
	} else if (h2c->recv.payload_len) {
		h2c->recv.handler = ngx_http2_upstream_read_setting_params;
		h2c->recv.min_len = h2c->recv.payload_len;
		return NGX_OK;
	}
	h2c->recv.min_len = 9;
	h2c->recv.handler = ngx_http2_upstream_read_frame_head;
	return NGX_OK;

}
static int ngx_http2_upstream_read_ping_frame(ngx_http2_connection_t* h2c) {
	ngx_http2_frame_t * frame;
	ngx_http_upstream_http2_srv_conf_t scf = h2c->server->scf;
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
	h2c->recv.handler = ngx_http2_upstream_read_frame_head;
	return NGX_OK;

}
static int ngx_http2_upstream_read_data_frame(ngx_http2_connection_t* h2c) {
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


static int ngx_http2_upstream_read_continuation_head(ngx_http2_connection_t* h2c){
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


static int ngx_http2_upstream_process_field_cnt(ngx_http2_connection_t* h2c){
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

static int ngx_http2_upstream_read_field_cnt(ngx_http2_connection_t* h2c){
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
			h2c->recv.handler = ngx_http2_upstream_read_headers_item;
		}else{
			h2c->recv_paser_value= 1;
			h2c->recv.min_len=1;
			h2c->recv.handler = ngx_http2_upstream_read_field_len;
		}

	}else{
		h2c->recv.min_len =h2c->recv.payload_len+ h2c->recv.padding+ 9;
		h2c->recv.next_handler =ngx_http2_upstream_read_field_cnt;
		h2c->recv.handler = ngx_http2_upstream_read_continuation_head;

	}
	return NGX_OK;

	failed: ngx_destroy_pool(h2c->recv.pool);
	h2c->recv.pool = NULL;
	return NGX_ERROR;
}
static int ngx_http2_upstream_read_field_len(ngx_http2_connection_t* h2c) {
	u_char ch;
	u_char* p;
	ngx_int_t value;
	ngx_uint_t huff, shift, octet, len;
	if (h2c->recv.payload_len) {
		if ((h2c->recv.payload_len < 4) && (!(h2c->recv.flag & NGX_HTTP2_END_HEADERS_FLAG))) {
			h2c->recv.min_len = 9 + h2c->recv.padding + h2c->recv.payload_len;
			h2c->recv.next_handler = ngx_http2_upstream_read_field_len;
			h2c->recv.handler = ngx_http2_upstream_read_continuation_head;
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
			if(value > (h2c->server->scf->buffer_size - 9 /*frame head size*/-256/*max padding + 1*/)){
				// header_name or header_value too large
				return NGX_ERROR;
			}
			h2c->recv.pos+=len;
			h2c->recv.len-=len;
			h2c->recv.payload_len -=len;
			h2c->recv.field_len = value;
			h2c->recv.min_len = value <= h2c->recv.payload_len ? value : (h2c->recv.payload_len+h2c->recv.padding+9);
			h2c->recv.handler = ngx_http2_upstream_read_field_cnt;
		}
	} else if (h2c->recv.flag & NGX_HTTP2_END_HEADERS_FLAG) {
		goto failed;
	} else {
		h2c->recv.min_len = 9 + h2c->recv.padding;
		h2c->recv.next_handler = ngx_http2_upstream_read_field_len;
		h2c->recv.handler = ngx_http2_upstream_read_continuation_head;
	}
	return NGX_OK;

	failed: ngx_destroy_pool(h2c->recv.pool);
	h2c->recv.pool = NULL;
	return NGX_ERROR;

}

static int ngx_http2_upstream_read_headers_item(ngx_http2_connection_t* h2c){
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
			h2c->recv.next_handler = ngx_http2_upstream_read_headers_item;
			h2c->recv.handler = ngx_http2_upstream_read_continuation_head;
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
				h2c->recv.handler = ngx_http2_upstream_read_field_len;
			}
		}
	}else if(h2c->recv.flag & NGX_HTTP2_END_HEADERS_FLAG) {
		stream = ngx_http_upstream_http2_find_stream(h2c, h2c->recv.sid);
		if(stream){
			ngx_queue_init(&stream->res_headers_queue);
			queue=&h2c->recv.headers_queue;
			for (q = ngx_queue_head(queue); q != ngx_queue_sentinel(queue); q = ngx_queue_next(q)) {
				header = ngx_queue_data(q, ngx_http2_header_t, queue);
				stream_header = ngx_alloc(stream->request->pool, sizeof(ngx_http2_header_t));
				if (stream_header) {
					ngx_queue_insert_tail(&stream->res_headers_queue, &stream_header->queue);
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

				ngx_queue_remove(&stream->queue);
				stream->event.error = 1;
				ngx_post_event(&stream->event,&ngx_posted_events);
				stream = NULL;
				break;

			}
			if(stream && (h2c->recv.flag & NGX_HTTP2_END_STREAM_FLAG)){
				stream->state = NGX_HTTP2_STREAM_STATE__CLOSED;
				ngx_queue_remove(&stream->queue);
				ngx_post_event(&stream->event,&ngx_posted_events);
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
			h2c->recv.handler =ngx_http2_upstream_read_skip_data;
		}else{
			h2c->recv.min_len = 9;
			h2c->recv.handler = ngx_http2_upstream_read_frame_head;
		}
	}else{
		h2c->recv.min_len = 9 + h2c->recv.padding;
		h2c->recv.next_handler = ngx_http2_upstream_read_headers_item;
		h2c->recv.handler = ngx_http2_upstream_read_continuation_head;
	}
	return NGX_OK;

	failed:
		ngx_destroy_pool(h2c->recv.pool);
		h2c->recv.pool = NULL;
		return NGX_ERROR;

}
static int ngx_http2_upstream_read_headers_priority(ngx_http2_connection_t* h2c){
	//TODO: ignore priority
	h2c->recv.len-=sizeof(uint32_t)+1;
	h2c->recv.pos+=sizeof(uint32_t)+1;
	h2c->recv.payload_len-=sizeof(uint32_t)+1;
	h2c->recv.min_len = 0;
	h2c->recv.handler = ngx_http2_upstream_read_headers_item;
	h2c->recv.pool = ngx_create_pool(h2c->server->scf->header_pool_size ,h2c->server->scf->log);
	if(!h2c->recv.pool){
		return NGX_ERROR;
	}
	return NGX_OK;
}
static int ngx_http2_upstream_read_headers_frame(ngx_http2_connection_t* h2c) {
//
//	if(h2c->max_streams){
		h2c->recv_index = 0;
		h2c->recv.padding = 0;
		ngx_queue_init(&h2c->recv.headers_queue);
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
			h2c->recv.handler = ngx_http2_upstream_read_headers_priority;
		}else{
			h2c->recv.min_len = 0;
			h2c->recv.handler = ngx_http2_upstream_read_headers_item;
			h2c->recv.pool = ngx_create_pool(h2c->server->scf->header_pool_size,h2c->server->scf->log);
			if(!h2c->recv.pool){
				return NGX_ERROR;
			}
		}
//	}else{
//		h2c->recv.min_len = 1;
//		h2c->recv.handler =ngx_http_upstream_http2_read_skip_data;
//	}
	return NGX_OK;
}


static int ngx_http2_upstream_read_priority_frame(ngx_http2_connection_t* h2c) {
	if (NGX_HTTP2_PRIORITY_SIZE != h2c->recv.payload_len) {
		return NGX_ERROR;
	}
	h2c->recv.len -= NGX_HTTP2_PRIORITY_SIZE;
	h2c->recv.pos += NGX_HTTP2_PRIORITY_SIZE;
	h2c->recv.min_len = 9;
	h2c->recv.handler = ngx_http2_upstream_read_frame_head;
	return NGX_OK;
}
static int ngx_http2_upstream_read_rest_stream_frame(ngx_http2_connection_t* h2c) {
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
		stream->event.error=1;
		ngx_queue_remove(&stream->queue);

		if (h2c->processing == h2c->max_streams) {
			ngx_queue_insert_tail(&server->connection_queue, &h2c->queue);
		}
		--h2c->processing;
		if (stream->state == NGX_HTTP2_STREAM_STATE_OPENED) {
			if (stream->waiting) {
				stream->waiting = 0;
				ngx_queue_remove(&stream->queue_in_waiting);
			}
		}
		ngx_post_event(&stream->event, &ngx_posted_events);
	}
	h2c->recv.len -= NGX_HTTP2_RST_STREAM_SIZE;
	h2c->recv.pos += NGX_HTTP2_RST_STREAM_SIZE;
	h2c->recv.min_len = 9;
	h2c->recv.handler = ngx_http2_upstream_read_frame_head;
	return NGX_OK;
}
static int ngx_http2_upstream_read_push_promise_frame(ngx_http2_connection_t* h2c) {
	return NGX_ERROR;
}
static int ngx_http2_upstream_read_goaway_frame(ngx_http2_connection_t* h2c) {
	u_char* p;
	ngx_uint_t lsid,err_code;
	ngx_connection_t* c;
	ngx_queue_t *queue,*q;
	ngx_http2_stream_t* stream;
	int i;
	int sid_mask = h2c->server->scf->sid_mask;

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
	while(!(ngx_queue_empty(queue))){
		q=ngx_queue_head(queue);
		stream = ngx_queue_data(q, ngx_http2_stream_t, queue);
		ngx_queue_remove(q);
		--h2c->processing;
		if(stream->event.posted){
			ngx_queue_remove(&stream->event.queue);
			stream->event.posted = 0;
		}
		stream->state = NGX_HTTP2_STREAM_STATE_WATTING_IN_SERVER;
		ngx_queue_insert_tail(&h2c->server->stream_queue,&stream->queue);
	}
	if(h2c->server->connection==NULL && (!(ngx_queue_empty(&h2c->server->stream_queue)))){
		ngx_http2_upstream_accecpt_streams(h2c->server);
	}
	queue = &h2c->streams;
	i = 0;
	while (i <= sid_mask) {
		for (q = ngx_queue_head(queue); q != ngx_queue_sentinel(queue); q = ngx_queue_next(q)) {
			stream = ngx_queue_data(q, ngx_http2_stream_t, queue);
			if (stream->id > lsid) {
				ngx_queue_remove(q);
				stream->event.error=1;
				if (((u_char) NGX_HTTP2_STREAM_STATE_OPENED) == stream->state && (stream->waiting)) {
						stream->waiting = 0;
						ngx_queue_remove(&stream->queue_in_waiting);
				}
				ngx_post_event(&stream->event, &ngx_posted_events);
				--h2c->processing;
			}
		}
		++i;
		++queue;
	}
	h2c->recv.min_len =1;
	h2c->recv.handler = ngx_http2_upstream_read_skip_data;
	return NGX_OK;
}
static int ngx_http2_upstream_read_window_update_frame(ngx_http2_connection_t* h2c) {
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
			stream = ngx_http2_upstream_find_stream(h2c, h2c->recv.sid);
			if (stream) {
				if (window > NGX_HTTP2_MAX_FLOW_CONTROL_SIZE - stream->send_window) {
					frame = ngx_http2_get_frame(h2c->server->scf);
					if (frame) {
						ngx_memzero(frame, sizeof(void*)+9+NGX_HTTP2_RST_STREAM_SIZE);
						p = &frame->payload;
						p[2] = NGX_HTTP2_RST_STREAM_SIZE;
						p[3] = NGX_HTTP2_RST_STREAM_FRAME;
						p[5] = h2c->recv.sid << 24;
						p[6] = h2c->recv.sid << 16;
						p[7] = h2c->recv.sid << 8;
						p[8] = h2c->recv.sid;
						p[12] = NGX_HTTP2_FLOW_CTRL_ERROR;
						h2c->send_frame(h2c, frame);
						ngx_queue_remove(&stream->queue);
						if (stream->waiting) {
							ngx_queue_remove(&stream->queue_in_waiting);
							stream->waiting = 0;
						}
						stream->event.error = 1;
						ngx_post_event(&stream->event, &ngx_posted_events);
					} else {
						return NGX_AGAIN;
					}
				} else if (stream->state == NGX_HTTP2_STREAM_STATE_OPENED){
					if(stream->send_window<=0 &&  ((stream->send_window+window)>0)) {
						ngx_post_event(&stream->event, &ngx_posted_events);
					}
					stream->send_window+=window;
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
						//TODO:    thundering herd
						stream = ngx_queue_data(q, ngx_http2_stream_t, queue_in_waiting);
						stream->waiting = 0;
						ngx_post_event(&stream->event, &ngx_posted_events);
					}
					ngx_queue_init(queue);
				}
			}
		}
	} else {
		if (h2c->recv.sid) {
			stream = ngx_http2_upstream_find_stream(h2c, h2c->recv.sid);
			if (stream) {
				frame = ngx_http2_get_frame(h2c->server->scf);
				if (frame) {
					ngx_memzero(frame, sizeof(void*)+9+NGX_HTTP2_RST_STREAM_SIZE);
					p = &frame->payload;
					p[2] = NGX_HTTP2_RST_STREAM_SIZE;
					p[3] = NGX_HTTP2_RST_STREAM_FRAME;
					p[5] = h2c->recv.sid << 24;
					p[6] = h2c->recv.sid << 16;
					p[7] = h2c->recv.sid << 8;
					p[8] = h2c->recv.sid;
					p[12] = NGX_HTTP2_FLOW_CTRL_ERROR;
					h2c->send_frame(h2c, frame);
					ngx_queue_remove(&stream->queue);
					if (stream->waiting) {
						ngx_queue_remove(&stream->queue_in_waiting);
						stream->waiting = 0;
					}
					stream->event.error=1;
					ngx_post_event(&stream->event, &ngx_posted_events);

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
	h2c->recv.handler = ngx_http2_upstream_read_frame_head;
	return NGX_OK;

}
static int ngx_http2_upstream_read_continuation_frame(ngx_http2_connection_t* h2c) {
	//if(h2c->max_streams){
		return NGX_ERROR;
//	}else{
//		h2c->recv.min_len = 1;
//		h2c->recv.handler = ngx_http2_upstream_read_skip_data;
//		return NGX_OK;
//	}
}
static int ngx_http2_upstream_read_skip_data(ngx_http2_connection_t* h2c) {
	if(h2c->recv.payload_len <= h2c->recv.len){
		h2c->recv.len-=h2c->recv.payload_len;
		h2c->recv.pos +=h2c->recv.payload_len;
		h2c->recv.min_len = 9;
		h2c->recv.handler = ngx_http2_upstream_read_frame_head;
	}else{
		h2c->recv.payload_len -=h2c->recv.len;
		h2c->recv.pos = h2c->recv.buffer;
		h2c->recv.readable_size = h2c->server->scf->buffer_size;
		h2c->recv.len=0;
	}
	return NGX_OK;
}

static int ngx_http2_upstream_read_frame_head(ngx_http2_connection_t* h2c) {
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
	ngx_http2_upstream_srv_conf_t* scf = server->scf;
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
	c->read->handler = ngx_http2_upstream_block_event;
	if (h2c->send_error) {
		queue = &h2c->streams;
		i = 0;
		while (i <= scf->sid_mask) {
			for (q = ngx_queue_head(queue); q != ngx_queue_sentinel(queue); q = ngx_queue_next(q)) {
				stream = ngx_queue_data(q, ngx_http2_stream_t, queue);
				stream->event.error=1;
				--h2c->processing;
				ngx_post_event(&stream->event, &ngx_posted_events);
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
		--server->use_conns;
	} else if (h2c->send_goaway) {
		if (h2c->recv.buffer) {
			ngx_http2_free_frame(h2c->recv.buffer);
			h2c->recv.buffer = NULL;
		}
		if(h2c->recv.hpack.data){
			ngx_free(h2c->recv.hpack.data);
			h2c->recv.hpack.data = NULL;
		}
		ngx_post_event(c->write,&ngx_posted_events);
	} else {
		if(h2c->recv.hpack.data){
			ngx_free(h2c->recv.hpack.data);
			h2c->recv.hpack.data = NULL;
		}
		queue = &h2c->idle_streams;
		while(!(ngx_queue_empty(queue))){
			q=ngx_queue_head(queue);
			stream = ngx_queue_data(q, ngx_http2_stream_t, queue);
			ngx_queue_remove(q);
			--h2c->processing;
			if(stream->event.posted){
				ngx_queue_remove(&stream->event.queue);
				stream->event.posted = 0;
			}
			stream->state = NGX_HTTP2_STREAM_STATE_WATTING_IN_SERVER;
			ngx_queue_insert_tail(&h2c->server->stream_queue,&stream->queue);
		}
		if(h2c->server->connection==NULL && (!(ngx_queue_empty(&h2c->server->stream_queue)))){
			ngx_http2_upstream_accecpt_streams(h2c->server);
		}
		queue = &h2c->streams;
		i = 0;
		while (i <= scf->sid_mask) {
			while(!(ngx_queue_empty(queue))){
				ngx_queue_remove(q);
				stream = ngx_queue_data(q, ngx_http2_stream_t, queue);
				stream->event.error = 1;
				--h2c->processing;
				ngx_post_event(&stream->event, &ngx_posted_events);
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
	ngx_http2_upstream_srv_conf_t* scf = server->scf;
	ngx_queue_t* queue, *q;
	ngx_http2_stream_t * stream;
	ngx_http2_frame_t* frame, *next;

	int i;
	h2c->send_frame = ngx_http2_upstream_send_queue_frame_ignore;
	h2c->send_ping = ngx_http2_upstream_send_ping_frame_ignore;
	h2c->send_headers = ngx_http2_upstream_send_header_frame_ignore;


	h2c->send_error = 1;
	if (h2c->processing < h2c->max_streams) {
		ngx_queue_remove(&h2c->queue);
	}
	h2c->max_streams = 0;
	c->write->handler = ngx_http2_upstream_block_event;
	if (h2c->recv_error) {
		ngx_close_connection(c);
		h2c->data = scf->free_connections;
		scf->free_connections = h2c;
		--server->use_conns;
		return;
	} else {
		queue = &h2c->idle_streams;
		while(!(ngx_queue_empty(queue))){
			q=ngx_queue_head(queue);
			stream = ngx_queue_data(q, ngx_http2_stream_t, queue);
			ngx_queue_remove(q);
			--h2c->processing;
			if(stream->event.posted){
				ngx_queue_remove(&stream->event.queue);
				stream->event.posted = 0;
			}
			stream->state = NGX_HTTP2_STREAM_STATE_WATTING_IN_SERVER;
			ngx_queue_insert_tail(&h2c->server->stream_queue,&stream->queue);
		}
		if(h2c->server->connection==NULL && (!(ngx_queue_empty(&h2c->server->stream_queue)))){
			ngx_http2_upstream_accecpt_streams(h2c->server);
		}
		queue = &h2c->streams;
		i = 0;
		i = 0;
		while (i <= scf->sid_mask) {
			while(!(ngx_queue_empty(queue))){
				ngx_queue_remove(q);
				stream = ngx_queue_data(q, ngx_http2_stream_t, queue);
				stream->event.error = 1;
				--h2c->processing;
				ngx_post_event(&stream->event, &ngx_posted_events);
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

static void ngx_http2_upstream_frame_read_handler(ngx_event_t* rev) {
	ngx_connection_t* c = rev->data;
	ngx_http2_connection_t* h2c = c->data;
	ngx_http2_server_t *server = h2c->server;
	ngx_http2_upstream_srv_conf_t* scf = server->scf;
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
				ngx_memmove(h2c->recv.buffer, h2c->recv.pos, len);
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

static void ngx_http2_upstream_gracefuly_close(ngx_event_t* wev) {
	ngx_connection_t* c = wev->data;
	ngx_http2_connection_t* h2c = c->data;
	ngx_http2_server_t *server = h2c->server;
	ngx_http2_upstream_srv_conf_t* scf = server->scf;
	ssize_t rc;

	wev->handler = ngx_http2_upstream_gracefuly_close;
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

	c->write->handler = ngx_http2_upstream_block_event;
	c->read->handler = ngx_http2_upstream_block_event;

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
	--h2c->server->use_conns;
}

static void ngx_http2_upstream_frame_write_handler(ngx_event_t* wev) {
	ngx_connection_t* c = wev->data;
	ngx_http2_connection_t* h2c = c->data;
	ngx_http2_server_t *server = h2c->server;
	ngx_http2_upstream_srv_conf_t* scf = server->scf;
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
						stream = ngx_http2_upstream_find_stream(h2c, (p[5] << 24) | (p[5] << 16) | (p[5] << 8) | p[5]);
						//TODO:  buffering handler
						if (stream && (stream->send_window > 0) && (!stream->waiting)) {
							ngx_post_event(&stream->event, &ngx_posted_events);
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
		c->write->handler = ngx_http2_upstream_block_event;
		ngx_close_connection(c);
		h2c->data = scf->free_connections;
		scf->free_connections = h2c;
		--h2c->server->use_conns;
		return;
	}else if (h2c->processing) {
		return;
	}else if (h2c->max_streams == 0) {
		h2c->send_frame = ngx_http2_upstream_send_queue_frame_ignore;
		h2c->send_ping = ngx_http2_upstream_send_ping_frame_ignore;
		h2c->send_headers = ngx_http2_upstream_send_header_frame_ignore;
		h2c->send_goaway = 1;
		ngx_http2_upstream_gracefuly_close(wev);
	} else {
		//TODO idle_timeout
	}
}

static void ngx_http2_upstream_first_read_handler(ngx_event_t* rev) {
	ngx_connection_t* c = rev->data;
	ngx_http2_connection_t* h2c = c->data;
	ngx_http2_server_t *server = h2c->server;
	ngx_http2_upstream_srv_conf_t* scf = server->conf;
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

				ngx_http2_upstream_accecpt_streams(h2c);
				rev->handler = ngx_http2_upstream_frame_read_handler;
				h2c->recv.min_len = 9;
				h2c->recv.handler = ngx_http2_upstream_read_frame_head;
				c->write->handler = ngx_http2_upstream_frame_write_handler;
				ngx_post_event(c->write, &ngx_posted_events);
				ngx_http2_upstream_frame_read_handler(rev);
			}
		}
	} else {
		goto failed;
	}
	return;

	failed: ngx_http2_free_frame(scf, h2c->send.first_frame);
	ngx_http2_free_frame(scf, h2c->recv.buffer);
	rev->handler = ngx_http2_upstream_block_io;
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
	ngx_http2_upstream_close_stream_in_server(server);
	server->connection = NULL;
}

static void ngx_http2_upstream_first_write_handler(ngx_event_t* wev) {
	ngx_connection_t* c = wev->data;
	ngx_http2_connection_t* h2c = c->data;
	ngx_http2_server_t *server = h2c->server;
	ngx_http2_upstream_srv_conf_t* scf = server->conf;
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
		wev->handler = ngx_http2_upstream_block_io;
		ngx_close_connection(c);
		h2c->data = scf->free_connections;
		scf->free_connections = h2c;
		ngx_http2_upstream_close_stream_in_server(server);
		server->connection = NULL;
	} else if (rc == NGX_AGAIN) {
		return;
	} else if (h2c->send.len == rc) {
		wev->handler = ngx_http2_upstream_block_io;
		c->read->handler = ngx_http2_upstream_first_read_handler;
		ngx_http2_upstream_first_read_handler(c->read);
	} else if (rc) {
		h2c->send.pos += rc;
		h2c->send.len -= rc;
	}
}

//void ngx_http2_upstream_connection_init(ngx_http2_connection_t* h2c) {
//	ngx_int_t i;
//	ngx_connection_t* c = h2c->data;
//	ngx_queue_t* queue = &h2c->streams;
//	h2c->processing = 0;
//	h2c->max_streams = h2c->server->conf->max_streams;
//	h2c->headers_table_size = 4096;
//	c->read->handler = ngx_http2_upstream_block_io;
//	c->write->handler = ngx_http2_upstream_first_write_handler;
//	ngx_queue_init(&h2c->queue);
//	ngx_memzero(&h2c->send, sizeof(ngx_http2_connection_send_part_t));
//	ngx_memzero(&h2c->recv, sizeof(ngx_http2_connection_recv_part_t));
//	h2c->recv_error = 0;
//	h2c->recv_goaway = 0;
//	h2c->send_error = 0;
//	h2c->send_goaway = 0;
//	h2c-> recv_index=0;
//	h2c->recv_paser_value=0;
//	queue = &h2c->streams;
//	for (i = 0; i <= h2c->server->conf->sid_mask; ++i) {
//		ngx_queue_init(queue);
//		++queue;
//	}
//




















ngx_int_t ngx_http2_upstream_create(ngx_http_request_t *r) {
	ngx_http2_stream_t *u;

	u = (ngx_http2_stream_t *)r->upstream;

	if (u ) {
		ngx_memzero(u,sizeof(ngx_http2_stream_t));
		u->request = r;
		u->event.data = u;
		return NGX_OK;
	}

	u = ngx_pcalloc(r->pool, sizeof(ngx_http2_stream_t));
	if (u == NULL) {
		return NGX_ERROR;
	}

	r->upstream = (ngx_http_upstream_t*)u;
	u->event.data = u;
	u->request = r;
	return NGX_OK;
}

void ngx_http2_upstream_init(ngx_http_request_t *r) {
	ngx_connection_t *c;

	c = r->connection;

	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
			"http init upstream, client timer: %d", c->read->timer_set);

#if (NGX_HTTP_V2)
	if (r->stream) {
		ngx_http2_upstream_init_request(r);
		return;
	}
#endif

	if (c->read->timer_set) {
		ngx_del_timer(c->read);
	}

	if (!c->write->active) {
		if (ngx_add_event(c->write, NGX_WRITE_EVENT,
				NGX_CLEAR_EVENT) == NGX_ERROR) {
			ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
			return;
		}
	}

	ngx_http2_upstream_init_request(r);
}

static void ngx_http2_upstream_init_request(ngx_http_request_t *r) {
	ngx_str_t *host;
	ngx_uint_t i;
	ngx_resolver_ctx_t *ctx, temp;
	ngx_http_cleanup_t *cln;
	ngx_http2_stream_t *u;
	ngx_http_core_loc_conf_t *clcf;
	ngx_http2_upstream_srv_conf_t *uscf, **uscfp;
	ngx_http2_upstream_main_conf_t *umcf;

	if (r->aio) {
		return;
	}

	u = (ngx_http2_stream_t) r->upstream;
	u->state = NGX_HTTP2_STREAM_STATE_WATTING_WITHOUT_SERVER;

	//	u->store = u->conf->store;
	//
	//	if (!u->store && !r->post_action && !u->conf->ignore_client_abort) {
	//		r->read_event_handler = ngx_http2_upstream_rd_check_broken_connection;
	//		r->write_event_handler = ngx_http2_upstream_wr_check_broken_connection;
	//	}

	if (r->request_body) {
		u->request_bufs = r->request_body->bufs;
	}
	uscf = NULL;
	host = u->host;
	umcf = ngx_http_get_module_main_conf(r, ngx_http2_upstream_module);

	uscfp = umcf->upstreams.elts;

	for (i = 0; i < umcf->upstreams.nelts; i++) {
		uscf = uscfp[i];
		if (uscf->host.len == host->len && ngx_strncasecmp(uscf->host.data, host->data, host->len) == 0) {
			u->upstream = uscf;
				#if (NGX_HTTP_SSL)
				u->ssl_name = uscf->host;
				#endif
				uscf->choose_server(r, uscf);
				if (u->server) {
					ngx_http2_upstream_connect(u);
				} else {
					ngx_http2_upstream_finalize_stream(u, NGX_HTTP_INTERNAL_SERVER_ERROR);
				}
				return;
		}
	}
	ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0, "no http2_upstream configuration");
	ngx_http2_upstream_finalize_stream(u, NGX_HTTP_INTERNAL_SERVER_ERROR);
	return;
}



static void ngx_http2_upstream_handler(ngx_event_t *ev) {
	ngx_connection_t *c;
	ngx_http_request_t *r;
	ngx_http2_stream_t *u;

	c = ev->data;
	r = c->data;

	u = r->upstream;
	c = r->connection;

	ngx_http_set_log_request(c->log, r);

	ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
			"http upstream request: \"%V?%V\"", &r->uri, &r->args);

	if (ev->delayed && ev->timedout) {
		ev->delayed = 0;
		ev->timedout = 0;
	}

	if (ev->write) {
		u->write_event_handler(r, u);

	} else {
		u->read_event_handler(r, u);
	}

	ngx_http_run_posted_requests(c);
}

static ngx_int_t ngx_http2_upstream_connect_to_server(ngx_http2_server_t* server){

	int rc, type;
	in_port_t port;
		ngx_int_t event;
		ngx_err_t err;
		ngx_uint_t level;
		ngx_socket_t s;
		ngx_event_t *rev, *wev;
		ngx_connection_t *c;
		ngx_log_t *log;
		int i;
		ngx_queue_t *queue;
		ngx_http2_connection_t* h2c;
		h2c= server->connection;

		h2c->server= server;

		s = ngx_socket(server->addrs[0].sockaddr->sa_family, SOCK_STREAM, 0);
		if (s == (ngx_socket_t) -1) {
			return NGX_ERROR;
		}
		c = ngx_get_connection(s, server->scf->log);
		if (c == NULL) {
			if (ngx_close_socket(s) == -1) {
				ngx_log_error(NGX_LOG_ALERT,server->scf->log, ngx_socket_errno,
						ngx_close_socket_n "failed");
			}

			return NGX_ERROR;
		}
		c->type = SOCK_STREAM;

		if (server->scf->recvbuf) {
				if (setsockopt(s, SOL_SOCKET, SO_RCVBUF, (const void *) &server->scf->recvbuf,
						sizeof(int)) == -1) {
					ngx_log_error(NGX_LOG_ALERT, c->log, ngx_socket_errno,"setsockopt(SO_RCVBUF) failed");
					goto failed;
				}
		}
		if (ngx_nonblocking(s) == -1) {
			ngx_log_error(NGX_LOG_ALERT,c->log, ngx_socket_errno,	ngx_nonblocking_n " failed");
			goto failed;
		}

		if (server->scf->local) {

		#if (NGX_HAVE_IP_BIND_ADDRESS_NO_PORT || NGX_LINUX)
			port = ngx_inet_get_port(server->scf->local->sockaddr);
		#endif

	#if (NGX_HAVE_IP_BIND_ADDRESS_NO_PORT)
			if (server->addrs[0].sockaddr->sa_family != AF_UNIX && port == 0) {
				static int bind_address_no_port = 1;

				if (bind_address_no_port) {
					if (setsockopt(s, IPPROTO_IP, IP_BIND_ADDRESS_NO_PORT,
									(const void *) &bind_address_no_port,
									sizeof(int)) == -1)
					{
						err = ngx_socket_errno;

						if (err != NGX_EOPNOTSUPP && err != NGX_ENOPROTOOPT) {
							ngx_log_error(NGX_LOG_ALERT, server->scf->log, err,
									"setsockopt(IP_BIND_ADDRESS_NO_PORT) "
									"failed, ignored");

						} else {
							bind_address_no_port = 0;
						}
					}
				}
			}

	#endif

			if (bind(s, server->addrs[0].sockaddr,server->addrs[0].socklen) == -1) {
				ngx_log_error(NGX_LOG_CRIT, c->log, ngx_socket_errno,			"bind(%V) failed", &server->scf->local->name);

				goto failed;
			}
		}


			c->recv = ngx_recv;
			c->send = ngx_send;
			c->recv_chain = ngx_recv_chain;
			c->send_chain = ngx_send_chain;

			c->sendfile = 0;

			if (server->addrs[0].sockaddr->sa_family == AF_UNIX) {
				c->tcp_nopush = NGX_TCP_NOPUSH_DISABLED;
				c->tcp_nodelay = NGX_TCP_NODELAY_DISABLED;

	#if (NGX_SOLARIS)
				/* Solaris's sendfilev() supports AF_NCA, AF_INET, and AF_INET6 */
				c->sendfile = 0;
	#endif
			}


		c->log_error =server->scf->log;

		rev = c->read;
		wev = c->write;

		rev->log =server->scf->log;
		wev->log = server->scf->log;

		h2c->data = c;

		c->number = ngx_atomic_fetch_add(ngx_connection_counter, 1);

		if (ngx_add_conn) {
			if (ngx_add_conn(c) == NGX_ERROR) {
				goto failed;
			}
		}

		ngx_log_debug3(NGX_LOG_DEBUG_EVENT,server->scf->log, 0,
				"connect to %V, fd:%d #%uA", pc->name, s, c->number);

		rc = connect(s, server->addrs[0].sockaddr,server->addrs[0].socklen);

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
						&server->name);

				ngx_close_connection(c);
				return NGX_ERROR;
			}
		}

		if (ngx_add_conn) {
			if (rc == -1) {

				/* NGX_EINPROGRESS */

				return NGX_AGAIN;
			}

			ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0, "connected");

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

		ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0, "connected");

		wev->ready = 1;

		return NGX_OK;

		failed:

		ngx_close_connection(c);
		return NGX_ERROR;
}

static void ngx_http2_upstream_first_read_handler(ngx_event_t* rev) {
	ngx_connection_t* c = rev->data;
	ngx_http2_connection_t* h2c = c->data;
	ngx_http2_server_t *server = h2c->server;
	ngx_http2_upstream_srv_conf_t* scf = server->scf;
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
				h2c->send.pos= p;
				h2c->send.len = 9;

				ngx_http2_upstream_accecpt_streams(server);
				rev->handler = ngx_http2_upstream_frame_read_handler;
				h2c->recv.min_len = 9;
				h2c->recv.handler = ngx_http2_upstream_read_frame_head;
				c->write->handler = ngx_http2_upstream_frame_write_handler;
				ngx_post_event(c->write, &ngx_posted_events);
				ngx_http2_upstream_frame_read_handler(rev);
			}
		}
	} else {
		goto failed;
	}
	return;

failed:
	ngx_http2_free_frame(scf, h2c->send.first_frame);
	ngx_http2_free_frame(scf, h2c->recv.buffer);
	rev->handler = ngx_http2_upstream_block_event;
	if(h2c->recv.hpack.data){
		ngx_free(h2c->recv.hpack.data);
		h2c->recv.hpack.data = NULL;
	}
	ngx_close_connection(c);
	h2c->data = scf->free_connections;
	scf->free_connections = h2c;
	server->connection = NULL;
	--server->use_conns;
	ngx_http2_upstream_close_stream_in_server(server);

}

static u_char ngx_http2_connection_start[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" /* connection preface */

		"\x00\x00\x12\x04\x00\x00\x00\x00\x00" /* settings frame */
		"\x00\x01\x00\x00\x00\x00" /* header table size */
		"\x00\x02\x00\x00\x00\x00" /* disable push */
		"\x00\x04\x7f\xff\xff\xff" /* initial window */

		"\x00\x00\x04\x08\x00\x00\x00\x00\x00" /* window update frame */
		"\x7f\xff\x00\x00";
static void ngx_http2_upstream_first_write_handler(ngx_event_t* wev) {
	ngx_connection_t* c = wev->data;
	ngx_http2_connection_t* h2c = c->data;
	ngx_http2_server_t *server = h2c->server;
	ngx_http2_upstream_srv_conf_t* scf = server->scf;
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
		wev->handler = ngx_http2_upstream_block_event;
		ngx_close_connection(c);
		h2c->data = scf->free_connections;
		scf->free_connections = h2c;
		server->connection = NULL;
		--server->use_conns;
		ngx_http2_upstream_close_stream_in_server(server);
	} else if (rc == NGX_AGAIN) {
		return;
	} else if (h2c->send.len == rc) {
		wev->handler = ngx_http2_upstream_block_event;
		c->read->handler = ngx_http2_upstream_first_read_handler;
		ngx_http2_upstream_first_read_handler(c->read);
	} else if (rc) {
		h2c->send.pos += rc;
		h2c->send.len -= rc;
	}
}
void ngx_http2_upstream_connection_init(ngx_http2_connection_t* h2c) {
	ngx_int_t i;
	ngx_connection_t* c = h2c->data;
	ngx_queue_t* queue = &h2c->streams;
	h2c->processing = 0;
	h2c->max_streams = h2c->server->scf->max_streams;
	h2c->headers_table_size = 4096;
	c->read->handler = ngx_http2_upstream_block_event;
	c->write->handler = ngx_http2_upstream_first_write_handler;
	queue = &h2c->streams;
	for (i = 0; i <= h2c->server->scf->sid_mask; ++i) {
		ngx_queue_init(queue);
		++queue;
	}
	queue = h2c->idle_streams;
	ngx_queue_init(queue);
	queue = &h2c->send.flow_control_queue;
	ngx_queue_init(queue);
	h2c->send_frame = ngx_http2_upstream_send_queue_frame;
	h2c->send_ping = ngx_http2_upstream_send_ping_frame;
	h2c->send_headers = ngx_http2_upstream_send_header_frame;
}
static void ngx_http2_upstream_connect(ngx_http2_stream_t *stream) {
	ngx_int_t rc;
	ngx_connection_t *c;
	ngx_http2_connection_t *h2c;
	ngx_http2_server_t *server;
	ngx_queue_t *queue;

	stream->request->connection->log->action = "connecting to upstream";
	server = stream->server;
	stream->event.handler = ngx_http2_upstream_stream_write_header_event;


	if(server->connection){
		stream->state =NGX_HTTP2_STREAM_STATE_WATTING_IN_SERVER;
		ngx_queue_insert_tail(&server->stream_queue,&stream->queue);
	}else if(!ngx_queue_empty(&server->connection_queue)){
		stream->state =NGX_HTTP2_STREAM_STATE_WATTING_IN_CONNECTION;
		h2c = ngx_queue_data(ngx_queue_head(&server->connection_queue),ngx_http2_connection_t,queue);
		++h2c->processing;
		if(h2c->processing >= h2c->max_streams){
			ngx_queue_remove(&h2c->queue);
		}
		ngx_queue_insert_tail(&h2c->idle_streams,&stream->queue);
		ngx_post_event(&stream->event,&ngx_posted_events);
	}else{
		stream->state =NGX_HTTP2_STREAM_STATE_WATTING_IN_SERVER;
		ngx_queue_insert_tail(&server->stream_queue,&stream->queue);

		server->connection = server->scf->free_connections;
		if(server->connection){
			server->scf->free_connections = server->connection->data;
			ngx_memzero(server->connection,sizeof(ngx_http2_connection_t));
		}else{
			server->connection = ngx_pcalloc(server->scf->pool,(sizeof(ngx_http2_connection_t)+ (sizeof(ngx_queue_t)* server->scf->sid_mask)));
			if(!server->connection){
				ngx_http2_upstream_finalize_stream(stream,NGX_HTTP_INTERNAL_SERVER_ERROR);
				return;
			}
		}
		++server->use_conns;
		rc = ngx_http2_upstream_connect_to_server(server);
		if(rc == NGX_ERROR){
			--server->use_conns;
			server->connection->data = server->scf->free_connections;
			server->scf->free_connections = server->connection;
			server->connection = NULL;
			ngx_queue_remove(&stream->queue);
			stream->event.error = 1;
			stream->state = NGX_HTTP2_STREAM_STATE_WATTING_WITHOUT_SERVER;
			ngx_post_event(&stream->event,&ngx_posted_events);
		}else {
			//TODO init ssl;
			c = server->connection->data;
			c->data = server->connection;
			ngx_http2_upstream_http2_connection_init(server->connection);
			if(rc == NGX_OK){
				ngx_http2_upstream_first_write_handler(c->write);
			}
		}
	}



	if (u->request_sent) {
		if (ngx_http2_upstream_reinit(r, u) != NGX_OK) {
			ngx_http2_upstream_finalize_request(r, u,
			NGX_HTTP_INTERNAL_SERVER_ERROR);
			return;
		}
	}

	if (r->request_body && r->request_body->buf && r->request_body->temp_file
			&& r == r->main) {
		/*
		 * the r->request_body->buf can be reused for one request only,
		 * the subrequests should allocate their own temporary bufs
		 */

		u->output.free = ngx_alloc_chain_link(r->pool);
		if (u->output.free == NULL) {
			ngx_http2_upstream_finalize_request(r, u,
			NGX_HTTP_INTERNAL_SERVER_ERROR);
			return;
		}

		u->output.free->buf = r->request_body->buf;
		u->output.free->next = NULL;
		u->output.allocated = 1;

		r->request_body->buf->pos = r->request_body->buf->start;
		r->request_body->buf->last = r->request_body->buf->start;
		r->request_body->buf->tag = u->output.tag;
	}

	u->request_sent = 0;
	u->request_body_sent = 0;
	u->request_body_blocked = 0;

	if (rc == NGX_AGAIN) {
		ngx_add_timer(c->write, u->conf->connect_timeout);
		return;
	}

#if (NGX_HTTP_SSL)

	if (u->ssl && c->ssl == NULL) {
		ngx_http2_upstream_ssl_init_connection(r, u, c);
		return;
	}

#endif

	ngx_http2_upstream_send_request(r, u, 1);
}

#if (NGX_HTTP_SSL)

static void ngx_http2_upstream_ssl_init_connection(ngx_http_request_t *r,
		ngx_http2_stream_t *u, ngx_connection_t *c) {
	ngx_int_t rc;
	ngx_http_core_loc_conf_t *clcf;

	if (ngx_http2_stream_test_connect(c) != NGX_OK) {
		ngx_http2_upstream_next(r, u, ngx_http2_upstream_FT_ERROR);
		return;
	}

	if (ngx_ssl_create_connection(u->conf->ssl, c,
	NGX_SSL_BUFFER | NGX_SSL_CLIENT) != NGX_OK) {
		ngx_http2_upstream_finalize_request(r, u,
		NGX_HTTP_INTERNAL_SERVER_ERROR);
		return;
	}

	c->sendfile = 0;
	u->output.sendfile = 0;

	if (u->conf->ssl_server_name || u->conf->ssl_verify) {
		if (ngx_http2_upstream_ssl_name(r, u, c) != NGX_OK) {
			ngx_http2_upstream_finalize_request(r, u,
			NGX_HTTP_INTERNAL_SERVER_ERROR);
			return;
		}
	}

	if (u->conf->ssl_session_reuse) {
		if (u->peer.set_session(&u->peer, u->peer.data) != NGX_OK) {
			ngx_http2_upstream_finalize_request(r, u,
			NGX_HTTP_INTERNAL_SERVER_ERROR);
			return;
		}

		/* abbreviated SSL handshake may interact badly with Nagle */

		clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

		if (clcf->tcp_nodelay && ngx_tcp_nodelay(c) != NGX_OK) {
			ngx_http2_upstream_finalize_request(r, u,
			NGX_HTTP_INTERNAL_SERVER_ERROR);
			return;
		}
	}

	r->connection->log->action = "SSL handshaking to upstream";

	rc = ngx_ssl_handshake(c);

	if (rc == NGX_AGAIN) {

		if (!c->write->timer_set) {
			ngx_add_timer(c->write, u->conf->connect_timeout);
		}

		c->ssl->handler = ngx_http2_upstream_ssl_handshake_handler;
		return;
	}

	ngx_http2_upstream_ssl_handshake(r, u, c);
}

static void ngx_http2_upstream_ssl_handshake_handler(ngx_connection_t *c) {
	ngx_http_request_t *r;
	ngx_http2_stream_t *u;

	r = c->data;

	u = r->upstream;
	c = r->connection;

	ngx_http_set_log_request(c->log, r);

	ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
			"http upstream ssl handshake: \"%V?%V\"",
			&r->uri, &r->args);

	ngx_http2_upstream_ssl_handshake(r, u, u->peer.connection);

	ngx_http_run_posted_requests(c);
}

static void ngx_http2_upstream_ssl_handshake(ngx_http_request_t *r,
		ngx_http2_stream_t *u, ngx_connection_t *c) {
	long rc;

	if (c->ssl->handshaked) {

		if (u->conf->ssl_verify) {
			rc = SSL_get_verify_result(c->ssl->connection);

			if (rc != X509_V_OK) {
				ngx_log_error(NGX_LOG_ERR, c->log, 0,
						"upstream SSL certificate verify error: (%l:%s)", rc,
						X509_verify_cert_error_string(rc));
				goto failed;
			}

			if (ngx_ssl_check_host(c, &u->ssl_name) != NGX_OK) {
				ngx_log_error(NGX_LOG_ERR, c->log, 0,
						"upstream SSL certificate does not match \"%V\"",
						&u->ssl_name);
				goto failed;
			}
		}

		if (u->conf->ssl_session_reuse) {
			u->peer.save_session(&u->peer, u->peer.data);
		}

		c->write->handler = ngx_http2_upstream_handler;
		c->read->handler = ngx_http2_upstream_handler;

		ngx_http2_upstream_send_request(r, u, 1);

		return;
	}

	if (c->write->timedout) {
		ngx_http2_upstream_next(r, u, ngx_http2_upstream_FT_TIMEOUT);
		return;
	}

	failed:

	ngx_http2_upstream_next(r, u, ngx_http2_upstream_FT_ERROR);
}

static ngx_int_t ngx_http2_upstream_ssl_name(ngx_http_request_t *r,
		ngx_http2_stream_t *u, ngx_connection_t *c) {
	u_char *p, *last;
	ngx_str_t name;

	if (u->conf->ssl_name) {
		if (ngx_http_complex_value(r, u->conf->ssl_name, &name) != NGX_OK) {
			return NGX_ERROR;
		}

	} else {
		name = u->ssl_name;
	}

	if (name.len == 0) {
		goto done;
	}

	/*
	 * ssl name here may contain port, notably if derived from $proxy_host
	 * or $http_host; we have to strip it
	 */

	p = name.data;
	last = name.data + name.len;

	if (*p == '[') {
		p = ngx_strlchr(p, last, ']');

		if (p == NULL) {
			p = name.data;
		}
	}

	p = ngx_strlchr(p, last, ':');

	if (p != NULL) {
		name.len = p - name.data;
	}

	if (!u->conf->ssl_server_name) {
		goto done;
	}

#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME

	/* as per RFC 6066, literal IPv4 and IPv6 addresses are not permitted */

	if (name.len == 0 || *name.data == '[') {
		goto done;
	}

	if (ngx_inet_addr(name.data, name.len) != INADDR_NONE) {
		goto done;
	}

	/*
	 * SSL_set_tlsext_host_name() needs a null-terminated string,
	 * hence we explicitly null-terminate name here
	 */

	p = ngx_pnalloc(r->pool, name.len + 1);
	if (p == NULL) {
		return NGX_ERROR;
	}

	(void) ngx_cpystrn(p, name.data, name.len + 1);

	name.data = p;

	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
			"upstream SSL server name: \"%s\"", name.data);

	if (SSL_set_tlsext_host_name(c->ssl->connection,
			(char *) name.data) == 0) {
		ngx_ssl_error(NGX_LOG_ERR, r->connection->log, 0,
				"SSL_set_tlsext_host_name(\"%s\") failed", name.data);
		return NGX_ERROR;
	}

#endif

	done:

	u->ssl_name = name;

	return NGX_OK;
}

#endif

static ngx_int_t ngx_http2_upstream_reinit(ngx_http_request_t *r,
		ngx_http2_stream_t *u) {
	off_t file_pos;
	ngx_chain_t *cl;

	if (u->reinit_request(r) != NGX_OK) {
		return NGX_ERROR;
	}

	u->keepalive = 0;
	u->upgrade = 0;

	ngx_memzero(&u->headers_in, sizeof(ngx_http2_upstream_headers_in_t));
	u->headers_in.content_length_n = -1;
	u->headers_in.last_modified_time = -1;

	if (ngx_list_init(&u->headers_in.headers, r->pool, 8,
			sizeof(ngx_table_elt_t)) != NGX_OK) {
		return NGX_ERROR;
	}

	if (ngx_list_init(&u->headers_in.trailers, r->pool, 2,
			sizeof(ngx_table_elt_t)) != NGX_OK) {
		return NGX_ERROR;
	}

	/* reinit the request chain */

	file_pos = 0;

	for (cl = u->request_bufs; cl; cl = cl->next) {
		cl->buf->pos = cl->buf->start;

		/* there is at most one file */

		if (cl->buf->in_file) {
			cl->buf->file_pos = file_pos;
			file_pos = cl->buf->file_last;
		}
	}

	/* reinit the subrequest's ngx_output_chain() context */

	if (r->request_body && r->request_body->temp_file && r != r->main
			&& u->output.buf) {
		u->output.free = ngx_alloc_chain_link(r->pool);
		if (u->output.free == NULL) {
			return NGX_ERROR;
		}

		u->output.free->buf = u->output.buf;
		u->output.free->next = NULL;

		u->output.buf->pos = u->output.buf->start;
		u->output.buf->last = u->output.buf->start;
	}

	u->output.buf = NULL;
	u->output.in = NULL;
	u->output.busy = NULL;

	/* reinit u->buffer */

	u->buffer.pos = u->buffer.start;



	u->buffer.last = u->buffer.pos;

	return NGX_OK;
}

static void ngx_http2_upstream_send_request(ngx_http_request_t *r,
		ngx_http2_stream_t *u, ngx_uint_t do_write) {
	ngx_int_t rc;
	ngx_connection_t *c;

	c = u->peer.connection;

	ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
			"http upstream send request");

	if (u->state->connect_time == (ngx_msec_t) -1) {
		u->state->connect_time = ngx_current_msec - u->state->response_time;
	}

	if (!u->request_sent && ngx_http2_stream_test_connect(c) != NGX_OK) {
		ngx_http2_upstream_next(r, u, ngx_http2_upstream_FT_ERROR);
		return;
	}

	c->log->action = "sending request to upstream";

	rc = ngx_http2_upstream_send_request_body(r, u, do_write);

	if (rc == NGX_ERROR) {
		ngx_http2_upstream_next(r, u, ngx_http2_upstream_FT_ERROR);
		return;
	}

	if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
		ngx_http2_upstream_finalize_request(r, u, rc);
		return;
	}

	if (rc == NGX_AGAIN) {
		if (!c->write->ready || u->request_body_blocked) {
			ngx_add_timer(c->write, u->conf->send_timeout);

		} else if (c->write->timer_set) {
			ngx_del_timer(c->write);
		}

		if (ngx_handle_write_event(c->write, u->conf->send_lowat) != NGX_OK) {
			ngx_http2_upstream_finalize_request(r, u,
			NGX_HTTP_INTERNAL_SERVER_ERROR);
			return;
		}

		return;
	}

	/* rc == NGX_OK */

	u->request_body_sent = 1;

	if (c->write->timer_set) {
		ngx_del_timer(c->write);
	}

	if (c->tcp_nopush == NGX_TCP_NOPUSH_SET) {
		if (ngx_tcp_push(c->fd) == -1) {
			ngx_log_error(NGX_LOG_CRIT, c->log, ngx_socket_errno,
					ngx_tcp_push_n " failed");
			ngx_http2_upstream_finalize_request(r, u,
			NGX_HTTP_INTERNAL_SERVER_ERROR);
			return;
		}

		c->tcp_nopush = NGX_TCP_NOPUSH_UNSET;
	}

	if (!u->conf->preserve_output) {
		u->write_event_handler = ngx_http2_upstream_dummy_handler;
	}

	if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
		ngx_http2_upstream_finalize_request(r, u,
		NGX_HTTP_INTERNAL_SERVER_ERROR);
		return;
	}

	ngx_add_timer(c->read, u->conf->read_timeout);

	if (c->read->ready) {
		ngx_http2_upstream_process_header(r, u);
		return;
	}
}

static ngx_int_t ngx_http2_upstream_send_request_body(ngx_http_request_t *r,
		ngx_http2_stream_t *u, ngx_uint_t do_write) {
	ngx_int_t rc;
	ngx_chain_t *out, *cl, *ln;
	ngx_connection_t *c;
	ngx_http_core_loc_conf_t *clcf;

	ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
			"http upstream send request body");

	if (!r->request_body_no_buffering) {

		/* buffered request body */

		if (!u->request_sent) {
			u->request_sent = 1;
			out = u->request_bufs;

		} else {
			out = NULL;
		}

		rc = ngx_output_chain(&u->output, out);

		if (rc == NGX_AGAIN) {
			u->request_body_blocked = 1;

		} else {
			u->request_body_blocked = 0;
		}

		return rc;
	}

	if (!u->request_sent) {
		u->request_sent = 1;
		out = u->request_bufs;

		if (r->request_body->bufs) {
			for (cl = out; cl->next; cl = out->next) { /* void */
			}
			cl->next = r->request_body->bufs;
			r->request_body->bufs = NULL;
		}

		c = u->peer.connection;
		clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

		if (clcf->tcp_nodelay && ngx_tcp_nodelay(c) != NGX_OK) {
			return NGX_ERROR;
		}

		r->read_event_handler = ngx_http2_upstream_read_request_handler;

	} else {
		out = NULL;
	}

	for (;;) {

		if (do_write) {
			rc = ngx_output_chain(&u->output, out);

			if (rc == NGX_ERROR) {
				return NGX_ERROR;
			}

			while (out) {
				ln = out;
				out = out->next;
				ngx_free_chain(r->pool, ln);
			}

			if (rc == NGX_AGAIN) {
				u->request_body_blocked = 1;

			} else {
				u->request_body_blocked = 0;
			}

			if (rc == NGX_OK && !r->reading_body) {
				break;
			}
		}

		if (r->reading_body) {
			/* read client request body */

			rc = ngx_http_read_unbuffered_request_body(r);

			if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
				return rc;
			}

			out = r->request_body->bufs;
			r->request_body->bufs = NULL;
		}

		/* stop if there is nothing to send */

		if (out == NULL) {
			rc = NGX_AGAIN;
			break;
		}

		do_write = 1;
	}

	if (!r->reading_body) {
		if (!u->store && !r->post_action && !u->conf->ignore_client_abort) {
			r->read_event_handler =
					ngx_http2_upstream_rd_check_broken_connection;
		}
	}

	return rc;
}

static void ngx_http2_upstream_send_request_handler(ngx_http_request_t *r,
		ngx_http2_stream_t *u) {
	ngx_connection_t *c;

	c = u->peer.connection;

	ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
			"http upstream send request handler");

	if (c->write->timedout) {
		ngx_http2_upstream_next(r, u, ngx_http2_upstream_FT_TIMEOUT);
		return;
	}

#if (NGX_HTTP_SSL)

	if (u->ssl && c->ssl == NULL) {
		ngx_http2_upstream_ssl_init_connection(r, u, c);
		return;
	}

#endif

	if (u->header_sent && !u->conf->preserve_output) {
		u->write_event_handler = ngx_http2_upstream_dummy_handler;

		(void) ngx_handle_write_event(c->write, 0);

		return;
	}

	ngx_http2_upstream_send_request(r, u, 1);
}

static void ngx_http2_upstream_read_request_handler(ngx_http_request_t *r) {
	ngx_connection_t *c;
	ngx_http2_stream_t *u;

	c = r->connection;
	u = r->upstream;

	ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
			"http upstream read request handler");

	if (c->read->timedout) {
		c->timedout = 1;
		ngx_http2_upstream_finalize_request(r, u, NGX_HTTP_REQUEST_TIME_OUT);
		return;
	}

	ngx_http2_upstream_send_request(r, u, 0);
}

static void ngx_http2_upstream_process_header(ngx_http_request_t *r,
		ngx_http2_stream_t *u) {
	ssize_t n;
	ngx_int_t rc;
	ngx_connection_t *c;

	c = u->peer.connection;

	ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
			"http upstream process header");

	c->log->action = "reading response header from upstream";

	if (c->read->timedout) {
		ngx_http2_upstream_next(r, u, ngx_http2_upstream_FT_TIMEOUT);
		return;
	}

	if (!u->request_sent && ngx_http2_stream_test_connect(c) != NGX_OK) {
		ngx_http2_upstream_next(r, u, ngx_http2_upstream_FT_ERROR);
		return;
	}

	if (u->buffer.start == NULL) {
		u->buffer.start = ngx_palloc(r->pool, u->conf->buffer_size);
		if (u->buffer.start == NULL) {
			ngx_http2_upstream_finalize_request(r, u,
			NGX_HTTP_INTERNAL_SERVER_ERROR);
			return;
		}

		u->buffer.pos = u->buffer.start;
		u->buffer.last = u->buffer.start;
		u->buffer.end = u->buffer.start + u->conf->buffer_size;
		u->buffer.temporary = 1;

		u->buffer.tag = u->output.tag;

		if (ngx_list_init(&u->headers_in.headers, r->pool, 8,
				sizeof(ngx_table_elt_t)) != NGX_OK) {
			ngx_http2_upstream_finalize_request(r, u,
			NGX_HTTP_INTERNAL_SERVER_ERROR);
			return;
		}

		if (ngx_list_init(&u->headers_in.trailers, r->pool, 2,
				sizeof(ngx_table_elt_t)) != NGX_OK) {
			ngx_http2_upstream_finalize_request(r, u,
			NGX_HTTP_INTERNAL_SERVER_ERROR);
			return;
		}


	}

	for (;;) {

		n = c->recv(c, u->buffer.last, u->buffer.end - u->buffer.last);

		if (n == NGX_AGAIN) {
#if 0
			ngx_add_timer(rev, u->read_timeout);
#endif

			if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
				ngx_http2_upstream_finalize_request(r, u,
				NGX_HTTP_INTERNAL_SERVER_ERROR);
				return;
			}

			return;
		}

		if (n == 0) {
			ngx_log_error(NGX_LOG_ERR, c->log, 0,
					"upstream prematurely closed connection");
		}

		if (n == NGX_ERROR || n == 0) {
			ngx_http2_upstream_next(r, u, ngx_http2_upstream_FT_ERROR);
			return;
		}

		u->state->bytes_received += n;

		u->buffer.last += n;

#if 0
		u->valid_header_in = 0;

		u->peer.cached = 0;
#endif

		rc = u->process_header(r);

		if (rc == NGX_AGAIN) {

			if (u->buffer.last == u->buffer.end) {
				ngx_log_error(NGX_LOG_ERR, c->log, 0,
						"upstream sent too big header");

				ngx_http2_upstream_next(r, u,
				ngx_http2_upstream_FT_INVALID_HEADER);
				return;
			}

			continue;
		}

		break;
	}

	if (rc == ngx_http2_upstream_INVALID_HEADER) {
		ngx_http2_upstream_next(r, u, ngx_http2_upstream_FT_INVALID_HEADER);
		return;
	}

	if (rc == NGX_ERROR) {
		ngx_http2_upstream_finalize_request(r, u,
		NGX_HTTP_INTERNAL_SERVER_ERROR);
		return;
	}

	/* rc == NGX_OK */

	u->state->header_time = ngx_current_msec - u->state->response_time;

	if (u->headers_in.status_n >= NGX_HTTP_SPECIAL_RESPONSE) {

		if (ngx_http2_stream_test_next(r, u) == NGX_OK) {
			return;
		}

		if (ngx_http2_upstream_intercept_errors(r, u) == NGX_OK) {
			return;
		}
	}

	if (ngx_http2_upstream_process_headers(r, u) != NGX_OK) {
		return;
	}

	ngx_http2_upstream_send_response(r, u);
}

static ngx_int_t ngx_http2_stream_test_next(ngx_http_request_t *r,
		ngx_http2_stream_t *u) {
	ngx_uint_t status;
	ngx_http2_upstream_next_t *un;

	status = u->headers_in.status_n;

	for (un = ngx_http2_upstream_next_errors; un->status; un++) {

		if (status != un->status) {
			continue;
		}

		if (u->peer.tries > 1 && (u->conf->next_upstream & un->mask)) {
			ngx_http2_upstream_next(r, u, un->mask);
			return NGX_OK;
		}


	}


	return NGX_DECLINED;
}

static ngx_int_t ngx_http2_upstream_intercept_errors(ngx_http_request_t *r,
		ngx_http2_stream_t *u) {
	ngx_int_t status;
	ngx_uint_t i;
	ngx_table_elt_t *h;
	ngx_http_err_page_t *err_page;
	ngx_http_core_loc_conf_t *clcf;

	status = u->headers_in.status_n;

	if (status == NGX_HTTP_NOT_FOUND && u->conf->intercept_404) {
		ngx_http2_upstream_finalize_request(r, u, NGX_HTTP_NOT_FOUND);
		return NGX_OK;
	}

	if (!u->conf->intercept_errors) {
		return NGX_DECLINED;
	}

	clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

	if (clcf->error_pages == NULL) {
		return NGX_DECLINED;
	}

	err_page = clcf->error_pages->elts;
	for (i = 0; i < clcf->error_pages->nelts; i++) {

		if (err_page[i].status == status) {

			if (status == NGX_HTTP_UNAUTHORIZED
					&& u->headers_in.www_authenticate) {
				h = ngx_list_push(&r->headers_out.headers);

				if (h == NULL) {
					ngx_http2_upstream_finalize_request(r, u,
					NGX_HTTP_INTERNAL_SERVER_ERROR);
					return NGX_OK;
				}

				*h = *u->headers_in.www_authenticate;

				r->headers_out.www_authenticate = h;
			}


			ngx_http2_upstream_finalize_request(r, u, status);

			return NGX_OK;
		}
	}

	return NGX_DECLINED;
}

static ngx_int_t ngx_http2_stream_test_connect(ngx_connection_t *c) {
	int err;
	socklen_t len;


	{
		err = 0;
		len = sizeof(int);

		/*
		 * BSDs and Linux return 0 and set a pending error in err
		 * Solaris returns -1 and sets errno
		 */

		if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, (void *) &err, &len)
				== -1) {
			err = ngx_socket_errno;
		}

		if (err) {
			c->log->action = "connecting to upstream";
			(void) ngx_connection_error(c, err, "connect() failed");
			return NGX_ERROR;
		}
	}

	return NGX_OK;
}

static ngx_int_t ngx_http2_upstream_process_headers(ngx_http_request_t *r,
		ngx_http2_stream_t *u) {
	ngx_str_t uri, args;
	ngx_uint_t i, flags;
	ngx_list_part_t *part;
	ngx_table_elt_t *h;
	ngx_http2_upstream_header_t *hh;
	ngx_http2_upstream_main_conf_t *umcf;

	umcf = ngx_http_get_module_main_conf(r, ngx_http2_upstream_module);

	if (u->headers_in.x_accel_redirect
			&& !(u->conf->ignore_headers & ngx_http2_upstream_IGN_XA_REDIRECT)) {
		ngx_http2_upstream_finalize_request(r, u, NGX_DECLINED);

		part = &u->headers_in.headers.part;
		h = part->elts;

		for (i = 0; /* void */; i++) {

			if (i >= part->nelts) {
				if (part->next == NULL) {
					break;
				}

				part = part->next;
				h = part->elts;
				i = 0;
			}

			hh = ngx_hash_find(&umcf->headers_in_hash, h[i].hash,
					h[i].lowcase_key, h[i].key.len);

			if (hh && hh->redirect) {
				if (hh->copy_handler(r, &h[i], hh->conf) != NGX_OK) {
					ngx_http_finalize_request(r,
					NGX_HTTP_INTERNAL_SERVER_ERROR);
					return NGX_DONE;
				}
			}
		}

		uri = u->headers_in.x_accel_redirect->value;

		if (uri.data[0] == '@') {
			ngx_http_named_location(r, &uri);

		} else {
			ngx_str_null(&args);
			flags = NGX_HTTP_LOG_UNSAFE;

			if (ngx_http_parse_unsafe_uri(r, &uri, &args, &flags) != NGX_OK) {
				ngx_http_finalize_request(r, NGX_HTTP_NOT_FOUND);
				return NGX_DONE;
			}

			if (r->method != NGX_HTTP_HEAD) {
				r->method = NGX_HTTP_GET;
				r->method_name = ngx_http_core_get_method;
			}

			ngx_http_internal_redirect(r, &uri, &args);
		}

		ngx_http_finalize_request(r, NGX_DONE);
		return NGX_DONE;
	}

	part = &u->headers_in.headers.part;
	h = part->elts;

	for (i = 0; /* void */; i++) {

		if (i >= part->nelts) {
			if (part->next == NULL) {
				break;
			}

			part = part->next;
			h = part->elts;
			i = 0;
		}

		if (ngx_hash_find(&u->conf->hide_headers_hash, h[i].hash,
				h[i].lowcase_key, h[i].key.len)) {
			continue;
		}

		hh = ngx_hash_find(&umcf->headers_in_hash, h[i].hash, h[i].lowcase_key,
				h[i].key.len);

		if (hh) {
			if (hh->copy_handler(r, &h[i], hh->conf) != NGX_OK) {
				ngx_http2_upstream_finalize_request(r, u,
				NGX_HTTP_INTERNAL_SERVER_ERROR);
				return NGX_DONE;
			}

			continue;
		}

		if (ngx_http2_upstream_copy_header_line(r, &h[i], 0) != NGX_OK) {
			ngx_http2_upstream_finalize_request(r, u,
			NGX_HTTP_INTERNAL_SERVER_ERROR);
			return NGX_DONE;
		}
	}

	if (r->headers_out.server && r->headers_out.server->value.data == NULL) {
		r->headers_out.server->hash = 0;
	}

	if (r->headers_out.date && r->headers_out.date->value.data == NULL) {
		r->headers_out.date->hash = 0;
	}

	r->headers_out.status = u->headers_in.status_n;
	r->headers_out.status_line = u->headers_in.status_line;

	r->headers_out.content_length_n = u->headers_in.content_length_n;

	r->disable_not_modified = !u->cacheable;

	if (u->conf->force_ranges) {
		r->allow_ranges = 1;
		r->single_range = 1;

	}

	u->length = -1;

	return NGX_OK;
}

static ngx_int_t ngx_http2_upstream_process_trailers(ngx_http_request_t *r,
		ngx_http2_stream_t *u) {
	ngx_uint_t i;
	ngx_list_part_t *part;
	ngx_table_elt_t *h, *ho;

	if (!u->conf->pass_trailers) {
		return NGX_OK;
	}

	part = &u->headers_in.trailers.part;
	h = part->elts;

	for (i = 0; /* void */; i++) {

		if (i >= part->nelts) {
			if (part->next == NULL) {
				break;
			}

			part = part->next;
			h = part->elts;
			i = 0;
		}

		if (ngx_hash_find(&u->conf->hide_headers_hash, h[i].hash,
				h[i].lowcase_key, h[i].key.len)) {
			continue;
		}

		ho = ngx_list_push(&r->headers_out.trailers);
		if (ho == NULL) {
			return NGX_ERROR;
		}

		*ho = h[i];
	}

	return NGX_OK;
}

static void ngx_http2_upstream_send_response(ngx_http_request_t *r,
		ngx_http2_stream_t *u) {
	ssize_t n;
	ngx_int_t rc;
	ngx_event_pipe_t *p;
	ngx_connection_t *c;
	ngx_http_core_loc_conf_t *clcf;

	rc = ngx_http_send_header(r);

	if (rc == NGX_ERROR || rc > NGX_OK || r->post_action) {
		ngx_http2_upstream_finalize_request(r, u, rc);
		return;
	}

	u->header_sent = 1;

	if (u->upgrade) {



		ngx_http2_upstream_upgrade(r, u);
		return;
	}

	c = r->connection;

	if (r->header_only) {

		if (!u->buffering) {
			ngx_http2_upstream_finalize_request(r, u, rc);
			return;
		}

		if (!u->cacheable && !u->store) {
			ngx_http2_upstream_finalize_request(r, u, rc);
			return;
		}

		u->pipe->downstream_error = 1;
	}

	if (r->request_body && r->request_body->temp_file && r == r->main
			&& !r->preserve_body) {
		ngx_pool_run_cleanup_file(r->pool, r->request_body->temp_file->file.fd);
		r->request_body->temp_file->file.fd = NGX_INVALID_FILE;
	}

	clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

	if (!u->buffering) {



		if (u->input_filter == NULL) {
			u->input_filter_init = ngx_http2_upstream_non_buffered_filter_init;
			u->input_filter = ngx_http2_upstream_non_buffered_filter;
			u->input_filter_ctx = r;
		}

		u->read_event_handler = ngx_http2_upstream_process_non_buffered_upstream;
		r->write_event_handler =
				ngx_http2_upstream_process_non_buffered_downstream;

		r->limit_rate = 0;

		if (u->input_filter_init(u->input_filter_ctx) == NGX_ERROR) {
			ngx_http2_upstream_finalize_request(r, u, NGX_ERROR);
			return;
		}

		if (clcf->tcp_nodelay && ngx_tcp_nodelay(c) != NGX_OK) {
			ngx_http2_upstream_finalize_request(r, u, NGX_ERROR);
			return;
		}

		n = u->buffer.last - u->buffer.pos;

		if (n) {
			u->buffer.last = u->buffer.pos;

			u->state->response_length += n;

			if (u->input_filter(u->input_filter_ctx, n) == NGX_ERROR) {
				ngx_http2_upstream_finalize_request(r, u, NGX_ERROR);
				return;
			}

			ngx_http2_upstream_process_non_buffered_downstream(r);

		} else {
			u->buffer.pos = u->buffer.start;
			u->buffer.last = u->buffer.start;

			if (ngx_http_send_special(r, NGX_HTTP_FLUSH) == NGX_ERROR) {
				ngx_http2_upstream_finalize_request(r, u, NGX_ERROR);
				return;
			}

			if (u->peer.connection->read->ready || u->length == 0) {
				ngx_http2_upstream_process_non_buffered_upstream(r, u);
			}
		}

		return;
	}


	p = u->pipe;

	p->output_filter = ngx_http2_upstream_output_filter;
	p->output_ctx = r;
	p->tag = u->output.tag;
	p->bufs = u->conf->bufs;
	p->busy_size = u->conf->busy_buffers_size;
	p->upstream = u->peer.connection;
	p->downstream = c;
	p->pool = r->pool;
	p->log = c->log;
	p->limit_rate = u->conf->limit_rate;
	p->start_sec = ngx_time();

	p->cacheable = u->cacheable || u->store;

	p->temp_file = ngx_pcalloc(r->pool, sizeof(ngx_temp_file_t));
	if (p->temp_file == NULL) {
		ngx_http2_upstream_finalize_request(r, u, NGX_ERROR);
		return;
	}

	p->temp_file->file.fd = NGX_INVALID_FILE;
	p->temp_file->file.log = c->log;
	p->temp_file->path = u->conf->temp_path;
	p->temp_file->pool = r->pool;

	if (p->cacheable) {
		p->temp_file->persistent = 1;

#if (NGX_HTTP_CACHE)
		if (r->cache && !r->cache->file_cache->use_temp_path) {
			p->temp_file->path = r->cache->file_cache->path;
			p->temp_file->file.name = r->cache->file.name;
		}
#endif

	} else {
		p->temp_file->log_level = NGX_LOG_WARN;
		p->temp_file->warn = "an upstream response is buffered "
				"to a temporary file";
	}

	p->max_temp_file_size = u->conf->max_temp_file_size;
	p->temp_file_write_size = u->conf->temp_file_write_size;



	p->preread_bufs = ngx_alloc_chain_link(r->pool);
	if (p->preread_bufs == NULL) {
		ngx_http2_upstream_finalize_request(r, u, NGX_ERROR);
		return;
	}

	p->preread_bufs->buf = &u->buffer;
	p->preread_bufs->next = NULL;
	u->buffer.recycled = 1;

	p->preread_size = u->buffer.last - u->buffer.pos;

	if (u->cacheable) {

		p->buf_to_file = ngx_calloc_buf(r->pool);
		if (p->buf_to_file == NULL) {
			ngx_http2_upstream_finalize_request(r, u, NGX_ERROR);
			return;
		}

		p->buf_to_file->start = u->buffer.start;
		p->buf_to_file->pos = u->buffer.start;
		p->buf_to_file->last = u->buffer.pos;
		p->buf_to_file->temporary = 1;
	}


	/* TODO: p->free_bufs = 0 if use ngx_create_chain_of_bufs() */
	p->free_bufs = 1;

	/*
	 * event_pipe would do u->buffer.last += p->preread_size
	 * as though these bytes were read
	 */
	u->buffer.last = u->buffer.pos;

	if (u->conf->cyclic_temp_file) {

		/*
		 * we need to disable the use of sendfile() if we use cyclic temp file
		 * because the writing a new data may interfere with sendfile()
		 * that uses the same kernel file pages (at least on FreeBSD)
		 */

		p->cyclic_temp_file = 1;
		c->sendfile = 0;

	} else {
		p->cyclic_temp_file = 0;
	}

	p->read_timeout = u->conf->read_timeout;
	p->send_timeout = clcf->send_timeout;
	p->send_lowat = clcf->send_lowat;

	p->length = -1;

	if (u->input_filter_init && u->input_filter_init(p->input_ctx) != NGX_OK) {
		ngx_http2_upstream_finalize_request(r, u, NGX_ERROR);
		return;
	}

	u->read_event_handler = ngx_http2_upstream_process_upstream;
	r->write_event_handler = ngx_http2_upstream_process_downstream;

	ngx_http2_upstream_process_upstream(r, u);
}

static void ngx_http2_upstream_upgrade(ngx_http_request_t *r,
		ngx_http2_stream_t *u) {
	ngx_connection_t *c;
	ngx_http_core_loc_conf_t *clcf;

	c = r->connection;
	clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

	/* TODO: prevent upgrade if not requested or not possible */

	if (r != r->main) {
		ngx_log_error(NGX_LOG_ERR, c->log, 0,
				"connection upgrade in subrequest");
		ngx_http2_upstream_finalize_request(r, u, NGX_ERROR);
		return;
	}

	r->keepalive = 0;
	c->log->action = "proxying upgraded connection";

	u->read_event_handler = ngx_http2_upstream_upgraded_read_upstream;
	u->write_event_handler = ngx_http2_upstream_upgraded_write_upstream;
	r->read_event_handler = ngx_http2_upstream_upgraded_read_downstream;
	r->write_event_handler = ngx_http2_upstream_upgraded_write_downstream;

	if (clcf->tcp_nodelay) {

		if (ngx_tcp_nodelay(c) != NGX_OK) {
			ngx_http2_upstream_finalize_request(r, u, NGX_ERROR);
			return;
		}

		if (ngx_tcp_nodelay(u->peer.connection) != NGX_OK) {
			ngx_http2_upstream_finalize_request(r, u, NGX_ERROR);
			return;
		}
	}

	if (ngx_http_send_special(r, NGX_HTTP_FLUSH) == NGX_ERROR) {
		ngx_http2_upstream_finalize_request(r, u, NGX_ERROR);
		return;
	}

	if (u->peer.connection->read->ready || u->buffer.pos != u->buffer.last) {
		ngx_post_event(c->read, &ngx_posted_events);
		ngx_http2_upstream_process_upgraded(r, 1, 1);
		return;
	}

	ngx_http2_upstream_process_upgraded(r, 0, 1);
}

static void ngx_http2_upstream_upgraded_read_downstream(ngx_http_request_t *r) {
	ngx_http2_upstream_process_upgraded(r, 0, 0);
}

static void ngx_http2_upstream_upgraded_write_downstream(ngx_http_request_t *r) {
	ngx_http2_upstream_process_upgraded(r, 1, 1);
}

static void ngx_http2_upstream_upgraded_read_upstream(ngx_http_request_t *r,
		ngx_http2_stream_t *u) {
	ngx_http2_upstream_process_upgraded(r, 1, 0);
}

static void ngx_http2_upstream_upgraded_write_upstream(ngx_http_request_t *r,
		ngx_http2_stream_t *u) {
	ngx_http2_upstream_process_upgraded(r, 0, 1);
}

static void ngx_http2_upstream_process_upgraded(ngx_http_request_t *r,
		ngx_uint_t from_upstream, ngx_uint_t do_write) {
	size_t size;
	ssize_t n;
	ngx_buf_t *b;
	ngx_connection_t *c, *downstream, *upstream, *dst, *src;
	ngx_http2_stream_t *u;
	ngx_http_core_loc_conf_t *clcf;

	c = r->connection;
	u = r->upstream;

	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
			"http upstream process upgraded, fu:%ui", from_upstream);

	downstream = c;
	upstream = u->peer.connection;

	if (downstream->write->timedout) {
		c->timedout = 1;
		ngx_connection_error(c, NGX_ETIMEDOUT, "client timed out");
		ngx_http2_upstream_finalize_request(r, u, NGX_HTTP_REQUEST_TIME_OUT);
		return;
	}

	if (upstream->read->timedout || upstream->write->timedout) {
		ngx_connection_error(c, NGX_ETIMEDOUT, "upstream timed out");
		ngx_http2_upstream_finalize_request(r, u, NGX_HTTP_GATEWAY_TIME_OUT);
		return;
	}

	if (from_upstream) {
		src = upstream;
		dst = downstream;
		b = &u->buffer;

	} else {
		src = downstream;
		dst = upstream;
		b = &u->from_client;

		if (r->header_in->last > r->header_in->pos) {
			b = r->header_in;
			b->end = b->last;
			do_write = 1;
		}

		if (b->start == NULL) {
			b->start = ngx_palloc(r->pool, u->conf->buffer_size);
			if (b->start == NULL) {
				ngx_http2_upstream_finalize_request(r, u, NGX_ERROR);
				return;
			}

			b->pos = b->start;
			b->last = b->start;
			b->end = b->start + u->conf->buffer_size;
			b->temporary = 1;
			b->tag = u->output.tag;
		}
	}

	for (;;) {

		if (do_write) {

			size = b->last - b->pos;

			if (size && dst->write->ready) {

				n = dst->send(dst, b->pos, size);

				if (n == NGX_ERROR) {
					ngx_http2_upstream_finalize_request(r, u, NGX_ERROR);
					return;
				}

				if (n > 0) {
					b->pos += n;

					if (b->pos == b->last) {
						b->pos = b->start;
						b->last = b->start;
					}
				}
			}
		}

		size = b->end - b->last;

		if (size && src->read->ready) {

			n = src->recv(src, b->last, size);

			if (n == NGX_AGAIN || n == 0) {
				break;
			}

			if (n > 0) {
				do_write = 1;
				b->last += n;

				if (from_upstream) {
					u->state->bytes_received += n;
				}

				continue;
			}

			if (n == NGX_ERROR) {
				src->read->eof = 1;
			}
		}

		break;
	}

	if ((upstream->read->eof && u->buffer.pos == u->buffer.last)
			|| (downstream->read->eof
					&& u->from_client.pos == u->from_client.last)
			|| (downstream->read->eof && upstream->read->eof)) {
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
				"http upstream upgraded done");
		ngx_http2_upstream_finalize_request(r, u, 0);
		return;
	}

	clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

	if (ngx_handle_write_event(upstream->write, u->conf->send_lowat) != NGX_OK) {
		ngx_http2_upstream_finalize_request(r, u, NGX_ERROR);
		return;
	}

	if (upstream->write->active && !upstream->write->ready) {
		ngx_add_timer(upstream->write, u->conf->send_timeout);

	} else if (upstream->write->timer_set) {
		ngx_del_timer(upstream->write);
	}

	if (ngx_handle_read_event(upstream->read, 0) != NGX_OK) {
		ngx_http2_upstream_finalize_request(r, u, NGX_ERROR);
		return;
	}

	if (upstream->read->active && !upstream->read->ready) {
		ngx_add_timer(upstream->read, u->conf->read_timeout);

	} else if (upstream->read->timer_set) {
		ngx_del_timer(upstream->read);
	}

	if (ngx_handle_write_event(downstream->write, clcf->send_lowat) != NGX_OK) {
		ngx_http2_upstream_finalize_request(r, u, NGX_ERROR);
		return;
	}

	if (ngx_handle_read_event(downstream->read, 0) != NGX_OK) {
		ngx_http2_upstream_finalize_request(r, u, NGX_ERROR);
		return;
	}

	if (downstream->write->active && !downstream->write->ready) {
		ngx_add_timer(downstream->write, clcf->send_timeout);

	} else if (downstream->write->timer_set) {
		ngx_del_timer(downstream->write);
	}
}

static void ngx_http2_upstream_process_non_buffered_downstream(
		ngx_http_request_t *r) {
	ngx_event_t *wev;
	ngx_connection_t *c;
	ngx_http2_stream_t *u;

	c = r->connection;
	u = r->upstream;
	wev = c->write;

	ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
			"http upstream process non buffered downstream");

	c->log->action = "sending to client";

	if (wev->timedout) {
		c->timedout = 1;
		ngx_connection_error(c, NGX_ETIMEDOUT, "client timed out");
		ngx_http2_upstream_finalize_request(r, u, NGX_HTTP_REQUEST_TIME_OUT);
		return;
	}

	ngx_http2_upstream_process_non_buffered_request(r, 1);
}

static void ngx_http2_upstream_process_non_buffered_upstream(
		ngx_http_request_t *r, ngx_http2_stream_t *u) {
	ngx_connection_t *c;

	c = u->peer.connection;

	ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
			"http upstream process non buffered upstream");

	c->log->action = "reading upstream";

	if (c->read->timedout) {
		ngx_connection_error(c, NGX_ETIMEDOUT, "upstream timed out");
		ngx_http2_upstream_finalize_request(r, u, NGX_HTTP_GATEWAY_TIME_OUT);
		return;
	}

	ngx_http2_upstream_process_non_buffered_request(r, 0);
}

static void ngx_http2_upstream_process_non_buffered_request(
		ngx_http_request_t *r, ngx_uint_t do_write) {
	size_t size;
	ssize_t n;
	ngx_buf_t *b;
	ngx_int_t rc;
	ngx_connection_t *downstream, *upstream;
	ngx_http2_stream_t *u;
	ngx_http_core_loc_conf_t *clcf;

	u = r->upstream;
	downstream = r->connection;
	upstream = u->peer.connection;

	b = &u->buffer;

	do_write = do_write || u->length == 0;

	for (;;) {

		if (do_write) {

			if (u->out_bufs || u->busy_bufs || downstream->buffered) {
				rc = ngx_http_output_filter(r, u->out_bufs);

				if (rc == NGX_ERROR) {
					ngx_http2_upstream_finalize_request(r, u, NGX_ERROR);
					return;
				}

				ngx_chain_update_chains(r->pool, &u->free_bufs, &u->busy_bufs,
						&u->out_bufs, u->output.tag);
			}

			if (u->busy_bufs == NULL) {

				if (u->length == 0
						|| (upstream->read->eof && u->length == -1)) {
					ngx_http2_upstream_finalize_request(r, u, 0);
					return;
				}

				if (upstream->read->eof) {
					ngx_log_error(NGX_LOG_ERR, upstream->log, 0,
							"upstream prematurely closed connection");

					ngx_http2_upstream_finalize_request(r, u,
					NGX_HTTP_BAD_GATEWAY);
					return;
				}

				if (upstream->read->error) {
					ngx_http2_upstream_finalize_request(r, u,
					NGX_HTTP_BAD_GATEWAY);
					return;
				}

				b->pos = b->start;
				b->last = b->start;
			}
		}

		size = b->end - b->last;

		if (size && upstream->read->ready) {

			n = upstream->recv(upstream, b->last, size);

			if (n == NGX_AGAIN) {
				break;
			}

			if (n > 0) {
				u->state->bytes_received += n;
				u->state->response_length += n;

				if (u->input_filter(u->input_filter_ctx, n) == NGX_ERROR) {
					ngx_http2_upstream_finalize_request(r, u, NGX_ERROR);
					return;
				}
			}

			do_write = 1;

			continue;
		}

		break;
	}

	clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

	if (downstream->data == r) {
		if (ngx_handle_write_event(downstream->write,
				clcf->send_lowat) != NGX_OK) {
			ngx_http2_upstream_finalize_request(r, u, NGX_ERROR);
			return;
		}
	}

	if (downstream->write->active && !downstream->write->ready) {
		ngx_add_timer(downstream->write, clcf->send_timeout);

	} else if (downstream->write->timer_set) {
		ngx_del_timer(downstream->write);
	}

	if (ngx_handle_read_event(upstream->read, 0) != NGX_OK) {
		ngx_http2_upstream_finalize_request(r, u, NGX_ERROR);
		return;
	}

	if (upstream->read->active && !upstream->read->ready) {
		ngx_add_timer(upstream->read, u->conf->read_timeout);

	} else if (upstream->read->timer_set) {
		ngx_del_timer(upstream->read);
	}
}

static ngx_int_t ngx_http2_upstream_non_buffered_filter_init(void *data) {
	return NGX_OK;
}

static ngx_int_t ngx_http2_upstream_non_buffered_filter(void *data,
		ssize_t bytes) {
	ngx_http_request_t *r = data;

	ngx_buf_t *b;
	ngx_chain_t *cl, **ll;
	ngx_http2_stream_t *u;

	u = r->upstream;

	for (cl = u->out_bufs, ll = &u->out_bufs; cl; cl = cl->next) {
		ll = &cl->next;
	}

	cl = ngx_chain_get_free_buf(r->pool, &u->free_bufs);
	if (cl == NULL) {
		return NGX_ERROR;
	}

	*ll = cl;

	cl->buf->flush = 1;
	cl->buf->memory = 1;

	b = &u->buffer;

	cl->buf->pos = b->last;
	b->last += bytes;
	cl->buf->last = b->last;
	cl->buf->tag = u->output.tag;

	if (u->length == -1) {
		return NGX_OK;
	}

	u->length -= bytes;

	return NGX_OK;
}



static ngx_int_t ngx_http2_upstream_output_filter(void *data, ngx_chain_t *chain) {
	ngx_int_t rc;
	ngx_event_pipe_t *p;
	ngx_http_request_t *r;

	r = data;
	p = r->upstream->pipe;

	rc = ngx_http_output_filter(r, chain);

	p->aio = r->aio;

	return rc;
}

static void ngx_http2_upstream_process_downstream(ngx_http_request_t *r) {
	ngx_event_t *wev;
	ngx_connection_t *c;
	ngx_event_pipe_t *p;
	ngx_http2_stream_t *u;

	c = r->connection;
	u = r->upstream;
	p = u->pipe;
	wev = c->write;

	ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
			"http upstream process downstream");

	c->log->action = "sending to client";



	if (wev->timedout) {

		p->downstream_error = 1;
		c->timedout = 1;
		ngx_connection_error(c, NGX_ETIMEDOUT, "client timed out");

	} else {

		if (wev->delayed) {

			ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
					"http downstream delayed");

			if (ngx_handle_write_event(wev, p->send_lowat) != NGX_OK) {
				ngx_http2_upstream_finalize_request(r, u, NGX_ERROR);
			}

			return;
		}

		if (ngx_event_pipe(p, 1) == NGX_ABORT) {
			ngx_http2_upstream_finalize_request(r, u, NGX_ERROR);
			return;
		}
	}

	ngx_http2_upstream_process_request(r, u);
}

static void ngx_http2_upstream_process_upstream(ngx_http_request_t *r,
		ngx_http2_stream_t *u) {
	ngx_event_t *rev;
	ngx_event_pipe_t *p;
	ngx_connection_t *c;

	c = u->peer.connection;
	p = u->pipe;
	rev = c->read;

	ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
			"http upstream process upstream");

	c->log->action = "reading upstream";

	if (rev->timedout) {

		p->upstream_error = 1;
		ngx_connection_error(c, NGX_ETIMEDOUT, "upstream timed out");

	} else {

		if (rev->delayed) {

			ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
					"http upstream delayed");

			if (ngx_handle_read_event(rev, 0) != NGX_OK) {
				ngx_http2_upstream_finalize_request(r, u, NGX_ERROR);
			}

			return;
		}

		if (ngx_event_pipe(p, 0) == NGX_ABORT) {
			ngx_http2_upstream_finalize_request(r, u, NGX_ERROR);
			return;
		}
	}

	ngx_http2_upstream_process_request(r, u);
}

static void ngx_http2_upstream_process_request(ngx_http_request_t *r,
		ngx_http2_stream_t *u) {
	ngx_temp_file_t *tf;
	ngx_event_pipe_t *p;

	p = u->pipe;



	if (u->peer.connection) {

		if (u->store) {

			if (p->upstream_eof || p->upstream_done) {

				tf = p->temp_file;

				if (u->headers_in.status_n == NGX_HTTP_OK
						&& (p->upstream_done || p->length == -1)
						&& (u->headers_in.content_length_n == -1
								|| u->headers_in.content_length_n == tf->offset)) {
					ngx_http2_upstream_store(r, u);
				}
			}
		}



		if (p->upstream_done || p->upstream_eof || p->upstream_error) {
			ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
					"http upstream exit: %p", p->out);

			if (p->upstream_done || (p->upstream_eof && p->length == -1)) {
				ngx_http2_upstream_finalize_request(r, u, 0);
				return;
			}

			if (p->upstream_eof) {
				ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
						"upstream prematurely closed connection");
			}

			ngx_http2_upstream_finalize_request(r, u, NGX_HTTP_BAD_GATEWAY);
			return;
		}
	}

	if (p->downstream_error) {
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
				"http upstream downstream error");

		if (!u->cacheable && !u->store && u->peer.connection) {
			ngx_http2_upstream_finalize_request(r, u, NGX_ERROR);
		}
	}
}

static void ngx_http2_upstream_store(ngx_http_request_t *r,
		ngx_http2_stream_t *u) {
	size_t root;
	time_t lm;
	ngx_str_t path;
	ngx_temp_file_t *tf;
	ngx_ext_rename_file_t ext;

	tf = u->pipe->temp_file;

	if (tf->file.fd == NGX_INVALID_FILE) {

		/* create file for empty 200 response */

		tf = ngx_pcalloc(r->pool, sizeof(ngx_temp_file_t));
		if (tf == NULL) {
			return;
		}

		tf->file.fd = NGX_INVALID_FILE;
		tf->file.log = r->connection->log;
		tf->path = u->conf->temp_path;
		tf->pool = r->pool;
		tf->persistent = 1;

		if (ngx_create_temp_file(&tf->file, tf->path, tf->pool, tf->persistent,
				tf->clean, tf->access) != NGX_OK) {
			return;
		}

		u->pipe->temp_file = tf;
	}

	ext.access = u->conf->store_access;
	ext.path_access = u->conf->store_access;
	ext.time = -1;
	ext.create_path = 1;
	ext.delete_file = 1;
	ext.log = r->connection->log;

	if (u->headers_in.last_modified) {

		lm = ngx_parse_http_time(u->headers_in.last_modified->value.data,
				u->headers_in.last_modified->value.len);

		if (lm != NGX_ERROR) {
			ext.time = lm;
			ext.fd = tf->file.fd;
		}
	}

	if (u->conf->store_lengths == NULL) {

		if (ngx_http_map_uri_to_path(r, &path, &root, 0) == NULL) {
			return;
		}

	} else {
		if (ngx_http_script_run(r, &path, u->conf->store_lengths->elts, 0,
				u->conf->store_values->elts) == NULL) {
			return;
		}
	}

	path.len--;

	ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
			"upstream stores \"%s\" to \"%s\"",
			tf->file.name.data, path.data);

	(void) ngx_ext_rename_file(&tf->file.name, &path, &ext);

	u->store = 0;
}

static void ngx_http2_upstream_dummy_handler(ngx_http_request_t *r,
		ngx_http2_stream_t *u) {
	ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
			"http upstream dummy handler");
}

static void ngx_http2_upstream_next(ngx_http_request_t *r,
		ngx_http2_stream_t *u, ngx_uint_t ft_type) {
	ngx_msec_t timeout;
	ngx_uint_t status, state;

	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
			"http next upstream, %xi", ft_type);

	if (u->peer.sockaddr) {

		if (ft_type == ngx_http2_upstream_FT_HTTP_403
				|| ft_type == ngx_http2_upstream_FT_HTTP_404) {
			state = NGX_PEER_NEXT;

		} else {
			state = NGX_PEER_FAILED;
		}

		u->peer.free(&u->peer, u->peer.data, state);
		u->peer.sockaddr = NULL;
	}

	if (ft_type == ngx_http2_upstream_FT_TIMEOUT) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, NGX_ETIMEDOUT,
				"upstream timed out");
	}

	if (u->peer.cached && ft_type == ngx_http2_upstream_FT_ERROR) {
		/* TODO: inform balancer instead */
		u->peer.tries++;
	}

	switch (ft_type) {

	case ngx_http2_upstream_FT_TIMEOUT:
	case ngx_http2_upstream_FT_HTTP_504:
		status = NGX_HTTP_GATEWAY_TIME_OUT;
		break;

	case ngx_http2_upstream_FT_HTTP_500:
		status = NGX_HTTP_INTERNAL_SERVER_ERROR;
		break;

	case ngx_http2_upstream_FT_HTTP_503:
		status = NGX_HTTP_SERVICE_UNAVAILABLE;
		break;

	case ngx_http2_upstream_FT_HTTP_403:
		status = NGX_HTTP_FORBIDDEN;
		break;

	case ngx_http2_upstream_FT_HTTP_404:
		status = NGX_HTTP_NOT_FOUND;
		break;

	case ngx_http2_upstream_FT_HTTP_429:
		status = NGX_HTTP_TOO_MANY_REQUESTS;
		break;

		/*
		 * ngx_http2_upstream_FT_BUSY_LOCK and ngx_http2_upstream_FT_MAX_WAITING
		 * never reach here
		 */

	default:
		status = NGX_HTTP_BAD_GATEWAY;
	}

	if (r->connection->error) {
		ngx_http2_upstream_finalize_request(r, u,
		NGX_HTTP_CLIENT_CLOSED_REQUEST);
		return;
	}

	u->state->status = status;

	timeout = u->conf->next_upstream_timeout;

	if (u->request_sent
			&& (r->method & (NGX_HTTP_POST | NGX_HTTP_LOCK | NGX_HTTP_PATCH))) {
		ft_type |= ngx_http2_upstream_FT_NON_IDEMPOTENT;
	}

	if (u->peer.tries == 0 || ((u->conf->next_upstream & ft_type) != ft_type)
			|| (u->request_sent && r->request_body_no_buffering)
			|| (timeout && ngx_current_msec - u->peer.start_time >= timeout)) {


		ngx_http2_upstream_finalize_request(r, u, status);
		return;
	}

	if (u->peer.connection) {
		ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
				"close http upstream connection: %d",
				u->peer.connection->fd);
#if (NGX_HTTP_SSL)

		if (u->peer.connection->ssl) {
			u->peer.connection->ssl->no_wait_shutdown = 1;
			u->peer.connection->ssl->no_send_shutdown = 1;

			(void) ngx_ssl_shutdown(u->peer.connection);
		}
#endif

		if (u->peer.connection->pool) {
			ngx_destroy_pool(u->peer.connection->pool);
		}

		ngx_close_connection(u->peer.connection);
		u->peer.connection = NULL;
	}

	ngx_http2_upstream_connect(r);
}


static void ngx_http2_upstream_finalize_request(ngx_http_request_t *r,ngx_int_t rc) {
	ngx_uint_t flush;
	ngx_http2_stream_t *u = (ngx_http2_stream_t *)r->upstream;
	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"finalize http2 upstream request: %i", rc);


	if(u->event.posted){
		ngx_queue_remove(&u->event.queue);
	}

	if (u->cleanup == NULL) {
		/* the request was already finalized */
		ngx_http_finalize_request(r, NGX_DONE);
		return;
	}

	u->finalize_request(r, rc);



	r->read_event_handler = ngx_http_block_reading;

	if (rc == NGX_DECLINED) {
		return;
	}

	r->connection->log->action = "sending to client";

	if (!u->header_sent || rc == NGX_HTTP_REQUEST_TIME_OUT
			|| rc == NGX_HTTP_CLIENT_CLOSED_REQUEST) {
		ngx_http_finalize_request(r, rc);
		return;
	}

	flush = 0;

	if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
		rc = NGX_ERROR;
		flush = 1;
	}

	if (r->header_only || (u->pipe && u->pipe->downstream_error)) {
		ngx_http_finalize_request(r, rc);
		return;
	}

	if (rc == 0) {

		if (ngx_http2_upstream_process_trailers(r, u) != NGX_OK) {
			ngx_http_finalize_request(r, NGX_ERROR);
			return;
		}

		rc = ngx_http_send_special(r, NGX_HTTP_LAST);

	} else if (flush) {
		r->keepalive = 0;
		rc = ngx_http_send_special(r, NGX_HTTP_FLUSH);
	}

	ngx_http_finalize_request(r, rc);
}

static ngx_int_t ngx_http2_upstream_process_header_line(ngx_http_request_t *r,
		ngx_table_elt_t *h, ngx_uint_t offset) {
	ngx_table_elt_t **ph;

	ph = (ngx_table_elt_t **) ((char *) &r->upstream->headers_in + offset);

	if (*ph == NULL) {
		*ph = h;
	}

	return NGX_OK;
}

static ngx_int_t ngx_http2_upstream_ignore_header_line(ngx_http_request_t *r,
		ngx_table_elt_t *h, ngx_uint_t offset) {
	return NGX_OK;
}

static ngx_int_t ngx_http2_upstream_process_content_length(ngx_http_request_t *r,
		ngx_table_elt_t *h, ngx_uint_t offset) {
	ngx_http2_stream_t *u;

	u = r->upstream;

	u->headers_in.content_length = h;
	u->headers_in.content_length_n = ngx_atoof(h->value.data, h->value.len);

	return NGX_OK;
}

static ngx_int_t ngx_http2_upstream_process_last_modified(ngx_http_request_t *r,
		ngx_table_elt_t *h, ngx_uint_t offset) {
	ngx_http2_stream_t *u;

	u = r->upstream;

	u->headers_in.last_modified = h;
	u->headers_in.last_modified_time = ngx_parse_http_time(h->value.data,
			h->value.len);

	return NGX_OK;
}

static ngx_int_t ngx_http2_upstream_process_set_cookie(ngx_http_request_t *r,
		ngx_table_elt_t *h, ngx_uint_t offset) {
	ngx_array_t *pa;
	ngx_table_elt_t **ph;
	ngx_http2_stream_t *u;

	u = r->upstream;
	pa = &u->headers_in.cookies;

	if (pa->elts == NULL) {
		if (ngx_array_init(pa, r->pool, 1, sizeof(ngx_table_elt_t *)) != NGX_OK) {
			return NGX_ERROR;
		}
	}

	ph = ngx_array_push(pa);
	if (ph == NULL) {
		return NGX_ERROR;
	}

	*ph = h;


	return NGX_OK;
}

static ngx_int_t ngx_http2_upstream_process_cache_control(ngx_http_request_t *r,
		ngx_table_elt_t *h, ngx_uint_t offset) {
	ngx_array_t *pa;
	ngx_table_elt_t **ph;
	ngx_http2_stream_t *u;

	u = r->upstream;
	pa = &u->headers_in.cache_control;

	if (pa->elts == NULL) {
		if (ngx_array_init(pa, r->pool, 2, sizeof(ngx_table_elt_t *)) != NGX_OK) {
			return NGX_ERROR;
		}
	}

	ph = ngx_array_push(pa);
	if (ph == NULL) {
		return NGX_ERROR;
	}

	*ph = h;



	return NGX_OK;
}

static ngx_int_t ngx_http2_upstream_process_expires(ngx_http_request_t *r,
		ngx_table_elt_t *h, ngx_uint_t offset) {
	ngx_http2_stream_t *u;

	u = r->upstream;
	u->headers_in.expires = h;



	return NGX_OK;
}

static ngx_int_t ngx_http2_upstream_process_accel_expires(ngx_http_request_t *r,
		ngx_table_elt_t *h, ngx_uint_t offset) {
	ngx_http2_stream_t *u;

	u = r->upstream;
	u->headers_in.x_accel_expires = h;


	return NGX_OK;
}

static ngx_int_t ngx_http2_upstream_process_limit_rate(ngx_http_request_t *r,
		ngx_table_elt_t *h, ngx_uint_t offset) {
	ngx_int_t n;
	ngx_http2_stream_t *u;

	u = r->upstream;
	u->headers_in.x_accel_limit_rate = h;

	if (u->conf->ignore_headers & ngx_http2_upstream_IGN_XA_LIMIT_RATE) {
		return NGX_OK;
	}

	n = ngx_atoi(h->value.data, h->value.len);

	if (n != NGX_ERROR) {
		r->limit_rate = (size_t) n;
	}

	return NGX_OK;
}

static ngx_int_t ngx_http2_upstream_process_buffering(ngx_http_request_t *r,
		ngx_table_elt_t *h, ngx_uint_t offset) {
	u_char c0, c1, c2;
	ngx_http2_stream_t *u;

	u = r->upstream;

	if (u->conf->ignore_headers & ngx_http2_upstream_IGN_XA_BUFFERING) {
		return NGX_OK;
	}

	if (u->conf->change_buffering) {

		if (h->value.len == 2) {
			c0 = ngx_tolower(h->value.data[0]);
			c1 = ngx_tolower(h->value.data[1]);

			if (c0 == 'n' && c1 == 'o') {
				u->buffering = 0;
			}

		} else if (h->value.len == 3) {
			c0 = ngx_tolower(h->value.data[0]);
			c1 = ngx_tolower(h->value.data[1]);
			c2 = ngx_tolower(h->value.data[2]);

			if (c0 == 'y' && c1 == 'e' && c2 == 's') {
				u->buffering = 1;
			}
		}
	}

	return NGX_OK;
}

static ngx_int_t ngx_http2_upstream_process_charset(ngx_http_request_t *r,
		ngx_table_elt_t *h, ngx_uint_t offset) {
	if (r->upstream->conf->ignore_headers & ngx_http2_upstream_IGN_XA_CHARSET) {
		return NGX_OK;
	}

	r->headers_out.override_charset = &h->value;

	return NGX_OK;
}

static ngx_int_t ngx_http2_upstream_process_connection(ngx_http_request_t *r,
		ngx_table_elt_t *h, ngx_uint_t offset) {
	r->upstream->headers_in.connection = h;

	if (ngx_strlcasestrn(h->value.data, h->value.data + h->value.len,
			(u_char *) "close", 5 - 1) != NULL) {
		r->upstream->headers_in.connection_close = 1;
	}

	return NGX_OK;
}

static ngx_int_t ngx_http2_upstream_process_transfer_encoding(
		ngx_http_request_t *r, ngx_table_elt_t *h, ngx_uint_t offset) {
	r->upstream->headers_in.transfer_encoding = h;

	if (ngx_strlcasestrn(h->value.data, h->value.data + h->value.len,
			(u_char *) "chunked", 7 - 1) != NULL) {
		r->upstream->headers_in.chunked = 1;
	}

	return NGX_OK;
}

static ngx_int_t ngx_http2_upstream_process_vary(ngx_http_request_t *r,
		ngx_table_elt_t *h, ngx_uint_t offset) {
	ngx_http2_stream_t *u;

	u = r->upstream;
	u->headers_in.vary = h;



	return NGX_OK;
}

static ngx_int_t ngx_http2_upstream_copy_header_line(ngx_http_request_t *r,
		ngx_table_elt_t *h, ngx_uint_t offset) {
	ngx_table_elt_t *ho, **ph;

	ho = ngx_list_push(&r->headers_out.headers);
	if (ho == NULL) {
		return NGX_ERROR;
	}

	*ho = *h;

	if (offset) {
		ph = (ngx_table_elt_t **) ((char *) &r->headers_out + offset);
		*ph = ho;
	}

	return NGX_OK;
}

static ngx_int_t ngx_http2_upstream_copy_multi_header_lines(
		ngx_http_request_t *r, ngx_table_elt_t *h, ngx_uint_t offset) {
	ngx_array_t *pa;
	ngx_table_elt_t *ho, **ph;

	pa = (ngx_array_t *) ((char *) &r->headers_out + offset);

	if (pa->elts == NULL) {
		if (ngx_array_init(pa, r->pool, 2, sizeof(ngx_table_elt_t *)) != NGX_OK) {
			return NGX_ERROR;
		}
	}

	ho = ngx_list_push(&r->headers_out.headers);
	if (ho == NULL) {
		return NGX_ERROR;
	}

	*ho = *h;

	ph = ngx_array_push(pa);
	if (ph == NULL) {
		return NGX_ERROR;
	}

	*ph = ho;

	return NGX_OK;
}

static ngx_int_t ngx_http2_upstream_copy_content_type(ngx_http_request_t *r,
		ngx_table_elt_t *h, ngx_uint_t offset) {
	u_char *p, *last;

	r->headers_out.content_type_len = h->value.len;
	r->headers_out.content_type = h->value;
	r->headers_out.content_type_lowcase = NULL;

	for (p = h->value.data; *p; p++) {

		if (*p != ';') {
			continue;
		}

		last = p;

		while (*++p == ' ') { /* void */
		}

		if (*p == '\0') {
			return NGX_OK;
		}

		if (ngx_strncasecmp(p, (u_char *) "charset=", 8) != 0) {
			continue;
		}

		p += 8;

		r->headers_out.content_type_len = last - h->value.data;

		if (*p == '"') {
			p++;
		}

		last = h->value.data + h->value.len;

		if (*(last - 1) == '"') {
			last--;
		}

		r->headers_out.charset.len = last - p;
		r->headers_out.charset.data = p;

		return NGX_OK;
	}

	return NGX_OK;
}

static ngx_int_t ngx_http2_upstream_copy_last_modified(ngx_http_request_t *r,
		ngx_table_elt_t *h, ngx_uint_t offset) {
	ngx_table_elt_t *ho;

	ho = ngx_list_push(&r->headers_out.headers);
	if (ho == NULL) {
		return NGX_ERROR;
	}

	*ho = *h;

	r->headers_out.last_modified = ho;
	r->headers_out.last_modified_time =
			r->upstream->headers_in.last_modified_time;

	return NGX_OK;
}

static ngx_int_t ngx_http2_upstream_rewrite_location(ngx_http_request_t *r,
		ngx_table_elt_t *h, ngx_uint_t offset) {
	ngx_int_t rc;
	ngx_table_elt_t *ho;

	ho = ngx_list_push(&r->headers_out.headers);
	if (ho == NULL) {
		return NGX_ERROR;
	}

	*ho = *h;

	if (r->upstream->rewrite_redirect) {
		rc = r->upstream->rewrite_redirect(r, ho, 0);

		if (rc == NGX_DECLINED) {
			return NGX_OK;
		}

		if (rc == NGX_OK) {
			r->headers_out.location = ho;

			ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
					"rewritten location: \"%V\"", &ho->value);
		}

		return rc;
	}

	if (ho->value.data[0] != '/') {
		r->headers_out.location = ho;
	}

	/*
	 * we do not set r->headers_out.location here to avoid handling
	 * relative redirects in ngx_http_header_filter()
	 */

	return NGX_OK;
}

static ngx_int_t ngx_http2_upstream_rewrite_refresh(ngx_http_request_t *r,
		ngx_table_elt_t *h, ngx_uint_t offset) {
	u_char *p;
	ngx_int_t rc;
	ngx_table_elt_t *ho;

	ho = ngx_list_push(&r->headers_out.headers);
	if (ho == NULL) {
		return NGX_ERROR;
	}

	*ho = *h;

	if (r->upstream->rewrite_redirect) {

		p = ngx_strcasestrn(ho->value.data, "url=", 4 - 1);

		if (p) {
			rc = r->upstream->rewrite_redirect(r, ho, p + 4 - ho->value.data);

		} else {
			return NGX_OK;
		}

		if (rc == NGX_DECLINED) {
			return NGX_OK;
		}

		if (rc == NGX_OK) {
			r->headers_out.refresh = ho;

			ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
					"rewritten refresh: \"%V\"", &ho->value);
		}

		return rc;
	}

	r->headers_out.refresh = ho;

	return NGX_OK;
}

static ngx_int_t ngx_http2_upstream_rewrite_set_cookie(ngx_http_request_t *r,
		ngx_table_elt_t *h, ngx_uint_t offset) {
	ngx_int_t rc;
	ngx_table_elt_t *ho;

	ho = ngx_list_push(&r->headers_out.headers);
	if (ho == NULL) {
		return NGX_ERROR;
	}

	*ho = *h;

	if (r->upstream->rewrite_cookie) {
		rc = r->upstream->rewrite_cookie(r, ho);

		if (rc == NGX_DECLINED) {
			return NGX_OK;
		}

#if (NGX_DEBUG)
		if (rc == NGX_OK) {
			ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
					"rewritten cookie: \"%V\"", &ho->value);
		}
#endif

		return rc;
	}

	return NGX_OK;
}

static ngx_int_t ngx_http2_upstream_copy_allow_ranges(ngx_http_request_t *r,
		ngx_table_elt_t *h, ngx_uint_t offset) {
	ngx_table_elt_t *ho;

	if (r->upstream->conf->force_ranges) {
		return NGX_OK;
	}



	ho = ngx_list_push(&r->headers_out.headers);
	if (ho == NULL) {
		return NGX_ERROR;
	}

	*ho = *h;

	r->headers_out.accept_ranges = ho;

	return NGX_OK;
}

#if (NGX_HTTP_GZIP)

static ngx_int_t ngx_http2_upstream_copy_content_encoding(ngx_http_request_t *r,
		ngx_table_elt_t *h, ngx_uint_t offset) {
	ngx_table_elt_t *ho;

	ho = ngx_list_push(&r->headers_out.headers);
	if (ho == NULL) {
		return NGX_ERROR;
	}

	*ho = *h;

	r->headers_out.content_encoding = ho;

	return NGX_OK;
}

#endif

static ngx_int_t ngx_http2_upstream_add_variables(ngx_conf_t *cf) {
	ngx_http_variable_t *var, *v;

	for (v = ngx_http2_upstream_vars; v->name.len; v++) {
		var = ngx_http_add_variable(cf, &v->name, v->flags);
		if (var == NULL) {
			return NGX_ERROR;
		}

		var->get_handler = v->get_handler;
		var->data = v->data;
	}

	return NGX_OK;
}

static ngx_int_t ngx_http2_upstream_addr_variable(ngx_http_request_t *r,
		ngx_http_variable_value_t *v, uintptr_t data) {
	u_char *p;
	size_t len;
	ngx_uint_t i;
	ngx_http2_upstream_state_t *state;

	v->valid = 1;
	v->no_cacheable = 0;
	v->not_found = 0;

	if (r->upstream_states == NULL || r->upstream_states->nelts == 0) {
		v->not_found = 1;
		return NGX_OK;
	}

	len = 0;
	state = r->upstream_states->elts;

	for (i = 0; i < r->upstream_states->nelts; i++) {
		if (state[i].peer) {
			len += state[i].peer->len + 2;

		} else {
			len += 3;
		}
	}

	p = ngx_pnalloc(r->pool, len);
	if (p == NULL) {
		return NGX_ERROR;
	}

	v->data = p;

	i = 0;

	for (;;) {
		if (state[i].peer) {
			p = ngx_cpymem(p, state[i].peer->data, state[i].peer->len);
		}

		if (++i == r->upstream_states->nelts) {
			break;
		}

		if (state[i].peer) {
			*p++ = ',';
			*p++ = ' ';

		} else {
			*p++ = ' ';
			*p++ = ':';
			*p++ = ' ';

			if (++i == r->upstream_states->nelts) {
				break;
			}

			continue;
		}
	}

	v->len = p - v->data;

	return NGX_OK;
}

static ngx_int_t ngx_http2_upstream_status_variable(ngx_http_request_t *r,
		ngx_http_variable_value_t *v, uintptr_t data) {
	u_char *p;
	size_t len;
	ngx_uint_t i;
	ngx_http2_upstream_state_t *state;

	v->valid = 1;
	v->no_cacheable = 0;
	v->not_found = 0;

	if (r->upstream_states == NULL || r->upstream_states->nelts == 0) {
		v->not_found = 1;
		return NGX_OK;
	}

	len = r->upstream_states->nelts * (3 + 2);

	p = ngx_pnalloc(r->pool, len);
	if (p == NULL) {
		return NGX_ERROR;
	}

	v->data = p;

	i = 0;
	state = r->upstream_states->elts;

	for (;;) {
		if (state[i].status) {
			p = ngx_sprintf(p, "%ui", state[i].status);

		} else {
			*p++ = '-';
		}

		if (++i == r->upstream_states->nelts) {
			break;
		}

		if (state[i].peer) {
			*p++ = ',';
			*p++ = ' ';

		} else {
			*p++ = ' ';
			*p++ = ':';
			*p++ = ' ';

			if (++i == r->upstream_states->nelts) {
				break;
			}

			continue;
		}
	}

	v->len = p - v->data;

	return NGX_OK;
}

static ngx_int_t ngx_http2_upstream_response_time_variable(ngx_http_request_t *r,
		ngx_http_variable_value_t *v, uintptr_t data) {
	u_char *p;
	size_t len;
	ngx_uint_t i;
	ngx_msec_int_t ms;
	ngx_http2_upstream_state_t *state;

	v->valid = 1;
	v->no_cacheable = 0;
	v->not_found = 0;

	if (r->upstream_states == NULL || r->upstream_states->nelts == 0) {
		v->not_found = 1;
		return NGX_OK;
	}

	len = r->upstream_states->nelts * (NGX_TIME_T_LEN + 4 + 2);

	p = ngx_pnalloc(r->pool, len);
	if (p == NULL) {
		return NGX_ERROR;
	}

	v->data = p;

	i = 0;
	state = r->upstream_states->elts;

	for (;;) {
		if (state[i].status) {

			if (data == 1 && state[i].header_time != (ngx_msec_t) -1) {
				ms = state[i].header_time;

			} else if (data == 2 && state[i].connect_time != (ngx_msec_t) -1) {
				ms = state[i].connect_time;

			} else {
				ms = state[i].response_time;
			}

			ms = ngx_max(ms, 0);
			p = ngx_sprintf(p, "%T.%03M", (time_t) ms / 1000, ms % 1000);

		} else {
			*p++ = '-';
		}

		if (++i == r->upstream_states->nelts) {
			break;
		}

		if (state[i].peer) {
			*p++ = ',';
			*p++ = ' ';

		} else {
			*p++ = ' ';
			*p++ = ':';
			*p++ = ' ';

			if (++i == r->upstream_states->nelts) {
				break;
			}

			continue;
		}
	}

	v->len = p - v->data;

	return NGX_OK;
}

static ngx_int_t ngx_http2_upstream_response_length_variable(
		ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
	u_char *p;
	size_t len;
	ngx_uint_t i;
	ngx_http2_upstream_state_t *state;

	v->valid = 1;
	v->no_cacheable = 0;
	v->not_found = 0;

	if (r->upstream_states == NULL || r->upstream_states->nelts == 0) {
		v->not_found = 1;
		return NGX_OK;
	}

	len = r->upstream_states->nelts * (NGX_OFF_T_LEN + 2);

	p = ngx_pnalloc(r->pool, len);
	if (p == NULL) {
		return NGX_ERROR;
	}

	v->data = p;

	i = 0;
	state = r->upstream_states->elts;

	for (;;) {

		if (data == 1) {
			p = ngx_sprintf(p, "%O", state[i].bytes_received);

		} else {
			p = ngx_sprintf(p, "%O", state[i].response_length);
		}

		if (++i == r->upstream_states->nelts) {
			break;
		}

		if (state[i].peer) {
			*p++ = ',';
			*p++ = ' ';

		} else {
			*p++ = ' ';
			*p++ = ':';
			*p++ = ' ';

			if (++i == r->upstream_states->nelts) {
				break;
			}

			continue;
		}
	}

	v->len = p - v->data;

	return NGX_OK;
}

static ngx_int_t ngx_http2_upstream_header_variable(ngx_http_request_t *r,
		ngx_http_variable_value_t *v, uintptr_t data) {
	if (r->upstream == NULL) {
		v->not_found = 1;
		return NGX_OK;
	}

	return ngx_http_variable_unknown_header(v, (ngx_str_t *) data,
			&r->upstream->headers_in.headers.part, sizeof("upstream_http_") - 1);
}

static ngx_int_t ngx_http2_stream_trailer_variable(ngx_http_request_t *r,
		ngx_http_variable_value_t *v, uintptr_t data) {
	if (r->upstream == NULL) {
		v->not_found = 1;
		return NGX_OK;
	}

	return ngx_http_variable_unknown_header(v, (ngx_str_t *) data,
			&r->upstream->headers_in.trailers.part,
			sizeof("upstream_trailer_") - 1);
}

static ngx_int_t ngx_http2_upstream_cookie_variable(ngx_http_request_t *r,
		ngx_http_variable_value_t *v, uintptr_t data) {
	ngx_str_t *name = (ngx_str_t *) data;

	ngx_str_t cookie, s;

	if (r->upstream == NULL) {
		v->not_found = 1;
		return NGX_OK;
	}

	s.len = name->len - (sizeof("upstream_cookie_") - 1);
	s.data = name->data + sizeof("upstream_cookie_") - 1;

	if (ngx_http_parse_set_cookie_lines(&r->upstream->headers_in.cookies, &s,
			&cookie) == NGX_DECLINED) {
		v->not_found = 1;
		return NGX_OK;
	}

	v->len = cookie.len;
	v->valid = 1;
	v->no_cacheable = 0;
	v->not_found = 0;
	v->data = cookie.data;

	return NGX_OK;
}

static void ngx_http2_upstream_default_choose_server(ngx_http_request_t* request,ngx_http2_upstream_srv_conf_t *scf){
	ngx_http2_stream_t *stream ;
	ngx_uint_t i;
	ngx_http2_server_t* server;
	stream=(ngx_http2_stream_t*) request->upstream;
	stream->server = NULL;
	server = scf->servers->elts;
	for(i=0;i < scf->servers.nelts;++i){
		if(server->connection || (!ngx_queue_empty(&server[i].connection_queue)) || (server[i].use_conns < server[i].max_conns)){
			stream->server = &server[i];
			return ;
		}
	}
}

static char *
ngx_http2_upstream(ngx_conf_t *cf, ngx_command_t *cmd, void *dummy) {
	char *rv;
	void *mconf;
	ngx_str_t *value;
	ngx_url_t u;
	ngx_uint_t m;
	ngx_conf_t pcf;
	ngx_http_module_t *module;
	ngx_http_conf_ctx_t *ctx, *http_ctx;
	ngx_http2_upstream_srv_conf_t *uscf;

	ngx_memzero(&u, sizeof(ngx_url_t));

	value = cf->args->elts;
	u.host = value[1];
	u.no_resolve = 1;
	u.no_port = 1;

	uscf = ngx_http2_upstream_add(cf, &u);
	if (uscf == NULL) {
		return NGX_CONF_ERROR ;
	}
	uscf->choose_server = ngx_http2_upstream_default_choose_server;
	uscf->log = cf->log;
	uscf->recvbuf = 8192;
	uscf->log_error = NGX_ERROR_ERR;

	ctx = ngx_pcalloc(cf->pool, sizeof(ngx_http_conf_ctx_t));
	if (ctx == NULL) {
		return NGX_CONF_ERROR ;
	}

	http_ctx = cf->ctx;
	ctx->main_conf = http_ctx->main_conf;

	/* the upstream{}'s srv_conf */

	ctx->srv_conf = ngx_pcalloc(cf->pool, sizeof(void *) * ngx_http_max_module);
	if (ctx->srv_conf == NULL) {
		return NGX_CONF_ERROR ;
	}

	ctx->srv_conf[ngx_http2_upstream_module.ctx_index] = uscf;

	uscf->srv_conf = ctx->srv_conf;

	/* the upstream{}'s loc_conf */

	ctx->loc_conf = ngx_pcalloc(cf->pool, sizeof(void *) * ngx_http_max_module);
	if (ctx->loc_conf == NULL) {
		return NGX_CONF_ERROR ;
	}

	for (m = 0; cf->cycle->modules[m]; m++) {
		if (cf->cycle->modules[m]->type != NGX_HTTP_MODULE) {
			continue;
		}

		module = cf->cycle->modules[m]->ctx;

		if (module->create_srv_conf) {
			mconf = module->create_srv_conf(cf);
			if (mconf == NULL) {
				return NGX_CONF_ERROR ;
			}

			ctx->srv_conf[cf->cycle->modules[m]->ctx_index] = mconf;
		}

		if (module->create_loc_conf) {
			mconf = module->create_loc_conf(cf);
			if (mconf == NULL) {
				return NGX_CONF_ERROR ;
			}

			ctx->loc_conf[cf->cycle->modules[m]->ctx_index] = mconf;
		}
	}

	uscf->servers = ngx_array_create(cf->pool, 4,
			sizeof(ngx_http2_server_t));
	if (uscf->servers == NULL) {
		return NGX_CONF_ERROR ;
	}

	/* parse inside upstream{} */

	pcf = *cf;
	cf->ctx = ctx;
	cf->cmd_type = NGX_HTTP_UPS_CONF;

	rv = ngx_conf_parse(cf, NULL);

	*cf = pcf;

	if (rv != NGX_CONF_OK) {
		return rv;
	}

	if (uscf->servers->nelts == 0) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
				"no servers are inside http2_upstream");
		return NGX_CONF_ERROR ;
	}

	return rv;
}

static char *
ngx_http2_upstream_server(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
	ngx_http2_upstream_srv_conf_t *uscf = conf;

	time_t fail_timeout;
	ngx_str_t *value, s;
	ngx_url_t u;
	ngx_int_t weight, max_conns, max_fails;
	ngx_uint_t i;
	ngx_http2_server_t *us;

	us = ngx_array_push(uscf->servers);
	if (us == NULL) {
		return NGX_CONF_ERROR ;
	}

	ngx_memzero(us, sizeof(ngx_http2_server_t));

	ngx_queue_init(&us->connection_queue);
	ngx_queue_init(&us->stream_queue);

	value = cf->args->elts;

	weight = 1;
	max_conns = 0;
	max_fails = 1;
	fail_timeout = 10;

	for (i = 2; i < cf->args->nelts; i++) {

		if (ngx_strncmp(value[i].data, "weight=", 7) == 0) {
			weight = ngx_atoi(&value[i].data[7], value[i].len - 7);
			if (weight == NGX_ERROR || weight == 0) {
				goto invalid;
			}
			continue;
		}

		if (ngx_strncmp(value[i].data, "max_conns=", 10) == 0) {
			max_conns = ngx_atoi(&value[i].data[10], value[i].len - 10);
			if (max_conns == NGX_ERROR) {
				goto invalid;
			}
			continue;
		}
		if (ngx_strncmp(value[i].data, "max_fails=", 10) == 0) {
			max_fails = ngx_atoi(&value[i].data[10], value[i].len - 10);
			if (max_fails == NGX_ERROR) {
				goto invalid;
			}
			continue;
		}

		if (ngx_strncmp(value[i].data, "fail_timeout=", 13) == 0) {
			s.len = value[i].len - 13;
			s.data = &value[i].data[13];
			fail_timeout = ngx_parse_time(&s, 1);
			if (fail_timeout == (time_t) NGX_ERROR) {
				goto invalid;
			}
			continue;
		}

		if (ngx_strcmp(value[i].data, "backup") == 0) {
			us->backup = 1;
			continue;
		}

		if (ngx_strcmp(value[i].data, "down") == 0) {
			us->down = 1;
			continue;
		}

		goto invalid;
	}

	ngx_memzero(&u, sizeof(ngx_url_t));

	u.url = value[1];
	u.default_port = 80;

	if (ngx_parse_url(cf->pool, &u) != NGX_OK) {
		if (u.err) {
			ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "%s in upstream \"%V\"",
					u.err, &u.url);
		}

		return NGX_CONF_ERROR ;
	}

	us->name = u.url;
	us->addrs = u.addrs;
	us->naddrs = u.naddrs;
	us->weight = weight;
	us->max_conns = max_conns;
	us->max_fails = max_fails;
	us->fail_timeout = fail_timeout;
	return NGX_CONF_OK;

	invalid:

	ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid parameter \"%V\"",
			&value[i]);
	return NGX_CONF_ERROR ;
}

ngx_http2_upstream_srv_conf_t * ngx_http2_upstream_add(ngx_conf_t *cf, ngx_url_t *u) {
	ngx_uint_t i;
	ngx_http2_server_t *us;
	ngx_http2_upstream_srv_conf_t *uscf, **uscfp;
	ngx_http2_upstream_main_conf_t *umcf;

	umcf = ngx_http_conf_get_module_main_conf(cf, ngx_http2_upstream_module);

	uscfp = umcf->upstreams.elts;

	for (i = 0; i < umcf->upstreams.nelts; i++) {
		if (uscfp[i]->host.len != u->host.len
				|| ngx_strncasecmp(uscfp[i]->host.data, u->host.data,
						u->host.len) != 0) {
			continue;
		}
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,"duplicate http2_upstream \"%V\"", &u->host);
		return NULL;
	}

	uscf = ngx_pcalloc(cf->pool, sizeof(ngx_http2_upstream_srv_conf_t));
	if (uscf == NULL) {
		return NULL;
	}
	uscf->host = u->host;
	ngx_queue_init(&uscf->free_connections);
	ngx_queue_init(&uscf->need_free_frame_queue);
	uscf->buffer_count = 10240;
	uscf->buffer_size = 8192;
	uscf->max_streams = 512;
	uscf->sid_mask = 32;
	uscf->header_pool_size = 8192;
	uscf->pool = cf->pool;


	uscfp = ngx_array_push(&umcf->upstreams);
	if (uscfp == NULL) {
		return NULL;
	}

	*uscfp = uscf;
	return uscf;
}

char *
ngx_http2_upstream_bind_set_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
	char *p = conf;

	ngx_int_t rc;
	ngx_str_t *value;
	ngx_http_complex_value_t cv;
	ngx_http2_upstream_local_t **plocal, *local;
	ngx_http_compile_complex_value_t ccv;

	plocal = (ngx_http2_upstream_local_t **) (p + cmd->offset);

	if (*plocal != NGX_CONF_UNSET_PTR) {
		return "is duplicate";
	}

	value = cf->args->elts;

	if (cf->args->nelts == 2 && ngx_strcmp(value[1].data, "off") == 0) {
		*plocal = NULL;
		return NGX_CONF_OK;
	}

	ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

	ccv.cf = cf;
	ccv.value = &value[1];
	ccv.complex_value = &cv;

	if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
		return NGX_CONF_ERROR ;
	}

	local = ngx_pcalloc(cf->pool, sizeof(ngx_http2_upstream_local_t));
	if (local == NULL) {
		return NGX_CONF_ERROR ;
	}

	*plocal = local;

	if (cv.lengths) {
		local->value = ngx_palloc(cf->pool, sizeof(ngx_http_complex_value_t));
		if (local->value == NULL) {
			return NGX_CONF_ERROR ;
		}

		*local->value = cv;

	} else {
		local->addr = ngx_palloc(cf->pool, sizeof(ngx_addr_t));
		if (local->addr == NULL) {
			return NGX_CONF_ERROR ;
		}

		rc = ngx_parse_addr_port(cf->pool, local->addr, value[1].data,
				value[1].len);

		switch (rc) {
		case NGX_OK:
			local->addr->name = value[1];
			break;

		case NGX_DECLINED:
			ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid address \"%V\"",
					&value[1]);
			/* fall through */

		default:
			return NGX_CONF_ERROR ;
		}
	}

	if (cf->args->nelts > 2) {
		if (ngx_strcmp(value[2].data, "transparent") == 0) {
#if (NGX_HAVE_TRANSPARENT_PROXY)
			ngx_core_conf_t *ccf;

			ccf = (ngx_core_conf_t *) ngx_get_conf(cf->cycle->conf_ctx,
					ngx_core_module);

			ccf->transparent = 1;
			local->transparent = 1;
#else
			ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
					"transparent proxying is not supported "
					"on this platform, ignored");
#endif
		} else {
			ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid parameter \"%V\"",
					&value[2]);
			return NGX_CONF_ERROR ;
		}
	}

	return NGX_CONF_OK;
}

static ngx_int_t ngx_http2_upstream_set_local(ngx_http_request_t *r,
		ngx_http2_stream_t *u, ngx_http2_upstream_local_t *local) {
	ngx_int_t rc;
	ngx_str_t val;
	ngx_addr_t *addr;

	if (local == NULL) {
		u->peer.local = NULL;
		return NGX_OK;
	}

#if (NGX_HAVE_TRANSPARENT_PROXY)
	u->peer.transparent = local->transparent;
#endif

	if (local->value == NULL) {
		u->peer.local = local->addr;
		return NGX_OK;
	}

	if (ngx_http_complex_value(r, local->value, &val) != NGX_OK) {
		return NGX_ERROR;
	}

	if (val.len == 0) {
		return NGX_OK;
	}

	addr = ngx_palloc(r->pool, sizeof(ngx_addr_t));
	if (addr == NULL) {
		return NGX_ERROR;
	}

	rc = ngx_parse_addr_port(r->pool, addr, val.data, val.len);
	if (rc == NGX_ERROR) {
		return NGX_ERROR;
	}

	if (rc != NGX_OK) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
				"invalid local address \"%V\"", &val);
		return NGX_OK;
	}

	addr->name = val;
	u->peer.local = addr;

	return NGX_OK;
}

char *
ngx_http2_upstream_param_set_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
	char *p = conf;

	ngx_str_t *value;
	ngx_array_t **a;
	ngx_http2_upstream_param_t *param;

	a = (ngx_array_t **) (p + cmd->offset);

	if (*a == NULL) {
		*a = ngx_array_create(cf->pool, 4, sizeof(ngx_http2_upstream_param_t));
		if (*a == NULL) {
			return NGX_CONF_ERROR ;
		}
	}

	param = ngx_array_push(*a);
	if (param == NULL) {
		return NGX_CONF_ERROR ;
	}

	value = cf->args->elts;

	param->key = value[1];
	param->value = value[2];
	param->skip_empty = 0;

	if (cf->args->nelts == 4) {
		if (ngx_strcmp(value[3].data, "if_not_empty") != 0) {
			ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid parameter \"%V\"",
					&value[3]);
			return NGX_CONF_ERROR ;
		}

		param->skip_empty = 1;
	}

	return NGX_CONF_OK;
}

ngx_int_t ngx_http2_upstream_hide_headers_hash(ngx_conf_t *cf,
		ngx_http2_upstream_conf_t *conf, ngx_http2_upstream_conf_t *prev,
		ngx_str_t *default_hide_headers, ngx_hash_init_t *hash) {
	ngx_str_t *h;
	ngx_uint_t i, j;
	ngx_array_t hide_headers;
	ngx_hash_key_t *hk;

	if (conf->hide_headers == NGX_CONF_UNSET_PTR
			&& conf->pass_headers == NGX_CONF_UNSET_PTR) {
		conf->hide_headers = prev->hide_headers;
		conf->pass_headers = prev->pass_headers;

		conf->hide_headers_hash = prev->hide_headers_hash;

		if (conf->hide_headers_hash.buckets) {
			return NGX_OK;
		}

	} else {
		if (conf->hide_headers == NGX_CONF_UNSET_PTR) {
			conf->hide_headers = prev->hide_headers;
		}

		if (conf->pass_headers == NGX_CONF_UNSET_PTR) {
			conf->pass_headers = prev->pass_headers;
		}
	}

	if (ngx_array_init(&hide_headers, cf->temp_pool, 4,
			sizeof(ngx_hash_key_t)) != NGX_OK) {
		return NGX_ERROR;
	}

	for (h = default_hide_headers; h->len; h++) {
		hk = ngx_array_push(&hide_headers);
		if (hk == NULL) {
			return NGX_ERROR;
		}

		hk->key = *h;
		hk->key_hash = ngx_hash_key_lc(h->data, h->len);
		hk->value = (void *) 1;
	}

	if (conf->hide_headers != NGX_CONF_UNSET_PTR) {

		h = conf->hide_headers->elts;

		for (i = 0; i < conf->hide_headers->nelts; i++) {

			hk = hide_headers.elts;

			for (j = 0; j < hide_headers.nelts; j++) {
				if (ngx_strcasecmp(h[i].data, hk[j].key.data) == 0) {
					goto exist;
				}
			}

			hk = ngx_array_push(&hide_headers);
			if (hk == NULL) {
				return NGX_ERROR;
			}

			hk->key = h[i];
			hk->key_hash = ngx_hash_key_lc(h[i].data, h[i].len);
			hk->value = (void *) 1;

			exist:

			continue;
		}
	}

	if (conf->pass_headers != NGX_CONF_UNSET_PTR) {

		h = conf->pass_headers->elts;
		hk = hide_headers.elts;

		for (i = 0; i < conf->pass_headers->nelts; i++) {
			for (j = 0; j < hide_headers.nelts; j++) {

				if (hk[j].key.data == NULL) {
					continue;
				}

				if (ngx_strcasecmp(h[i].data, hk[j].key.data) == 0) {
					hk[j].key.data = NULL;
					break;
				}
			}
		}
	}

	hash->hash = &conf->hide_headers_hash;
	hash->key = ngx_hash_key_lc;
	hash->pool = cf->pool;
	hash->temp_pool = NULL;

	if (ngx_hash_init(hash, hide_headers.elts, hide_headers.nelts) != NGX_OK) {
		return NGX_ERROR;
	}

	/*
	 * special handling to preserve conf->hide_headers_hash
	 * in the "http" section to inherit it to all servers
	 */

	if (prev->hide_headers_hash.buckets == NULL
			&& conf->hide_headers == prev->hide_headers
			&& conf->pass_headers == prev->pass_headers) {
		prev->hide_headers_hash = conf->hide_headers_hash;
	}

	return NGX_OK;
}

static void *
ngx_http2_upstream_create_main_conf(ngx_conf_t *cf) {
	ngx_http2_upstream_main_conf_t *umcf;

	umcf = ngx_pcalloc(cf->pool, sizeof(ngx_http2_upstream_main_conf_t));
	if (umcf == NULL) {
		return NULL;
	}

	if (ngx_array_init(&umcf->upstreams, cf->pool, 4,
			sizeof(ngx_http2_upstream_srv_conf_t *)) != NGX_OK) {
		return NULL;
	}

	return umcf;
}

static char *
ngx_http2_upstream_init_main_conf(ngx_conf_t *cf, void *conf) {
	ngx_http2_upstream_main_conf_t *umcf = conf;

	ngx_uint_t i;
	ngx_array_t headers_in;
	ngx_hash_key_t *hk;
	ngx_hash_init_t hash;
	ngx_http2_upstream_init_pt init;
	ngx_http2_upstream_header_t *header;
	ngx_http2_upstream_srv_conf_t **uscfp;

	uscfp = umcf->upstreams.elts;

	for (i = 0; i < umcf->upstreams.nelts; i++) {

		init = uscfp[i]->peer.init_upstream ?
				uscfp[i]->peer.init_upstream :
				ngx_http2_upstream_init_round_robin;

		if (init(cf, uscfp[i]) != NGX_OK) {
			return NGX_CONF_ERROR ;
		}
	}

	/* upstream_headers_in_hash */

	if (ngx_array_init(&headers_in, cf->temp_pool, 32,
			sizeof(ngx_hash_key_t)) != NGX_OK) {
		return NGX_CONF_ERROR ;
	}

	for (header = ngx_http2_upstream_headers_in; header->name.len; header++) {
		hk = ngx_array_push(&headers_in);
		if (hk == NULL) {
			return NGX_CONF_ERROR ;
		}

		hk->key = header->name;
		hk->key_hash = ngx_hash_key_lc(header->name.data, header->name.len);
		hk->value = header;
	}

	hash.hash = &umcf->headers_in_hash;
	hash.key = ngx_hash_key_lc;
	hash.max_size = 512;
	hash.bucket_size = ngx_align(64, ngx_cacheline_size);
	hash.name = "upstream_headers_in_hash";
	hash.pool = cf->pool;
	hash.temp_pool = NULL;

	if (ngx_hash_init(&hash, headers_in.elts, headers_in.nelts) != NGX_OK) {
		return NGX_CONF_ERROR ;
	}

	return NGX_CONF_OK;
}


static char* ngx_http2_upstream_buffer_size(ngx_conf_t *cf, ngx_command_t *cmd, void *conf){
	ngx_int_t n;
	ngx_str_t * value = cf->args->elts;
	ngx_http2_upstream_srv_conf_t *kcf = conf;
	n = ngx_atoi(value[1].data, value[1].len);
	if (n == NGX_ERROR || n == 0) {
		return "invalid paramter http2_buffer_size";
	}
	if (n > 8192) {
		kcf->buffer_size = n;
	}
	return NGX_CONF_OK;
}

static char* ngx_http2_upstream_buffer_count(ngx_conf_t *cf, ngx_command_t *cmd, void *conf){
	ngx_int_t n;
	ngx_str_t * value = cf->args->elts;
	ngx_http2_upstream_srv_conf_t *kcf = conf;
	n = ngx_atoi(value[1].data, value[1].len);
	if (n == NGX_ERROR || n == 0) {
		return "invalid paramter http2_buffer_count";
	}
	if (n > 1024) {
		kcf->buffer_count = n;
	}
	return NGX_CONF_OK;
}
static char* ngx_http2_upstream_sid_mask(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
	ngx_uint_t n;
	ngx_uint_t mask;
	ngx_str_t * value = cf->args->elts;
	ngx_http2_upstream_srv_conf_t *kcf = conf;
	n = ngx_atoi(value[1].data, value[1].len);
	if (n == NGX_ERROR || n == 0) {
		return "invalid paramter http2_sid_mask";
	}
	if (n > 8) {

		mask = n - 1;

		if (n == 0 || (n & mask)) {
			return "invalid paramter http2_sid_mask:must be a power of two";
		}

		kcf->sid_mask = mask;

	}
	return NGX_CONF_OK;

}
static char* ngx_http2_upstream_header_pool_size(ngx_conf_t *cf, ngx_command_t *cmd, void *conf){
	ngx_int_t n;
		ngx_str_t * value = cf->args->elts;
		ngx_http2_upstream_srv_conf_t *kcf = conf;
		n = ngx_atoi(value[1].data, value[1].len);
		if (n == NGX_ERROR || n == 0) {
			return "invalid paramter http2_header_pool_size";
		}
		if (n > 1024) {
			kcf->header_pool_size = n;
		}
		return NGX_CONF_OK;



}
static char*ngx_http2_upstream_max_streams(ngx_conf_t *cf, ngx_command_t *cmd, void *conf){
	ngx_int_t n;
	ngx_str_t * value = cf->args->elts;
	ngx_http2_upstream_srv_conf_t *kcf = conf;
	n = ngx_atoi(value[1].data, value[1].len);
	if (n == NGX_ERROR || n == 0) {
		return "invalid paramter http2_max_streams";
	}
	kcf->max_streams = n;
	return NGX_CONF_OK;
}
