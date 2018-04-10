/*
 * ngx_http_upstream_http2_connection.c
 *
 *  Created on: Apr 10, 2018
 *      Author: root
 */
#include <ngx_http_upstream_http2.h>



ngx_http2_connection_t* ngx_http_upstream_http2_connection_create(ngx_http_upstream_http2_srv_conf_t *us) {
	ngx_queue_t *queue;
	int i ;
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
