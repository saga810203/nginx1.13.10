/*
 * ngx_http_upstream_http2_hpack.c
 *
 *  Created on: Apr 20, 2018
 *      Author: root
 */

#include <ngx_http_upstream_http2.h>



typedef struct{
	ngx_str_t name;
	ngx_str_t value;
} ngx_http2_static_headers_item;



static ngx_http2_static_headers_item ngx_http2_headers_static[]={
	{ ngx_string(":authority"), ngx_string("") },
	{ ngx_string(":method"), ngx_string("GET") },
	{ ngx_string(":method"), ngx_string("POST") },
	{ ngx_string(":path"), ngx_string("/") },
	{ ngx_string(":path"), ngx_string("/index.html") },
	{ ngx_string(":scheme"), ngx_string("http") },
	{ ngx_string(":scheme"), ngx_string("https") },
	{ ngx_string(":status"), ngx_string("200") },
	{ ngx_string(":status"), ngx_string("204") },
	{ ngx_string(":status"), ngx_string("206") },
	{ ngx_string(":status"), ngx_string("304") },
	{ ngx_string(":status"), ngx_string("400") },
	{ ngx_string(":status"), ngx_string("404") },
	{ ngx_string(":status"), ngx_string("500") },
	{ ngx_string("accept-charset"), ngx_string("") },
	{ ngx_string("accept-encoding"), ngx_string("gzip, deflate") },
	{ ngx_string("accept-language"), ngx_string("") },
	{ ngx_string("accept-ranges"), ngx_string("") },
	{ ngx_string("accept"), ngx_string("") },
	{ ngx_string("access-control-allow-origin"), ngx_string("") },
	{ ngx_string("age"), ngx_string("") },
	{ ngx_string("allow"), ngx_string("") },
	{ ngx_string("authorization"), ngx_string("") },
	{ ngx_string("cache-control"), ngx_string("") },
	{ ngx_string("content-disposition"), ngx_string("") },
	{ ngx_string("content-encoding"), ngx_string("") },
	{ ngx_string("content-language"), ngx_string("") },
	{ ngx_string("content-length"), ngx_string("") },
	{ ngx_string("content-location"), ngx_string("") },
	{ ngx_string("content-range"), ngx_string("") },
	{ ngx_string("content-type"), ngx_string("") },
	{ ngx_string("cookie"), ngx_string("") },
	{ ngx_string("date"), ngx_string("") },
	{ ngx_string("etag"), ngx_string("") },
	{ ngx_string("expect"), ngx_string("") },
	{ ngx_string("expires"), ngx_string("") },
	{ ngx_string("from"), ngx_string("") },
	{ ngx_string("host"), ngx_string("") },
	{ ngx_string("if-match"), ngx_string("") },
	{ ngx_string("if-modified-since"), ngx_string("") },
	{ ngx_string("if-none-match"), ngx_string("") },
	{ ngx_string("if-range"), ngx_string("") },
	{ ngx_string("if-unmodified-since"), ngx_string("") },
	{ ngx_string("last-modified"), ngx_string("") },
	{ ngx_string("link"), ngx_string("") },
	{ ngx_string("location"), ngx_string("") },
	{ ngx_string("max-forwards"), ngx_string("") },
	{ ngx_string("proxy-authenticate"), ngx_string("") },
	{ ngx_string("proxy-authorization"), ngx_string("") },
	{ ngx_string("range"), ngx_string("") },
	{ ngx_string("referer"), ngx_string("") },
	{ ngx_string("refresh"), ngx_string("") },
	{ ngx_string("retry-after"), ngx_string("") },
	{ ngx_string("server"), ngx_string("") },
	{ ngx_string("set-cookie"), ngx_string("") },
	{ ngx_string("strict-transport-security"), ngx_string("") },
	{ ngx_string("transfer-encoding"), ngx_string("") },
	{ ngx_string("user-agent"), ngx_string("") },
	{ ngx_string("vary"), ngx_string("") },
	{ ngx_string("via"), ngx_string("") },
	{ ngx_string("www-authenticate"), ngx_string("") },
};

int32_t ngx_http2_hpack_get_index_header(ngx_http2_connection_t* h2c,int32_t idx,int32_t nameonly){
	ngx_http2_static_headers_item* sheader;
	ngx_str_t* value;

	ngx_http2_header_t* header;

	header = ngx_pcalloc(h2c->recv.pool,sizeof(ngx_http2_header_t));
	ngx_queue_insert_tail(&h2c->recv.headers_queue,&header->queue);
	h2c->recv.c_header = header;

	if(idx){
		--idx;
		if(idx< 61){
			sheader = &ngx_http2_headers_static[idx];
			header->name.len = sheader->name.len;
			header->name.data = sheader->name.data;
			if(!nameonly){
				header->value.len = sheader->value.len;
				header->value.data = sheader->value.data;
			}
		}else{
			idx-=61;
		}
	}else{
		return NGX_ERROR;
	}


}

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
	ngx_http2_static_headers_item* sheader;
	ngx_str_t* value;

	ngx_http2_header_t* header;

	header = ngx_pcalloc(h2c->recv.pool,sizeof(ngx_http2_header_t));
	if(header){
		ngx_queue_insert_tail(&h2c->recv.headers_queue,&header->queue);
		h2c->recv.c_header = header;
		if(idx){
			--idx;
			if(idx< 61){
				sheader = &ngx_http2_headers_static[idx];
				header->name.len = sheader->name.len;
				header->name.data = sheader->name.data;
				if(!nameonly){
					header->value.len = sheader->value.len;
					header->value.data = sheader->value.data;
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





