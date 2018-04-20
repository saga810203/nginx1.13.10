/*
 * ngx_http_upstream_http2_hpack.c
 *
 *  Created on: Apr 20, 2018
 *      Author: root
 */

#include <ngx_http_upstream_http2.h>



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
		ngx_memcpy(hpack->data,b_index, hpack->bytes_headers - (32 - (sizeof(uint32_t) * 2))) ;
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

	p = hpack->index;
	p -=sizeof(void*);
	if(hpack->rds_headers){
		ngx_memcpy(p,hpack->index,sizeof(void*)* hpack->rds_headers);
	}
	hpack->index = (u_char**)p;
	hpack->index[hpack->rds_headers++] = n;
	return 0;
}

ngx_str_t* ngx_http2_hpack_index_name(ngx_http2_hpack_t* hpack,uint32_t idx){
	ngx_str_t  ret;
	uint32_t *len;
	u_char* data;

	if(idx>=hpack->rds_headers){
		return NULL;
	}

	len = (uint32_t*)hpack->index[idx];

	ret.len = *len;
	ret.data = ((u_char*)len)+sizeof(uint32_t);
	return &ret;
}
ngx_str_t* ngx_http2_hpack_index_header(ngx_http2_hpack_t* hpack,uint32_t idx){
	ngx_str_t  ret[2];
	uint32_t *len;
	u_char* data;

	if(idx>=hpack->rds_headers){
		return NULL;
	}

	len = (uint32_t*)hpack->index[idx];
	ret[0].len = *len;
	ret[0].data = ((u_char*)len)+sizeof(uint32_t);
	len =(uint32_t*)(ret[0].data + ret[0].len);
	ret[1].len = *len;
	ret[1].data = ((u_char*)len)+sizeof(uint32_t);
	return ret;
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







