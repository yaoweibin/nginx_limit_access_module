
#ifndef _NGX_HTTP_LIMIT_ACCESS_MODULE_H_INCLUDED_
#define _NGX_HTTP_LIMIT_ACCESS_MODULE_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#define HASH_IP       0x01
#define HASH_VARIABLE 0x02

typedef struct {
    time_t      expire;
    ngx_uint_t  status;
    ngx_buf_t  *buf;
} ngx_http_limit_access_request_ctx_t;

typedef struct ngx_http_limit_access_bucket_s {
    struct ngx_http_limit_access_bucket_s *next;

    ngx_uint_t key;
    time_t     expire;
    u_short    len;
    u_char     value[0];
} ngx_http_limit_access_bucket_t;

typedef struct {
    ngx_uint_t                       valid;
    ngx_http_limit_access_bucket_t  *free;
    ngx_http_limit_access_bucket_t **buckets;
} ngx_http_limit_access_hash_t;

typedef struct {
    ngx_uint_t                    type;
    ngx_uint_t                    bucket_number;
    ngx_int_t                     index;
    ngx_str_t                     var;
    ngx_slab_pool_t              *shpool;
    ngx_http_limit_access_hash_t *sh;
} ngx_http_limit_access_ctx_t;

typedef struct {
    ngx_shm_zone_t              *shm_zone;
    time_t                       default_expire;
    ngx_uint_t                   limit_log_level;
    unsigned                     limit_check;
} ngx_http_limit_access_conf_t;

typedef ngx_int_t (*ngx_http_limit_access_process_value_pt) 
    (ngx_http_request_t *r, ngx_str_t *value);

typedef struct {
    ngx_str_t                              name;
    ngx_http_limit_access_process_value_pt handler;
} ngx_http_limit_access_directive_t;

ngx_http_limit_access_bucket_t *ngx_alloc_limit_access_bucket(
        ngx_http_limit_access_ctx_t *ctx, size_t len);
void ngx_free_limit_access_bucket(ngx_http_limit_access_ctx_t *ctx,
        ngx_http_limit_access_bucket_t **p);

void ngx_http_limit_access_process_handler(ngx_http_request_t *r);

ngx_int_t ngx_http_limit_access_lookup_ip(ngx_http_request_t *r, 
        ngx_http_limit_access_ctx_t *ctx);
ngx_int_t ngx_http_limit_access_lookup_variable(ngx_http_request_t *r, 
        ngx_http_limit_access_ctx_t *ctx);

extern ngx_module_t  ngx_http_limit_access_module;

#endif
