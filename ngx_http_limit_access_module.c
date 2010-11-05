
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#define HASH_IP  0x01
#define HASH_URL 0x02

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
    u_char     value[1];
} ngx_http_limit_access_bucket_t;

typedef struct {
    ngx_uint_t   valid;
    ngx_http_limit_access_bucket_t *free;
    ngx_http_limit_access_bucket_t *buckets;
} ngx_http_limit_access_hash_t;

typedef struct {
    ngx_uint_t                    type;
    ngx_uint_t                    bucket_number;
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
    ngx_str_t name;
    ngx_http_limit_access_process_value_pt handler;
} ngx_http_limit_access_directive_t;

static ngx_http_limit_access_bucket_t *ngx_alloc_limit_access_bucket(
        ngx_http_limit_access_ctx_t *ctx);
#define ngx_free_limit_access_bucket(sh, bucket)                              \
    bucket->next = sh->free;                                                  \
    sh->free = bucket; 

static ngx_int_t ngx_http_limit_access_interface_handler(ngx_http_request_t *r);
static void ngx_http_limit_access_process_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_limit_access_process_post(ngx_http_request_t *r, 
        u_char *data, size_t len);
static ngx_int_t ngx_http_limit_access_process_param(ngx_http_request_t *r, 
        ngx_str_t *param);

static ngx_int_t ngx_http_limit_access_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_limit_access_status_handler(ngx_http_request_t *r);

static void *ngx_http_limit_access_create_conf(ngx_conf_t *cf);
static char *ngx_http_limit_access_merge_conf(ngx_conf_t *cf, void *parent,
    void *child);
static char *ngx_http_limit_access_zone(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_limit_access(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_limit_access_status(ngx_conf_t *cf, ngx_command_t *cmd, 
        void *conf);
static char * ngx_http_limit_access_interface(ngx_conf_t *cf, 
        ngx_command_t *cmd, void *conf);

static ngx_int_t ngx_http_limit_access_init(ngx_conf_t *cf);


static ngx_int_t limit_access_ban_expire(ngx_http_request_t *r, ngx_str_t *value);
static ngx_int_t limit_access_ban_list(ngx_http_request_t *r, ngx_str_t *value);
static ngx_int_t limit_access_free_list(ngx_http_request_t *r, ngx_str_t *value);
static ngx_int_t limit_access_show_list(ngx_http_request_t *r, ngx_str_t *value);
static ngx_int_t limit_access_destory_list(ngx_http_request_t *r, ngx_str_t *value);
static ngx_int_t limit_access_expire_list(ngx_http_request_t *r, ngx_str_t *value);

static ngx_int_t ngx_http_limit_access_lookup_ip(ngx_http_request_t *r, 
        ngx_http_limit_access_ctx_t *ctx);
static ngx_int_t ngx_http_limit_access_ban_ip(ngx_http_request_t *r, 
        ngx_http_limit_access_ctx_t *ctx, in_addr_t ip);
static ngx_int_t ngx_http_limit_access_free_ip(ngx_http_request_t *r, 
        ngx_http_limit_access_ctx_t *ctx, in_addr_t ip);
static ngx_int_t ngx_http_limit_access_show_ip(ngx_http_request_t *r, 
        ngx_http_limit_access_ctx_t *ctx, ngx_buf_t *b);
static ngx_int_t ngx_http_limit_access_destory_list(ngx_http_request_t *r, 
        ngx_http_limit_access_ctx_t *ctx);
static ngx_int_t ngx_http_limit_access_expire_list(ngx_http_request_t *r, 
        ngx_http_limit_access_ctx_t *ctx);

static ngx_conf_enum_t  ngx_http_limit_access_log_levels[] = {
    { ngx_string("info"),   NGX_LOG_INFO },
    { ngx_string("notice"), NGX_LOG_NOTICE },
    { ngx_string("warn"),   NGX_LOG_WARN },
    { ngx_string("error"),  NGX_LOG_ERR },
    { ngx_null_string, 0 }
};

static ngx_http_limit_access_directive_t directives[] = {
    { ngx_string("ban_type"),   NULL },
    { ngx_string("ban_expire"), limit_access_ban_expire },
    { ngx_string("ban_list"),   limit_access_ban_list },
    { ngx_string("free_type"),  NULL },
    { ngx_string("free_list"),  limit_access_free_list },
    { ngx_string("show_type"),  NULL },
    { ngx_string("show_list"),  limit_access_show_list },
    { ngx_string("destory_list"),  limit_access_destory_list },
    { ngx_string("expire_list"),  limit_access_expire_list },
    { ngx_null_string, NULL }
};


static ngx_command_t  ngx_http_limit_access_commands[] = {

    { ngx_string("limit_access_zone"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE123,
      ngx_http_limit_access_zone,
      0,
      0,
      NULL },

    { ngx_string("limit_access"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE12,
      ngx_http_limit_access,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("limit_access_log_level"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_limit_access_conf_t, limit_log_level),
      &ngx_http_limit_access_log_levels },

    { ngx_string("limit_access_status"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_limit_access_status,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("limit_access_interface"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_limit_access_interface,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_limit_access_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_limit_access_init,            /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_limit_access_create_conf,        /* create location configration */
    ngx_http_limit_access_merge_conf          /* merge location configration */
};


ngx_module_t  ngx_http_limit_access_module = {
    NGX_MODULE_V1,
    &ngx_http_limit_access_module_ctx,     /* module context */
    ngx_http_limit_access_commands,        /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_http_limit_access_interface_handler(ngx_http_request_t *r)
{
    ngx_int_t                              rc;
    ngx_http_limit_access_request_ctx_t   *request_ctx;
    ngx_http_limit_access_conf_t          *lacf;

    if (r->method != NGX_HTTP_POST) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    request_ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_limit_access_request_ctx_t));
    if (request_ctx == NULL) {
        return NGX_ERROR;
    }

    lacf = ngx_http_get_module_loc_conf(r, ngx_http_limit_access_module);

    request_ctx->status = NGX_HTTP_OK;
    request_ctx->expire = lacf->default_expire;

    ngx_http_set_ctx(r, request_ctx, ngx_http_limit_access_module);

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "limit_access_interface_handler");

    rc = ngx_http_read_client_request_body(r, ngx_http_limit_access_process_handler);

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }

    return NGX_DONE;
}


static void
ngx_http_limit_access_process_handler(ngx_http_request_t *r)
{
    u_char       *p;
    size_t        len;
    ngx_buf_t    *buf, *next;
    ngx_int_t     rc;
    ngx_chain_t  *cl;
    ngx_chain_t   out;

    ngx_http_limit_access_request_ctx_t  *request_ctx;

    request_ctx = ngx_http_get_module_ctx(r, ngx_http_limit_access_module);

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "limit_access_process_handler");

    if (r->request_body == NULL
        || r->request_body->bufs == NULL
        || r->request_body->temp_file)
    {
        request_ctx->status = NGX_HTTP_NO_CONTENT;

        goto finish;
    }

    if (r->request_body->bufs) {
        cl = r->request_body->bufs;
        buf = cl->buf;

        if (cl->next == NULL) {
            len = buf->last - buf->pos;
            p = buf->pos;
        }
        else {
            next = cl->next->buf;
            len = (buf->last - buf->pos) + (next->last - next->pos);

            p = ngx_pnalloc(r->pool, len);
            if (p == NULL) {
                request_ctx->status = NGX_HTTP_INTERNAL_SERVER_ERROR;

                goto finish;
            }

            p = ngx_cpymem(p, buf->pos, buf->last - buf->pos);
            ngx_memcpy(p, next->pos, next->last - next->pos);
        }
    }
    else {
        len = r->request_body->temp_file->file.name.len;
        p = r->request_body->temp_file->file.name.data;
    }

    request_ctx->buf = ngx_create_temp_buf(r->pool, ngx_pagesize * 10);
    if (request_ctx->buf == NULL) {
        request_ctx->status = NGX_HTTP_INTERNAL_SERVER_ERROR;

        goto finish;
    }

    rc = ngx_http_limit_access_process_post(r, p, len);

    if (rc != NGX_OK) {
        request_ctx->status = NGX_HTTP_BAD_REQUEST;
    }

finish:

    r->headers_out.status = request_ctx->status;

    if (r->headers_out.status == NGX_HTTP_OK) {
        buf = request_ctx->buf;

        if (buf->last != buf->pos) {
            r->headers_out.content_length_n = buf->last - buf->pos;

            out.buf = buf;
            out.next = NULL;
            buf->last_buf = 1;

            rc = ngx_http_send_header(r);

            if (rc == NGX_OK) {
                rc = ngx_http_output_filter(r, &out);
            }
        }
        else {
            r->header_only = 1;
            rc = ngx_http_send_header(r);
        }
    }
    else {
        r->header_only = 1;
        rc = ngx_http_send_header(r);
    }

    ngx_http_finalize_request(r, rc);
}


static ngx_int_t 
ngx_http_limit_access_process_post(ngx_http_request_t *r, 
        u_char *data, size_t len)
{
    u_char    *p, *last;
    ngx_int_t  rc;
    ngx_str_t  param;

    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
            "limit_access_post body:\"%*s\"", len, data);

    p = data;
    last = data + len;
    do {
        param.data = p;
        param.len = 0;

        while (p != last) {
            if (*p == '&') {
                p++;
                break;
            }

            if (*p == CR || *p == LF) {
                p = last;
                break;
            }

            param.len++;
            p++;
        }

        if(param.len != 0) {
            rc = ngx_http_limit_access_process_param(r, &param);

            if(rc != NGX_OK) {
                return rc;
            }
        }
    } while (p != last);

    return NGX_OK;
}


static ngx_int_t 
ngx_http_limit_access_process_param(ngx_http_request_t *r, ngx_str_t *param)
{
    u_char                            *p, *src, *dst;

    ngx_str_t                          name;
    ngx_str_t                          value;
    ngx_uint_t                         i;
    ngx_http_limit_access_directive_t *cmd;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "limit_access: preparam=\"%V\"", param);

    p = (u_char *) ngx_strlchr(param->data, param->data + param->len, '=');

    if (p) {
        name.data = param->data;
        name.len = p - param->data;

        value.data = p + 1;
        value.len = param->len - name.len - 1;

        src = dst = value.data;

        ngx_unescape_uri(&dst, &src, value.len, NGX_UNESCAPE_URI);

        value.len = dst - value.data;
    }
    else {
        name.data = param->data;
        name.len = param->len;

        value.data = NULL;
        value.len = 0;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "limit_access: param: \"%V\"=\"%V\"", &name, &value);

    cmd = directives;
    for(i = 0; ;i++) {
        if (cmd[i].name.len == name.len 
                && (ngx_strncmp(cmd[i].name.data, name.data, name.len) == 0)) {

            if (cmd[i].handler) {
                return cmd[i].handler(r, &value);
            }
            else {
                return NGX_OK;
            }
        }

        if (cmd[i].name.len == 0) {
            break;
        }
    }

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "limit_access: invalid param: \"%V\"=\"%V\"", &name, &value);

    return NGX_ERROR;
}


static ngx_uint_t
ngx_atoui(u_char *line, size_t n)
{
    ngx_uint_t  value;

    if (n == 0) {
        return NGX_ERROR;
    }

    for (value = 0; n--; line++) {
        if (*line < '0' || *line > '9') {
            return NGX_ERROR;
        }

        value = value * 10 + (*line - '0');
    }

    return value;
}


static ngx_int_t 
limit_access_ban_expire(ngx_http_request_t *r, ngx_str_t *value)
{
    time_t                                expire;
    ngx_http_limit_access_request_ctx_t  *request_ctx;

    request_ctx = ngx_http_get_module_ctx(r, ngx_http_limit_access_module);

    expire = ngx_parse_time(value, 1);
    if (expire == (time_t) NGX_ERROR) {

        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "limit_access: invalid ban expire: \"%V\"", &value);

        return NGX_ERROR;
    }

    request_ctx->expire = expire;

    return NGX_OK;
}

static ngx_int_t 
limit_access_ban_list(ngx_http_request_t *r, ngx_str_t *value)
{
    u_char                                *start, *pos, *last;
    ngx_int_t                              rc, is_binary;
    in_addr_t                              ip;
    ngx_buf_t                             *b;
    ngx_http_limit_access_ctx_t           *ctx;
    ngx_http_limit_access_hash_t          *hash;
    ngx_http_limit_access_conf_t          *lacf;
    ngx_http_limit_access_request_ctx_t   *request_ctx;

    request_ctx = ngx_http_get_module_ctx(r, ngx_http_limit_access_module);

    lacf = ngx_http_get_module_loc_conf(r, ngx_http_limit_access_module);

    if (lacf->shm_zone == NULL) {
        return NGX_ERROR;
    }

    ctx = lacf->shm_zone->data;

    ngx_shmtx_lock(&ctx->shpool->mutex);

    hash = ctx->sh;

    if (!hash->valid) {
        goto fail;
    }

    is_binary = 0;

    last = value->data + value->len;
    for (start = pos = value->data; pos < last; pos++) {

        if (*pos == ',' || pos == last - 1) {

            if (pos == last - 1) {
                pos = last;
            }

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                    "limit_access: string_ban_ip=\"%*s\"", pos - start, start);

            if (!is_binary) {
                ip = ngx_inet_addr(start, pos - start);

                if (ip == INADDR_NONE) {
                    is_binary = 1;
                }
            }

            if (is_binary) {
                ip = (in_addr_t)ngx_atoui(start, pos - start);
                if (ip == (in_addr_t)NGX_ERROR) {
                    goto fail;
                }
            }

            if (ctx->type == HASH_IP) {
                rc = ngx_http_limit_access_ban_ip(r, ctx, ip);
                if (rc == NGX_ERROR) {
                    goto fail;
                }
            }

            pos++;
            start = pos;
        }
    }

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    b = request_ctx->buf;

    b->last = ngx_snprintf(b->last, b->end - b->last, "ban ip list succeed\n");

    return NGX_OK;

fail:

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "limit_access: invalid ban ip list: \"%V\"", &value);

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    return NGX_ERROR;
}


static ngx_http_limit_access_bucket_t *
ngx_alloc_limit_access_bucket(ngx_http_limit_access_ctx_t *ctx) 
{
    ngx_http_limit_access_hash_t          *hash;
    ngx_http_limit_access_bucket_t        *bucket;

    hash = ctx->sh;

    bucket = hash->free;
    
    if (bucket) {
        hash->free = bucket->next;
    }

    bucket = ngx_slab_alloc_locked(ctx->shpool,
            sizeof(ngx_http_limit_access_bucket_t));

    return bucket;
}


static ngx_int_t 
ngx_http_limit_access_ban_ip(ngx_http_request_t *r, 
        ngx_http_limit_access_ctx_t *ctx, in_addr_t ip)
{
    time_t                                expire;
    ngx_uint_t                            key;
    ngx_http_limit_access_hash_t         *hash;
    ngx_http_limit_access_bucket_t       *bucket, *new;
    ngx_http_limit_access_request_ctx_t  *request_ctx;

    request_ctx = ngx_http_get_module_ctx(r, ngx_http_limit_access_module);

    hash = ctx->sh;

    key = (ngx_uint_t) ip;

    bucket = &hash->buckets[key % ctx->bucket_number];

    expire = ngx_time() + request_ctx->expire;
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "limit_access: add ban_ip=%d, expire=%d", ip, expire);

    do {
        if (bucket->key == key) {
            bucket->expire = expire;
            return NGX_OK;
        }

        if (bucket->key == 0) {
            bucket->key = key;
            bucket->expire = expire;
            return NGX_OK;
        }

        ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "limit_access: free_list, bucket[%d]=%p, bucket->next=%p", 
                key, bucket, bucket->next);

        bucket = bucket->next;

    } while (bucket);

    new = ngx_alloc_limit_access_bucket(ctx);
    if (new == NULL) {
        ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0,
                "limit_access: not enough share memory");

        return NGX_ERROR;
    }

    bucket->next = new;
    new->key = key;
    new->expire = expire;
    new->next = NULL;

    return NGX_OK;
}


static ngx_int_t 
limit_access_free_list(ngx_http_request_t *r, ngx_str_t *value)
{
    u_char                                *start, *pos, *last;
    ngx_buf_t                             *b;
    ngx_int_t                              rc, is_binary;
    in_addr_t                             ip;
    ngx_http_limit_access_ctx_t           *ctx;
    ngx_http_limit_access_hash_t          *hash;
    ngx_http_limit_access_conf_t          *lacf;
    ngx_http_limit_access_request_ctx_t   *request_ctx;

    request_ctx = ngx_http_get_module_ctx(r, ngx_http_limit_access_module);

    lacf = ngx_http_get_module_loc_conf(r, ngx_http_limit_access_module);

    if (lacf->shm_zone == NULL) {
        return NGX_ERROR;
    }

    ctx = lacf->shm_zone->data;

    ngx_shmtx_lock(&ctx->shpool->mutex);

    hash = ctx->sh;

    if (!hash->valid) {
        goto fail;
    }

    is_binary = 0;

    last = value->data + value->len;
    for (start = pos = value->data; pos < last; pos++) {

        if (*pos == ',' || pos == last - 1) {

            if (pos == last - 1) {
                pos = last;
            }

            if (!is_binary) {
                ip = ngx_inet_addr(start, pos - start);

                if (ip == INADDR_NONE) {
                    is_binary = 1;
                }
            }

            if (is_binary) {
                ip = (in_addr_t)ngx_atoui(start, pos - start);
                if (ip == (in_addr_t)NGX_ERROR) {
                    goto fail;
                }
            }

            if (ctx->type == HASH_IP) {
                rc = ngx_http_limit_access_free_ip(r, ctx, ip);
                if (rc == NGX_ERROR) {
                    goto fail;
                }
            }

            pos++;
            start = pos;
        }
    }

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    b = request_ctx->buf;

    b->last = ngx_snprintf(b->last, b->end - b->last, "free ip list succeed\n");

    return NGX_OK;

fail:

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "limit_access: invalid free ip list: \"%V\"", &value);

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    return NGX_OK;
}


static ngx_int_t 
ngx_http_limit_access_free_ip(ngx_http_request_t *r, 
        ngx_http_limit_access_ctx_t *ctx, in_addr_t ip)
{
    ngx_uint_t                      key;
    ngx_http_limit_access_hash_t   *hash;
    ngx_http_limit_access_bucket_t *bucket, *header, *pre;

    hash = ctx->sh;

    key = (ngx_uint_t) ip;

    pre = header = bucket = &hash->buckets[key % ctx->bucket_number];

    do {
        if (bucket->key == key) {

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                    "limit_access: free, ip=%d", key);

            bucket->key = 0;
            bucket->expire = 0;

            if (bucket != header) {
                pre->next = bucket->next;
                ngx_free_limit_access_bucket(hash, bucket);
            }

            return NGX_OK;
        }

        ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "limit_access: free_list, bucket[%d]=%p, bucket->next=%p", 
                key, bucket, bucket->next);

        pre = bucket;
        bucket = bucket->next;

    } while (bucket);

    return NGX_OK;
}


static ngx_int_t
limit_access_show_list(ngx_http_request_t *r, ngx_str_t *value)
{
    ngx_buf_t                             *b;
    ngx_http_limit_access_ctx_t           *ctx;
    ngx_http_limit_access_hash_t          *hash;
    ngx_http_limit_access_conf_t          *lacf;
    ngx_http_limit_access_request_ctx_t   *request_ctx;

    request_ctx = ngx_http_get_module_ctx(r, ngx_http_limit_access_module);

    lacf = ngx_http_get_module_loc_conf(r, ngx_http_limit_access_module);

    if (lacf->shm_zone == NULL) {
        return NGX_ERROR;
    }

    ctx = lacf->shm_zone->data;

    hash = ctx->sh;

    b = request_ctx->buf;

    ngx_shmtx_lock(&ctx->shpool->mutex);

    if (!hash->valid) {

        b->last = ngx_snprintf(b->last, b->end - b->last, "Not invalid ban hash table!");
        ngx_shmtx_unlock(&ctx->shpool->mutex);

        return NGX_OK;
    }

    b->last = ngx_snprintf(b->last, b->end - b->last, "Ban hash table:\n");

    if (ctx->type == HASH_IP) {
        ngx_http_limit_access_show_ip(r, ctx, b); 
    }

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    return NGX_OK;
}


static ngx_int_t 
ngx_http_limit_access_show_ip(ngx_http_request_t *r, 
        ngx_http_limit_access_ctx_t *ctx, ngx_buf_t *b)
{
    u_char                          addr_buffer[16] = {0};
    u_char                          time_buffer[64] = {0};
    time_t                          now;
    ngx_uint_t                      i;
    ngx_http_limit_access_hash_t   *hash;
    ngx_http_limit_access_bucket_t *bucket;

    now = ngx_time();
    hash = ctx->sh;

    for (i = 0; i < ctx->bucket_number; i++) {
        bucket = &hash->buckets[i];

        do {
            if (bucket->key) {

                ngx_inet_ntop(AF_INET, (void *) &bucket->key, addr_buffer, sizeof(addr_buffer));

                if (bucket->expire > now) {
                    ngx_http_time(time_buffer, bucket->expire);

                    b->last = ngx_snprintf(b->last, b->end - b->last, 
                            "key[%d]: ip=%s(%d), expire=%s\n", 
                            i, addr_buffer, bucket->key, time_buffer);
                }
                else {
                    b->last = ngx_snprintf(b->last, b->end - b->last, 
                            "key[%d]: ip=%s(%d), expire=expired\n", 
                            i, addr_buffer, bucket->key);
                }

                ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                        "limit_access: show_ip: ip=%s(%d), expire=%s", 
                        addr_buffer, bucket->key, time_buffer);
            }

            bucket = bucket->next;

        } while (bucket);
    }

    return NGX_OK;
}


static ngx_int_t
limit_access_destory_list(ngx_http_request_t *r, ngx_str_t *value)
{
    ngx_buf_t                             *b;
    ngx_http_limit_access_ctx_t           *ctx;
    ngx_http_limit_access_hash_t          *hash;
    ngx_http_limit_access_conf_t          *lacf;
    ngx_http_limit_access_request_ctx_t   *request_ctx;

    request_ctx = ngx_http_get_module_ctx(r, ngx_http_limit_access_module);

    lacf = ngx_http_get_module_loc_conf(r, ngx_http_limit_access_module);

    if (lacf->shm_zone == NULL) {
        return NGX_ERROR;
    }

    ctx = lacf->shm_zone->data;

    hash = ctx->sh;

    b = request_ctx->buf;

    ngx_shmtx_lock(&ctx->shpool->mutex);

    if (!hash->valid) {

        b->last = ngx_snprintf(b->last, b->end - b->last, "Not invalid ban hash table!");
        ngx_shmtx_unlock(&ctx->shpool->mutex);

        return NGX_OK;
    }

    if (ctx->type == HASH_IP) {
        ngx_http_limit_access_destory_list(r, ctx); 
    }

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    b->last = ngx_snprintf(b->last, b->end - b->last, "Ban hash table destoryed.\n");

    return NGX_OK;
}


static ngx_int_t 
ngx_http_limit_access_destory_list(ngx_http_request_t *r, 
        ngx_http_limit_access_ctx_t *ctx)
{
    ngx_uint_t                      i;
    ngx_http_limit_access_hash_t   *hash;
    ngx_http_limit_access_bucket_t *bucket, *next;

    hash = ctx->sh;

    for (i = 0; i < ctx->bucket_number; i++) {
        bucket = &hash->buckets[i];

        bucket->key = 0;
        bucket->expire = 0;

        bucket = bucket->next;
        while (bucket) {

            bucket->key = 0;
            bucket->expire = 0;

            next = bucket->next;

            ngx_free_limit_access_bucket(hash, bucket);

            bucket = next;
        }
    }

    return NGX_OK;
}


static ngx_int_t
limit_access_expire_list(ngx_http_request_t *r, ngx_str_t *value)
{
    ngx_buf_t                             *b;
    ngx_http_limit_access_ctx_t           *ctx;
    ngx_http_limit_access_hash_t          *hash;
    ngx_http_limit_access_conf_t          *lacf;
    ngx_http_limit_access_request_ctx_t   *request_ctx;

    request_ctx = ngx_http_get_module_ctx(r, ngx_http_limit_access_module);

    lacf = ngx_http_get_module_loc_conf(r, ngx_http_limit_access_module);

    if (lacf->shm_zone == NULL) {
        return NGX_ERROR;
    }

    ctx = lacf->shm_zone->data;

    hash = ctx->sh;

    b = request_ctx->buf;

    ngx_shmtx_lock(&ctx->shpool->mutex);

    if (!hash->valid) {

        b->last = ngx_snprintf(b->last, b->end - b->last, "Not invalid ban hash table!");
        ngx_shmtx_unlock(&ctx->shpool->mutex);

        return NGX_OK;
    }

    if (ctx->type == HASH_IP) {
        ngx_http_limit_access_expire_list(r, ctx); 
    }

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    b->last = ngx_snprintf(b->last, b->end - b->last, "Ban hash table expired.\n");

    return NGX_OK;
}


static ngx_int_t 
ngx_http_limit_access_expire_list(ngx_http_request_t *r, 
        ngx_http_limit_access_ctx_t *ctx)
{
    time_t                          now;
    ngx_uint_t                      i;
    ngx_http_limit_access_hash_t   *hash;
    ngx_http_limit_access_bucket_t *bucket, *next;

    now = ngx_time();
    hash = ctx->sh;

    for (i = 0; i < ctx->bucket_number; i++) {
        bucket = &hash->buckets[i];

        if (bucket->expire < now) {
            bucket->key = 0;
            bucket->expire = 0;
        }

        bucket = bucket->next;

        while (bucket) {
            next = bucket->next;

            if (bucket->expire < now) {
                bucket->key = 0;
                bucket->expire = 0;

                ngx_free_limit_access_bucket(hash, bucket);
            }

            bucket = next;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_limit_access_handler(ngx_http_request_t *r)
{
    ngx_int_t                              rc;
    ngx_http_limit_access_ctx_t           *ctx;
    ngx_http_limit_access_conf_t          *lacf;
    ngx_http_limit_access_hash_t          *hash;

    lacf = ngx_http_get_module_loc_conf(r, ngx_http_limit_access_module);

    if (lacf->shm_zone == NULL || !lacf->limit_check) {
        return NGX_DECLINED;
    }

    ctx = lacf->shm_zone->data;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "limit_access_handler");

    ngx_shmtx_lock(&ctx->shpool->mutex);

    hash = ctx->sh;

    if (!hash->valid) {
        goto done;
    }

    rc = 0;

    if (ctx->type == HASH_IP) {
        rc = ngx_http_limit_access_lookup_ip(r, ctx);
    }

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    if (rc == 1) {

        ngx_log_error(lacf->limit_log_level, r->connection->log, 0,
                "access forbidden by limit_access");

        return NGX_HTTP_FORBIDDEN;
    }

done:

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    return NGX_DECLINED;
}


static ngx_int_t
ngx_http_limit_access_lookup_ip(ngx_http_request_t *r, ngx_http_limit_access_ctx_t *ctx)
{
    time_t                          now;
    ngx_uint_t                      key;
    struct sockaddr_in             *sin;
    ngx_http_limit_access_hash_t   *hash;
    ngx_http_limit_access_bucket_t *bucket;

    hash = ctx->sh;

    /* TODO: AF_INET6 */
    if (r->connection->sockaddr->sa_family != AF_INET) {
        return 0;
    }

    sin = (struct sockaddr_in *) r->connection->sockaddr;
    key = (ngx_uint_t) sin->sin_addr.s_addr;

    now = ngx_time();
    bucket = &hash->buckets[key % ctx->bucket_number];

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "limit_access: look_up_ip=%d, now=%T", key, now);

    do {
        if (bucket->key == key) {

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                    "limit_access: find ip, expire=%T", bucket->expire);

            if (bucket->expire > now) {
                return 1;
            }

            return 0;
        }

        bucket = bucket->next;

    } while (bucket);

    return 0;
}


static ngx_int_t
ngx_http_limit_access_status_handler(ngx_http_request_t *r)
{
    return NGX_DECLINED;
}


static ngx_int_t
ngx_http_limit_access_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_http_limit_access_ctx_t  *octx = data;

    size_t                        len;
    ngx_http_limit_access_ctx_t  *ctx;

    ctx = shm_zone->data;

    if (octx) {
        if (ctx->bucket_number != octx->bucket_number) {
            ngx_log_error(NGX_LOG_EMERG, shm_zone->shm.log, 0,
                          "limit_access \"%V\" uses the bucket_number=%d "
                          "while previously it used the bucket_number=%d ",
                          &shm_zone->shm.name, ctx->bucket_number, octx->bucket_number);
            return NGX_ERROR;
        }

        ctx->sh = octx->sh;
        ctx->shpool = octx->shpool;

        return NGX_OK;
    }

    ctx->shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    if (shm_zone->shm.exists) {
        ctx->sh = ctx->shpool->data;

        return NGX_OK;
    }

    ctx->sh = ngx_slab_alloc(ctx->shpool, sizeof(ngx_http_limit_access_hash_t));
    if (ctx->sh == NULL) {
        return NGX_ERROR;
    }

    ctx->shpool->data = ctx->sh;

    ctx->sh->buckets = ngx_slab_alloc(ctx->shpool, 
            ctx->bucket_number * sizeof(ngx_http_limit_access_bucket_t));
    if (ctx->sh->buckets == NULL) {
        return NGX_ERROR;
    }

    ngx_memzero(ctx->sh->buckets, 
            ctx->bucket_number * sizeof(ngx_http_limit_access_bucket_t));

    ctx->sh->valid = 1;


    len = sizeof(" in limit_access zone \"\"") + shm_zone->shm.name.len;

    ctx->shpool->log_ctx = ngx_slab_alloc(ctx->shpool, len);
    if (ctx->shpool->log_ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_sprintf(ctx->shpool->log_ctx, " in limit_access zone \"%V\"%Z",
                &shm_zone->shm.name);

    return NGX_OK;
}


static char *
ngx_http_limit_access_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    u_char                       *p;
    size_t                        size, len;
    ngx_str_t                    *value, name, s;
    ngx_int_t                     number;
    ngx_uint_t                    i;
    ngx_uint_t                    type;
    ngx_shm_zone_t               *shm_zone;
    ngx_http_limit_access_ctx_t  *ctx;

    value = cf->args->elts;

    number = NGX_HASH_LARGE_HSIZE;
    name.len = 0;
    size = 0;
    type = HASH_IP;

    for (i = 1; i < cf->args->nelts; i++) {
        if (ngx_strncmp(value[i].data, "zone=", 5) == 0) {

            name.data = value[i].data + 5;

            p = (u_char *) ngx_strchr(name.data, ':');

            if (p) {
                *p = '\0';

                name.len = p - name.data;

                p++;

                s.len = value[i].data + value[i].len - p;
                s.data = p;

                size = ngx_parse_size(&s);
                if (size > 8191) {
                    continue;
                }
            }

            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid zone size \"%V\"", &value[i]);
            return NGX_CONF_ERROR;
        }

        if (ngx_strncmp(value[i].data, "bucket_number=", 14) == 0) {

            len = value[i].len - 14;
            p = value[i].data + 14;

            number = ngx_atoi(p, len);
            if (number <= NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid number \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "type=", 5) == 0) {

            len = value[i].len - 5;
            p = value[i].data + 5;

            if (ngx_strncmp(p, "ip", len) == 0) {
                type = HASH_IP;
            }
            else if (ngx_strncmp(p, "url", len) == 0) {
                /*TODO*/
                type = HASH_URL;
            }
            else {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid type \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            continue;
        }


        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[i]);
        return NGX_CONF_ERROR;
    }

    shm_zone = ngx_shared_memory_add(cf, &name, size,
                                     &ngx_http_limit_access_module);
    if (shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    if (shm_zone->data) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                   "limit_access_zone \"%V\" is already used.",
                   &value[1]);
        return NGX_CONF_ERROR;
    }

    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_http_limit_access_ctx_t));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    ctx->type = type;
    ctx->bucket_number = number;

    shm_zone->init = ngx_http_limit_access_init_zone;
    shm_zone->data = ctx;

    return NGX_CONF_OK;
}


static char *
ngx_http_limit_access(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_limit_access_conf_t  *lacf = conf;

    time_t       expire;
    ngx_str_t   *value, name, s;
    ngx_uint_t   i;

    if (lacf->shm_zone) {
        return "is duplicate";
    }

    value = cf->args->elts;

    /* 1 day = 60 * 60 * 24 */
    expire = 60 * 60 * 24;
    name.len = 0;

    for (i = 1; i < cf->args->nelts; i++) {
        if (ngx_strncmp(value[i].data, "zone=", 5) == 0) {
            name.len = value[i].len - 5;
            name.data = value[i].data + 5;
        }

        if (ngx_strncmp(value[i].data, "expire=", 7) == 0) {
            s.len = value[i].len - 7;
            s.data = value[i].data + 7;

            expire = ngx_parse_time(&s, 1);
            if (expire == (time_t) NGX_ERROR) {
                return NGX_CONF_ERROR;
            }
        }
    }

    if (name.len == 0) {
        return "should set the zone's name.";
    }

    lacf->shm_zone = ngx_shared_memory_add(cf, &name, 0,
            &ngx_http_limit_access_module);
    if (lacf->shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    lacf->default_expire = expire;
    lacf->limit_check = 1;

    return NGX_CONF_OK;
}


static char *
ngx_http_limit_access_interface(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t   *value, s;

    ngx_http_core_loc_conf_t      *clcf;
    ngx_http_limit_access_conf_t  *lacf = conf;

    if (lacf->shm_zone) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (ngx_strncmp(value[1].data, "zone=", 5) == 0) {

        s.len = value[1].len - 5;
        s.data = value[1].data + 5;

        lacf->shm_zone = ngx_shared_memory_add(cf, &s, 0,
                &ngx_http_limit_access_module);
        if (lacf->shm_zone == NULL) {
            return NGX_CONF_ERROR;
        }
    }
    else {
        return "should set the zone's name.";
    }

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_limit_access_interface_handler;

    return NGX_CONF_OK;
}


static char *ngx_http_limit_access_status(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t   *value, s;

    ngx_http_core_loc_conf_t      *clcf;
    ngx_http_limit_access_conf_t  *lacf = conf;

    if (lacf->shm_zone) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (ngx_strncmp(value[1].data, "zone=", 5) == 0) {

        s.len = value[1].len - 5;
        s.data = value[1].data + 5;

        lacf->shm_zone = ngx_shared_memory_add(cf, &s, 0,
                &ngx_http_limit_access_module);
        if (lacf->shm_zone == NULL) {
            return NGX_CONF_ERROR;
        }
    }
    else {
        return "should set the zone's name.";
    }

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_limit_access_status_handler;

    return NGX_CONF_OK;
}


static void *
ngx_http_limit_access_create_conf(ngx_conf_t *cf)
{
    ngx_http_limit_access_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_limit_access_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->shm_zone = NULL;
     */

    conf->limit_log_level = NGX_CONF_UNSET_UINT;
    conf->default_expire = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_http_limit_access_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_limit_access_conf_t *prev = parent;
    ngx_http_limit_access_conf_t *conf = child;

    if (conf->shm_zone == NULL) {
        *conf = *prev;
    }

    ngx_conf_merge_uint_value(conf->limit_log_level, prev->limit_log_level,
                              NGX_LOG_ERR);
    ngx_conf_merge_sec_value(conf->default_expire, prev->default_expire, 
            60 * 60 * 24);

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_limit_access_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_limit_access_handler;

    return NGX_OK;
}
