
#include "ngx_http_limit_access_module.h"


static ngx_int_t ngx_http_limit_access_process_post(ngx_http_request_t *r, 
        u_char *data, size_t len);
static ngx_int_t ngx_http_limit_access_process_param(ngx_http_request_t *r, 
        ngx_str_t *param);

static ngx_int_t limit_access_ban_expire(ngx_http_request_t *r, ngx_str_t *value);
static ngx_int_t limit_access_ban_list(ngx_http_request_t *r, ngx_str_t *value);
static ngx_int_t limit_access_free_list(ngx_http_request_t *r, ngx_str_t *value);
static ngx_int_t limit_access_show_list(ngx_http_request_t *r, ngx_str_t *value);
static ngx_int_t limit_access_destory_list(ngx_http_request_t *r, ngx_str_t *value);
static ngx_int_t limit_access_expire_list(ngx_http_request_t *r, ngx_str_t *value);

ngx_int_t ngx_http_limit_access_lookup_ip(ngx_http_request_t *r, 
        ngx_http_limit_access_ctx_t *ctx);
static ngx_int_t ngx_http_limit_access_ban_ip(ngx_http_request_t *r, 
        ngx_http_limit_access_ctx_t *ctx, in_addr_t ip);
static ngx_int_t ngx_http_limit_access_free_ip(ngx_http_request_t *r, 
        ngx_http_limit_access_ctx_t *ctx, in_addr_t ip);
static ngx_int_t ngx_http_limit_access_show_ip(ngx_http_request_t *r, 
        ngx_http_limit_access_ctx_t *ctx, ngx_buf_t *b, in_addr_t ip);
static ngx_int_t ngx_http_limit_access_destory_list(ngx_http_request_t *r, 
        ngx_http_limit_access_ctx_t *ctx);
static ngx_int_t ngx_http_limit_access_expire_list(ngx_http_request_t *r, 
        ngx_http_limit_access_ctx_t *ctx);

static ngx_http_limit_access_directive_t directives[] = {
    { ngx_string("ban_type"),     NULL },
    { ngx_string("ban_expire"),   limit_access_ban_expire },
    { ngx_string("ban_list"),     limit_access_ban_list },
    { ngx_string("free_type"),    NULL },
    { ngx_string("free_list"),    limit_access_free_list },
    { ngx_string("show_type"),    NULL },
    { ngx_string("show_list"),    limit_access_show_list },
    { ngx_string("destory_list"), limit_access_destory_list },
    { ngx_string("expire_list"),  limit_access_expire_list },
    { ngx_null_string, NULL }
};


void
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
                ip = (in_addr_t) ngx_atoui(start, pos - start);
                if (ip == (in_addr_t) NGX_ERROR) {
                    goto fail;
                }
                ip = (in_addr_t) htonl(ip);
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


ngx_http_limit_access_bucket_t *
ngx_alloc_limit_access_bucket(ngx_http_limit_access_ctx_t *ctx) 
{
    ngx_http_limit_access_hash_t          *hash;
    ngx_http_limit_access_bucket_t        *bucket;

    hash = ctx->sh;

    bucket = hash->free;
    
    if (bucket) {
        hash->free = bucket->next;
        return bucket;
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
            "limit_access: add ban_ip=%ud, expire=%T", ntohl(ip), expire);

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
                ip = (in_addr_t) ngx_atoui(start, pos - start);
                if (ip == (in_addr_t) NGX_ERROR) {
                    goto fail;
                }
                ip = (in_addr_t) htonl(ip);
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
                    "limit_access: free, ip=%ud", ntohl(key));

            bucket->key = 0;
            bucket->expire = 0;

            if (bucket != header) {
                pre->next = bucket->next;
                ngx_free_limit_access_bucket(hash, bucket);
            }

            return NGX_OK;
        }

        pre = bucket;
        bucket = bucket->next;

    } while (bucket);

    return NGX_OK;
}


static ngx_int_t
limit_access_show_list(ngx_http_request_t *r, ngx_str_t *value)
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

    hash = ctx->sh;

    b = request_ctx->buf;

    ngx_shmtx_lock(&ctx->shpool->mutex);

    if (!hash->valid) {
        b->last = ngx_snprintf(b->last, b->end - b->last, "Not invalid ban hash table!");

        ngx_shmtx_unlock(&ctx->shpool->mutex);
        return NGX_OK;
    }

    b->last = ngx_snprintf(b->last, b->end - b->last, "Ban hash table:\n");

    is_binary = 0;

    if (value->len == 0) {
        rc = ngx_http_limit_access_show_ip(r, ctx, b, INADDR_NONE); 

        if (rc == NGX_ERROR) {
            goto fail;
        }
        else {
            ngx_shmtx_unlock(&ctx->shpool->mutex);
            return NGX_OK;
        }
    }

    last = value->data + value->len;
    for (start = pos = value->data; pos < last; pos++) {

        if (*pos == ',' || pos == last - 1) {

            if (pos == last - 1) {
                pos = last;
            }

            /* compare with string:"all" */
            if ((pos- start == sizeof("all") - 1) && 
                    ngx_strncmp(start, "all", sizeof("all") - 1) == 0) {

                rc = ngx_http_limit_access_show_ip(r, ctx, b, INADDR_NONE); 
                if (rc == NGX_ERROR) {
                    goto fail;
                }

                break;
            }

            if (!is_binary) {
                ip = ngx_inet_addr(start, pos - start);

                if (ip == INADDR_NONE) {
                    is_binary = 1;
                }
            }

            if (is_binary) {
                ip = (in_addr_t) ngx_atoui(start, pos - start);
                if (ip == (in_addr_t) NGX_ERROR) {
                    goto fail;
                }
                ip = (in_addr_t) htonl(ip);
            }

            if (ctx->type == HASH_IP) {
                rc = ngx_http_limit_access_show_ip(r, ctx, b, ip); 
                if (rc == NGX_ERROR) {
                    goto fail;
                }
            }

            pos++;
            start = pos;
        }
    }

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    return NGX_OK;

fail:

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "limit_access: invalid show list: \"%V\"", &value);

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    return NGX_OK;
}


static ngx_int_t 
ngx_http_limit_access_show_ip(ngx_http_request_t *r, 
        ngx_http_limit_access_ctx_t *ctx, ngx_buf_t *b, in_addr_t ip)
{
    u_char                          addr_buffer[16] = {0};
    u_char                          time_buffer[64] = {0};
    time_t                          now;
    ngx_uint_t                      i, total;
    ngx_http_limit_access_hash_t   *hash;
    ngx_http_limit_access_bucket_t *bucket;

    now = ngx_time();
    hash = ctx->sh;

    /* show the sepcific ip */
    if (ip != INADDR_NONE) {

        bucket = &hash->buckets[ip % ctx->bucket_number];
        ngx_inet_ntop(AF_INET, (void *) &ip, addr_buffer, sizeof(addr_buffer));

        do {
            if (bucket->key == ip) {

                if (bucket->expire > now) {
                    ngx_http_time(time_buffer, bucket->expire);

                    b->last = ngx_snprintf(b->last, b->end - b->last, 
                            "ip=%s(%ud), expire=%s\n", 
                            addr_buffer, ntohl(bucket->key), time_buffer);
                }
                else {
                    b->last = ngx_snprintf(b->last, b->end - b->last, 
                            "ip=%s(%ud), expire=expired\n", 
                            addr_buffer, ntohl(bucket->key));
                }

                ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                        "limit_access: show_ip: ip=%s(%ud), expire=%s", 
                        addr_buffer, ntohl(bucket->key), time_buffer);

                return NGX_OK;
            }

            bucket = bucket->next;

        } while (bucket);

        b->last = ngx_snprintf(b->last, b->end - b->last, 
                "ip=%s(%ud), there is no this record.\n", 
                addr_buffer, ntohl(ip));

        return NGX_OK;
    }

    /* show all the list */

    total = 0;
    for (i = 0; i < ctx->bucket_number; i++) {
        bucket = &hash->buckets[i];

        do {
            if (bucket->key) {

                total++;
                ngx_inet_ntop(AF_INET, (void *) &bucket->key, addr_buffer, sizeof(addr_buffer));

                if (bucket->expire > now) {
                    ngx_http_time(time_buffer, bucket->expire);

                    b->last = ngx_snprintf(b->last, b->end - b->last, 
                            "key[%ud]: ip=%s(%ud), expire=%s\n", 
                            i, addr_buffer, ntohl(bucket->key), time_buffer);
                }
                else {
                    b->last = ngx_snprintf(b->last, b->end - b->last, 
                            "key[%ud]: ip=%s(%ud), expire=expired\n", 
                            i, addr_buffer, ntohl(bucket->key));
                }

                ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                        "limit_access: show_ip: ip=%s(%ud), expire=%s", 
                        addr_buffer, ntohl(bucket->key), time_buffer);
            }

            bucket = bucket->next;

        } while (bucket);
    }

    b->last = ngx_snprintf(b->last, b->end - b->last, 
            "total record = %ud\n", total);

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


ngx_int_t
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
            "limit_access: look_up_ip=%ud, now=%T", ntohl(key), now);

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

