
#include "ngx_http_limit_access_module.h"


static ngx_http_limit_access_bucket_t *ngx_alloc_limit_access_bucket(
        ngx_http_limit_access_ctx_t *ctx, size_t len);
static void ngx_free_limit_access_bucket(ngx_http_limit_access_ctx_t *ctx,
        ngx_http_limit_access_bucket_t *bucket);

static ngx_int_t ngx_http_limit_access_process_post(ngx_http_request_t *r, 
        u_char *data, size_t len);
static ngx_int_t ngx_http_limit_access_process_param(ngx_http_request_t *r, 
        ngx_str_t *param);

static ngx_int_t limit_access_type(ngx_http_request_t *r, ngx_str_t *value);
static ngx_int_t limit_access_ban_expire(ngx_http_request_t *r, ngx_str_t *value);
static ngx_int_t limit_access_ban_list(ngx_http_request_t *r, ngx_str_t *value);
static ngx_int_t limit_access_free_list(ngx_http_request_t *r, ngx_str_t *value);
static ngx_int_t limit_access_show_list(ngx_http_request_t *r, ngx_str_t *value);
static ngx_int_t limit_access_destroy_list(ngx_http_request_t *r, ngx_str_t *value);
static ngx_int_t limit_access_expire_list(ngx_http_request_t *r, ngx_str_t *value);

static ngx_int_t ngx_http_limit_access_ban_ip(ngx_http_request_t *r, 
        ngx_http_limit_access_ctx_t *ctx, in_addr_t ip);
static ngx_int_t ngx_http_limit_access_free_ip(ngx_http_request_t *r, 
        ngx_http_limit_access_ctx_t *ctx, in_addr_t ip);
static ngx_int_t ngx_http_limit_access_show_ip(ngx_http_request_t *r, 
        ngx_http_limit_access_ctx_t *ctx, ngx_buf_t *b, in_addr_t ip);

static ngx_int_t ngx_http_limit_access_ban_variable(ngx_http_request_t *r, 
        ngx_http_limit_access_ctx_t *ctx, ngx_str_t *variable);
static ngx_int_t ngx_http_limit_access_free_variable(ngx_http_request_t *r, 
        ngx_http_limit_access_ctx_t *ctx, ngx_str_t *variable);
static ngx_int_t ngx_http_limit_access_show_variable(ngx_http_request_t *r, 
        ngx_http_limit_access_ctx_t *ctx, ngx_buf_t *b, ngx_str_t *variable);

static ngx_int_t ngx_http_limit_access_destroy_list(ngx_http_request_t *r, 
        ngx_http_limit_access_ctx_t *ctx);
static ngx_int_t ngx_http_limit_access_expire_list(ngx_http_request_t *r, 
        ngx_http_limit_access_ctx_t *ctx);

static ngx_http_limit_access_directive_t directives[] = {
    { ngx_string("ban_type"),     limit_access_type },
    { ngx_string("ban_expire"),   limit_access_ban_expire },
    { ngx_string("ban_list"),     limit_access_ban_list },
    { ngx_string("free_type"),    limit_access_type },
    { ngx_string("free_list"),    limit_access_free_list },
    { ngx_string("show_type"),    limit_access_type },
    { ngx_string("show_list"),    limit_access_show_list },
    { ngx_string("destroy_list"), limit_access_destroy_list },
    { ngx_string("expire_list"),  limit_access_expire_list },
    { ngx_null_string, NULL }
};

static ngx_http_limit_access_type_name_t limit_types[] = {
    { ngx_string("ip"),       HASH_IP },
    { ngx_string("variable"), HASH_VARIABLE },
    { ngx_null_string,        0 }
};


void
ngx_http_limit_access_process_handler(ngx_http_request_t *r)
{
    u_char       *p, *data;
    ssize_t       size;
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
        || r->request_body->bufs == NULL)
    {
        request_ctx->status = NGX_HTTP_NO_CONTENT;
        goto finish;
    }

    request_ctx->buf = ngx_create_temp_buf(r->pool, ngx_pagesize * 10);
    if (request_ctx->buf == NULL) {
        request_ctx->status = NGX_HTTP_INTERNAL_SERVER_ERROR;

        goto finish;
    }

    data = NULL;
    len = 0;

    if(r->request_body->temp_file) {
        cl = r->request_body->bufs;

        while (cl) {
            buf = cl->buf;

            if (buf->in_file) {
                len += buf->file_last - buf->file_pos;
            }
            else {
                len += buf->last - buf->pos;
            }

            cl = cl->next;
        }

        data = p = ngx_pnalloc(r->pool, len);
        if (p == NULL) {
            request_ctx->status = NGX_HTTP_INTERNAL_SERVER_ERROR;
            goto finish;
        }

        cl = r->request_body->bufs;

        while (cl) {
            buf = cl->buf;
            if (buf->in_file) {
                size = ngx_read_file(buf->file, p,
                        buf->file_last - buf->file_pos, buf->file_pos);
                if (size == NGX_ERROR) {
                    request_ctx->status = NGX_HTTP_INTERNAL_SERVER_ERROR;
                    goto finish;
                }

                p += size;
            }
            else {
                p = ngx_cpymem(p, buf->pos, buf->last - buf->pos);
            }

            cl = cl->next;
        }
    }
    else {
        cl = r->request_body->bufs;
        buf = cl->buf;

        if (cl->next == NULL) {
            len = buf->last - buf->pos;
            data = p = buf->pos;
        }
        else {
            next = cl->next->buf;
            len = (buf->last - buf->pos) + (next->last - next->pos);

            data = p = ngx_pnalloc(r->pool, len);
            if (p == NULL) {
                request_ctx->status = NGX_HTTP_INTERNAL_SERVER_ERROR;
                goto finish;
            }

            p = ngx_cpymem(p, buf->pos, buf->last - buf->pos);
            ngx_memcpy(p, next->pos, next->last - next->pos);
        }
    }

    rc = ngx_http_limit_access_process_post(r, data, len);

    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "limit_access: invalid post body: \"%*s\"", len, data);

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

        while (p < last) {
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
    } while (p < last);

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


static ngx_int_t 
limit_access_type(ngx_http_request_t *r, ngx_str_t *value)
{
    ngx_uint_t                             i;
    ngx_http_limit_access_ctx_t           *ctx;
    ngx_http_limit_access_conf_t          *lacf;
    ngx_http_limit_access_type_name_t     *type;

    lacf = ngx_http_get_module_loc_conf(r, ngx_http_limit_access_module);

    if (lacf->shm_zone == NULL) {
        return NGX_ERROR;
    }

    ctx = lacf->shm_zone->data;

    type = limit_types;
    for(i = 0; ;i++) {
        if (type[i].name.len == value->len 
                && (ngx_strncmp(type[i].name.data, value->data, value->len) == 0)) {

            if (type[i].flag != ctx->type) {

                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                        "limit_access: type not match: %ud != %ud", 
                        type[i].flag, ctx->type);

                return NGX_ERROR;
            }

            return NGX_OK;
        }

        if (type[i].name.len == 0) {
            break;
        }
    }

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "limit_access: invalid type \"%V\"", value);

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
                "limit_access: invalid ban expire: \"%V\"", value);

        return NGX_ERROR;
    }

    request_ctx->expire = expire;

    return NGX_OK;
}


static ngx_int_t 
limit_access_ban_list(ngx_http_request_t *r, ngx_str_t *value)
{
    u_char                                *start, *pos, *last;
    ngx_str_t                              variable;
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

            if (ctx->type == HASH_IP) {
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

                rc = ngx_http_limit_access_ban_ip(r, ctx, ip);
                if (rc == NGX_ERROR) {
                    goto fail;
                }
            }
            else if (ctx->type == HASH_VARIABLE) {
                ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                        "limit_access: string_ban_variable=\"%*s\"", pos - start, start);

                variable.len = pos - start;
                variable.data = start;

                rc = ngx_http_limit_access_ban_variable(r, ctx, &variable);
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

    b->last = ngx_snprintf(b->last, b->end - b->last, "ban list succeed\n");

    return NGX_OK;

fail:

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "limit_access: invalid ban list: \"%V\"", value);

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    return NGX_ERROR;
}


static ngx_http_limit_access_bucket_t *
ngx_alloc_limit_access_bucket(ngx_http_limit_access_ctx_t *ctx, size_t len) 
{
    ngx_http_limit_access_hash_t          *hash;
    ngx_http_limit_access_bucket_t        *bucket;

    if (ctx->type == HASH_IP) {
        hash = ctx->sh;
        bucket = hash->free;

        if (bucket) {
            hash->free = bucket->next;
            return bucket;
        }
    }

    bucket = ngx_slab_alloc_locked(ctx->shpool, len);

    return bucket;
}


static void ngx_free_limit_access_bucket( ngx_http_limit_access_ctx_t *ctx,
        ngx_http_limit_access_bucket_t *bucket)
{
    ngx_http_limit_access_hash_t          *hash;

    if (ctx->type == HASH_IP) {
        hash = ctx->sh;

        bucket->next = hash->free;
        hash->free = bucket;
    }
    else {
        ngx_slab_free_locked(ctx->shpool, bucket);
    }
}


static ngx_int_t 
ngx_http_limit_access_ban_ip(ngx_http_request_t *r, 
        ngx_http_limit_access_ctx_t *ctx, in_addr_t ip)
{
    time_t                                expire;
    ngx_uint_t                            key;
    ngx_http_limit_access_hash_t         *hash;
    ngx_http_limit_access_bucket_t       *bucket, **p, *new;
    ngx_http_limit_access_request_ctx_t  *request_ctx;

    request_ctx = ngx_http_get_module_ctx(r, ngx_http_limit_access_module);

    hash = ctx->sh;

    key = (ngx_uint_t) ip;

    p = &hash->buckets[key % ctx->bucket_number];
    bucket = *p;

    expire = ngx_time() + request_ctx->expire;
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "limit_access: add ban_ip=%ud, expire=%T", ntohl(ip), expire);

    while (bucket) {
        if (bucket->key == key) {
            bucket->expire = expire;
            return NGX_OK;
        }

        if (bucket->key == 0) {
            bucket->key = key;
            bucket->expire = expire;
            return NGX_OK;
        }

        p = &bucket->next;
        bucket = bucket->next;
    }

    new = ngx_alloc_limit_access_bucket(ctx, 
            sizeof(ngx_http_limit_access_bucket_t));
    if (new == NULL) {
        ngx_http_limit_access_expire_list(r, ctx);

        new = ngx_alloc_limit_access_bucket(ctx, 
                sizeof(ngx_http_limit_access_bucket_t));

        if (new == NULL) {
            ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0,
                    "limit_access: not enough shared memory");

            return NGX_ERROR;
        }
    }

    *p = new;
    new->key = key;
    new->expire = expire;
    new->len = 0;
    new->next = NULL;

    return NGX_OK;
}


static ngx_int_t 
limit_access_free_list(ngx_http_request_t *r, ngx_str_t *value)
{
    u_char                                *start, *pos, *last;
    ngx_buf_t                             *b;
    ngx_str_t                              variable;
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

            if (ctx->type == HASH_IP) {
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

                rc = ngx_http_limit_access_free_ip(r, ctx, ip);
                if (rc == NGX_ERROR) {
                    goto fail;
                }
            }
            else if (ctx->type == HASH_VARIABLE) {
                variable.len = pos - start;
                variable.data = start;

                rc = ngx_http_limit_access_free_variable(r, ctx, &variable);
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
    b->last = ngx_snprintf(b->last, b->end - b->last, "free list succeed\n");

    return NGX_OK;

fail:

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "limit_access: invalid free list: \"%V\"", value);

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    return NGX_ERROR;
}


static ngx_int_t 
ngx_http_limit_access_free_ip(ngx_http_request_t *r, 
        ngx_http_limit_access_ctx_t *ctx, in_addr_t ip)
{
    ngx_uint_t                      key;
    ngx_http_limit_access_hash_t   *hash;
    ngx_http_limit_access_bucket_t *bucket, **h, *pre;

    hash = ctx->sh;

    key = (ngx_uint_t) ip;

    h = &hash->buckets[key % ctx->bucket_number];
    pre = bucket = *h;

    while (bucket) {
        if (bucket->key == key) {

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                    "limit_access: free, ip=%ud", ntohl(key));

            bucket->key = 0;
            bucket->expire = 0;

            if (*h == bucket) {
                *h = NULL;
            }

            if (pre != bucket) {
                pre->next = bucket->next;
            }

            ngx_free_limit_access_bucket(ctx, bucket);

            return NGX_OK;
        }

        pre = bucket;
        bucket = bucket->next;
    }

    return NGX_OK;
}


static ngx_int_t
limit_access_show_list(ngx_http_request_t *r, ngx_str_t *value)
{
    u_char                                *start, *pos, *last;
    ngx_str_t                              variable;
    ngx_buf_t                             *b;
    ngx_int_t                              rc, is_binary;
    in_addr_t                              ip;
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
        b->last = ngx_snprintf(b->last, b->end - b->last, "Invalid ban hash table!");

        ngx_shmtx_unlock(&ctx->shpool->mutex);
        return NGX_OK;
    }

    b->last = ngx_snprintf(b->last, b->end - b->last, "Ban hash table:\n");

    is_binary = 0;
    rc = NGX_OK;

    if (value->len == 0) {
        if (ctx->type == HASH_IP) {
            rc = ngx_http_limit_access_show_ip(r, ctx, b, INADDR_NONE); 
        }
        else if (ctx->type == HASH_VARIABLE) {
            rc = ngx_http_limit_access_show_variable(r, ctx, b, NULL); 
        }

        if (rc == NGX_ERROR) {
            goto fail;
        }

        ngx_shmtx_unlock(&ctx->shpool->mutex);
        return NGX_OK;
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

                if (ctx->type == HASH_IP) {
                    rc = ngx_http_limit_access_show_ip(r, ctx, b, INADDR_NONE); 
                }
                else if (ctx->type == HASH_VARIABLE) {
                    rc = ngx_http_limit_access_show_variable(r, ctx, b, NULL); 
                }

                if (rc == NGX_ERROR) {
                    goto fail;
                }

                break;
            }

            if (ctx->type == HASH_IP) {
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

                rc = ngx_http_limit_access_show_ip(r, ctx, b, ip); 
            }
            else if (ctx->type == HASH_VARIABLE) {
                variable.len = pos - start;
                variable.data = start;
                rc = ngx_http_limit_access_show_variable(r, ctx, b, &variable); 
            }

            if (rc == NGX_ERROR) {
                goto fail;
            }

            pos++;
            start = pos;
        }
    }

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    return NGX_OK;

fail:

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "limit_access: invalid show list: \"%V\"", value);

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    return NGX_ERROR;
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

        bucket = hash->buckets[ip % ctx->bucket_number];
        ngx_inet_ntop(AF_INET, (void *) &ip, addr_buffer, sizeof(addr_buffer));

        while (bucket) {
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
        }

        b->last = ngx_snprintf(b->last, b->end - b->last, 
                "ip=%s(%ud), there is no this record.\n", 
                addr_buffer, ntohl(ip));

        return NGX_OK;
    }

    /* show all the list */
    total = 0;
    for (i = 0; i < ctx->bucket_number; i++) {
        bucket = hash->buckets[i];
        
        while (bucket) {
            if (bucket->key) {

                total++;
                ngx_memzero(addr_buffer, sizeof(addr_buffer));
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
        }
    }

    b->last = ngx_snprintf(b->last, b->end - b->last, 
            "total record = %ud\n", total);

    return NGX_OK;
}


static ngx_int_t 
ngx_http_limit_access_ban_variable(ngx_http_request_t *r, 
        ngx_http_limit_access_ctx_t *ctx, ngx_str_t *variable)
{
    time_t                                expire;
    ngx_uint_t                            key, len;
    ngx_http_limit_access_hash_t         *hash;
    ngx_http_limit_access_bucket_t       *bucket, **p, *new;
    ngx_http_limit_access_request_ctx_t  *request_ctx;

    request_ctx = ngx_http_get_module_ctx(r, ngx_http_limit_access_module);

    hash = ctx->sh;

    key = ngx_hash_key(variable->data, variable->len);

    p = &hash->buckets[key % ctx->bucket_number];
    bucket = *p;

    expire = ngx_time() + request_ctx->expire;

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "limit_access: add ban_variable=\"%V\", key=%d, expire=%d", variable, key, expire);

    while (bucket) {
        if (bucket->key == key && 
                bucket->len == variable->len && 
                ngx_strncmp(bucket->value, variable->data, variable->len) == 0) {

            bucket->expire = expire;
            return NGX_OK;
        }

        ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "limit_access: free_list, bucket[%d]=%p, bucket->next=%p", 
                key, bucket, bucket->next);

        p = &bucket->next;
        bucket = *p;
    }

    len = variable->len + sizeof(ngx_http_limit_access_bucket_t);
    new = ngx_alloc_limit_access_bucket(ctx, len);
    if (new == NULL) {
        ngx_http_limit_access_expire_list(r, ctx);

        new = ngx_alloc_limit_access_bucket(ctx, len);
        if (new == NULL) {
            ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0,
                    "limit_access: not enough shared memory");

            return NGX_ERROR;
        }
    }

    *p = new;
    new->key = key;
    new->expire = expire;
    new->len = variable->len;
    ngx_memcpy(new->value, variable->data, variable->len);
    new->next = NULL;

    return NGX_OK;
}


static ngx_int_t 
ngx_http_limit_access_free_variable(ngx_http_request_t *r, 
        ngx_http_limit_access_ctx_t *ctx, ngx_str_t *variable)
{
    ngx_uint_t                      key;
    ngx_http_limit_access_hash_t   *hash;
    ngx_http_limit_access_bucket_t *bucket, **h, *pre;

    hash = ctx->sh;

    key = ngx_hash_key(variable->data, variable->len);

    h = &hash->buckets[key % ctx->bucket_number];
    pre = bucket = *h;

    while (bucket) {
        if (bucket->key == key && 
                bucket->len == variable->len && 
                ngx_strncmp(bucket->value, variable->data, variable->len) == 0) {

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                    "limit_access: free, variable=\"%V\"", variable);

            bucket->key = 0;
            bucket->expire = 0;
            bucket->len = 0;

            if (*h == bucket) {
                *h = NULL;
            }

            if (pre != bucket) {
                pre->next = bucket->next;
            }

            ngx_free_limit_access_bucket(ctx, bucket);

            return NGX_OK;
        }

        pre = bucket;
        bucket = bucket->next;
    }

    return NGX_OK;
}


static ngx_int_t 
ngx_http_limit_access_show_variable(ngx_http_request_t *r, 
        ngx_http_limit_access_ctx_t *ctx, ngx_buf_t *b, ngx_str_t *variable)
{
    u_char                          time_buffer[64] = {0};
    time_t                          now;
    ngx_uint_t                      key;
    ngx_uint_t                      i, total;
    ngx_http_limit_access_hash_t   *hash;
    ngx_http_limit_access_bucket_t *bucket;

    now = ngx_time();
    hash = ctx->sh;

    /* show the sepcific variable */
    if (variable != NULL) {

        key = ngx_hash_key(variable->data, variable->len);
        bucket = hash->buckets[key % ctx->bucket_number];

        while (bucket) {
            if (bucket->key == key && 
                    bucket->len == variable->len && 
                    ngx_strncmp(bucket->value, variable->data, variable->len) == 0) {

                if (bucket->expire > now) {
                    ngx_http_time(time_buffer, bucket->expire);

                    b->last = ngx_snprintf(b->last, b->end - b->last, 
                            "variable=\"%V\", expire=%s\n", 
                            variable, time_buffer);
                }
                else {
                    b->last = ngx_snprintf(b->last, b->end - b->last, 
                            "variable=\"%V\", expire=expired\n", variable);
                }

                ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                        "limit_access: show_variable=\"%V\", expire=%s",
                        variable, time_buffer);

                return NGX_OK;
            }

            bucket = bucket->next;
        }

        b->last = ngx_snprintf(b->last, b->end - b->last, 
                "variable=\"%V\", there is no this record.\n", variable);

        return NGX_OK;
    }

    /* show all the list */

    total = 0;
    for (i = 0; i < ctx->bucket_number; i++) {
        bucket = hash->buckets[i];
        
        while (bucket) {
            if (bucket->key) {

                total++;

                if (bucket->expire > now) {
                    ngx_http_time(time_buffer, bucket->expire);

                    b->last = ngx_snprintf(b->last, b->end - b->last, 
                            "key[%ud]: variable=\"%*s\", expire=%s\n", 
                            i, bucket->len, bucket->value, time_buffer);
                }
                else {
                    b->last = ngx_snprintf(b->last, b->end - b->last, 
                            "key[%ud]: variable=\"%*s\", expire=expired\n", 
                            i, bucket->len, bucket->value);
                }

                ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                        "limit_access: key[%ud]: variable=\"%*s\", expire=%s\n", 
                        i, bucket->len, bucket->value, time_buffer);
            }

            bucket = bucket->next;
        }
    }

    b->last = ngx_snprintf(b->last, b->end - b->last, 
            "total record = %ud\n", total);

    return NGX_OK;
}


static ngx_int_t
limit_access_destroy_list(ngx_http_request_t *r, ngx_str_t *value)
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

        b->last = ngx_snprintf(b->last, b->end - b->last, "Invalid ban hash table!");
        ngx_shmtx_unlock(&ctx->shpool->mutex);

        return NGX_OK;
    }

    ngx_http_limit_access_destroy_list(r, ctx); 

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    b->last = ngx_snprintf(b->last, b->end - b->last, "Ban hash table destroyed.\n");

    return NGX_OK;
}


static ngx_int_t 
ngx_http_limit_access_destroy_list(ngx_http_request_t *r, 
        ngx_http_limit_access_ctx_t *ctx)
{
    ngx_uint_t                      i;
    ngx_http_limit_access_hash_t   *hash;
    ngx_http_limit_access_bucket_t *bucket, **h, *next;

    hash = ctx->sh;

    for (i = 0; i < ctx->bucket_number; i++) {
        h = &hash->buckets[i];
        bucket = *h;
        *h = NULL;

        while (bucket) {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                    "limit_access: bucket=%p", bucket);

            bucket->key = 0;
            bucket->expire = 0;
            bucket->len = 0;
            
            next = bucket->next;

            ngx_free_limit_access_bucket(ctx, bucket);

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

    ngx_http_limit_access_expire_list(r, ctx); 

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
    ngx_http_limit_access_bucket_t *bucket, **h, *next;

    now = ngx_time();
    hash = ctx->sh;

    for (i = 0; i < ctx->bucket_number; i++) {
        h = &hash->buckets[i];
        bucket = *h;

        while (bucket) {
            next = bucket->next;

            if (bucket->expire < now) {

                if (*h == bucket) {
                    *h = NULL;
                }

                bucket->key = 0;
                bucket->expire = 0;
                bucket->len = 0;

                ngx_free_limit_access_bucket(ctx, bucket);
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
    bucket = hash->buckets[key % ctx->bucket_number];

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "limit_access: look_up_ip=%ud, now=%T", ntohl(key), now);

    while (bucket) {
        if (bucket->key == key) {

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                    "limit_access: find ip, expire=%T", bucket->expire);

            if (bucket->expire > now) {
                return 1;
            }

            return 0;
        }

        bucket = bucket->next;
    }

    return 0;
}


ngx_int_t 
ngx_http_limit_access_lookup_variable(ngx_http_request_t *r, 
        ngx_http_limit_access_ctx_t *ctx)
{
    time_t                          now;
    ngx_str_t                       variable;
    ngx_uint_t                      key;
    ngx_http_variable_value_t      *vv;
    ngx_http_limit_access_hash_t   *hash;
    ngx_http_limit_access_bucket_t *bucket;

    hash = ctx->sh;

    vv = ngx_http_get_indexed_variable(r, ctx->index);

    if (vv == NULL || vv->not_found) {
        return 0;
    }

    if (vv->len == 0) {
        return 0;
    }

    if (vv->len > 65535) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "the value of the \"%V\" variable "
                      "is more than 65535 bytes: \"%v\"",
                      &ctx->var, vv);
        return 0;
    }

    variable.len = vv->len;
    variable.data = vv->data;

    key = ngx_hash_key(variable.data, variable.len);

    now = ngx_time();
    bucket = hash->buckets[key % ctx->bucket_number];

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "limit_access: look_up_variable=\"%V\", key=%d, now=%T", &variable, key, now);

    while (bucket) {
        if (bucket->key == key && bucket->len == variable.len) {

            if (ngx_strncmp(bucket->value, variable.data, variable.len) == 0) {

                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                        "limit_access: find variable, expire=%T", bucket->expire);

                if (bucket->expire > now) {
                    return 1;
                }

                return 0;
            }
        }

        bucket = bucket->next;
    }

    return 0;
}


