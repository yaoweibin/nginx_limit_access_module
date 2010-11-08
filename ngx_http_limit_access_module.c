
#include "ngx_http_limit_access_module.h"

static ngx_int_t ngx_http_limit_access_interface_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_limit_access_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_limit_access_status_handler(ngx_http_request_t *r);

static void *ngx_http_limit_access_create_conf(ngx_conf_t *cf);
static char *ngx_http_limit_access_merge_conf(ngx_conf_t *cf, void *parent,
    void *child);
static char *ngx_http_limit_access_zone(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_limit_access(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char * ngx_http_limit_access_interface(ngx_conf_t *cf, 
        ngx_command_t *cmd, void *conf);
static char *ngx_http_limit_access_status(ngx_conf_t *cf, ngx_command_t *cmd, 
        void *conf);
static char *ngx_http_limit_access_variable(ngx_conf_t *cf, ngx_command_t *cmd, 
        void *conf);
static ngx_int_t ngx_http_limit_access_deny_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);

static ngx_int_t ngx_http_limit_access_init(ngx_conf_t *cf);

static ngx_conf_enum_t  ngx_http_limit_access_log_levels[] = {
    { ngx_string("info"),   NGX_LOG_INFO },
    { ngx_string("notice"), NGX_LOG_NOTICE },
    { ngx_string("warn"),   NGX_LOG_WARN },
    { ngx_string("error"),  NGX_LOG_ERR },
    { ngx_null_string, 0 }
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

    { ngx_string("limit_access_interface"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_limit_access_interface,
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

    { ngx_string("limit_access_variable"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
      ngx_http_limit_access_variable,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_limit_access_module_ctx = {
    NULL,                                     /* preconfiguration */
    ngx_http_limit_access_init,               /* postconfiguration */

    NULL,                                     /* create main configuration */
    NULL,                                     /* init main configuration */

    NULL,                                     /* create server configuration */
    NULL,                                     /* merge server configuration */

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


static ngx_int_t 
ngx_http_limit_access_deny_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_int_t                              rc;
    ngx_http_limit_access_ctx_t           *ctx;
    ngx_http_limit_access_conf_t          *lacf;
    ngx_http_limit_access_hash_t          *hash;

    lacf = ngx_http_get_module_loc_conf(r, ngx_http_limit_access_module);

    if (lacf->shm_zone == NULL) {
        goto not_found;
    }

    ctx = lacf->shm_zone->data;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "limit_access_deny_variable");

    ngx_shmtx_lock(&ctx->shpool->mutex);

    hash = ctx->sh;

    if (!hash->valid) {
        ngx_shmtx_unlock(&ctx->shpool->mutex);
        goto not_found;
    }

    rc = 0;

    if (ctx->type == HASH_IP) {
        rc = ngx_http_limit_access_lookup_ip(r, ctx);
    }

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    if (rc == 1) {
        *v = ngx_http_variable_true_value;
        return NGX_OK;
    }

not_found:

    *v = ngx_http_variable_null_value;
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
        ngx_shmtx_unlock(&ctx->shpool->mutex);
        return NGX_DECLINED;
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

    return NGX_DECLINED;
}


static ngx_int_t
ngx_http_limit_access_status_handler(ngx_http_request_t *r)
{
    return NGX_DECLINED;
}


static ngx_int_t
ngx_http_limit_access_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    size_t                        len;
    ngx_http_limit_access_ctx_t  *ctx;
    ngx_http_limit_access_ctx_t  *octx = data;

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
    ngx_str_t                     *value, s;
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


static char *
ngx_http_limit_access_status(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t                     *value, s;
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


static char *
ngx_http_limit_access_variable(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t                     *value, name;
    ngx_uint_t                     i;
    ngx_http_variable_t           *v;
    ngx_http_limit_access_conf_t  *lacf = conf;

    if (lacf->shm_zone) {
        return "is duplicate";
    }

    value = cf->args->elts;
    for (i = 1; i < cf->args->nelts; i++) {
        if (ngx_strncmp(value[i].data, "zone=", 5) == 0) {
            name.len = value[i].len - 5;
            name.data = value[i].data + 5;
        }

        if (value[i].data[0] == '$') {
            value[i].len--;
            value[i].data++;

            v = ngx_http_add_variable(cf, &value[i], NGX_HTTP_VAR_CHANGEABLE);
            if (v == NULL) {
                return NGX_CONF_ERROR;
            }

            v->get_handler = ngx_http_limit_access_deny_variable;
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
