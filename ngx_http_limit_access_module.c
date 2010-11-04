
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#define HASH_IP  0x01
#define HASH_URL 0x02

typedef struct {
    unsigned set;
} ngx_http_limit_access_request_ctx_t;

typedef struct ngx_http_limit_access_bucket_s {
    struct ngx_http_limit_access_bucket_s *next;

    ngx_uint_t key;
    time_t     expire;
    u_short    len;
    u_char     value[1];
} ngx_http_limit_access_bucket_t;

typedef struct {
    ngx_atomic_t lock;
    ngx_uint_t   valid;
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
    ngx_uint_t                   limit_log_level;
    unsigned                     limit_check;
} ngx_http_limit_access_conf_t;


static ngx_int_t ngx_http_limit_access_interface_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_limit_access_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_limit_access_lookup_ip(ngx_http_request_t *r, 
        ngx_http_limit_access_ctx_t *ctx);
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


static ngx_conf_enum_t  ngx_http_limit_access_log_levels[] = {
    { ngx_string("info"), NGX_LOG_INFO },
    { ngx_string("notice"), NGX_LOG_NOTICE },
    { ngx_string("warn"), NGX_LOG_WARN },
    { ngx_string("error"), NGX_LOG_ERR },
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
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
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
    return NGX_DECLINED;
}


static ngx_int_t
ngx_http_limit_access_handler(ngx_http_request_t *r)
{
    ngx_int_t                              rc;
    ngx_http_limit_access_hash_t          *hash;
    ngx_http_limit_access_ctx_t           *ctx;
    ngx_http_limit_access_conf_t          *lacf;
    ngx_http_limit_access_request_ctx_t   *request_ctx;

    lacf = ngx_http_get_module_loc_conf(r, ngx_http_limit_access_module);

    if (lacf->shm_zone == NULL || !lacf->limit_check) {
        return NGX_DECLINED;
    }

    request_ctx = ngx_http_get_module_ctx(r, ngx_http_limit_access_module);
    if (request_ctx == NULL) {
        request_ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_limit_access_request_ctx_t));
        if (request_ctx == NULL) {
            return NGX_ERROR;
        }

        ngx_http_set_ctx(r, request_ctx, ngx_http_limit_access_module);
    }

    if (request_ctx->set) {
        return NGX_DECLINED;
    }

    request_ctx->set = 1;

    ctx = lacf->shm_zone->data;

    ngx_shmtx_lock(&ctx->shpool->mutex);

    hash = ctx->sh;

    if (!hash->valid) {
        goto done;
    }

    rc = 0;

    if (ctx->type == HASH_IP) {
        rc = ngx_http_limit_access_lookup_ip(r, ctx);
    }

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

    while (bucket) {
        if (bucket->key == key) {

            if (bucket->expire > now) {
                return 1;
            }

            return 0;
        }

        bucket = bucket->next;
    }

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
                          "while previously it used the bucket_number",
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

    number = 2048;
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

    ngx_str_t   *value, s;

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

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_limit_access_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_limit_access_handler;

    return NGX_OK;
}
