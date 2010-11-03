
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef struct {
    unsigned set;
} ngx_http_limit_access_loc_ctx_t;

typedef struct {
    ngx_uint_t key;
    time_t     expire;
    u_short    len;
    u_char     value[1];
} ngx_http_limit_access_bucket_t;

typedef struct {
    ngx_uint_t   type;
    ngx_uint_t   bucket_number;
    ngx_array_t *buckets;
} ngx_http_limit_access_hash_t;

typedef struct {
    ngx_http_limit_access_hash_t *sh;
    ngx_slab_pool_t              *shpool;
} ngx_http_limit_access_ctx_t;

typedef struct {
    ngx_shm_zone_t              *shm_zone;
    ngx_uint_t                   limit_log_level;
    ngx_uint_t                   bucket_number;
} ngx_http_limit_access_conf_t;


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
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE3,
      ngx_http_limit_access_zone,
      0,
      0,
      NULL },

    { ngx_string("limit_access"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE123,
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
    ngx_http_limit_access_init,               /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_limit_access_create_conf,        /* create location configration */
    ngx_http_limit_access_merge_conf          /* merge location configration */
};


ngx_module_t  ngx_http_limit_access_module = {
    NGX_MODULE_V1,
    &ngx_http_limit_access_module_ctx,        /* module context */
    ngx_http_limit_access_commands,           /* module directives */
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
ngx_http_limit_access_handler(ngx_http_request_t *r)
{
    return NGX_DECLINED;
}


static ngx_int_t
ngx_http_limit_access_check_handler(ngx_http_request_t *r)
{
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
    ngx_shm_zone_t            *shm_zone;
    ngx_http_limit_access_ctx_t  *ctx;

    value = cf->args->elts;

    number = 2048;
    name.len = 0;
    size = 0;

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

    shm_zone->init = ngx_http_limit_access_init_zone;
    shm_zone->data = ctx;

    return NGX_CONF_OK;
}


static char *
ngx_http_limit_access(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_limit_access_conf_t  *lacf = conf;

    ngx_str_t   *value;
    ngx_uint_t   i;

    if (lacf->shm_zone) {
        return "is duplicate";
    }

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {

    }

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
    clcf->handler = ngx_http_limit_access_handler;

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

    *h = ngx_http_limit_access_check_handler;

    return NGX_OK;
}
