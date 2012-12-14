/*-----------------------------------------------------------------------------
 *  Description:  implements resin's mod_caucho function for nginx
 *      Version:  0.5
 *       Author:  bin wang
 *      Company:  netease
 *         Mail:  163.beijing@gmail.com
 *    Attension:  
 *                  1) it is tested in linux only 
 *                  2) we have already tested eight projects for this module:
 *                          resin-doc
 *                          jackrabbit
 *                          hudson
 *                          jetspeed
 *                          geoserver
 *                          VQWiki
 *                          struts2-showcase
 *                          spring-security-samples
 *                     all are easily deployed in resin (web war)
 *                  3) this module references yaoweibin's nginx ajp module
 *                  4) if you use keepalive module,you should set accept_mutex 
 *                     off in multiprocess environment
 *                  5) if you have any problems or bugs, please contact me
 *
 *  The following describes the hmux protocol implemented in this module
 *
 *                 hmux protocol
 *  A GET request:
 *      Frontend                Backend
 *      CSE_METHOD
 *      ...
 *      CSE_HEADER/CSE_VALUE
 *      CSE_END
 *                              CSE_DATA
 *                              CSE_DATA
 *                              CSE_END
 *
 *  Short POST:
 *      Frontend                Backend
 *      CSE_METHOD
 *      ...
 *      CSE_HEADER/CSE_VALUE
 *      CSE_DATA
 *      CSE_END
 *                              CSE_DATA
 *                              CSE_DATA
 *                              CSE_END
 *
 *  Long POST:
 *      Frontend                Backend
 *      CSE_METHOD
 *      ...
 *      CSE_HEADER/CSE_VALUE
 *      CSE_DATA
 *                              CSE_DATA (optional)   #here we buffer resp data
 *      CSE_DATA
 *                              CSE_ACK
 *                              CSE_DATA (optional)   #here we buffer resp data
 *      CSE_DATA
 *                              CSE_ACK
 *      CSE_END
 *                              CSE_DATA
 *                              CSE_END
 *
 *
 *---------------------------------------------------------------------------*/

#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#define HMUX_CHANNEL        'C'
#define HMUX_ACK            'A'
#define HMUX_ERROR          'E'
#define HMUX_YIELD          'Y'
#define HMUX_QUIT           'Q'
#define HMUX_EXIT           'X'

#define HMUX_DATA           'D'
#define HMUX_URL            'U'
#define HMUX_STRING         'S'
#define HMUX_HEADER         'H'
#define HMUX_META_HEADER    'M'
#define HMUX_PROTOCOL       'P'

#define CSE_NULL            '?'
#define CSE_PATH_INFO       'b'
#define CSE_PROTOCOL        'c'
#define CSE_REMOTE_USER     'd'
#define CSE_QUERY_STRING    'e'
#define CSE_SERVER_PORT     'g'
#define CSE_REMOTE_HOST     'h'
#define CSE_REMOTE_ADDR     'i'
#define CSE_REMOTE_PORT     'j'
#define CSE_REAL_PATH       'k'
#define CSE_AUTH_TYPE       'n'
#define CSE_URI             'o'
#define CSE_CONTENT_LENGTH  'p'
#define CSE_CONTENT_TYPE    'q'
#define CSE_IS_SECURE       'r'
#define CSE_SESSION_GROUP   's'
#define CSE_CLIENT_CERT     't'
#define CSE_SERVER_TYPE     'u'

#define HMUX_METHOD         'm'
#define HMUX_FLUSH          'f'
#define HMUX_SERVER_NAME    'v'
#define HMUX_STATUS         's'
#define HMUX_CLUSTER        'c'
#define HMUX_SRUN           's'
#define HMUX_SRUN_BACKUP    'b'
#define HMUX_SRUN_SSL       'e'
#define HMUX_UNAVAILABLE    'u'
#define HMUX_WEB_APP_UNAVAILABLE 'U'

#define CSE_HEADER          'H'
#define CSE_VALUE           'V'

#define CSE_STATUS          'S'
#define CSE_SEND_HEADER     'G'

#define CSE_PING            'P'
#define CSE_QUERY           'Q'

#define CSE_ACK             'A'
#define CSE_DATA            'D'
#define CSE_FLUSH           'F'
#define CSE_KEEPALIVE       'K'
#define CSE_END             'Z'
#define CSE_CLOSE           'X'

#define HMUX_CMD_SZ 8
#define HMUX_DATA_SEG_SZ 8
#define HMUX_META_DATA_LEN   3
#define HMUX_MSG_BUFFER_SZ 8192
#define HMUX_MAX_BUFFER_SZ  65536

#define HMUX_DISPATCH_PROTOCOL 0x102
#define HMUX_QUERY 0x102
#define HMUX_EOVERFLOW  1001

ngx_module_t               ngx_hmux_module;
typedef struct hmux_msg_s  hmux_msg_t;


struct hmux_msg_s
{
    ngx_buf_t *buf;
};


typedef struct {

    size_t                         hmux_header_packet_buffer_size_conf;
    size_t                         max_hmux_data_packet_size_conf;
    ngx_flag_t                     hmux_set_header_x_forwarded_for;
    ngx_array_t                   *hmux_lengths;
    ngx_array_t                   *hmux_values;
    ngx_http_upstream_conf_t       upstream;
#if (NGX_HTTP_CACHE)
    ngx_http_complex_value_t       cache_key;
#endif

} ngx_hmux_loc_conf_t;


typedef enum {
    ngx_hmux_st_init_state = 0,
    ngx_hmux_st_forward_request_sent,
    ngx_hmux_st_request_body_data_sending,
    ngx_hmux_st_request_send_all_done,
    ngx_hmux_st_response_recv_headers,
    ngx_hmux_st_response_parse_headers_done,
    ngx_hmux_st_response_headers_sent,
    ngx_hmux_st_response_body_data_sending,
    ngx_hmux_st_response_end
} ngx_hmux_state_e;

typedef struct {
    hmux_msg_t                  msg;
    ngx_hmux_state_e            state;
    /* 
     * this is for fixing the problem  
     * when  request content length is not equal to content-length
     */
    off_t                       req_body_send_len;

    off_t                       req_body_len;
    /* request body which has not been sent to the backend */
    ngx_chain_t                *req_body;
    /* buffer for Long POST disposure */
    ngx_chain_t                *resp_body;
    /* for input filter disposure */
    void                       *undisposed;
    size_t                      undisposed_size;
    /* the response body chunk packet's length */
    size_t                      resp_chunk_len;
    unsigned int                req_body_sent_over:1;
    unsigned int                head_send_flag:1;
    unsigned int                long_post_flag:1;
    unsigned int                flush_flag:1;
    unsigned int                restore_flag:1;
    unsigned int                code:8;
    unsigned int                mend_flag:8;
} ngx_hmux_ctx_t;



#if (NGX_HTTP_CACHE)
static ngx_int_t ngx_hmux_create_key(ngx_http_request_t *r);
#endif
static ngx_int_t ngx_hmux_eval(ngx_http_request_t *r,
        ngx_hmux_loc_conf_t *hlcf);
static ngx_int_t ngx_hmux_create_request(ngx_http_request_t *r);
static ngx_int_t ngx_hmux_reinit_request(ngx_http_request_t *r);
static ngx_int_t ngx_hmux_process_header(ngx_http_request_t *r);
static ngx_int_t ngx_hmux_input_filter(ngx_event_pipe_t *p, 
        ngx_buf_t *buf);
static void ngx_hmux_abort_request(ngx_http_request_t *r);
static void ngx_hmux_finalize_request(ngx_http_request_t *r,
        ngx_int_t rc);

static ngx_int_t ngx_http_upstream_send_request_body(ngx_http_request_t *r, 
        ngx_http_upstream_t *u);
static ngx_chain_t *hmux_data_msg_send_body(ngx_http_request_t *r, 
        size_t max_size, ngx_chain_t **body);
static void ngx_http_upstream_send_request_body_handler(ngx_http_request_t *r,
        ngx_http_upstream_t *u);
static void ngx_http_upstream_dummy_handler(ngx_http_request_t *r,
        ngx_http_upstream_t *u);

#if (NGX_HTTP_CACHE)
static char *ngx_hmux_cache(ngx_conf_t *cf, ngx_command_t *cmd,
        void *conf);
static char *ngx_hmux_cache_key(ngx_conf_t *cf, ngx_command_t *cmd,
        void *conf);
#endif
static char *ngx_hmux_pass(ngx_conf_t *cf, ngx_command_t *cmd,
        void *conf);
static char *ngx_hmux_store(ngx_conf_t *cf, ngx_command_t *cmd,
        void *conf);
static char *ngx_hmux_lowat_check(ngx_conf_t *cf, void *post,
        void *data);
static char *ngx_hmux_upstream_max_fails_unsupported(ngx_conf_t *cf,
        ngx_command_t *cmd, void *conf);
static char *ngx_hmux_upstream_fail_timeout_unsupported(ngx_conf_t *cf,
        ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_hmux_get_x_forwarded_for_value(ngx_http_request_t *r,
        ngx_str_t *v, uintptr_t data);

static void *ngx_hmux_create_loc_conf(ngx_conf_t *cf);
static char *ngx_hmux_merge_loc_conf(ngx_conf_t *cf, void *parent,
        void *child);
static int hmux_log_overflow(ngx_uint_t level, hmux_msg_t *msg, 
        const char *context);

/*
 * protocol functions
 */
static ngx_int_t hmux_start_channel(hmux_msg_t *msg,
        unsigned short channel);
static ngx_int_t hmux_write_string(hmux_msg_t *msg,
        char code, ngx_str_t *value);

static ngx_int_t hmux_read_len(hmux_msg_t *msg, uint16_t *rlen);
static ngx_int_t hmux_read_byte(hmux_msg_t *s, u_char *rvalue);
static ngx_int_t hmux_read_string(hmux_msg_t *msg, ngx_str_t *rvalue);

static hmux_msg_t *hmux_msg_reuse(hmux_msg_t *msg);
static ngx_int_t hmux_data_msg_begin(hmux_msg_t *msg, size_t size); 
static ngx_chain_t *hmux_cmd_msg(ngx_hmux_ctx_t *ctx, ngx_http_request_t *r,
        u_char code);
static ngx_int_t hmux_msg_create_buffer(ngx_pool_t *pool, size_t size, 
        hmux_msg_t *msg);

static ngx_int_t hmux_marshal_into_msg(hmux_msg_t *msg,
        ngx_http_request_t *r, ngx_hmux_loc_conf_t *hlcf);

static ngx_int_t hmux_unmarshal_response(hmux_msg_t *msg, 
        ngx_http_request_t *r, ngx_hmux_loc_conf_t *hlcf);


static ngx_conf_post_t  ngx_hmux_lowat_post = { ngx_hmux_lowat_check };

static ngx_conf_bitmask_t  ngx_hmux_next_upstream_masks[] = {
    { ngx_string("error"), NGX_HTTP_UPSTREAM_FT_ERROR },
    { ngx_string("timeout"), NGX_HTTP_UPSTREAM_FT_TIMEOUT },
    { ngx_string("invalid_header"), NGX_HTTP_UPSTREAM_FT_INVALID_HEADER },
    { ngx_string("http_500"), NGX_HTTP_UPSTREAM_FT_HTTP_500 },
    { ngx_string("http_502"), NGX_HTTP_UPSTREAM_FT_HTTP_502 },
    { ngx_string("http_503"), NGX_HTTP_UPSTREAM_FT_HTTP_503 },
    { ngx_string("http_504"), NGX_HTTP_UPSTREAM_FT_HTTP_504 },
    { ngx_string("http_404"), NGX_HTTP_UPSTREAM_FT_HTTP_404 },
    { ngx_string("updating"), NGX_HTTP_UPSTREAM_FT_UPDATING },
    { ngx_string("off"), NGX_HTTP_UPSTREAM_FT_OFF },
    { ngx_null_string, 0 }
};

static ngx_path_init_t  ngx_hmux_temp_path = {
    ngx_string("hmux_temp"), { 1, 2, 0 }
};


static ngx_str_t  ngx_hmux_hide_headers[] = {
    ngx_string("Status"),
    ngx_string("X-Accel-Expires"),
    ngx_string("X-Accel-Redirect"),
    ngx_string("X-Accel-Limit-Rate"),
    ngx_string("X-Accel-Buffering"),
    ngx_string("X-Accel-Charset"),
    ngx_null_string
};

#if (NGX_HTTP_CACHE)
static ngx_str_t  ngx_hmux_hide_cache_headers[] = {
    ngx_string("Status"),
    ngx_string("X-Accel-Expires"),
    ngx_string("X-Accel-Redirect"),
    ngx_string("X-Accel-Limit-Rate"),
    ngx_string("X-Accel-Buffering"),
    ngx_string("X-Accel-Charset"),
    ngx_string("Set-Cookie"),
    ngx_string("P3P"),
    ngx_null_string
};
#endif


static ngx_command_t  ngx_hmux_commands[] = {

    { ngx_string("hmux_pass"),
        NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
        ngx_hmux_pass,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL },

    { ngx_string("hmux_header_packet_buffer_size"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_size_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_hmux_loc_conf_t, hmux_header_packet_buffer_size_conf),
        NULL },

    { ngx_string("hmux_max_data_packet_size"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_hmux_loc_conf_t, max_hmux_data_packet_size_conf),
        NULL },

    { ngx_string("hmux_store"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_hmux_store,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL },

    { ngx_string("hmux_store_access"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE123,
        ngx_conf_set_access_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_hmux_loc_conf_t, upstream.store_access),
        NULL },

    { ngx_string("hmux_ignore_client_abort"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
        ngx_conf_set_flag_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_hmux_loc_conf_t, upstream.ignore_client_abort),
        NULL },

    { ngx_string("hmux_connect_timeout"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_msec_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_hmux_loc_conf_t, upstream.connect_timeout),
        NULL },

    { ngx_string("hmux_send_timeout"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_msec_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_hmux_loc_conf_t, upstream.send_timeout),
        NULL },

    { ngx_string("hmux_send_lowat"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_size_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_hmux_loc_conf_t, upstream.send_lowat),
        &ngx_hmux_lowat_post },

    { ngx_string("hmux_buffer_size"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_size_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_hmux_loc_conf_t, upstream.buffer_size),
        NULL },

    { ngx_string("hmux_pass_request_headers"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
        ngx_conf_set_flag_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_hmux_loc_conf_t, upstream.pass_request_headers),
        NULL },

    { ngx_string("hmux_pass_request_body"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
        ngx_conf_set_flag_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_hmux_loc_conf_t, upstream.pass_request_body),
        NULL },

    { ngx_string("hmux_intercept_errors"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
        ngx_conf_set_flag_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_hmux_loc_conf_t, upstream.intercept_errors),
        NULL },

    { ngx_string("hmux_read_timeout"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_msec_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_hmux_loc_conf_t, upstream.read_timeout),
        NULL },

    { ngx_string("hmux_buffers"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
        ngx_conf_set_bufs_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_hmux_loc_conf_t, upstream.bufs),
        NULL },

    { ngx_string("hmux_busy_buffers_size"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_size_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_hmux_loc_conf_t, upstream.busy_buffers_size_conf),
        NULL },

#if (NGX_HTTP_CACHE)
    { ngx_string("hmux_cache"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
        ngx_hmux_cache,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL },

    { ngx_string("hmux_cache_key"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
        ngx_hmux_cache_key,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL },

    { ngx_string("hmux_cache_path"),
        NGX_HTTP_MAIN_CONF|NGX_CONF_2MORE,
        ngx_http_file_cache_set_slot,
        0,
        0,
        &ngx_hmux_module },

    { ngx_string("hmux_cache_valid"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
        ngx_http_file_cache_valid_set_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_hmux_loc_conf_t, upstream.cache_valid),
        NULL },

    { ngx_string("hmux_cache_min_uses"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_num_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_hmux_loc_conf_t, upstream.cache_min_uses),
        NULL },

    { ngx_string("hmux_cache_use_stale"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
        ngx_conf_set_bitmask_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_hmux_loc_conf_t, upstream.cache_use_stale),
        &ngx_hmux_next_upstream_masks },

    { ngx_string("hmux_cache_methods"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
        ngx_conf_set_bitmask_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_hmux_loc_conf_t, upstream.cache_methods),
        &ngx_http_upstream_cache_method_mask },
#endif 

    { ngx_string("hmux_temp_path"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1234,
        ngx_conf_set_path_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_hmux_loc_conf_t, upstream.temp_path),
        NULL },

    { ngx_string("hmux_max_temp_file_size"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_size_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_hmux_loc_conf_t, upstream.max_temp_file_size_conf),
        NULL },

    { ngx_string("hmux_temp_file_write_size"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_size_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_hmux_loc_conf_t, upstream.temp_file_write_size_conf),
        NULL },

    { ngx_string("hmux_next_upstream"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
        ngx_conf_set_bitmask_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_hmux_loc_conf_t, upstream.next_upstream),
        &ngx_hmux_next_upstream_masks },

    { ngx_string("hmux_upstream_max_fails"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_hmux_upstream_max_fails_unsupported,
        0,
        0,
        NULL },

    { ngx_string("hmux_upstream_fail_timeout"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_hmux_upstream_fail_timeout_unsupported,
        0,
        0,
        NULL },

    { ngx_string("hmux_pass_header"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
        ngx_conf_set_str_array_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_hmux_loc_conf_t, upstream.pass_headers),
        NULL },

    { ngx_string("hmux_hide_header"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
        ngx_conf_set_str_array_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_hmux_loc_conf_t, upstream.hide_headers),
        NULL },

    { ngx_string("hmux_ignore_headers"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
        ngx_conf_set_bitmask_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_hmux_loc_conf_t, upstream.ignore_headers),
        &ngx_http_upstream_ignore_headers_masks},

    { ngx_string("hmux_x_forwarded_for"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
        ngx_conf_set_flag_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_hmux_loc_conf_t, hmux_set_header_x_forwarded_for),
        NULL },

    ngx_null_command
};


static ngx_http_module_t  ngx_hmux_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_hmux_create_loc_conf,              /* create location configuration */
    ngx_hmux_merge_loc_conf                /* merge location configuration */
};


ngx_module_t  ngx_hmux_module = {
    NGX_MODULE_V1,
    &ngx_hmux_module_ctx,                   /* module context */
    ngx_hmux_commands,                      /* module directives */
    NGX_HTTP_MODULE,                        /* module type */
    NULL,                                   /* init master */
    NULL,                                   /* init module */
    NULL,                                   /* init process */
    NULL,                                   /* init thread */
    NULL,                                   /* exit thread */
    NULL,                                   /* exit process */
    NULL,                                   /* exit master */
    NGX_MODULE_V1_PADDING
};

ngx_int_t
ngx_hmux_handler(ngx_http_request_t *r)
{
    ngx_int_t                    rc;
    ngx_http_upstream_t         *u;
    ngx_hmux_ctx_t              *ctx;
    ngx_hmux_loc_conf_t         *hlcf;

    if (r->subrequest_in_memory) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "ngx_hmux_module does not support "
                "subrequest in memory");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ngx_http_set_content_type(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ngx_http_upstream_create(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_hmux_ctx_t));
    if (NULL == ctx) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (r->headers_in.content_length_n > 0){
        ctx->req_body_len=r->headers_in.content_length_n;
    }

    ctx->state = ngx_hmux_st_init_state;

    ngx_http_set_ctx(r, ctx, ngx_hmux_module);

    hlcf = ngx_http_get_module_loc_conf(r, ngx_hmux_module);

    if (hlcf->hmux_lengths) {
        if (ngx_hmux_eval(r, hlcf) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    u = r->upstream;
    u->schema.len  = sizeof("hmux://") - 1;
    u->schema.data = (u_char *) "hmux://";
    u->output.tag  = (ngx_buf_tag_t) &ngx_hmux_module;
    u->conf        = &hlcf->upstream;
#if (NGX_HTTP_CACHE)
    u->create_key  = ngx_hmux_create_key;
#endif

    u->create_request   = ngx_hmux_create_request;
    u->reinit_request   = ngx_hmux_reinit_request;
    u->process_header   = ngx_hmux_process_header;
    u->abort_request    = ngx_hmux_abort_request;
    u->finalize_request = ngx_hmux_finalize_request;

    u->buffering = 1;

    u->pipe = ngx_pcalloc(r->pool, sizeof(ngx_event_pipe_t));
    if (NULL == u->pipe) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    u->pipe->input_filter = ngx_hmux_input_filter;
    u->pipe->input_ctx    = r;

    rc = ngx_http_read_client_request_body(r, ngx_http_upstream_init);

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }

    return NGX_DONE;
}


static ngx_int_t
ngx_hmux_eval(ngx_http_request_t *r, ngx_hmux_loc_conf_t *hlcf)
{
    ngx_url_t  u;

    ngx_memzero(&u, sizeof(ngx_url_t));

    if (ngx_http_script_run(r, &u.url, hlcf->hmux_lengths->elts, 0,
                hlcf->hmux_values->elts) == NULL)
    {
        return NGX_ERROR;
    }

    u.no_resolve = 1;

    if (ngx_parse_url(r->pool, &u) != NGX_OK) {
        if (u.err) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "%s in upstream \"%V\"", u.err, &u.url);
        }

        return NGX_ERROR;
    }

    if (u.no_port) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "no port in upstream \"%V\"", &u.url);
        return NGX_ERROR;
    }

    r->upstream->resolved = ngx_pcalloc(r->pool,
            sizeof(ngx_http_upstream_resolved_t));
    if (NULL == r->upstream->resolved ) {
        return NGX_ERROR;
    }

    if (u.addrs && u.addrs[0].sockaddr) {
        r->upstream->resolved->sockaddr = u.addrs[0].sockaddr;
        r->upstream->resolved->socklen  = u.addrs[0].socklen;
        r->upstream->resolved->naddrs   = 1;
        r->upstream->resolved->host     = u.addrs[0].name;

    } else {
        r->upstream->resolved->host = u.host;
        r->upstream->resolved->port = u.port;
    }

    return NGX_OK;
}

#if (NGX_HTTP_CACHE)
static ngx_int_t
ngx_hmux_create_key(ngx_http_request_t *r)
{
    ngx_str_t                    *key;
    ngx_hmux_loc_conf_t          *hlcf;

    key = ngx_array_push(&r->cache->keys);
    if (NULL == key) {
        return NGX_ERROR;
    }

    hlcf = ngx_http_get_module_loc_conf(r, ngx_hmux_module);

    if (ngx_http_complex_value(r, &hlcf->cache_key, key) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}
#endif

static ngx_int_t
ngx_hmux_create_request(ngx_http_request_t *r)
{
    ngx_int_t                    rc;
    hmux_msg_t                  *msg;
    ngx_chain_t                 *cl, *last;
    ngx_hmux_ctx_t              *ctx;
    ngx_hmux_loc_conf_t         *hlcf;

    ctx  = ngx_http_get_module_ctx(r, ngx_hmux_module);
    hlcf = ngx_http_get_module_loc_conf(r, ngx_hmux_module);

    if (NULL == ctx || NULL == hlcf) {
        return NGX_ERROR;
    }

    msg = hmux_msg_reuse(&ctx->msg);

    /* creates buffer for header */
    if (NGX_OK != hmux_msg_create_buffer(r->pool,
                hlcf->hmux_header_packet_buffer_size_conf, msg)) {
        return NGX_ERROR;
    }

    rc = hmux_marshal_into_msg(msg, r, hlcf);
    if (NGX_OK != rc) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                "hmux_header_packet_buffer_size is too small:%u", 
                hlcf->hmux_header_packet_buffer_size_conf);

        return rc;
    }

    cl = ngx_alloc_chain_link(r->pool);
    if (NULL == cl) {
        return NGX_ERROR;
    }

    cl->buf = msg->buf;
    cl->buf->flush = 1;

    ctx->state = ngx_hmux_st_forward_request_sent;

    if (hlcf->upstream.pass_request_body) {
        ctx->req_body = r->upstream->request_bufs;
        r->upstream->request_bufs = cl;

        cl->next = hmux_data_msg_send_body(r,
                hlcf->max_hmux_data_packet_size_conf, &ctx->req_body);

        last = cl;
        while (last->next != NULL){
            last = last->next;
        }

        if (ctx->req_body != NULL && !ctx->req_body_sent_over) {
            /* it has body data left for sending */
            ctx->state = ngx_hmux_st_request_body_data_sending;
            last->next = hmux_cmd_msg(ctx, r, HMUX_YIELD);
        } else {
            ctx->state = ngx_hmux_st_request_send_all_done;
            last->next = hmux_cmd_msg(ctx, r, HMUX_QUIT);
        }

    } else {
        ctx->req_body_sent_over = 1;
        ctx->state = ngx_hmux_st_request_send_all_done;
        r->upstream->request_bufs = cl;
        cl->next = hmux_cmd_msg(ctx, r, HMUX_QUIT);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_hmux_reinit_request(ngx_http_request_t *r)
{
    ngx_hmux_ctx_t           *ctx;
    ngx_hmux_loc_conf_t      *hlcf;

    ctx = ngx_http_get_module_ctx(r, ngx_hmux_module);
    hlcf = ngx_http_get_module_loc_conf(r, ngx_hmux_module);

    if (NULL == ctx || NULL== hlcf) {
        return NGX_ERROR;
    }

    memset(ctx, 0, sizeof(ngx_hmux_ctx_t));

    ctx->state = ngx_hmux_st_init_state;

    hmux_msg_reuse(&ctx->msg);

    return NGX_OK;
}


static ngx_int_t
ngx_hmux_process_header(ngx_http_request_t *r)
{
    ngx_hmux_ctx_t           *ctx;
    ngx_hmux_loc_conf_t      *hlcf;


    ctx = ngx_http_get_module_ctx(r, ngx_hmux_module);
    hlcf = ngx_http_get_module_loc_conf(r, ngx_hmux_module);

    if (NULL == ctx || NULL == hlcf) {
        return NGX_ERROR;
    }

    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
            "ngx_hmux_process_header: state(%d)", ctx->state);

    return hmux_unmarshal_response(&ctx->msg, r, hlcf);
}


static ngx_int_t
ngx_http_upstream_send_request_body(ngx_http_request_t *r, 
        ngx_http_upstream_t *u)
{
    ngx_int_t                     rc;
    ngx_chain_t                  *cl, *last;
    hmux_msg_t                   *msg;
    ngx_connection_t             *c;
    ngx_hmux_ctx_t               *ctx;
    ngx_hmux_loc_conf_t          *hlcf;

    c = u->peer.connection;

    ctx  = ngx_http_get_module_ctx(r, ngx_hmux_module);
    hlcf = ngx_http_get_module_loc_conf(r, ngx_hmux_module);

    if (NULL == ctx || NULL == hlcf)
    {
        return NGX_ERROR;
    }

    if (ctx->state > ngx_hmux_st_request_body_data_sending) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                "ngx_http_upstream_send_request_body: bad state(%d)", 
                ctx->state);
    }

    cl = hmux_data_msg_send_body(r, hlcf->max_hmux_data_packet_size_conf,
            &ctx->req_body);

    if (NULL == u->output.in && NULL == u->output.busy) {
        if (NULL == cl) {
            msg = hmux_msg_reuse(&ctx->msg);

            hmux_data_msg_begin(msg, 0);

            cl = ngx_alloc_chain_link(r->pool);
            if (NULL == cl ) {
                return NGX_ERROR;
            }

            cl->buf  = msg->buf;
            cl->next = NULL;
        }
    }

    last = cl;
    while (last->next != NULL){
        last = last->next;
    }

    if (ctx->req_body != NULL && !ctx->req_body_sent_over) {
        ctx->state = ngx_hmux_st_request_body_data_sending;
        last->next = hmux_cmd_msg(ctx, r, HMUX_YIELD);
    }
    else {
        last->next = hmux_cmd_msg(ctx, r, HMUX_QUIT);
        ctx->state = ngx_hmux_st_request_send_all_done;
    }

    c->log->action = "sending request body again to upstream";

    rc = ngx_output_chain(&u->output, cl);

    if (NGX_ERROR == rc) {
        return NGX_ERROR;
    }

    if (c->write->timer_set) {
        ngx_del_timer(c->write);
    }

    if (rc == NGX_AGAIN) {
        ngx_add_timer(c->write, u->conf->send_timeout);

        if (ngx_handle_write_event(c->write, u->conf->send_lowat) != NGX_OK) {
            return NGX_ERROR;
        }

        u->write_event_handler = ngx_http_upstream_send_request_body_handler;

        return NGX_AGAIN;
    }

    if (NGX_TCP_NOPUSH_SET == c->tcp_nopush) {
        if (NGX_ERROR == ngx_tcp_push(c->fd)) {
            ngx_log_error(NGX_LOG_CRIT, c->log, ngx_socket_errno,
                    ngx_tcp_push_n " failed");
            return NGX_ERROR;
        }

        c->tcp_nopush = NGX_TCP_NOPUSH_UNSET;
    }

    ngx_add_timer(c->read, u->conf->read_timeout);

    if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
        return NGX_ERROR;
    }

    u->write_event_handler = ngx_http_upstream_dummy_handler;

    return NGX_OK;
}


ngx_chain_t *
hmux_data_msg_send_body(ngx_http_request_t *r, size_t max_size, 
        ngx_chain_t **body)
{
    size_t                    size, actual_size, base_size, 
                              added_size, redundant_size;
    ngx_int_t                 rc;
    ngx_buf_t                *b_in, *b_out;
    ngx_chain_t              *out, *cl, *in;
    hmux_msg_t               *msg;
    ngx_hmux_ctx_t           *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_hmux_module);

    if (NULL == body || NULL == *body || NULL == ctx) {
        return NULL;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, 
            r->connection->log, 0, "hmux_data_msg_send_body");

    msg = hmux_msg_reuse(&ctx->msg);
    if ((rc = hmux_msg_create_buffer(r->pool, HMUX_DATA_SEG_SZ, msg))
            != NGX_OK) 
    {
        return NULL;
    }

    out = cl = ngx_alloc_chain_link(r->pool);
    if (NULL == cl ) {
        return NULL;
    }

    cl->buf        = msg->buf;
    max_size       = max_size-HMUX_META_DATA_LEN;
    size           = 0;
    actual_size    = 0;
    base_size      = 0;
    redundant_size = 0;
    added_size     = 0;
    in             = *body;

    b_out = NULL;
    while (in) {
        b_in = in->buf;

        b_out = ngx_alloc_buf(r->pool);
        if (NULL == b_out) {
            return NULL;
        }

        ngx_memcpy(b_out, b_in, sizeof(ngx_buf_t));
        base_size = size;
        if (b_in->in_file) {

            if ((size_t)(b_in->file_last - b_in->file_pos) <=
                    (max_size - size))
            {
                b_out->file_pos  = b_in->file_pos;
                b_out->file_last = b_in->file_pos = b_in->file_last;

                size += b_out->file_last - b_out->file_pos;

            } else if ((size_t)(b_in->file_last - b_in->file_pos) >
                    (max_size-size))
            {

                b_out->file_pos  = b_in->file_pos;
                b_in->file_pos  += max_size - size;
                b_out->file_last = b_in->file_pos;

                size += b_out->file_last - b_out->file_pos;

            }
        } else {
            if ((size_t)(b_in->last - b_in->pos) <= (max_size - size)) {

                b_out->pos  = b_in->pos;
                b_out->last = b_in->pos = b_in->last;

                size += b_out->last - b_out->pos;

            } else if ((size_t)(b_in->last - b_in->pos) > (max_size - size)) {

                b_out->pos = b_in->pos;
                b_in->pos += max_size - size;
                b_out->last = b_in->pos;

                size += b_out->last - b_out->pos;

            }
        }

        added_size   = size - base_size;
        actual_size += added_size;
        ctx->req_body_send_len += added_size;
        if (!r->chunked && ctx->req_body_len > 0){
            if (ctx->req_body_send_len > ctx->req_body_len) {
                ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                        "request body length is large than content-length");

                redundant_size = ctx->req_body_send_len - ctx->req_body_len;

                if (b_out->pos + redundant_size < b_out->last){

                    b_out->last = b_out->last-redundant_size;
                    ctx->req_body_send_len = ctx->req_body_send_len -
                        redundant_size;
                    actual_size = actual_size - redundant_size;

                } else {

                    b_out->last = b_out->pos;
                    ctx->req_body_send_len = ctx->req_body_send_len -
                        added_size;

                    actual_size = actual_size - added_size;
                }
            } else if (ctx->req_body_send_len == ctx->req_body_len) {
                ctx->req_body_sent_over = 1;
                b_out->last_buf = 1;
                ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                        "req_body_send_len finally equals req_body_len");
            }
        } else {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                        "chunked from client or has not req body len");
        }

        cl->next = ngx_alloc_chain_link(r->pool);
        if (NULL == cl->next) {
            return NULL;
        }

        cl      = cl->next;
        cl->buf = b_out;

        if (size >= max_size) {
            break;
        } else {
            in = in->next;
        }
    }

    *body = in;
    cl->next = NULL;
    if (ctx->req_body_send_len == ctx->req_body_len) {
        if (!ctx->req_body_sent_over) {
            if (in != NULL) {
                ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                        "not set req_body_sent_over before");
            }
            ctx->req_body_sent_over = 1;
        }
        if (b_out != NULL && !b_out->last_buf) {
            b_out->last_buf = 1;
        }
    }

    hmux_data_msg_begin(msg, actual_size); 

    return out;
}


static void
ngx_http_upstream_send_request_body_handler(ngx_http_request_t *r,
        ngx_http_upstream_t *u)
{
    ngx_int_t rc;

    rc = ngx_http_upstream_send_request_body(r, u);

    if (NGX_OK == rc ) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "ngx_http_upstream_send_request_body error");
    }
}


static void
ngx_http_upstream_dummy_handler(ngx_http_request_t *r,
        ngx_http_upstream_t *u)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "hmux upstream dummy handler");
    return;
}

static ngx_int_t
ngx_hmux_restore_request_body(ngx_http_request_t *r)
{
    ngx_buf_t    *buf, *next;
    ngx_chain_t  *cl;

    if (r->request_body == NULL
        || r->request_body->bufs == NULL
        || r->request_body->temp_file)
    {
        return NGX_OK;
    }

    cl = r->request_body->bufs;
    buf = cl->buf;
    buf->pos = buf->start;

    if (cl->next != NULL) {
        next = cl->next->buf;
        next->pos = next->start;
    }
    return NGX_OK;
}

/* processing response data here */
static ngx_int_t
ngx_hmux_input_filter(ngx_event_pipe_t *p, ngx_buf_t *buf)
{
    int                  need_read_resp_data, omit_flag, need_more_data;
    u_char              *pos, code;
    uint16_t             len;
    ngx_int_t            rc;
    ngx_str_t            str;
    ngx_buf_t           *b, **prev, *flush_buf, *mended_buf, *work_buf;
    hmux_msg_t          *msg;
    ngx_chain_t         *cl,*tmp_cl;
    ngx_hmux_ctx_t      *ctx;
    ngx_http_request_t  *r;
    ngx_http_upstream_t *u; 

    r = p->input_ctx;
    ctx = ngx_http_get_module_ctx(r, ngx_hmux_module);
    if (!ctx->restore_flag){
        ctx->restore_flag = 1;
        ngx_hmux_restore_request_body(r);
    }

    if (buf->pos == buf->last) {
        return NGX_OK;
    }

    u                   = r->upstream;
    need_read_resp_data = 0;
    omit_flag           = 0;
    b                   = NULL;
    pos                 = NULL;
    need_more_data      = 0;
    prev                = &buf->shadow;
    flush_buf           = NULL;
    msg                 = hmux_msg_reuse(&ctx->msg);

    if (ctx->undisposed != NULL) {
        ctx->mend_flag = ctx->mend_flag + 1;
        /* mend preread data to buf */
        len = ctx->undisposed_size + (buf->last - buf->pos);
        mended_buf = ngx_create_temp_buf(r->pool, len);
        if (NULL == mended_buf) {
            return NGX_ERROR;
        }
        ngx_memcpy(mended_buf->pos, ctx->undisposed, ctx->undisposed_size);
        ngx_memcpy(mended_buf->pos + ctx->undisposed_size,
                buf->pos, (buf->last - buf->pos)); 
        mended_buf->last = mended_buf->pos + len;
        ctx->undisposed  = NULL;
        ctx->undisposed_size = 0;
        work_buf             = mended_buf;

        work_buf->num        = buf->num;
        work_buf->temporary  = buf->temporary;
        work_buf->shadow     = buf->shadow;
        work_buf->tag        = buf->tag;
        work_buf->memory     = buf->memory;
        work_buf->recycled   = buf->recycled;
        work_buf->flush      = buf->flush;
        work_buf->last_buf   = buf->last_buf;
        work_buf->last_in_chain = buf->last_in_chain;
        work_buf->last_shadow   = buf->last_shadow;

    } else {
        work_buf = buf;
    }

    msg->buf = work_buf;

    while (work_buf->pos < work_buf->last) {

        if (0 == ctx->resp_chunk_len) {
            pos = work_buf->pos;
            rc  = hmux_read_byte(msg, &code);
            if (rc != NGX_OK) {
                ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                        "overflow when receiving command in filter");
                ctx->undisposed_size = work_buf->last-pos;
                ctx->undisposed = ngx_pcalloc(r->pool, ctx->undisposed_size);
                memcpy(ctx->undisposed, pos, ctx->undisposed_size);
                break;
            }

            switch (code) {
                case HMUX_DATA:
                    need_read_resp_data = 1;
                    break;

                case HMUX_FLUSH:
                    rc = hmux_read_len(msg, &len);
                    if (rc != NGX_OK) {
                        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                                "overflow when receiving flush cmd in filter");
                        need_more_data = 1;
                        ctx->mend_flag = ctx->mend_flag + 1;
                        break;
                    }
                    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                            "accept hmux flush command in filter");
                    ctx->flush_flag = 1;
                    omit_flag = 1;
                    break;

                case HMUX_QUIT:
                case HMUX_EXIT:
                    p->upstream_done = 1;
                    ctx->state = ngx_hmux_st_response_end;
                    ctx->code  = code;
                    if (ctx->mend_flag) {
                        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                                "ok for overflow recving data in filter:%d",
                                ctx->mend_flag);
                    }
                    return NGX_OK;

                default:
                    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                            "accept default command in filter");

                    if (code>127) {
                        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                "receive command more than 127 in filter");
                        return NGX_ERROR;
                    }
                    rc = hmux_read_string(msg, &str);
                    if (rc != NGX_OK) {
                        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                                "overflow when receiving default in filter");
                        need_more_data = 1;
                        ctx->mend_flag=ctx->mend_flag + 1;
                    }
                    break;
            }

            if (need_read_resp_data) {
                rc = hmux_read_len(msg, (uint16_t *)&ctx->resp_chunk_len);
                if (NGX_OK != rc) {
                    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                            "overflow when receiving data length in filter");
                    need_more_data = 1;
                    ctx->mend_flag = ctx->mend_flag + 1;
                }
                need_read_resp_data = 0;
            }
        }

        if (need_more_data) {
            ctx->undisposed_size = work_buf->last-pos;
            ctx->undisposed = ngx_pcalloc(r->pool, ctx->undisposed_size);
            memcpy(ctx->undisposed, pos, ctx->undisposed_size);
            break;
        }

        if (omit_flag) {
            omit_flag = 0;
            if (ctx->flush_flag && flush_buf != NULL) {
                flush_buf->flush = 1;
                flush_buf = NULL;
                ctx->flush_flag = 0;
            }
            continue;
        }

        if (p->free) {
            b = p->free->buf;
            p->free = p->free->next;
        } else {
            b = ngx_alloc_buf(p->pool);
            if (NULL == b ) {
                return NGX_ERROR;
            }   
        }

        ngx_memzero(b, sizeof(ngx_buf_t));

        b->pos       = work_buf->pos;
        b->start     = work_buf->start;
        b->end       = work_buf->end;
        b->tag       = p->tag;
        b->temporary = 1;
        b->recycled  = 1;

        *prev        = b;
        flush_buf    = b;
        prev         = &b->shadow;

        cl = ngx_alloc_chain_link(p->pool);                                                                                         
        if (NULL == cl) {
            return NGX_ERROR;
        }

        cl->buf = b;
        cl->next = NULL;

        if (p->in) {
            *p->last_in = cl;
        } else {
            if (ctx->long_post_flag) {
                ctx->long_post_flag = 0;
                /* add buffered response data */
                tmp_cl = ctx->resp_body;
                tmp_cl->buf->tag = p->tag;

                while (tmp_cl->next != NULL) {
                    tmp_cl = tmp_cl->next;
                    tmp_cl->buf->tag = p->tag;

                }

                p->in = ctx->resp_body;
                tmp_cl->next = cl;
            } else {
                p->in = cl;
            }
        }

        p->last_in = &cl->next;
        /* STUB */ b->num = work_buf->num;
        if (work_buf->pos + ctx->resp_chunk_len < work_buf->last) {
            work_buf->pos += ctx->resp_chunk_len;
            b->last = work_buf->pos;
            ctx->resp_chunk_len = 0;
        } else {
            ctx->resp_chunk_len -= work_buf->last - work_buf->pos;
            work_buf->pos = work_buf->last;
            b->last = work_buf->last;
        }

    }

    if (b) {
        b->shadow = work_buf; 
        b->last_shadow = 1; 
        b->flush = 1;
        ngx_log_debug2(NGX_LOG_DEBUG, p->log, 0,
                "input buf %s %z", b->pos, b->last - b->pos);

        return NGX_OK;
    }    

    if (ngx_event_pipe_add_free_buf(p, buf) != NGX_OK) {
        return NGX_ERROR;
    }  

    return NGX_OK;
}


static void
ngx_hmux_abort_request(ngx_http_request_t *r)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "abort http hmux request");
    return;
}


static void
ngx_hmux_finalize_request(ngx_http_request_t *r, ngx_int_t rc)
{

    ngx_hmux_ctx_t      *ctx;
    ngx_http_upstream_t *u;

    u = r->upstream;
    ctx = ngx_http_get_module_ctx(r, ngx_hmux_module);

    if (u != NULL) {
        if (HMUX_QUIT == ctx->code) {
            u->length = 0;
#if defined(nginx_version) && nginx_version >= 1001004 
            u->keepalive = 1;
#endif
        } else {
#if defined(nginx_version) && nginx_version >= 1001004 
            u->keepalive = 0;
            u->length    = 0;
#endif
        }
    }
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "finalize http hmux request");

    return;
}

/*******************protocol functions begin ************************/

static ngx_int_t
hmux_start_channel(hmux_msg_t *msg, unsigned short channel)
{
    ngx_buf_t *buf;

    buf = msg->buf;

    if ((buf->last + 1 + sizeof(unsigned short)) > buf->end) {
        return hmux_log_overflow(NGX_LOG_WARN, msg, "hmux_start_channel");
    }

    *buf->last++ = (u_char)(HMUX_CHANNEL);
    *buf->last++ = (u_char)((channel>>8) & 0xff);
    *buf->last++ = (u_char)(channel & 0xff);

    return NGX_OK;

}

static ngx_int_t
hmux_write_string(hmux_msg_t *msg, char code, ngx_str_t *value)
{
    ngx_buf_t *buf;

    buf = msg->buf;

    if ((buf->last + 1 + 2 + value->len) > buf->end) {
        return hmux_log_overflow(NGX_LOG_WARN, msg, "hmux_write_string");
    }

    *buf->last++ = (u_char)(code);
    *buf->last++ = (u_char)((value->len>> 8) & 0xff);
    *buf->last++ = (u_char)((value->len) & 0xff);
    ngx_memcpy(buf->last, value->data, value->len); 

    buf->last  += value->len;

    return NGX_OK;
}

static ngx_int_t
hmux_read_byte(hmux_msg_t *msg, u_char *rvalue)
{
    if ((msg->buf->pos + 1) > msg->buf->last) {
        return hmux_log_overflow(NGX_LOG_INFO, msg, "hmux_read_byte");
    }   

    *rvalue = *msg->buf->pos++;

    return NGX_OK;
}

static ngx_int_t
hmux_read_len(hmux_msg_t *msg, uint16_t *rlen)
{
    int       l1, l2;
    u_char    tmp;
    ngx_int_t rc;

    rc = hmux_read_byte(msg, &tmp) & 0xff;
    if (NGX_OK != rc) {
        return rc;
    }

    l1 = tmp;

    rc = hmux_read_byte(msg, &tmp) & 0xff;
    if (NGX_OK != rc) {
        return rc;
    }
    l2 = tmp;

    *rlen = (l1 << 8) + l2;

    return NGX_OK;
}

static ngx_int_t
hmux_read_string(hmux_msg_t *msg, ngx_str_t *rvalue)
{
    u_char    *start;
    uint16_t   size;
    ngx_int_t  rc;
    ngx_buf_t *buf;

    buf = msg->buf;

    rc= hmux_read_len(msg, &size);
    if (NGX_OK!=rc) {
        return rc;
    }

    start = buf->pos;

    if (start + size > buf->last) {
        return hmux_log_overflow(NGX_LOG_INFO, msg, "hmux_read_string");
    }

    buf->pos += (size_t)size;
    rvalue->data = start;
    rvalue->len = size;

    return NGX_OK;
}

static hmux_msg_t *
hmux_msg_reuse(hmux_msg_t *msg)
{
    memset(msg, 0, sizeof(hmux_msg_t));
    return msg;
}

static ngx_int_t
hmux_data_msg_begin(hmux_msg_t *msg, size_t size) 
{
    ngx_buf_t *buf;

    buf = msg->buf;

    if ((buf->last + 1 + 2) > buf->end) {
        return hmux_log_overflow(NGX_LOG_WARN, msg, "hmux_data_msg_begin");
    }

    *buf->last++ = (u_char)(HMUX_DATA);
    *buf->last++ = (u_char)((size>> 8) & 0xff);
    *buf->last++ = (u_char)(size & 0xff);

    return NGX_OK;

}

static ngx_chain_t *
hmux_cmd_msg(ngx_hmux_ctx_t *ctx, ngx_http_request_t *r, u_char code)
{
    ngx_buf_t       *buf;
    hmux_msg_t      *msg;
    ngx_chain_t     *cl;

    msg = hmux_msg_reuse(&ctx->msg);
    /* create buffer for yield command */
    if (NGX_OK != hmux_msg_create_buffer(r->pool, HMUX_CMD_SZ, msg)) {
        return NULL;
    }

    cl = ngx_alloc_chain_link(r->pool);
    if (NULL == cl) {
        return NULL;
    }
    cl->next = NULL;
    cl->buf = msg->buf;
    cl->buf->flush = 1;


    buf = msg->buf;

    if ((buf->last + 1) > buf->end) {
        return NULL;
    }

    *buf->last++ = (u_char)(code);

    return cl;

}


static ngx_int_t
hmux_msg_create_buffer(ngx_pool_t *pool, size_t size, 
        hmux_msg_t *msg)
{
    msg->buf = ngx_create_temp_buf(pool, size);
    if (NULL == msg->buf) {
        return NGX_ERROR;
    }

    return NGX_OK;
}

/* this method is only valid when through hmux module */
static ngx_int_t 
check_url_valid(char*url, size_t len)
{
    size_t i;
    char buf[4096];

    memset(buf, '\0', sizeof(buf));

    for(i = 0; i < len ; i++) {
        buf[i] = ngx_tolower(url[i]);
    }

    if (NULL != strstr(buf, "web-inf")) {
        return NGX_HTTP_FORBIDDEN;
    }

    if (NULL != strstr(buf, "meta-inf")) {
        return NGX_HTTP_FORBIDDEN;
    }

    if (NULL != strstr(buf, ".war")) {
        return NGX_HTTP_FORBIDDEN;
    }

    return NGX_OK;

}

static ngx_int_t
write_env(hmux_msg_t *msg, ngx_http_request_t *r)
{
    char                     buf[4096];
    u_char                   ch;
    ngx_int_t                rc;
    ngx_str_t               *uri, *host, *remote_host, *remote_addr,
                             transfer_url, port_str;
    unsigned int             i, j;
    int                      is_sub_request = 1, port; /* for rewrite */
    struct sockaddr_in      *addr;

    if (is_sub_request) {
        uri = &r->uri;
    } else {
        uri = &r->unparsed_uri;
    }

    j = 0; 
    for (i = 0; (ch = uri->data[i]) && ch != '?' && (j + 3) < sizeof(buf)
            &&i < uri->len; i++) 
    {
        if ('%' == ch ) {
            buf[j++] = '%'; 
            buf[j++] = '2'; 
            buf[j++] = '5'; 
        } else {
            buf[j++] = ch;
        }
    }

    buf[j] = 0; 

    transfer_url.len  = strlen(buf);
    transfer_url.data = (u_char*)buf;

    /* check url validation */
    rc = check_url_valid(buf, transfer_url.len);
    if (rc != NGX_OK) {
        return rc;
    }

    /* writes transferred url */
    rc = hmux_write_string(msg, HMUX_URL, &transfer_url);
    if (rc != NGX_OK) {
        return rc;
    }

    /* writes method name */
    rc = hmux_write_string(msg, HMUX_METHOD, &r->method_name);
    if (rc != NGX_OK) {
        return rc;
    }

    /* writes protocol */
    rc = hmux_write_string(msg, CSE_PROTOCOL, &r->http_protocol);
    if (rc != NGX_OK) {
        return rc;
    }

    /* writes args */
    if (r->args.len > 0) {
        rc = hmux_write_string(msg, CSE_QUERY_STRING, &r->args);
        if (rc != NGX_OK) {
            return rc;
        }
    }

    /* writes the server name */
    host = &(r->headers_in.server);
    rc   = hmux_write_string(msg, HMUX_SERVER_NAME, host);
    if (rc != NGX_OK) {
        return rc;
    }

    /* writes server port */
    addr = (struct sockaddr_in *) r->connection->local_sockaddr;
    port = ntohs(addr->sin_port);
    sprintf(buf, "%u", port);
    port_str.len  = strlen(buf);
    port_str.data = (u_char*)buf;
    rc = hmux_write_string(msg, CSE_SERVER_PORT, &port_str);
    if (rc != NGX_OK) {
        return rc;
    }

    remote_host = remote_addr = &r->connection->addr_text;

    /* writes remote address */
    rc = hmux_write_string(msg, CSE_REMOTE_ADDR, remote_addr);
    if (rc != NGX_OK) {
        return rc;
    }

    /* writes remote host */
    rc = hmux_write_string(msg, CSE_REMOTE_HOST, remote_host);
    if (rc != NGX_OK) {
        return rc;
    }

    addr = (struct sockaddr_in *) r->connection->sockaddr;
    port = ntohs(addr->sin_port);
    sprintf(buf, "%u", port);
    port_str.len  = strlen(buf);
    port_str.data = (u_char*)buf;

    /* write remote port */
    rc = hmux_write_string(msg, CSE_REMOTE_PORT, &port_str);
    if (rc != NGX_OK) {
        return rc;
    }

    if (r->headers_in.user.len != 0) {
        /* write remote user */
        rc = hmux_write_string(msg, CSE_REMOTE_USER, &r->headers_in.user);
        if (rc != NGX_OK) {
            return rc;
        }
    }
    if (r->headers_in.authorization != NULL &&
            r->headers_in.authorization->value.len != 0)
    {
        /* write auth type */
        rc = hmux_write_string(msg, CSE_AUTH_TYPE, 
                &r->headers_in.authorization->value);   
        if (rc != NGX_OK) {
            return rc;
        }
    }

    return NGX_OK;
}


static ngx_int_t
write_headers(hmux_msg_t *msg, ngx_http_request_t *r, 
        ngx_hmux_loc_conf_t *hlcf)
{
    ngx_int_t            rc;
    unsigned int         i;
    ngx_list_part_t     *part;
    ngx_table_elt_t     *header;

    part   = &r->headers_in.headers.part;
    header = part->elts;

    for( i = 0; i < part->nelts; i++) {

        if (0 == header[i].key.len || 0 == header[i].value.len) {
            continue;
        }

        if (! strncasecmp((char*)header[i].key.data, "Content-Type",
                    sizeof("Content-Type")))
        {
            rc = hmux_write_string(msg, CSE_CONTENT_TYPE, &header[i].value);
            if (rc != NGX_OK) {
                return rc;
            }

        } else if (! strncasecmp((char*)header[i].key.data, "Content-Length",
                    sizeof("Content-Length")))
        {
            rc = hmux_write_string(msg, CSE_CONTENT_LENGTH, &header[i].value);
            if (rc != NGX_OK) {
                return rc;
            }

        } else if (! strncasecmp((char*)header[i].key.data, 
                    "Expect", sizeof("Expect"))) {
            /* expect=continue-100 shouldn't be passed to backend */
        } else {
            if (!strncasecmp((char*)header[i].key.data, "X-Forwarded-For",
                        sizeof("X-Forwarded-For")))
            {
                if ((NGX_CONF_UNSET != hlcf->hmux_set_header_x_forwarded_for )
                        && (hlcf->hmux_set_header_x_forwarded_for))
                {
                    /* dont output X-Forwarded-For here */
                    continue;
                }
            }

            rc = hmux_write_string(msg, HMUX_HEADER, &header[i].key);
            if (rc != NGX_OK) {
                return rc;
            }

            rc = hmux_write_string(msg, HMUX_STRING, &header[i].value);
            if (rc != NGX_OK) {
                return rc;
            }
        }   
    }

    return NGX_OK;
}

static ngx_int_t 
write_added_headers(hmux_msg_t *msg, ngx_http_request_t *r, 
        ngx_hmux_loc_conf_t *hlcf)
{
    ngx_int_t                 rc;
    ngx_str_t                 key, value;

    if ( (NGX_CONF_UNSET != hlcf->hmux_set_header_x_forwarded_for )
            && (hlcf->hmux_set_header_x_forwarded_for))
    {
        rc = ngx_hmux_get_x_forwarded_for_value(r, &value, 0);
        if (NGX_OK != rc) { 
            return rc;
        }
        key.len  = sizeof("X-Forwarded-For")-1;
        key.data = (u_char *)"X-Forwarded-For";
        rc = hmux_write_string(msg, HMUX_HEADER, &key);
        if (rc != NGX_OK) {
            return rc;
        }
        rc = hmux_write_string(msg, HMUX_STRING, &value);
        if (rc != NGX_OK) {
            return rc;
        }
    }

    return NGX_OK;
}


static ngx_int_t hmux_marshal_into_msg(hmux_msg_t *msg,
        ngx_http_request_t *r, ngx_hmux_loc_conf_t *hlcf)
{
    ngx_int_t            rc;
    ngx_log_t           *log;

    log = r->connection->log;

    rc = hmux_start_channel(msg, 1);
    if (rc != NGX_OK) {
        return  rc;
    }

    rc = write_env(msg, r);
    if (rc != NGX_OK) {
        return rc;
    }

    /* pass headers */
    if (hlcf->upstream.pass_request_headers) {

        rc = write_headers(msg, r, hlcf);
        if (rc != NGX_OK) {
            return rc;
        }

        rc = write_added_headers(msg, r , hlcf);
        if (rc != NGX_OK) {
            return rc;
        }
    }

    return NGX_OK;

}

static ngx_int_t
ngx_atoi2(u_char *line, size_t n)
{
    ngx_int_t  value;

    if (0 == n) {
        return NGX_ERROR;
    }

    for (value = 0; n--; line++) {
        if (*line < '0' || *line > '9') {
            break;
        }

        value = value * 10 + (*line - '0');
    }

    if (value < 0) {
        return NGX_ERROR;
    } else {
        return value;
    }
}

/* mainly process response header here */
static ngx_int_t hmux_unmarshal_response(hmux_msg_t *msg, 
        ngx_http_request_t *r, ngx_hmux_loc_conf_t *hlcf)
{
    int                             over; 
    u_char                          code, *pos;
    uint16_t                        len, data_len;
    ngx_buf_t                      *buf,*b;
    ngx_int_t                       rc;
    ngx_str_t                       str, str2; 
    ngx_chain_t                    *cl,*tmp;
    ngx_hmux_ctx_t                 *ctx;
    ngx_table_elt_t                *h;
    ngx_http_upstream_t            *u;
    ngx_hmux_loc_conf_t            *conf;
    ngx_http_upstream_header_t     *hh;
    ngx_http_upstream_main_conf_t  *umcf;

    code = HMUX_QUIT;
    ctx  = ngx_http_get_module_ctx(r, ngx_hmux_module);
    conf = ngx_http_get_module_loc_conf(r, ngx_hmux_module);
    umcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);
    over = 0;
    u    = r->upstream;


    if (NULL== ctx || NULL== conf||NULL== umcf) {
        return NGX_ERROR;
    }
    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
            "hmux_unmarshal_response: state(%d)", ctx->state);
    buf = msg->buf = &u->buffer;

    do{
        pos = buf->pos;
#if (NGX_HTTP_CACHE)
        if (pos ==  buf->last) {
            if (r->cache) {
                ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                        "header from cache is over");
                return NGX_OK;
            }
        }
#endif
        rc  = hmux_read_byte(msg, &code);
        if (rc != NGX_OK) {
            buf->pos = pos;
            return NGX_AGAIN;
        }

        switch(code) {
            case HMUX_CHANNEL:

                rc  = hmux_read_len(msg, &len);
                if (rc != NGX_OK) {
                    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                            "overflow when receiving channel command");
                    buf->pos = pos;
                    return NGX_AGAIN;
                }
                break;

            case HMUX_ACK:

                rc  = hmux_read_len(msg, &len);
                if (rc != NGX_OK) {
                    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                            "overflow when receiving ack command");
                    buf->pos = pos;
                    return NGX_AGAIN;
                }
                over = 1;
                ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                        "accept hmux ack command");
                break;

            case HMUX_STATUS:

                rc  = hmux_read_string(msg, &str);
                if (rc != NGX_OK) {
                    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                            "overflow when receiving status command");
                    buf->pos = pos;
                    return NGX_AGAIN;
                }
                u->headers_in.status_line.data = ngx_pstrdup(r->pool, &str);
                u->headers_in.status_line.len  = str.len;
                u->headers_in.status_n = ngx_atoi2(str.data, str.len);
                if (u->state) {
                    u->state->status = u->headers_in.status_n;
                }
                break;

            case HMUX_HEADER:

                rc = hmux_read_string(msg, &str);
                if (rc != NGX_OK) {
                    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                            "overflow when receiving header command 1");
                    buf->pos = pos;
                    return NGX_AGAIN;
                }

                rc = hmux_read_byte(msg, &code);
                if (rc != NGX_OK) {
                    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                            "overflow when receiving header command 2");
                    buf->pos = pos;
                    return NGX_AGAIN;
                }

                rc = hmux_read_string(msg, &str2);
                if (rc != NGX_OK) {
                    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                            "overflow when receiving header command 3");
                    buf->pos = pos;
                    return NGX_AGAIN;
                }

                h = ngx_list_push(&u->headers_in.headers);
                if (NULL == h) {
                    return NGX_ERROR;
                }
                h->key   = str;
                h->value = str2;
                h->lowcase_key = ngx_pnalloc(r->pool, h->key.len);
                if (NULL == h->lowcase_key) {
                    return NGX_ERROR;
                }
                h->hash = ngx_hash_strlow(h->lowcase_key, h->key.data, 
                        h->key.len); 

                hh = ngx_hash_find(&umcf->headers_in_hash, h->hash,
                        h->lowcase_key, h->key.len);
                ngx_log_error(NGX_LOG_DEBUG, r->connection->log,0,
                        "head key and value:\"%V: %V\"",&h->key, &h->value);
                if (hh && hh->handler(r, h, hh->offset) != NGX_OK) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                            " hh->handler error: \"%V: %V\"", 
                            &h->key, &h->value);

                    return NGX_ERROR;
                }

                break;

            case HMUX_META_HEADER:

                rc = hmux_read_string(msg, &str);
                if (rc != NGX_OK) {
                    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                            "overflow when receiving meta header command");
                    buf->pos = pos;
                    return NGX_AGAIN;
                }

                rc = hmux_read_byte(msg, &code);
                if (rc != NGX_OK) {
                    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                            "overflow when receiving meta header command");
                    buf->pos = pos;
                    return NGX_AGAIN;
                }

                rc = hmux_read_string(msg, &str);
                if (rc != NGX_OK) {
                    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                            "overflow when receiving meta header command");
                    buf->pos = pos;
                    return NGX_AGAIN;
                }

                break;

            case HMUX_DATA:

                if (ctx->resp_body != NULL && !ctx->req_body_sent_over) {

                    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                            "recv resp data before having sent the post data");

                    ctx->long_post_flag = 1;
                    rc = hmux_read_string(msg, &str);
                    if (rc != NGX_OK) {
                        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                                "overflow when recving data cmd in unmarshal");
                        buf->pos = pos;
                        return NGX_AGAIN;
                    }

                    cl = ngx_alloc_chain_link(r->pool);
                    if (NULL == cl) {
                        return NGX_ERROR;
                    }

                    b = ngx_calloc_buf(r->pool);
                    if (NULL == b ) {
                        return NGX_ERROR;
                    }   

                    cl->buf  = b;
                    cl->next = NULL;

                    b->pos  = ngx_pstrdup(r->pool, &str);
                    b->last = b->pos + str.len;
                    b->end  = b->last;
                    b->memory    = 1;
                    b->temporary = 1;
                    b->recycled  = 1;
                    if ( NULL== ctx->resp_body ) {
                        ctx->resp_body = cl;
                    } else {
                        tmp = ctx->resp_body;
                        while (tmp->next != NULL) {
                            tmp = tmp->next;
                        }
                        tmp->next = cl;
                    }
                    data_len = u->buffer.last - u->buffer.pos;
                    u->buffer.pos = u->buffer.pos - str.len - 2 - 1;
                    ngx_memcpy(u->buffer.pos, u->buffer.pos + 3 + str.len,
                            data_len); 
                    u->buffer.last = u->buffer.pos + data_len;

                } else {
                    ctx->head_send_flag = 0;
                    msg->buf->pos--;
                    over = 1;
                    ctx->state = ngx_hmux_st_response_body_data_sending;
                }
                ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                        "accept hmux data command in unmarshal");

                break;

            case HMUX_FLUSH:

                ctx->flush_flag = 1;
                rc = hmux_read_len(msg, &len);
                if (rc != NGX_OK) {
                    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                            "overflow when receiving flush cmd in unmarshal");
                    return NGX_AGAIN;
                }
                ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                        "accept hmux flush command in unmarshal");
                break;

            case CSE_KEEPALIVE:

                rc = hmux_read_len(msg, &len);
                if (rc != NGX_OK) {
                    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                            "overflow when receiving keepalive command");
                    return NGX_AGAIN;
                }
                ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                        "accept hmux keepalive command in unmarshal");
                break;

            case CSE_SEND_HEADER:
                ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                        "accept SEND_HEADER command");

                ctx->head_send_flag = 1;
                rc = hmux_read_len(msg, &len);
                if (rc != NGX_OK) {
                    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                            "overflow when receiving send header command");
                    return NGX_AGAIN;
                }
#if (NGX_HTTP_CACHE)
                if (r->cache) {
                    return NGX_OK;
                }
#endif
                ctx->state = ngx_hmux_st_response_parse_headers_done;
                break;

            case HMUX_QUIT:
            case HMUX_EXIT:
                ctx->code = code;
                ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                        "accept EXIT or QUIT command in unmarshal");
                over = 1;
                break;

            default:

                ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                        "accept default command in unmarshal");

                if ( code > 127) {
                    return NGX_ERROR;
                }
                rc = hmux_read_string(msg, &str);
                if (rc != NGX_OK) {
                    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                            "overflow when receiving default command");
                    return NGX_AGAIN;
                }

                ngx_log_debug2(NGX_LOG_DEBUG_EVENT, r->connection->log, 0,
                        "accept hmux default command:%s %z in unmarshal", 
                        str.data, str.len);
                break;
        }


    }while (!over);

    if (HMUX_ACK == code) {
        if (ctx->req_body != NULL && !ctx->req_body_sent_over) {

            data_len = u->buffer.last - u->buffer.pos;
            u->buffer.pos = u->buffer.pos - 3;
            ngx_memcpy(u->buffer.pos, u->buffer.pos + 3, data_len); 
            u->buffer.last = u->buffer.pos + data_len;
            rc = ngx_http_upstream_send_request_body(r, u);
            if (rc != NGX_OK) {
                return rc; 
            }   

        }
        return NGX_AGAIN;
    }

    if (ctx->head_send_flag && HMUX_QUIT == code) {
        r->header_only = 1;
        /* for sending to client quickly */
        r->headers_out.content_length_n = 0;
    }

    if (code != HMUX_DATA && code != HMUX_QUIT && code != HMUX_EXIT) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    return NGX_OK;
}


/*******************protocol functions end************************/


static char *
ngx_hmux_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{

    size_t                      add;
    u_short                     port;
    ngx_url_t                   u;
    ngx_str_t                  *value, *url;
    ngx_uint_t                  n;
    ngx_hmux_loc_conf_t        *hlcf = conf;
    ngx_http_core_loc_conf_t   *clcf;
    ngx_http_script_compile_t   sc;

    if (hlcf->upstream.upstream || hlcf->hmux_lengths) {
        return "is duplicate";
    }

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

    clcf->handler = ngx_hmux_handler;

    if ('/' == clcf->name.data[clcf->name.len - 1]) {
        clcf->auto_redirect = 1;
    }

    value = cf->args->elts;

    url = &value[1];

    n = ngx_http_script_variables_count(url);

    if (n) {

        ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));

        sc.cf = cf;
        sc.source = url;
        sc.lengths = &hlcf->hmux_lengths;
        sc.values = &hlcf->hmux_values;
        sc.variables = n;
        sc.complete_lengths = 1;
        sc.complete_values = 1;

        if (ngx_http_script_compile(&sc) != NGX_OK) {
            return NGX_CONF_ERROR;
        }

        return NGX_CONF_OK;
    }

    add = port = 0;
    if (ngx_strncasecmp(url->data, (u_char *) "hmux://", 7) == 0) {
        add = 7;
        port = 6800;
    }

    ngx_memzero(&u, sizeof(ngx_url_t));

    u.url.len = url->len - add;
    u.url.data = url->data + add;
    u.default_port = port;
    u.uri_part = 1;
    u.no_resolve = 1;

    hlcf->upstream.upstream = ngx_http_upstream_add(cf, &u, 0);
    if (NULL == hlcf->upstream.upstream) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static char *
ngx_hmux_store(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t                  *value;
    ngx_hmux_loc_conf_t        *hlcf = conf;
    ngx_http_script_compile_t   sc;

    if (hlcf->upstream.store != NGX_CONF_UNSET
            || hlcf->upstream.store_lengths)
    {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "off") == 0) {
        hlcf->upstream.store = 0;
        return NGX_CONF_OK;
    }

#if (NGX_HTTP_CACHE)
    if (hlcf->upstream.cache != NGX_CONF_UNSET_PTR
            && hlcf->upstream.cache != NULL)
    {
        return "is incompatible with \"hmux_cache\"";
    }
#endif

    if (ngx_strcmp(value[1].data, "on") == 0) {
        hlcf->upstream.store = 1;
        return NGX_CONF_OK;
    }

    /* include the terminating '\0' into script */
    value[1].len++;

    ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));

    sc.cf = cf;
    sc.source = &value[1];
    sc.lengths = &hlcf->upstream.store_lengths;
    sc.values = &hlcf->upstream.store_values;
    sc.variables = ngx_http_script_variables_count(&value[1]);
    sc.complete_lengths = 1;
    sc.complete_values = 1;

    if (ngx_http_script_compile(&sc) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static char *
ngx_hmux_lowat_check(ngx_conf_t *cf, void *post, void *data)
{

#if !(NGX_HAVE_SO_SNDLOWAT)
    ssize_t *np = data;

    ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
            "\"hmux_send_lowat\" is not supported, ignored");

    *np = 0;

#endif

    return NGX_CONF_OK;
}

#if (NGX_HTTP_CACHE)
static char *
ngx_hmux_cache(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{

    ngx_str_t           *value;
    ngx_hmux_loc_conf_t *hlcf = conf;

    value = cf->args->elts;

    if (hlcf->upstream.cache != NGX_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    if (ngx_strcmp(value[1].data, "off") == 0) {
        hlcf->upstream.cache = NULL;
        return NGX_CONF_OK;
    }

    if (hlcf->upstream.store > 0 || hlcf->upstream.store_lengths) {
        return "is incompatible with \"hmux_store\"";
    }

    hlcf->upstream.cache = ngx_shared_memory_add(cf, &value[1], 0,
            &ngx_hmux_module);

    if (NULL == hlcf->upstream.cache) {
        return NGX_CONF_ERROR;
    }
    return NGX_CONF_OK;
}

static char *
ngx_hmux_cache_key(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_hmux_loc_conf_t               *hlcf = conf;
    ngx_str_t                         *value;
    ngx_http_compile_complex_value_t   ccv;

    value = cf->args->elts;

    if (hlcf->cache_key.value.len) {
        return "is duplicate";
    }

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &hlcf->cache_key;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

#endif


static char *
ngx_hmux_upstream_max_fails_unsupported(ngx_conf_t *cf,
        ngx_command_t *cmd, void *conf)
{
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "\"hmux_upstream_max_fails\" is not supported, "
            "use the \"max_fails\" parameter of the \"server\" directive ",
            "inside the \"upstream\" block");

    return NGX_CONF_ERROR;
}


static char *
ngx_hmux_upstream_fail_timeout_unsupported(ngx_conf_t *cf,
        ngx_command_t *cmd, void *conf)
{
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "\"hmux_upstream_fail_timeout\" is not supported, "
            "use the \"fail_timeout\" parameter of the \"server\" directive ",
            "inside the \"upstream\" block");

    return NGX_CONF_ERROR;
}


static void *
ngx_hmux_create_loc_conf(ngx_conf_t *cf)
{
    ngx_hmux_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_hmux_loc_conf_t));
    if (NULL == conf) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->upstream.bufs.num = 0;
     *     conf->upstream.ignore_headers = 0;
     *     conf->upstream.next_upstream = 0;
     *     conf->upstream.cache_use_stale = 0;
     *     conf->upstream.cache_methods = 0;
     *     conf->upstream.temp_path = NULL;
     *     conf->upstream.hide_headers_hash = { NULL, 0 };
     *     conf->upstream.uri = { 0, NULL };
     *     conf->upstream.location = NULL;
     *     conf->upstream.store_lengths = NULL;
     *     conf->upstream.store_values = NULL;
     *
     */

    conf->hmux_header_packet_buffer_size_conf = NGX_CONF_UNSET_SIZE;
    conf->max_hmux_data_packet_size_conf = NGX_CONF_UNSET_SIZE;
    conf->hmux_set_header_x_forwarded_for= NGX_CONF_UNSET;

    conf->upstream.store = NGX_CONF_UNSET;
    conf->upstream.store_access = NGX_CONF_UNSET_UINT;
    conf->upstream.buffering = NGX_CONF_UNSET;
    conf->upstream.ignore_client_abort = NGX_CONF_UNSET;

    conf->upstream.connect_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.send_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.read_timeout = NGX_CONF_UNSET_MSEC;

    conf->upstream.send_lowat = NGX_CONF_UNSET_SIZE;
    conf->upstream.buffer_size = NGX_CONF_UNSET_SIZE;

    conf->upstream.busy_buffers_size_conf = NGX_CONF_UNSET_SIZE;
    conf->upstream.max_temp_file_size_conf = NGX_CONF_UNSET_SIZE;
    conf->upstream.temp_file_write_size_conf = NGX_CONF_UNSET_SIZE;

    conf->upstream.pass_request_headers = NGX_CONF_UNSET;
    conf->upstream.pass_request_body = NGX_CONF_UNSET;

#if (NGX_HTTP_CACHE)
    conf->upstream.cache = NGX_CONF_UNSET_PTR;
    conf->upstream.cache_min_uses = NGX_CONF_UNSET_UINT;
    conf->upstream.cache_valid = NGX_CONF_UNSET_PTR;
#endif

    conf->upstream.hide_headers = NGX_CONF_UNSET_PTR;
    conf->upstream.pass_headers = NGX_CONF_UNSET_PTR;

    conf->upstream.intercept_errors = NGX_CONF_UNSET;

    /* "hmux_cyclic_temp_file" is disabled */
    conf->upstream.cyclic_temp_file = 0;

    return conf;
}


static char *
ngx_hmux_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    size_t                        size;
    ngx_str_t                    *h;
    ngx_hash_init_t               hash;
    ngx_hmux_loc_conf_t          *prev, *conf;

    prev = parent;
    conf = child;

    if (conf->upstream.store != 0) {
        ngx_conf_merge_value(conf->upstream.store,
                prev->upstream.store, 0);

        if (NULL == conf->upstream.store_lengths) {
            conf->upstream.store_lengths = prev->upstream.store_lengths;
            conf->upstream.store_values = prev->upstream.store_values;
        }
    }

    ngx_conf_merge_size_value(conf->hmux_header_packet_buffer_size_conf,
            prev->hmux_header_packet_buffer_size_conf,
            (size_t) HMUX_MSG_BUFFER_SZ);

    ngx_conf_merge_size_value(conf->max_hmux_data_packet_size_conf,
            prev->max_hmux_data_packet_size_conf,
            (size_t) HMUX_MSG_BUFFER_SZ);

    ngx_conf_merge_value(conf->hmux_set_header_x_forwarded_for,
            prev->hmux_set_header_x_forwarded_for, 0);

    ngx_conf_merge_uint_value(conf->upstream.store_access,
            prev->upstream.store_access, 0600);

    ngx_conf_merge_value(conf->upstream.buffering,
            prev->upstream.buffering, 1);

    ngx_conf_merge_value(conf->upstream.ignore_client_abort,
            prev->upstream.ignore_client_abort, 0);

    ngx_conf_merge_msec_value(conf->upstream.connect_timeout,
            prev->upstream.connect_timeout, 60000);

    ngx_conf_merge_msec_value(conf->upstream.send_timeout,
            prev->upstream.send_timeout, 60000);

    ngx_conf_merge_msec_value(conf->upstream.read_timeout,
            prev->upstream.read_timeout, 60000);

    ngx_conf_merge_size_value(conf->upstream.send_lowat,
            prev->upstream.send_lowat, 0);

    ngx_conf_merge_size_value(conf->upstream.buffer_size,
            prev->upstream.buffer_size,
            (size_t) ngx_pagesize);

    ngx_conf_merge_bufs_value(conf->upstream.bufs, prev->upstream.bufs,
            8, ngx_pagesize);

    if (conf->upstream.bufs.num < 2) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "there must be at least 2 \"hmux_buffers\"");
        return NGX_CONF_ERROR;
    }

    if (conf->hmux_header_packet_buffer_size_conf > HMUX_MAX_BUFFER_SZ) {
        conf->hmux_header_packet_buffer_size_conf = HMUX_MAX_BUFFER_SZ;
    }

    if (conf->max_hmux_data_packet_size_conf < HMUX_MSG_BUFFER_SZ) {
        conf->max_hmux_data_packet_size_conf = HMUX_MSG_BUFFER_SZ;
    }
    else if (conf->max_hmux_data_packet_size_conf > HMUX_MAX_BUFFER_SZ ) {
        conf->max_hmux_data_packet_size_conf = HMUX_MAX_BUFFER_SZ;
    }

    size = conf->upstream.buffer_size;
    if (size < conf->upstream.bufs.size) {
        size = conf->upstream.bufs.size;
    }

    ngx_conf_merge_size_value(conf->upstream.busy_buffers_size_conf,
            prev->upstream.busy_buffers_size_conf,
            NGX_CONF_UNSET_SIZE);

    if (conf->upstream.busy_buffers_size_conf == NGX_CONF_UNSET_SIZE) {
        conf->upstream.busy_buffers_size = 2 * size;
    } else {
        conf->upstream.busy_buffers_size =
            conf->upstream.busy_buffers_size_conf;
    }

    if (conf->upstream.busy_buffers_size < size) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "\"hmux_busy_buffers_size\" must be equal or bigger than "
                "maximum of the value of \"hmux_buffer_size\" and "
                "one of the \"hmux_buffers\"");

        return NGX_CONF_ERROR;
    }

    if (conf->upstream.busy_buffers_size
            > (conf->upstream.bufs.num - 1) * conf->upstream.bufs.size)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "\"hmux_busy_buffers_size\" must be less than "
                "the size of all \"hmux_buffers\" minus one buffer");

        return NGX_CONF_ERROR;
    }

    ngx_conf_merge_size_value(conf->upstream.temp_file_write_size_conf,
            prev->upstream.temp_file_write_size_conf,
            NGX_CONF_UNSET_SIZE);

    if (conf->upstream.temp_file_write_size_conf == NGX_CONF_UNSET_SIZE) {
        conf->upstream.temp_file_write_size = 2 * size;
    } else {
        conf->upstream.temp_file_write_size =
            conf->upstream.temp_file_write_size_conf;
    }

    if (conf->upstream.temp_file_write_size < size) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "\"hmux_temp_file_write_size\" must be equal or bigger than "
                "maximum of the value of \"hmux_buffer_size\" and "
                "one of the \"hmux_buffers\"");

        return NGX_CONF_ERROR;
    }

    ngx_conf_merge_size_value(conf->upstream.max_temp_file_size_conf,
            prev->upstream.max_temp_file_size_conf,
            NGX_CONF_UNSET_SIZE);

    if (conf->upstream.max_temp_file_size_conf == NGX_CONF_UNSET_SIZE) {
        conf->upstream.max_temp_file_size = 1024 * 1024 * 1024;
    } else {
        conf->upstream.max_temp_file_size =
            conf->upstream.max_temp_file_size_conf;
    }

    if (conf->upstream.max_temp_file_size != 0
            && conf->upstream.max_temp_file_size < size)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "\"hmux_max_temp_file_size\" must be equal to zero to disable "
                "the temporary files usage or must be equal or bigger than "
                "maximum of the value of \"hmux_buffer_size\" and "
                "one of the \"hmux_buffers\"");

        return NGX_CONF_ERROR;
    }

    ngx_conf_merge_bitmask_value(conf->upstream.ignore_headers,
            prev->upstream.ignore_headers,
            NGX_CONF_BITMASK_SET);

    ngx_conf_merge_bitmask_value(conf->upstream.next_upstream,
            prev->upstream.next_upstream,
            (NGX_CONF_BITMASK_SET
             |NGX_HTTP_UPSTREAM_FT_ERROR
             |NGX_HTTP_UPSTREAM_FT_TIMEOUT));

    if (conf->upstream.next_upstream & NGX_HTTP_UPSTREAM_FT_OFF) {
        conf->upstream.next_upstream = NGX_CONF_BITMASK_SET
            |NGX_HTTP_UPSTREAM_FT_OFF;
    }

    if (ngx_conf_merge_path_value(cf, &conf->upstream.temp_path,
                prev->upstream.temp_path,
                &ngx_hmux_temp_path)
            != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

#if (NGX_HTTP_CACHE)
    ngx_conf_merge_ptr_value(conf->upstream.cache,
            prev->upstream.cache, NULL);

    if (conf->upstream.cache && conf->upstream.cache->data == NULL) {
        ngx_shm_zone_t  *shm_zone;

        shm_zone = conf->upstream.cache;

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "\"hmux_cache\" zone \"%V\" is unknown, "
                "Maybe you haven't set the hmux_cache_path",
                &shm_zone->shm.name);

        return NGX_CONF_ERROR;
    }

    ngx_conf_merge_uint_value(conf->upstream.cache_min_uses,
            prev->upstream.cache_min_uses, 1);

    ngx_conf_merge_bitmask_value(conf->upstream.cache_use_stale,
            prev->upstream.cache_use_stale, (NGX_CONF_BITMASK_SET
                |NGX_HTTP_UPSTREAM_FT_OFF));
    if (conf->upstream.cache_use_stale & NGX_HTTP_UPSTREAM_FT_OFF) {
        conf->upstream.cache_use_stale = NGX_CONF_BITMASK_SET
            |NGX_HTTP_UPSTREAM_FT_OFF;
    }

    if (conf->upstream.cache_methods == 0) {
        conf->upstream.cache_methods = prev->upstream.cache_methods;
    }

    conf->upstream.cache_methods |= NGX_HTTP_GET|NGX_HTTP_HEAD;

    ngx_conf_merge_ptr_value(conf->upstream.cache_valid,
            prev->upstream.cache_valid, NULL);

    if (conf->cache_key.value.data == NULL) {
        conf->cache_key = prev->cache_key;
    }

#endif

    ngx_conf_merge_value(conf->upstream.pass_request_headers,
            prev->upstream.pass_request_headers, 1);
    ngx_conf_merge_value(conf->upstream.pass_request_body,
            prev->upstream.pass_request_body, 1);

    ngx_conf_merge_value(conf->upstream.intercept_errors,
            prev->upstream.intercept_errors, 0);

    hash.max_size = 512;
    hash.bucket_size = ngx_align(64, ngx_cacheline_size);
    hash.name = "hmux_hide_headers_hash";

#if (NGX_HTTP_CACHE)
    h = conf->upstream.cache ? ngx_hmux_hide_cache_headers:
        ngx_hmux_hide_headers;
#else
    h = ngx_hmux_hide_headers;
#endif

    if (ngx_http_upstream_hide_headers_hash(cf, &conf->upstream,
                &prev->upstream, h, &hash)
            != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    if (NULL == conf->upstream.upstream) {
        conf->upstream.upstream = prev->upstream.upstream;
    }

    if (NULL == conf->hmux_lengths) {
        conf->hmux_lengths = prev->hmux_lengths;
        conf->hmux_values = prev->hmux_values;
    }

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_hmux_get_x_forwarded_for_value(ngx_http_request_t *r,
        ngx_str_t *v, uintptr_t data)
{   
    u_char  *p;

    if (r->headers_in.x_forwarded_for == NULL) {
        v->len = r->connection->addr_text.len;
        v->data = r->connection->addr_text.data;
        return NGX_OK;
    }

    v->len = r->headers_in.x_forwarded_for->value.len
        + sizeof(", ") - 1 + r->connection->addr_text.len;

    p = ngx_pnalloc(r->pool, v->len);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->data = p;

    p = ngx_copy(p, r->headers_in.x_forwarded_for->value.data,
            r->headers_in.x_forwarded_for->value.len);

    *p++ = ','; *p++ = ' ';

    ngx_memcpy(p, r->connection->addr_text.data, r->connection->addr_text.len);

    return NGX_OK;
}

static int
hmux_log_overflow(ngx_uint_t level, hmux_msg_t *msg, const char *context)
{
    ngx_log_error(level, ngx_cycle->log, 0,
            "%s(): BufferOverflowException pos:%p, last:%p, end:%p",
            context, msg->buf->pos, msg->buf->last, msg->buf->end);

    return HMUX_EOVERFLOW;
}

