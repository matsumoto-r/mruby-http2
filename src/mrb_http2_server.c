/*
// mrb_http2_server.c - to provide http2 methods
//
// See Copyright Notice in mrb_http2.c
*/
#include "mrb_http2.h"
#include "mrb_http2_server.h"
#include "mrb_http2_request.h"
#include "mrb_http2_data.h"
#include "mrb_http2_ssl.h"
#include "mrb_http2_error.c.h"
#include "mrb_http2_worker.h"

#include <event.h>
#include <event2/event.h>
#include <event2/bufferevent.h>
#include <event2/bufferevent_ssl.h>
#include <event2/listener.h>
#include <event2/keyvalq_struct.h>
#include <event2/util.h>
#include <event2/http.h>
#include <event2/http_compat.h>
#include <event2/http_struct.h>

#include "mruby/value.h"
#include "mruby/string.h"
#include "mruby/compile.h"

#include <sys/wait.h>
#include <sys/resource.h>
#include <sys/queue.h>
#include <unistd.h>

typedef struct {
  SSL_CTX *ssl_ctx;
  struct event_base *evbase;
  mrb_http2_server_t *server;
  mrb_http2_request_rec *r;
  mrb_value self;
} app_context;

typedef struct mrb_http2_request_body {
  char *data;
  int64_t len;
  size_t pos;
  unsigned int last:1;
} mrb_http2_request_body;

typedef struct http2_stream_data {
  struct http2_stream_data *prev, *next;
  char *request_path;
  char *request_args;
  mrb_http2_request_body *request_body;
  char *unparsed_uri;
  char *percent_encode_uri;
  char method[16];
  char scheme[8];
  char authority[1024];
  int32_t stream_id;
  int fd;
  int64_t readleft;
  nghttp2_nv nva[MRB_HTTP2_HEADER_MAX];
  size_t nvlen;
  struct evhttp_request *upstream_req;
} http2_stream_data;

typedef struct http2_session_data {
  http2_stream_data root;
  struct bufferevent *bev;
  app_context *app_ctx;
  nghttp2_session *session;
  char client_addr[NI_MAXHOST];
  mrb_http2_conn_rec *conn;
  struct event_base *upstream_base;
  struct evhttp_connection *upstream_conn;
} http2_session_data;

struct mrb_http2_upstream_client {
  http2_stream_data *stream_data;
  http2_session_data *session_data;
  nghttp2_session *session;
  app_context *app_ctx;
  struct evhttp_connection *conn;
};

static void mrb_http2_server_free(mrb_state *mrb, void *p)
{
  mrb_http2_data_t *data = (mrb_http2_data_t *)p;
  mrb_free(mrb, data->s->config);
  mrb_free(mrb, data->s);
  mrb_free(mrb, data->r);
  mrb_free(mrb, data);
  TRACER;
}

static const struct mrb_data_type mrb_http2_server_type = {
  "mrb_http2_server_t", mrb_http2_server_free,
};

//
//
// HTTP2::Server class
//
//

static void fixup_status_header(mrb_state *mrb, mrb_http2_request_rec *r);

static void callback_ruby_block(mrb_state *mrb, mrb_value self,
    unsigned int flag, const char *cbid, mruby_cb_list *list)
{
  mrb_value b;
  mrb_sym s;

  if (!flag || !cbid) {
    return;
  }

  s = mrb_intern_cstr(mrb, cbid);
  b = mrb_iv_get(mrb, self, s);
  TRACER;
  if (!mrb_nil_p(b)) {
    mrb_yield_argv(mrb, b, 0, NULL);
  TRACER;
    if (strcmp(cbid, "content_cb") == 0) {
  TRACER;
      mrb_iv_set(mrb, self, s, mrb_nil_value());
      list->content_cb = NULL;
    }
  }
}

static void mrb_http2_conn_rec_free(mrb_state *mrb,
    mrb_http2_conn_rec *conn)
{
  TRACER;
  mrb_free_unless_null(mrb, conn);
}

static void add_stream(http2_session_data *session_data,
    http2_stream_data *stream_data)
{
  stream_data->next = session_data->root.next;
  session_data->root.next = stream_data;
  stream_data->prev = &session_data->root;
  TRACER;
  if(stream_data->next) {
    stream_data->next->prev = stream_data;
  }
}

static void remove_stream(http2_session_data *session_data,
    http2_stream_data *stream_data)
{
  stream_data->prev->next = stream_data->next;
  TRACER;
  if(stream_data->next) {
    stream_data->next->prev = stream_data->prev;
  }
}

static http2_stream_data* create_http2_stream_data(mrb_state *mrb,
    http2_session_data *session_data, int32_t stream_id)
{
  http2_stream_data *stream_data;
  mrb_http2_server_t *server = session_data->app_ctx->server;
  mrb_http2_config_t *config = session_data->app_ctx->server->config;

  TRACER;
  stream_data = (http2_stream_data *)mrb_malloc(mrb,
      sizeof(http2_stream_data));
  memset(stream_data, 0, sizeof(http2_stream_data));
  stream_data->stream_id = stream_id;
  stream_data->fd = -1;
  stream_data->readleft = 0;
  stream_data->nvlen = 0;
  stream_data->request_body = NULL;
  stream_data->request_args = NULL;
  stream_data->request_path = NULL;
  stream_data->unparsed_uri = NULL;
  stream_data->percent_encode_uri = NULL;
  stream_data->method[0] = '\0';
  stream_data->scheme[0] = '\0';
  stream_data->authority[0] = '\0';
  stream_data->upstream_req = NULL;

  add_stream(session_data, stream_data);
  if (config->server_status) {
    server->worker->stream_requests_per_worker++;
    server->worker->active_stream++;
  }
  return stream_data;
}

static void delete_http2_stream_data(mrb_state *mrb,
    http2_session_data *session_data, http2_stream_data *stream_data)
{
  TRACER;
  if(stream_data->fd != -1) {
    close(stream_data->fd);
  }
  mrb_free(mrb, stream_data->unparsed_uri);
  mrb_free_unless_null(mrb, stream_data->percent_encode_uri);
  if (stream_data->request_args != NULL) {
    mrb_free(mrb, stream_data->request_path);
    mrb_free(mrb, stream_data->request_args);
  }
  if (stream_data->request_body != NULL) {
    stream_data->request_body->len = 0;
    stream_data->request_body->pos = 0;
    stream_data->request_body->last = 0;
    mrb_free(mrb, stream_data->request_body->data);
    mrb_free(mrb, stream_data->request_body);
  }
  if (stream_data->upstream_req != NULL) {
    evhttp_request_free(stream_data->upstream_req);
  }
  if (session_data->app_ctx->server->config->server_status) {
    session_data->app_ctx->server->worker->active_stream--;
  }
  mrb_free(mrb, stream_data);
}

static void delete_http2_session_data(http2_session_data *session_data)
{
  SSL *ssl;
  http2_stream_data *stream_data;
  mrb_state *mrb = session_data->app_ctx->server->mrb;
  mrb_http2_server_t *server = session_data->app_ctx->server;
  mrb_http2_config_t *config = session_data->app_ctx->server->config;

  TRACER;
  if (config->debug) {
    fprintf(stderr, "%s disconnected\n", session_data->client_addr);
  }
  nghttp2_session_del(session_data->session);
  if (config->tls) {
    ssl = bufferevent_openssl_get_ssl(session_data->bev);
    if(ssl) {
      SSL_set_shutdown(ssl, SSL_RECEIVED_SHUTDOWN);
      ERR_clear_error();
      SSL_shutdown(ssl);
    }
  }
  bufferevent_free(session_data->bev);
  for(stream_data = session_data->root.next; stream_data;) {
    http2_stream_data *next = stream_data->next;
    delete_http2_stream_data(mrb, session_data, stream_data);
    stream_data = next;
  }
  if (session_data->upstream_base != NULL) {
    event_base_free(session_data->upstream_base);
  }
  if (session_data->upstream_conn != NULL) {
    evhttp_connection_free(session_data->upstream_conn);
  }
  if (config->server_status) {
    server->worker->connected_sessions--;
  }
  mrb_http2_conn_rec_free(mrb, session_data->conn);
  mrb_free(mrb, session_data);
}

/* Serialize the frame and send (or buffer) the data to
   bufferevent. */
static int session_send(http2_session_data *session_data)
{
  int rv;

  TRACER;
  rv = nghttp2_session_send(session_data->session);
  if(rv != 0) {
    fprintf(stderr, "Fatal error: %s", nghttp2_strerror(rv));
    return -1;
  }
  TRACER;
  return 0;
}

#define MRB_HTTP2_TLS_PENDING_SIZE 1300

/* Read the data in the bufferevent and feed them into nghttp2 library
   function. Invocation of nghttp2_session_mem_recv() may make
   additional pending frames, so call session_send() at the end of the
   function. */
static int session_recv(http2_session_data *session_data)
{
  int rv;
  struct evbuffer *input = bufferevent_get_input(session_data->bev);
  size_t datalen = evbuffer_get_length(input);
  unsigned char *data = evbuffer_pullup(input, -1);

  TRACER;
  if (session_data->app_ctx->server->config->debug) {
    fprintf(stderr, "%s: datalen = %ld\n", __func__, datalen);
  }
  rv = nghttp2_session_mem_recv(session_data->session, data, datalen);
  if(rv < 0) {
    fprintf(stderr, "Fatal error: %s", nghttp2_strerror(rv));
    return -1;
  }
  evbuffer_drain(input, rv);
  TRACER;
  if(session_send(session_data) != 0) {
    return -1;
  }
  TRACER;
  return 0;
}

#define MRB_HTTP2_TLS_RECORD_SIZE 4096

static ssize_t server_send_callback(nghttp2_session *session,
    const uint8_t *data, size_t length, int flags, void *user_data)
{
  http2_session_data *session_data = (http2_session_data *)user_data;

  TRACER;

  /* Avoid excessive buffering in server side. */
  if(evbuffer_get_length(bufferevent_get_output(session_data->bev)) >=
     OUTPUT_WOULDBLOCK_THRESHOLD) {
    return NGHTTP2_ERR_WOULDBLOCK;
  }
  if (session_data->app_ctx->server->config->debug) {
    fprintf(stderr, "%s: datalen = %ld\n", __func__, length);
  }

  bufferevent_write(session_data->bev, data, length);
  TRACER;
  return length;
}

/* Returns int value of hex string character |c| */
static uint8_t hex_to_uint(uint8_t c)
{
  if('0' <= c && c <= '9') {
    return c - '0';
  }
  if('A' <= c && c <= 'F') {
    return c - 'A' + 10;
  }
  if('a' <= c && c <= 'f') {
    return c - 'a' + 10;
  }
  return 0;
}

/* Decodes percent-encoded byte string |value| with length |valuelen|
   and returns the decoded byte string in allocated buffer. The return
   value is NULL terminated. The caller must free the returned
   string. */
static char* percent_decode(mrb_state *mrb, const uint8_t *value,
    size_t valuelen)
{
  char *res;

  TRACER;
  res = (char *)mrb_malloc(mrb, valuelen + 1);
  if(valuelen > 3) {
    size_t i, j;
    for(i = 0, j = 0; i < valuelen - 2;) {
      if(value[i] != '%' ||
         !isxdigit(value[i + 1]) || !isxdigit(value[i + 2])) {
        res[j++] = value[i++];
        continue;
      }
      res[j++] = (hex_to_uint(value[i + 1]) << 4) + hex_to_uint(value[i + 2]);
      i += 3;
    }
    memcpy(&res[j], &value[i], 2);
    res[j + 2] = '\0';
  } else {
    memcpy(res, value, valuelen);
    res[valuelen] = '\0';
  }
  TRACER;
  return res;
}

static ssize_t upstream_read_callback(nghttp2_session *session,
    int32_t stream_id, uint8_t *buf, size_t length, uint32_t *data_flags,
    nghttp2_data_source *source, void *user_data)
{
  ssize_t nread;
  http2_stream_data *stream_data = source->ptr;
  struct evbuffer* upstream_buf;

  if (stream_data->upstream_req == NULL) {
    return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
  }
  upstream_buf = evhttp_request_get_input_buffer(stream_data->upstream_req);
  nread = evbuffer_remove(upstream_buf, buf, length);
  TRACER;

  if(nread == -1) {
    return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
  }

  stream_data->readleft -= nread;
  if(nread == 0 || stream_data->readleft == 0) {
    if (stream_data->readleft != 0) {
      return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
    }
    *data_flags |= NGHTTP2_DATA_FLAG_EOF;
  }
  TRACER;
  return nread;
}

static int send_upstream_response(app_context *app_ctx,
    nghttp2_session *session, nghttp2_nv *nva, size_t nvlen,
    http2_stream_data *stream_data)
{
  int rv;
  mrb_state *mrb = app_ctx->server->mrb;
  mrb_http2_request_rec *r = app_ctx->r;
  int i;

  nghttp2_data_provider data_prd;
  data_prd.source.ptr = stream_data;
  data_prd.read_callback = upstream_read_callback;

  if (app_ctx->server->config->debug) {
    for (i = 0; i < nvlen; i++) {
      debug_header(__func__, nva[i].name, nva[i].namelen, nva[i].value, nva[i].valuelen);
    }
  }

  TRACER;
  rv = nghttp2_submit_response(session, stream_data->stream_id, nva, nvlen,
      &data_prd);
  if(rv != 0) {
    fprintf(stderr, "Fatal error: %s", nghttp2_strerror(rv));
    mrb_http2_request_rec_free(mrb, r);
    return -1;
  }
  //
  // "set_logging_cb" callback ruby block
  //
  if (app_ctx->server->config->callback) {
    r->phase = MRB_HTTP2_SERVER_LOGGING;
    callback_ruby_block(mrb, app_ctx->self, app_ctx->server->config->callback,
        app_ctx->server->config->cb_list->logging_cb,
        app_ctx->server->config->cb_list);
  }

  mrb_http2_request_rec_free(mrb, r);
  TRACER;
  return 0;
}

static ssize_t file_read_callback(nghttp2_session *session,
    int32_t stream_id, uint8_t *buf, size_t length, uint32_t *data_flags,
    nghttp2_data_source *source, void *user_data)
{
  ssize_t nread;
  http2_stream_data *stream_data = source->ptr;

  while((nread = read(stream_data->fd, buf, length)) == -1 && errno == EINTR);
  TRACER;

  if(nread == -1) {
    return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
  }

  stream_data->readleft -= nread;
  if(nread == 0 || stream_data->readleft == 0) {
    if (stream_data->readleft != 0) {
      return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
    }
    *data_flags |= NGHTTP2_DATA_FLAG_EOF;
  }
  TRACER;
  return nread;
}

static int send_response(app_context *app_ctx, nghttp2_session *session,
    nghttp2_nv *nva, size_t nvlen, http2_stream_data *stream_data)
{
  int rv;
  mrb_state *mrb = app_ctx->server->mrb;
  mrb_http2_request_rec *r = app_ctx->r;
  int i;

  nghttp2_data_provider data_prd;
  data_prd.source.ptr = stream_data;
  data_prd.read_callback = file_read_callback;

  if (app_ctx->server->config->debug) {
    for (i = 0; i < nvlen; i++) {
      debug_header(__func__, nva[i].name, nva[i].namelen, nva[i].value, nva[i].valuelen);
    }
  }

  TRACER;
  rv = nghttp2_submit_response(session, stream_data->stream_id, nva, nvlen,
      &data_prd);
  if(rv != 0) {
    fprintf(stderr, "Fatal error: %s", nghttp2_strerror(rv));
    mrb_http2_request_rec_free(mrb, r);
    return -1;
  }
  //
  // "set_logging_cb" callback ruby block
  //
  if (app_ctx->server->config->callback) {
    r->phase = MRB_HTTP2_SERVER_LOGGING;
    callback_ruby_block(mrb, app_ctx->self, app_ctx->server->config->callback,
        app_ctx->server->config->cb_list->logging_cb, app_ctx->server->config->cb_list);
  }

  mrb_http2_request_rec_free(mrb, r);
  TRACER;
  return 0;
}

static void set_status_record(mrb_http2_request_rec *r, int status)
{
  r->status = status;
  snprintf(r->status_line, 4, "%d", r->status);
}

static int error_reply(app_context *app_ctx, nghttp2_session *session,
    http2_stream_data *stream_data)
{
  mrb_http2_request_rec *r = app_ctx->r;
  mrb_http2_config_t *config = app_ctx->server->config;
  mrb_state *mrb = app_ctx->server->mrb;
  int rv;
  int pipefd[2];
  int64_t size;
  const char *msg;

  fixup_status_header(mrb, r);

  // create headers for HTTP/2
  MRB_HTTP2_CREATE_NV_CS(mrb, &r->reshdrs[r->reshdrslen], "date", r->date);
  r->reshdrslen += 1;
  MRB_HTTP2_CREATE_NV_CS(mrb, &r->reshdrs[r->reshdrslen], "server", config->server_name);
  r->reshdrslen += 1;
  MRB_HTTP2_CREATE_NV_CS(mrb, &r->reshdrs[r->reshdrslen], "content-type", "text/html; charset=utf-8");
  r->reshdrslen += 1;

  TRACER;
  rv = pipe(pipefd);
  if(rv != 0) {
    mrb_warn(app_ctx->server->mrb, "Could not pipefd");
    rv = nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE,
        stream_data->stream_id, NGHTTP2_INTERNAL_ERROR);
    if(rv != 0) {
      fprintf(stderr, "Fatal error: %s", nghttp2_strerror(rv));
      return -1;
    }
    return 0;
  }

  msg = mrb_http2_error_message(r->status);
  size = strlen(msg);
  rv = write(pipefd[1], msg, size);

  close(pipefd[1]);
  stream_data->fd = pipefd[0];
  stream_data->readleft = size;

  // set content-length: max 10^64
  snprintf(r->content_length, 64, "%ld", size);
  MRB_HTTP2_CREATE_NV_CS(mrb, &r->reshdrs[r->reshdrslen], "content-length", r->content_length);
  r->reshdrslen += 1;

  //
  // "set_fixups_cb" callback ruby block
  //
  if (config->callback) {
    r->phase = MRB_HTTP2_SERVER_FIXUPS;
    callback_ruby_block(mrb, app_ctx->self, config->callback,
        config->cb_list->fixups_cb, config->cb_list);
  }

  TRACER;
  if(send_response(app_ctx, session, r->reshdrs, r->reshdrslen, stream_data) != 0) {
    close(pipefd[0]);
    if (r->reshdrslen >0) {
      mrb_http2_free_nva(mrb, r->reshdrs, r->reshdrslen);
      r->reshdrslen = 0;
    }
    return -1;
  }
  if (r->reshdrslen >0) {
    mrb_http2_free_nva(mrb, r->reshdrs, r->reshdrslen);
    r->reshdrslen = 0;
  }

  TRACER;
  return 0;
}

static int upstream_reply(app_context *app_ctx, nghttp2_session *session,
    http2_stream_data *stream_data)
{
  mrb_http2_request_rec *r = app_ctx->r;
  mrb_http2_config_t *config = app_ctx->server->config;
  mrb_state *mrb = app_ctx->server->mrb;

  TRACER;
  //
  // "set_fixups_cb" callback ruby block
  //
  if (config->callback) {
    r->phase = MRB_HTTP2_SERVER_FIXUPS;
    callback_ruby_block(mrb, app_ctx->self, config->callback,
        config->cb_list->fixups_cb, config->cb_list);
  }

  if(send_upstream_response(app_ctx, session, r->reshdrs, r->reshdrslen, stream_data) != 0) {
    close(stream_data->fd);
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  }
  TRACER;
  return 0;
}

void http_request_done(struct evhttp_request *req, void *user_data)
{
  struct mrb_http2_upstream_client *c = user_data;
  mrb_state *mrb = c->app_ctx->server->mrb;
  mrb_http2_request_rec *r = c->app_ctx->r;
  int find_via = 0;

  struct evkeyval *header;
  struct evkeyvalq *input_headers;

  if (req != NULL) {
    input_headers = evhttp_request_get_input_headers(req);
  } else {
    c->stream_data->upstream_req = req;
    event_base_loopexit(c->session_data->upstream_base, NULL);
    return;
  }

  TRACER;
  set_status_record(r, req->response_code);
  fixup_status_header(mrb, r);

  TAILQ_FOREACH(header, input_headers, next)
  {
    if (memcmp("Via", header->key, sizeof("Via") - 1) == 0) {
      MRB_HTTP2_CREATE_NV_CSCS(mrb, &r->reshdrs[r->reshdrslen], header->key,
          c->app_ctx->server->config->server_name);
      r->reshdrslen += 1;
      find_via = 1;
    } else if (strlen(header->key) == sizeof("Connection") - 1 && memcmp("Connection", header->key, sizeof("Connection") - 1) == 0) {
      // do nothing
    } else if (strlen(header->key) == sizeof("Transfer-Encoding") - 1 && memcmp("Transfer-Encoding", header->key, sizeof("Transfer-Encoding") - 1) == 0) {
      // do nothing
    } else if (strlen(header->key) == sizeof("Keep-Alive") - 1 && memcmp("Keep-Alive", header->key, sizeof("Keep-Alive") - 1) == 0) {
      // do nothing
    } else if (strlen(header->key) == sizeof("Proxy-Connection") - 1 && memcmp("Proxy-Connection", header->key, sizeof("Proxy-Connection") - 1) == 0) {
      // do nothing
    } else if (strlen(header->key) == sizeof("Upgrade") - 1 && memcmp("Upgrade", header->key, sizeof("Upgrade") - 1) == 0) {
      // do nothing
    } else if (strlen(header->key) == sizeof("Location") - 1 && memcmp("Location", header->key, sizeof("Location") - 1) == 0) {
      char *buf;
      // "+ 1" is to http[s]
      buf = alloca(strlen(header->value) - strlen(r->upstream->unparsed_host) + strlen(r->authority) + 1);
      memcpy(buf, header->value, strlen(header->value) + 1);
      mrb_http2_strrep(buf, r->upstream->unparsed_host, r->authority);

      // scheme checke
      // TODO: http(front) <=> https(back) check
      if (strlen(r->scheme) == 5 && memcmp(buf, r->scheme, strlen(r->scheme)) != 0) {
        mrb_http2_strrep(buf, "http", r->scheme);
      }

      MRB_HTTP2_CREATE_NV_CSCS(mrb, &r->reshdrs[r->reshdrslen], header->key,
          buf);
      r->reshdrslen += 1;
    } else {
      MRB_HTTP2_CREATE_NV_CSCS(mrb, &r->reshdrs[r->reshdrslen], header->key,
          header->value);
      r->reshdrslen += 1;
    }
  }
  if (!find_via) {
    MRB_HTTP2_CREATE_NV_CS(mrb, &r->reshdrs[r->reshdrslen], "via",
        c->app_ctx->server->config->server_name);
    r->reshdrslen += 1;
  }

  c->stream_data->readleft = req->body_size;
  snprintf(r->content_length, 64, "%ld", req->body_size);
  c->stream_data->upstream_req = req;
  event_base_loopexit(c->session_data->upstream_base, NULL);

  TRACER;
}

static int read_upstream_response(http2_session_data *session_data, app_context *app_ctx, nghttp2_session *session,
    http2_stream_data *stream_data)
{
  struct evhttp_request *req;
  struct mrb_http2_upstream_client *c;
  mrb_http2_request_rec *r = app_ctx->r;
  mrb_state *mrb = app_ctx->server->mrb;
  size_t len;
  int i;
  int method;
  char *cookiebuf = NULL;
  size_t cookiebuflen = 0;
  size_t cookiebaselen = 0;
  char root_path[] = "/";

  TRACER;
  if (session_data->upstream_base == NULL) {
    session_data->upstream_base = event_base_new();
  }
  if (session_data->upstream_conn == NULL) {
    session_data->upstream_conn = evhttp_connection_base_new(session_data->upstream_base, NULL, r->upstream->host, r->upstream->port);
  }
  if (session_data->upstream_conn == NULL) {
    fprintf(stderr, "evhttp_connection_base_new failed");
    return -1;
  }

  c = (struct mrb_http2_upstream_client *)alloca(sizeof(struct mrb_http2_upstream_client));
  c->app_ctx = app_ctx;
  c->stream_data = stream_data;
  c->session = session;
  c->session_data = session_data;

  req = evhttp_request_new(http_request_done, c);
  if (req == NULL) {
    fprintf(stderr, "evhttp_request_new failed");
    return -1;
  }
  evhttp_request_own(req);

  len = strlen(r->upstream->host) + sizeof(":65525");
  r->upstream->unparsed_host = alloca(len);
  snprintf(r->upstream->unparsed_host, len, "%s:%d", r->upstream->host, r->upstream->port);
  r->upstream->unparsed_host[len] = '\0';

  evhttp_add_header(req->output_headers, "Host", r->upstream->unparsed_host);
  req->major = r->upstream->proto_major;
  req->minor = r->upstream->proto_minor;
  if (!r->upstream->keepalive && r->upstream->proto_minor == 1) {
    evhttp_add_header(req->output_headers, "Connection", "close");
  }

  // r->reqhdr don't include HTTP/2 specified headders
  for (i = 0; i < r->reqhdrlen; i++) {
    char keybuf[4096], valbuf[4096];
    size_t len;

    if (memcmp("cookie", r->reqhdr[i].name, 6) == 0) {
      cookiebaselen = cookiebuflen;
      cookiebuflen += r->reqhdr[i].valuelen + 2;
      cookiebuf = mrb_realloc(mrb, cookiebuf, cookiebuflen);
      memcpy(cookiebuf + cookiebaselen, r->reqhdr[i].value, r->reqhdr[i].valuelen);
      memcpy(cookiebuf + cookiebaselen + r->reqhdr[i].valuelen, "; ", 2);
    } else {
      len = r->reqhdr[i].namelen;
      if (len > 4096)
        len = 4096;
      memcpy(keybuf, r->reqhdr[i].name, len);
      keybuf[len] = '\0';

      len = r->reqhdr[i].valuelen;
      if (len > 4096)
        len = 4096;
      memcpy(valbuf, r->reqhdr[i].value, len);
      valbuf[len] = '\0';

      evhttp_add_header(req->output_headers, keybuf, valbuf);
    }
  }
  if (cookiebuf != NULL) {
    cookiebuf[cookiebuflen] = '\0';
    evhttp_add_header(req->output_headers, "Cookie", cookiebuf);
    mrb_free(mrb, cookiebuf);
  }

  if (app_ctx->server->config->debug) {
    int i = 0;
    struct evkeyval *header;
    struct evkeyvalq *output_headers = evhttp_request_get_output_headers(req);
    fprintf(stderr, "== DBUEG: request header at proxy START\n");
    TAILQ_FOREACH(header, output_headers, next)
    {
      fprintf(stderr, "%s: nva[%d]={name=%s, value=%s}\n", __func__, i,
          header->key, header->value);
      i++;
    }
    fprintf(stderr, "== DBUEG: request header at proxy END\n");
  }

  // POST check
  if (memcmp(r->method, "POST", 4) == 0) {
    if (r->request_body != NULL) {
      evbuffer_add(req->output_buffer, r->request_body, strlen(r->request_body));
    }
    method = EVHTTP_REQ_POST;
    if (app_ctx->server->config->debug) {
      fprintf(stderr, "== DEBUG: send POST method to upstream server\n");
      fprintf(stderr, "== DEBUG: request body=%s\n", r->request_body);
    }
  } else {
    method = EVHTTP_REQ_GET;
    if (app_ctx->server->config->debug) {
      fprintf(stderr, "== DEBUG: send GET method to upstream server\n");
    }
  }
  if (r->upstream->uri == NULL) {
    r->upstream->uri = root_path;
  }

  if (evhttp_make_request(session_data->upstream_conn, req, method, r->upstream->uri) == -1) {
    evhttp_request_free(req);
    fprintf(stderr, "evhttp_connection_base_new failed");
    return -1;
  }

  evhttp_connection_set_timeout(req->evcon, r->upstream->timeout);
  event_base_dispatch(session_data->upstream_base);
  if (stream_data->upstream_req == NULL) {
    return -1;
  }
  TRACER;

  return 0;
}

static int content_cb_reply(app_context *app_ctx, nghttp2_session *session,
    http2_stream_data *stream_data)
{
  mrb_http2_request_rec *r = app_ctx->r;
  mrb_http2_config_t *config = app_ctx->server->config;
  mrb_state *mrb = app_ctx->server->mrb;

  int rv;
  int pipefd[2];
  int64_t size;

  TRACER;
  rv = pipe(pipefd);
  if(rv != 0) {
    rv = nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE,
        stream_data->stream_id, NGHTTP2_INTERNAL_ERROR);
    if(rv != 0) {
      fprintf(stderr, "Fatal error: %s", nghttp2_strerror(rv));
      return -1;
    }
    return 0;
  }

  r->write_fd = pipefd[1];

  //
  // "set_content" callback ruby block
  //
  if (config->callback) {
    r->phase = MRB_HTTP2_SERVER_CONTENT;
    callback_ruby_block(mrb, app_ctx->self, config->callback,
        config->cb_list->content_cb, config->cb_list);
  }

  fixup_status_header(mrb, r);

  // create headers for HTTP/2
  MRB_HTTP2_CREATE_NV_CS(mrb, &r->reshdrs[r->reshdrslen], "server", config->server_name);
  r->reshdrslen += 1;
  MRB_HTTP2_CREATE_NV_CS(mrb, &r->reshdrs[r->reshdrslen], "date", r->date);
  r->reshdrslen += 1;

  if (r->status >= 200 && r->status < 300) {
    size = r->write_size;
  } else {
    const char *msg = mrb_http2_error_message(r->status);
    size = strlen(msg);
    rv = write(pipefd[1], msg, size);
  }

  close(pipefd[1]);
  stream_data->fd = pipefd[0];
  stream_data->readleft = size;
  TRACER;

  // set content-length: max 10^64
  snprintf(r->content_length, 64, "%ld", size);
  MRB_HTTP2_CREATE_NV_CS(mrb, &r->reshdrs[r->reshdrslen], "content-length", r->content_length);
  r->reshdrslen += 1;

  //
  // "set_fixups_cb" callback ruby block
  //
  if (config->callback) {
    r->phase = MRB_HTTP2_SERVER_FIXUPS;
    callback_ruby_block(mrb, app_ctx->self, config->callback,
        config->cb_list->fixups_cb, config->cb_list);
  }

  if(send_response(app_ctx, session, r->reshdrs, r->reshdrslen, stream_data) != 0) {
    close(pipefd[0]);
    if (r->reshdrslen >0) {
      mrb_http2_free_nva(mrb, r->reshdrs, r->reshdrslen);
      r->reshdrslen = 0;
    }
    return -1;
  }
  if (r->reshdrslen >0) {
    mrb_http2_free_nva(mrb, r->reshdrs, r->reshdrslen);
    r->reshdrslen = 0;
  }
  TRACER;
  return 0;
}

static int mruby_reply(app_context *app_ctx, nghttp2_session *session,
    http2_stream_data *stream_data)
{
  mrb_http2_request_rec *r = app_ctx->r;
  mrb_http2_config_t *config = app_ctx->server->config;
  mrb_state *mrb = app_ctx->server->mrb;

  int rv;
  int pipefd[2];
  mrb_state *mrb_inner;
  struct mrb_parser_state* p = NULL;
  struct RProc *proc = NULL;
  FILE *rfp;
  mrbc_context *c;
  int64_t size;

  if (r->shared_mruby) {
    // share one mrb_state
    mrb_inner = mrb;
  } else if (r->mruby) {
    // when use new mrb_state
    mrb_inner = mrb_open();
  } else {
    mrb_inner = mrb_open();
  }


  rfp = fopen(r->filename, "r");
  if (rfp == NULL) {
    fprintf(stderr, "mruby file opened failed: %s", r->filename);
    return -1;
  }

  TRACER;
  rv = pipe(pipefd);
  if(rv != 0) {
    rv = nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE,
        stream_data->stream_id, NGHTTP2_INTERNAL_ERROR);
    if(rv != 0) {
      fprintf(stderr, "Fatal error: %s", nghttp2_strerror(rv));
      return -1;
    }
    return 0;
  }

  r->write_fd = pipefd[1];
  c = mrbc_context_new(mrb_inner);
  mrbc_filename(mrb_inner, c, r->filename);
  p = mrb_parse_file(mrb_inner, rfp, c);
  fclose(rfp);
  proc = mrb_generate_code(mrb_inner, p);
  mrb_pool_close(p->pool);
  mrb_run(mrb_inner, proc, app_ctx->self);

  if (mrb_inner->exc) {
    mrb_print_error(mrb_inner);
    set_status_record(r, HTTP_SERVICE_UNAVAILABLE);
    mrb_inner->exc = 0;
  } else {
    set_status_record(r, HTTP_OK);
  }
  mrbc_context_free(mrb_inner, c);

  // when use new mrb_state
  if (r->mruby) {
    mrb_close(mrb_inner);
  }

  fixup_status_header(mrb, r);

  // create headers for HTTP/2
  MRB_HTTP2_CREATE_NV_CS(mrb, &r->reshdrs[r->reshdrslen], "server", config->server_name);
  r->reshdrslen += 1;
  MRB_HTTP2_CREATE_NV_CS(mrb, &r->reshdrs[r->reshdrslen], "date", r->date);
  r->reshdrslen += 1;
  MRB_HTTP2_CREATE_NV_CS(mrb, &r->reshdrs[r->reshdrslen], "last-modified", r->last_modified);
  r->reshdrslen += 1;

  if (r->status >= 200 && r->status < 300) {
    size = r->write_size;
  } else {
    const char *msg = mrb_http2_error_message(r->status);
    size = strlen(msg);
    rv = write(pipefd[1], msg, size);
  }

  close(pipefd[1]);
  stream_data->fd = pipefd[0];
  stream_data->readleft = size;
  TRACER;

  // set content-length: max 10^64
  snprintf(r->content_length, 64, "%ld", size);
  MRB_HTTP2_CREATE_NV_CS(mrb, &r->reshdrs[r->reshdrslen], "content-length", r->content_length);
  r->reshdrslen += 1;

  //
  // "set_fixups_cb" callback ruby block
  //
  if (config->callback) {
    r->phase = MRB_HTTP2_SERVER_FIXUPS;
    callback_ruby_block(mrb, app_ctx->self, config->callback,
        config->cb_list->fixups_cb, config->cb_list);
  }

  if(send_response(app_ctx, session, r->reshdrs, r->reshdrslen, stream_data) != 0) {
    if(r->reshdrslen > 0) {
      mrb_http2_free_nva(mrb, r->reshdrs, r->reshdrslen);
      r->reshdrslen = 0;
    }
    close(pipefd[0]);
    return -1;
  }
  if(r->reshdrslen > 0) {
    mrb_http2_free_nva(mrb, r->reshdrs, r->reshdrslen);
    r->reshdrslen = 0;
  }
  TRACER;
  return 0;
}

/* Inspired by h2o header lookup.  https://github.com/h2o/h2o */
/* Reference as nghttp2 header lookup.  https://github.com/tatsuhiro-t/nghttp2 */

static int memeq(const void *a, const void *b, size_t n) {
  return memcmp(a, b, n) == 0;
}

#define streq(A, B, N) ((sizeof((A)) - 1) == (N) && memeq((A), (B), (N)))

typedef enum {
  NGHTTP2_TOKEN__AUTHORITY,
  NGHTTP2_TOKEN__METHOD,
  NGHTTP2_TOKEN__PATH,
  NGHTTP2_TOKEN__SCHEME,
  NGHTTP2_TOKEN_HOST,
} nghttp2_token;

static int lookup_token(const uint8_t *name, size_t namelen) {
  switch (namelen) {
  case 5:
    switch (name[namelen - 1]) {
    case 'h':
      if (streq(":pat", name, 4)) {
        return NGHTTP2_TOKEN__PATH;
      }
      break;
    }
    break;
  case 7:
    switch (name[namelen - 1]) {
    case 'd':
      if (streq(":metho", name, 6)) {
        return NGHTTP2_TOKEN__METHOD;
      }
      break;
    case 'e':
      if (streq(":schem", name, 6)) {
        return NGHTTP2_TOKEN__SCHEME;
      }
      break;
    }
    break;
  case 10:
    switch (name[namelen - 1]) {
    case 'y':
      if (streq(":authorit", name, 9)) {
        return NGHTTP2_TOKEN__AUTHORITY;
      }
      break;
    }
    break;
  }
  return -1;
}

static int server_on_header_callback(nghttp2_session *session,
    const nghttp2_frame *frame, const uint8_t *name, size_t namelen,
    const uint8_t *value, size_t valuelen, uint8_t flags, void *user_data)
{
  http2_session_data *session_data = (http2_session_data *)user_data;
  mrb_state *mrb = session_data->app_ctx->server->mrb;
  mrb_http2_config_t *config = session_data->app_ctx->server->config;

  http2_stream_data *stream_data;
  nghttp2_nv nv;

  if (frame->hd.type != NGHTTP2_HEADERS || frame->headers.cat != NGHTTP2_HCAT_REQUEST) {
    return 0;
  }

  stream_data = nghttp2_session_get_stream_user_data(session,
      frame->hd.stream_id);
  if(!stream_data) {
    return 0;
  }

  if (session_data->app_ctx->server->config->debug) {
    debug_header(__func__, name, namelen, value, valuelen);
  }

  switch (lookup_token(name, namelen)) {
    size_t j;
  case NGHTTP2_TOKEN__AUTHORITY:
    memcpy(stream_data->authority, value, valuelen);
    stream_data->authority[valuelen] = '\0';
    return 0;

  case NGHTTP2_TOKEN__METHOD:
    memcpy(stream_data->method, value, valuelen);
    stream_data->method[valuelen] = '\0';
    return 0;

  case NGHTTP2_TOKEN__SCHEME:
    memcpy(stream_data->scheme, value, valuelen);
    stream_data->scheme[valuelen] = '\0';
    return 0;

  case NGHTTP2_TOKEN__PATH:
    if (config->upstream) {
      stream_data->percent_encode_uri = mrb_http2_strcopy(mrb, (const char *)value, valuelen);
    }
    stream_data->unparsed_uri = percent_decode(mrb, value, valuelen);
    for(j = 0; j < valuelen && value[j] != '?'; ++j);
    if (j == valuelen) {
      stream_data->request_args = NULL;
      stream_data->request_path = stream_data->unparsed_uri;
    } else {
      stream_data->request_path = percent_decode(mrb, value, j);
      stream_data->request_args = percent_decode(mrb, value + j, valuelen - j);
    }
    return 0;

  default:
    break;
  }

  // create nv and add stream_data->nva except for HTTP/2 specified headers
  mrb_http2_create_nv(mrb, &nv, name, namelen, value, valuelen);
  stream_data->nvlen = mrb_http2_add_nv(stream_data->nva,
      stream_data->nvlen, &nv);

  return 0;
}

static int server_on_begin_headers_callback(nghttp2_session *session,
    const nghttp2_frame *frame, void *user_data)
{
  http2_session_data *session_data = (http2_session_data *)user_data;

  http2_stream_data *stream_data;

  TRACER;
  if(frame->hd.type != NGHTTP2_HEADERS ||
     frame->headers.cat != NGHTTP2_HCAT_REQUEST) {
    return 0;
  }
  stream_data = create_http2_stream_data(session_data->app_ctx->server->mrb,
      session_data, frame->hd.stream_id);
  nghttp2_session_set_stream_user_data(session, frame->hd.stream_id,
      stream_data);

  TRACER;
  return 0;
}

/* Minimum check for directory traversal. Returns nonzero if it is
   safe. */
static int check_path(const char *path) {
  size_t len = strlen(path);
  return path[0] == '/' && strchr(path, '\\') == NULL &&
         strstr(path, "/../") == NULL && strstr(path, "/./") == NULL &&
         (len < 3 || memcmp(path + len - 3, "/..", 3) != 0) &&
         (len < 2 || memcmp(path + len - 2, "/.", 2) != 0);
}

static void fixup_status_header(mrb_state *mrb, mrb_http2_request_rec *r)
{
  int i = mrb_http2_get_nv_id(r->reshdrs, r->reshdrslen, ":status");

  if (r->reshdrslen == 0) {
    MRB_HTTP2_CREATE_NV_CS(mrb, &r->reshdrs[r->reshdrslen], ":status", r->status_line);
    r->reshdrslen += 1;
    return;
  }

  if (i == MRB_HTTP2_HEADER_NOT_FOUND && r->reshdrslen > 0) {
    mrb_http2_create_nv(mrb, &r->reshdrs[r->reshdrslen], r->reshdrs[0].name,
        r->reshdrs[0].namelen, r->reshdrs[0].value, r->reshdrs[0].valuelen);
    r->reshdrslen += 1;
    MRB_HTTP2_CREATE_NV_CS(mrb, &r->reshdrs[0], ":status", r->status_line);
  } else if (i > 0) {
    mrb_http2_create_nv(mrb, &r->reshdrs[r->reshdrslen], r->reshdrs[0].name,
        r->reshdrs[0].namelen, r->reshdrs[0].value, r->reshdrs[0].valuelen);
    r->reshdrslen += 1;
    mrb_http2_create_nv(mrb, &r->reshdrs[0], r->reshdrs[i].name,
        r->reshdrs[i].namelen, r->reshdrs[i].value, r->reshdrs[i].valuelen);
  }
}

static int mrb_http2_send_custom_response(app_context *app_ctx,
    nghttp2_session *session, http2_stream_data *stream_data) {

  mrb_http2_request_rec *r = app_ctx->r;
  mrb_http2_config_t *config = app_ctx->server->config;
  mrb_state *mrb = app_ctx->server->mrb;

  if (r->status == 0) {
    set_status_record(r, HTTP_OK);
  }

  fixup_status_header(mrb, r);

  MRB_HTTP2_CREATE_NV_CS(mrb, &r->reshdrs[r->reshdrslen], "server", app_ctx->server->config->server_name);
  r->reshdrslen += 1;
  MRB_HTTP2_CREATE_NV_CS(mrb, &r->reshdrs[r->reshdrslen], "date", r->date);
  r->reshdrslen += 1;
  MRB_HTTP2_CREATE_NV_CS(mrb, &r->reshdrs[r->reshdrslen], "content-length", r->content_length);
  r->reshdrslen += 1;
  MRB_HTTP2_CREATE_NV_CS(mrb, &r->reshdrs[r->reshdrslen], "last-modified", r->last_modified);
  r->reshdrslen += 1;

  //
  // "set_fixups_cb" callback ruby block
  //
  if (config->callback) {
    r->phase = MRB_HTTP2_SERVER_FIXUPS;
    callback_ruby_block(mrb, app_ctx->self, config->callback,
        config->cb_list->fixups_cb, config->cb_list);
  }

  if(send_response(app_ctx, session, r->reshdrs, r->reshdrslen, stream_data) != 0) {
    close(stream_data->fd);
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  }
  return 0;
}

static int mrb_http2_send_200_response(app_context *app_ctx,
    nghttp2_session *session, http2_stream_data *stream_data) {

  int i;
  mrb_http2_request_rec *r = app_ctx->r;
  mrb_http2_config_t *config = app_ctx->server->config;
  mrb_state *mrb = app_ctx->server->mrb;
  nghttp2_nv hdrs[] = {
    MAKE_NV(":status", "200"),
    MAKE_NV_CS("server", app_ctx->server->config->server_name),
    MAKE_NV_CS("date", r->date),
    MAKE_NV_CS("content-length", r->content_length),
    MAKE_NV_CS("last-modified", r->last_modified)
  };

  r->reshdrslen = ARRLEN(hdrs);
  for (i = 0; i < r->reshdrslen; i++) {
    r->reshdrs[i] = hdrs[i];
  }
  r->status = 200;

  //
  // "set_fixups_cb" callback ruby block
  //
  if (config->callback) {
    r->phase = MRB_HTTP2_SERVER_FIXUPS;
    callback_ruby_block(mrb, app_ctx->self, config->callback,
        config->cb_list->fixups_cb, config->cb_list);
  }

  if(send_response(app_ctx, session, r->reshdrs, r->reshdrslen, stream_data) != 0) {
    r->reshdrslen = 0;
    close(stream_data->fd);
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  }
  r->reshdrslen = 0;
  return 0;
}

static int mrb_http2_process_request(nghttp2_session *session,
    http2_session_data *session_data, http2_stream_data *stream_data)
{
  int fd;
  struct stat finfo;
  time_t now = time(NULL);
  mrb_http2_request_rec *r = session_data->app_ctx->r;
  mrb_http2_config_t *config = session_data->app_ctx->server->config;
  mrb_state *mrb = session_data->app_ctx->server->mrb;

  //
  // Request process phase
  //

  // cached time string created strftime()
  // create r->date for error_reply
  if (config->callback) {
    r->phase = MRB_HTTP2_SERVER_READ_REQUEST;
  }
  if (now != r->prev_req_time) {
    r->prev_req_time = now;
    set_http_date_str(&now, r->date);
  }

  // get connection record
  r->conn = session_data->conn;

  // get requset header table and table length
  r->reqhdr = stream_data->nva;
  r->reqhdrlen = stream_data->nvlen;

  if (config->debug) {
    int i;
    for (i = 0; i < stream_data->nvlen; i++) {
      debug_header(__func__, stream_data->nva[i].name, stream_data->nva[i].namelen, stream_data->nva[i].value, stream_data->nva[i].valuelen);
    }
  }

  TRACER;
  if(!stream_data->request_path) {
    set_status_record(r, HTTP_SERVICE_UNAVAILABLE);
    if(error_reply(session_data->app_ctx, session, stream_data) != 0) {
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    return 0;
  }
  if (config->debug) {
    fprintf(stderr, "from %s to %s %s %s\n", session_data->client_addr,
        stream_data->authority, stream_data->method, stream_data->request_path);
  }
  TRACER;
  if(!check_path(stream_data->request_path)) {
    if (config->debug) {
      fprintf(stderr, "%s invalid request_path: %s\n",
          session_data->client_addr, stream_data->request_path);
    }
    set_status_record(r, HTTP_SERVICE_UNAVAILABLE);
    if(error_reply(session_data->app_ctx, session, stream_data) != 0) {
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    return 0;
  }

  // r-> will free at request_rec_free
  r->filename = mrb_http2_strcat(mrb, config->document_root,
      stream_data->request_path);

  r->authority = stream_data->authority;
  r->scheme = stream_data->scheme;
  r->method = stream_data->method;
  r->unparsed_uri = stream_data->unparsed_uri;
  r->percent_encode_uri = stream_data->percent_encode_uri;
  r->uri = stream_data->request_path;
  r->args = stream_data->request_args;

  if (stream_data->request_body != NULL) {
    r->request_body = stream_data->request_body->data;
  } else {
    r->request_body = NULL;
  }

  if (config->debug) {
    fprintf(stderr, "=== process request information start ===\n");
    fprintf(stderr, "percent_encode_uri: %s\n", r->percent_encode_uri);
    fprintf(stderr, "unparsed_uri: %s\n", r->unparsed_uri);
    fprintf(stderr, "uri: %s\n", r->uri);
    fprintf(stderr, "request_body: %s\n", r->request_body);
    fprintf(stderr, "args: %s\n", r->args);
    fprintf(stderr, "filename: %s\n", r->filename);
    fprintf(stderr, "hostname: %s\n", r->authority);
    fprintf(stderr, "scheme: %s\n", r->scheme);
    fprintf(stderr, "method: %s\n", r->method);
    fprintf(stderr, "client_addr: %s\n", session_data->client_addr);
    fprintf(stderr, "document_root: %s\n", config->document_root);
    fprintf(stderr, "=== process request information end ===\n");
  }

  //
  // "set_map_to_storage" callback ruby block
  //
  if (config->callback) {
    r->phase = MRB_HTTP2_SERVER_MAP_TO_STORAGE;
    callback_ruby_block(mrb, session_data->app_ctx->self, config->callback,
        config->cb_list->map_to_storage_cb, config->cb_list);
  }

  if (config->debug) {
    fprintf(stderr, "%s %s is mapped to %s\n", session_data->client_addr,
        r->uri, r->filename);
  }

  //
  // "set_access_checker" callback ruby block
  //
  if (config->callback) {
    r->phase = MRB_HTTP2_SERVER_ACCESS_CHECKER;
    callback_ruby_block(mrb, session_data->app_ctx->self, config->callback,
        config->cb_list->access_checker_cb, config->cb_list);
  }

  // check whether set status or not on access_checker callback
  if (r->status && r->status != HTTP_OK) {
    if(error_reply(session_data->app_ctx, session, stream_data) != 0) {
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    return 0;
  }

  // check proxy config
  if (config->upstream && r->upstream && r->upstream->host) {
    if (config->debug) {
      fprintf(stderr, "found upstream: server:%s:%d uri:%s\n",
          r->upstream->host, r->upstream->port, r->upstream->uri);
    }
    if (read_upstream_response(session_data, session_data->app_ctx, session, stream_data) != 0) {
      return  NGHTTP2_ERR_CALLBACK_FAILURE;
    }

    if (upstream_reply(session_data->app_ctx, session, stream_data) != 0) {
      return  NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    return 0;
  }

  // run mruby script
  if (r->mruby || r->shared_mruby) {
    set_status_record(r, HTTP_OK);
    if(mruby_reply(session_data->app_ctx, session, stream_data) != 0) {
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    return 0;
  }

  // hook content_cb
  if (config->callback && config->cb_list->content_cb) {
    set_status_record(r, HTTP_OK);
    if(content_cb_reply(session_data->app_ctx, session, stream_data) != 0) {
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    return 0;
  }

  // static contents response
  fd = open(r->filename, O_RDONLY);

  TRACER;
  if(fd == -1) {
    set_status_record(r, HTTP_NOT_FOUND);
    if(error_reply(session_data->app_ctx, session, stream_data) != 0) {
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    return 0;
  }

  stream_data->fd = fd;
  //set_status_record(r, HTTP_OK);

  TRACER;
  if (fstat(fd, &finfo) != 0) {
    set_status_record(r, HTTP_NOT_FOUND);
    if(error_reply(session_data->app_ctx, session, stream_data) != 0) {
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    return 0;
  }
  r->finfo = &finfo;

  // cached time string created strftime()
  if (r->finfo->st_mtime != r->prev_last_modified) {
    r->prev_last_modified = r->finfo->st_mtime;
    set_http_date_str(&r->finfo->st_mtime, r->last_modified);
  }

  // set content-length: max 10^64
  snprintf(r->content_length, 64, "%ld", r->finfo->st_size);
  stream_data->readleft = r->finfo->st_size;

  TRACER;
  if (r->reshdrslen > 0) {
    return mrb_http2_send_custom_response(session_data->app_ctx, session,
      stream_data);
  } else {
    return mrb_http2_send_200_response(session_data->app_ctx, session,
        stream_data);
  }
}

static int server_on_frame_recv_callback(nghttp2_session *session,
    const nghttp2_frame *frame, void *user_data)
{
  http2_session_data *session_data = (http2_session_data *)user_data;
  http2_stream_data *stream_data;

  TRACER;
  switch(frame->hd.type) {
  case NGHTTP2_DATA:
  case NGHTTP2_HEADERS:
    /* Check that the client request has finished */
    if(frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
      stream_data = nghttp2_session_get_stream_user_data(session,
          frame->hd.stream_id);
      /* For DATA and HEADERS frame, this callback may be called after
         on_stream_close_callback. Check that stream still alive. */
      if(!stream_data) {
        return 0;
      }

      return mrb_http2_process_request(session, session_data, stream_data);
    }
    break;
  default:
    break;
  }

  return 0;
}

#define MRB_HTTP2_MAX_POST_DATA_SIZE 1 << 24

static int server_on_data_chunk_recv_callback(nghttp2_session *session,
    uint8_t flags, int32_t stream_id, const uint8_t *data, size_t len,
    void *user_data)
{
  http2_session_data *session_data = (http2_session_data *)user_data;
  http2_stream_data *stream_data = nghttp2_session_get_stream_user_data(session,
      stream_id);
  mrb_state *mrb = session_data->app_ctx->server->mrb;
  int rv;

  if (session_data->app_ctx->server->config->debug) {
    fprintf(stderr, "%s: datalen = %ld\n", __func__, len);
  }

  // TODO: buffering and stored file or memory, currently store len byte
  // when callback only once
  if (stream_data->request_body == NULL) {
    stream_data->request_body = mrb_malloc(mrb, sizeof(mrb_http2_request_body));
    memset(stream_data->request_body, 0, sizeof(mrb_http2_request_body));
  }
  if (stream_data->request_body->last) {
    fprintf(stderr, "request_body length reached MRB_HTTP2_MAX_POST_DATA_SIZE");
    rv = nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE,
        stream_data->stream_id, NGHTTP2_INTERNAL_ERROR);
    if(rv != 0) {
      fprintf(stderr, "Fatal error: %s", nghttp2_strerror(rv));
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    return 0;
  } else {
    char *pos;
    stream_data->request_body->len += len;
    if (stream_data->request_body->len >= MRB_HTTP2_MAX_POST_DATA_SIZE) {
      fprintf(stderr, "post data length(%ld) exceed "
          "MRB_HTTP2_MAX_POST_DATA_SIZE(%d)\n", stream_data->request_body->len,
          MRB_HTTP2_MAX_POST_DATA_SIZE);
      stream_data->request_body->len = MRB_HTTP2_MAX_POST_DATA_SIZE;
      stream_data->request_body->last = 1;
      rv = nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE,
          stream_data->stream_id, NGHTTP2_INTERNAL_ERROR);
      if(rv != 0) {
        fprintf(stderr, "Fatal error: %s", nghttp2_strerror(rv));
        return NGHTTP2_ERR_CALLBACK_FAILURE;
      }
      return 0;
    }
    stream_data->request_body->data = mrb_realloc(mrb, stream_data->request_body->data, stream_data->request_body->len + 1);
    pos = stream_data->request_body->data;
    pos += stream_data->request_body->pos;
    memcpy(pos, data, stream_data->request_body->len - stream_data->request_body->pos);
    stream_data->request_body->pos += len;
    stream_data->request_body->data[stream_data->request_body->len] = '\0';
  }

  return 0;
}

static int server_on_stream_close_callback(nghttp2_session *session,
    int32_t stream_id, nghttp2_error_code error_code, void *user_data)
{
  http2_session_data *session_data = (http2_session_data *)user_data;
  mrb_state *mrb = session_data->app_ctx->server->mrb;
  http2_stream_data *stream_data;

  TRACER;
  stream_data = nghttp2_session_get_stream_user_data(session, stream_id);
  if(!stream_data) {
    return 0;
  }
  remove_stream(session_data, stream_data);
  delete_http2_stream_data(mrb, session_data, stream_data);
  TRACER;
  return 0;
}

static ssize_t fixed_data_source_length_callback(nghttp2_session *session,
    uint8_t frame_type, int32_t stream_id, int32_t session_remote_window_size,
    int32_t stream_remote_window_size, uint32_t remote_max_frame_size,
    void *user_data)
{
  return MRB_HTTP2_READ_LENGTH_MAX;
}

static void mrb_http2_server_session_init(http2_session_data *session_data)
{
  nghttp2_option *option;
  nghttp2_session_callbacks *callbacks;

  TRACER;
  nghttp2_option_new(&option);
  nghttp2_option_set_recv_client_preface(option, 1);

  nghttp2_session_callbacks_new(&callbacks);

  nghttp2_session_callbacks_set_send_callback(callbacks, server_send_callback);
  nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks,
      server_on_frame_recv_callback);
  nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks,
      server_on_data_chunk_recv_callback);
  nghttp2_session_callbacks_set_on_stream_close_callback(callbacks,
      server_on_stream_close_callback);
  nghttp2_session_callbacks_set_on_header_callback(callbacks,
      server_on_header_callback);
  nghttp2_session_callbacks_set_on_begin_headers_callback(callbacks,
      server_on_begin_headers_callback);
  nghttp2_session_callbacks_set_data_source_read_length_callback(callbacks,
      fixed_data_source_length_callback);

  nghttp2_session_server_new2(&session_data->session, callbacks, session_data,
      option);
  nghttp2_session_callbacks_del(callbacks);

  nghttp2_option_del(option);
}

/* Send HTTP/2.0 client connection header, which includes 24 bytes
   magic octets and SETTINGS frame */
static int send_server_connection_header(http2_session_data *session_data)
{
  nghttp2_settings_entry iv[2] = {
    { NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100 },
    { NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, ((1 << 18) - 1) }
  };
  int rv;

  rv = nghttp2_submit_settings(session_data->session, NGHTTP2_FLAG_NONE,
                               iv, ARRLEN(iv));
  TRACER;
  if(rv != 0) {
    fprintf(stderr, "Fatal error: %s", nghttp2_strerror(rv));
    return -1;
  }
  TRACER;
  return 0;
}

#define MRB_HTTP2_SSL_BUFSIZE 16384

static SSL* mrb_http2_create_ssl(mrb_state *mrb, SSL_CTX *ssl_ctx)
{
  SSL *ssl;

  if (ssl_ctx == NULL) {
    return NULL;
  }
  ssl = SSL_new(ssl_ctx);

  TRACER;
  if(!ssl) {
    mrb_raisef(mrb, E_RUNTIME_ERROR,
        "Could not create SSL/TLS session object: %S",
        mrb_str_new_cstr(mrb, ERR_error_string(ERR_get_error(), NULL)));
  }

  TRACER;
  return ssl;
}

static mrb_http2_conn_rec *mrb_http2_conn_rec_init(mrb_state *mrb,
    mrb_http2_config_t *config)
{
  mrb_http2_conn_rec *conn;

  if (!config->connection_record) {
    return NULL;
  }
  conn = (mrb_http2_conn_rec *)mrb_malloc(mrb,
      sizeof(mrb_http2_conn_rec));
  memset(conn, 0, sizeof(mrb_http2_conn_rec));

  conn->client_ip = NULL;

  return conn;
}

static void tune_packet_buffer(struct bufferevent *bev,
    mrb_http2_config_t *config)
{
  if (config->write_packet_buffer_limit_size > 0) {
    bufferevent_setwatermark(bev, EV_WRITE, 0,
        config->write_packet_buffer_limit_size);
  }

  if (config->write_packet_buffer_expand_size > 0) {
    evbuffer_expand(bev->output, config->write_packet_buffer_expand_size);
  }

  // TODO: need read_packet_buffer_expand_size ?
  //evbuffer_expand(session_data->bev->input, 4096);
}

static http2_session_data* create_http2_session_data(mrb_state *mrb,
    app_context *app_ctx, int fd, struct sockaddr *addr, int addrlen)
{
  int rv;
  http2_session_data *session_data;
  SSL *ssl;
  //char host[NI_MAXHOST];
  int val = 1;
  mrb_http2_server_t *server = app_ctx->server;
  mrb_http2_config_t *config = app_ctx->server->config;

  TRACER;
  ssl = mrb_http2_create_ssl(mrb, app_ctx->ssl_ctx);

  session_data = (http2_session_data *)mrb_malloc(mrb,
      sizeof(http2_session_data));
  memset(session_data, 0, sizeof(http2_session_data));

  session_data->app_ctx = app_ctx;
  // return NULL when connection_record option diabled
  session_data->conn = mrb_http2_conn_rec_init(mrb, config);

  if (config->tcp_nopush) {
#ifdef TCP_CORK
    setsockopt(fd, IPPROTO_TCP, TCP_CORK, (char *)&val, sizeof(val));
#endif

#ifdef TCP_NOPUSH
    setsockopt(fd, IPPROTO_TCP, TCP_NOPUSH, (char *)&val, sizeof(val));
#endif
  }

  setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char *)&val, sizeof(val));

  TRACER;
  session_data->bev = bufferevent_socket_new(app_ctx->evbase, fd,
     BEV_OPT_DEFER_CALLBACKS | BEV_OPT_CLOSE_ON_FREE);

  tune_packet_buffer(session_data->bev, config);

  if (ssl) {
    TRACER;
    session_data->bev = bufferevent_openssl_filter_new(app_ctx->evbase, session_data->bev, ssl,
        BUFFEREVENT_SSL_ACCEPTING,
        BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
  }

  bufferevent_enable(session_data->bev, EV_READ | EV_WRITE);

  rv = getnameinfo(addr, addrlen, session_data->client_addr, sizeof(session_data->client_addr), NULL, 0, NI_NUMERICHOST);
  if(rv != 0) {
    memcpy(session_data->client_addr, "(unknown)", sizeof("(unknown)"));
  }
  if (session_data->conn) {
    session_data->conn->client_ip = session_data->client_addr;
  }
  session_data->upstream_base = NULL;
  session_data->upstream_conn = NULL;

  if (config->server_status) {
    server->worker->session_requests_per_worker++;
    server->worker->connected_sessions++;
  }

  return session_data;
}

/* readcb for bufferevent after client connection header was
   checked. */
static void mrb_http2_server_readcb(struct bufferevent *bev, void *ptr)
{
  http2_session_data *session_data = (http2_session_data *)ptr;

  TRACER;
  if (session_data->app_ctx->server->config->tls) {
    // if tls, use session_recv2 and tls_session_send
    if (session_recv(session_data) != 0) {
      delete_http2_session_data(session_data);
      return;
    }
  } else {
    if (session_recv(session_data) != 0) {
      delete_http2_session_data(session_data);
      return;
    }
  }
}


static void mrb_http2_server_writecb(struct bufferevent *bev, void *ptr)
{
  http2_session_data *session_data = (http2_session_data *)ptr;

  TRACER;
  if(evbuffer_get_length(bufferevent_get_output(bev)) > 0) {
    return;
  }
  TRACER;
  if(nghttp2_session_want_read(session_data->session) == 0 &&
     nghttp2_session_want_write(session_data->session) == 0) {
    delete_http2_session_data(session_data);
    return;
  }
  TRACER;
  if (session_data->app_ctx->server->config->tls) {
    if(session_send(session_data) != 0) {
      delete_http2_session_data(session_data);
      return;
    }
  } else {
    if(session_send(session_data) != 0) {
      delete_http2_session_data(session_data);
      return;
    }
  }
  TRACER;
}

/* eventcb for bufferevent */
static void mrb_http2_server_eventcb(struct bufferevent *bev, short events,
    void *ptr)
{
  http2_session_data *session_data = (http2_session_data *)ptr;
  mrb_http2_config_t *config = session_data->app_ctx->server->config;

  TRACER;
  if(events & BEV_EVENT_CONNECTED) {
    if (config->debug) {
      fprintf(stderr, "%s connected\n", session_data->client_addr);
    }
    if (config->tls) {
      mrb_http2_server_session_init(session_data);
      if(send_server_connection_header(session_data) != 0) {
        delete_http2_session_data(session_data);
        return;
      }
    }
    return;
  }
  if (config->debug) {
    if(events & BEV_EVENT_EOF) {
      fprintf(stderr, "%s EOF\n", session_data->client_addr);
    } else if(events & BEV_EVENT_ERROR) {
      fprintf(stderr, "%s network error\n", session_data->client_addr);
    } else if(events & BEV_EVENT_TIMEOUT) {
      fprintf(stderr, "%s timeout\n", session_data->client_addr);
    }
  }
  TRACER;
  delete_http2_session_data(session_data);
}

static void mrb_http2_acceptcb(struct evconnlistener *listener, int fd,
    struct sockaddr *addr, int addrlen, void *ptr)
{
  app_context *app_ctx = (app_context *)ptr;
  http2_session_data *session_data;
  mrb_state *mrb = app_ctx->server->mrb;

  TRACER;
  session_data = create_http2_session_data(mrb, app_ctx, fd, addr, addrlen);
  if (session_data->bev == NULL) {
    // accept socket failed
    delete_http2_session_data(session_data);
    return;
  }
  bufferevent_setcb(session_data->bev, mrb_http2_server_readcb,
      mrb_http2_server_writecb, mrb_http2_server_eventcb, session_data);
  if (!app_ctx->server->config->tls) {
    bufferevent_enable(session_data->bev, EV_READ | EV_WRITE);
    mrb_http2_server_session_init(session_data);
    if(send_server_connection_header(session_data) != 0) {
      delete_http2_session_data(session_data);
      return;
    }
  }
  // don't call eventcb when createing bufferevent_socket_new, not tls
  //bufferevent_socket_connect(session_data->bev, NULL, 0);
}

static void set_dhparams(mrb_state *mrb, mrb_http2_config_t *config,
    SSL_CTX *ssl_ctx)
{
  DH *dh;
  BIO *bio = BIO_new_file(config->dh_params_file, "r");

  if (bio == NULL) {
    mrb_raisef(mrb, E_RUNTIME_ERROR, "dh_params_file open failed: %S",
        mrb_str_new_cstr(mrb, config->dh_params_file));
  }

  dh = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
  BIO_free(bio);

  if (dh == NULL) {
    mrb_raisef(mrb, E_RUNTIME_ERROR, "dh_params_file read failed: %S",
        mrb_str_new_cstr(mrb, config->dh_params_file));
  }

  SSL_CTX_set_tmp_dh(ssl_ctx, dh);
  DH_free(dh);
}

const char *npn_proto = "\x05h2-16\x05h2-14";

static int npn_advertise_cb(SSL *s, const unsigned char **data,
    unsigned int *len, void *proto)
{
    *data = proto;
    *len = (unsigned int)strlen(proto);
    return SSL_TLSEXT_ERR_OK;
}

static SSL_CTX* mrb_http2_create_ssl_ctx(mrb_state *mrb,
    mrb_http2_config_t *config, const char *key_file, const char *cert_file)
{
  const unsigned char sid_ctx[] = "mruby-http2";
  SSL_CTX *ssl_ctx;
  EC_KEY *ecdh;

  SSL_load_error_strings();
  SSL_library_init();
  OpenSSL_add_all_algorithms();

  ssl_ctx = SSL_CTX_new(SSLv23_server_method());
  TRACER;
  if(!ssl_ctx) {
    mrb_raisef(mrb, E_RUNTIME_ERROR, "Could not create SSL/TLS context: %S",
        mrb_str_new_cstr(mrb, ERR_error_string(ERR_get_error(), NULL)));
  }
  SSL_CTX_set_options(ssl_ctx, SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
  SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_COMPRESSION);
  SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);
  SSL_CTX_set_options(ssl_ctx, SSL_OP_SINGLE_ECDH_USE);
  SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_TICKET);
  SSL_CTX_set_options(ssl_ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);

  // in reference to nghttp2
  if (SSL_CTX_set_cipher_list(ssl_ctx, DEFAULT_CIPHER_LIST) == 0) {
    mrb_raisef(mrb, E_RUNTIME_ERROR, "SSL_CTX_set_cipher_list failed: %S",
         mrb_str_new_cstr(mrb, ERR_error_string(ERR_get_error(), NULL)));
  }
  SSL_CTX_set_mode(ssl_ctx, SSL_MODE_AUTO_RETRY);
  SSL_CTX_set_mode(ssl_ctx, SSL_MODE_RELEASE_BUFFERS);
  SSL_CTX_set_session_id_context(ssl_ctx, sid_ctx, sizeof(sid_ctx) - 1);
  SSL_CTX_set_session_cache_mode(ssl_ctx, SSL_SESS_CACHE_SERVER);

  ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  if(!ecdh) {
    mrb_raisef(mrb, E_RUNTIME_ERROR, "EC_KEY_new_by_curv_name failed: %S",
         mrb_str_new_cstr(mrb, ERR_error_string(ERR_get_error(), NULL)));
  }
  SSL_CTX_set_tmp_ecdh(ssl_ctx, ecdh);
  EC_KEY_free(ecdh);

  if (config->dh_params_file) {
    set_dhparams(mrb, config, ssl_ctx);
  }

  if(SSL_CTX_use_PrivateKey_file(ssl_ctx, key_file,
        SSL_FILETYPE_PEM) != 1) {
    mrb_raisef(mrb, E_RUNTIME_ERROR, "Could not read private key file %S",
        mrb_str_new_cstr(mrb, key_file));
  }
  if(SSL_CTX_use_certificate_chain_file(ssl_ctx, cert_file) != 1) {
    mrb_raisef(mrb, E_RUNTIME_ERROR, "Could not read certificate file %S",
        mrb_str_new_cstr(mrb, cert_file));
  }
  SSL_CTX_set_next_protos_advertised_cb(ssl_ctx, npn_advertise_cb, (void *)npn_proto);
  TRACER;
  return ssl_ctx;
}

static void init_app_context(app_context *actx, SSL_CTX *ssl_ctx,
    struct event_base *evbase)
{
  memset(actx, 0, sizeof(app_context));
  actx->ssl_ctx = ssl_ctx;
  actx->evbase = evbase;
}

static void set_run_user(mrb_state *mrb, mrb_http2_config_t *config)
{
  uid_t cur_uid = getuid();

  if (config->run_user == NULL && cur_uid != 0) {
    mrb_warn(mrb, "don't set run_user, so run with uid=%S\n",
        mrb_fixnum_value(cur_uid));
    return;
  } else if (config->run_user == NULL && cur_uid == 0) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "Could not run with root,"
       " Set 'run_user => user_name' instead of root in config");
  }

  config->run_uid = mrb_http2_get_uid(mrb, config->run_user);

  if (config->run_uid == 0) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "Could not run with root,"
       " Set 'run_user => user_name' instead of root in config");
  }

  // TODO: add config->run_gid
  // setgid :run_user for now
  if (setgid(config->run_uid)) {
    mrb_raisef(mrb, E_RUNTIME_ERROR, "Could not set gid: %S",
        mrb_fixnum_value(config->run_uid));
  }

  if (setuid(config->run_uid)) {
    mrb_raisef(mrb, E_RUNTIME_ERROR, "Could not set user: %S"
        " If running server with specific user, "
        "run server with root at first",
        mrb_str_new_cstr(mrb, config->run_user));
  }
}

static void mrb_start_listen(struct event_base *evbase,
    mrb_http2_config_t *config, app_context *app_ctx)
{
  int rv;
  struct addrinfo hints;
  struct addrinfo *res, *rp;
  mrb_state *mrb = app_ctx->server->mrb;

  TRACER;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;
#ifdef AI_ADDRCONFIG
  hints.ai_flags |= AI_ADDRCONFIG;
#endif

  rv = getaddrinfo(config->server_host, config->service, &hints, &res);
  if(rv != 0) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "getaddrinfo failed");
  }
  TRACER;
  for(rp = res; rp; rp = rp->ai_next) {
    struct evconnlistener *listener;
    if (config->worker > 0) {
      evutil_socket_t fd;
      int on = 1;
      fd = socket(rp->ai_family, SOCK_STREAM, IPPROTO_TCP);
      setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char *)&on, sizeof(on));
      setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *)&on, sizeof(on));
#if defined(__linux__) && defined(SO_REUSEPORT)
      setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, (char *)&on, sizeof(on));
#endif
      evutil_make_socket_nonblocking(fd);

      if (bind(fd, (struct sockaddr *) rp->ai_addr, rp->ai_addrlen) < 0) {
        mrb_raise(mrb, E_RUNTIME_ERROR, "Could not bind, "
            "don't support SO_REUSEPORT? So, can't use worker mode");
      }
      listener = evconnlistener_new(evbase, mrb_http2_acceptcb, app_ctx,
          LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE, -1, fd);
    } else {
      listener = evconnlistener_new_bind(evbase, mrb_http2_acceptcb, app_ctx,
          LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE, -1, rp->ai_addr,
          rp->ai_addrlen);
    }

    if (listener) {
      freeaddrinfo(res);
      set_run_user(mrb, config);
      return;
    }
  }
  mrb_raise(mrb, E_RUNTIME_ERROR, "Could not start listener");
}

static void mrb_http2_worker_run(mrb_state *mrb, mrb_value self,
    mrb_http2_server_t *server, mrb_http2_request_rec *r, app_context *app_ctx)
{

  SSL_CTX *ssl_ctx = NULL;
  struct event_base *evbase;

  if (server->config->tls) {
    ssl_ctx = mrb_http2_create_ssl_ctx(mrb, server->config, server->config->key,
        server->config->cert);
  }

  server->worker = mrb_http2_worker_init(mrb);

  evbase = event_base_new();

  init_app_context(app_ctx, ssl_ctx, evbase);
  app_ctx->server = server;
  app_ctx->r = r;
  app_ctx->self = self;

  TRACER;
  mrb_start_listen(evbase, server->config, app_ctx);
  event_base_loop(app_ctx->evbase, 0);
  event_base_free(app_ctx->evbase);
  if (server->config->tls) {
    SSL_CTX_free(app_ctx->ssl_ctx);
  }
  TRACER;
}

static int pid[MRB_HTTP2_WORKER_MAX];
static int prepare_kill = 0;

static void killall_worker(int flags)
{
  int i;
  prepare_kill = 1;
  for (i = 0; pid[i] != -1; i++) {
    kill(pid[i], SIGTERM);
  }
}

static mrb_value mrb_http2_server_run(mrb_state *mrb, mrb_value self)
{
  mrb_http2_data_t *data = DATA_PTR(self);
  app_context app_ctx;
  struct sigaction act;
  mrb_http2_config_t *config = data->s->config;
  memset(&act, 0, sizeof(struct sigaction));

  if (config->worker > 0) {
    int i, status;
    for (i=0; i< config->worker && (pid[i] = fork()) > 0; i++);

    if (i == config->worker){
      pid[i] = -1;
      while(1) {
        int wpid;
        act.sa_handler = killall_worker;
        sigaction(SIGTERM, &act, NULL);
        wpid = wait(&status);
        // monitoring workers
        if (prepare_kill) {
          // send term signal to master process
          // preparing killall worker
          return self;
        } else {
          if (config->debug) {
            fprintf(stderr, "worker(%d) is down\n", wpid);
          }
          for (i = 0; i< config->worker; i++) {
            if (wpid == pid[i]) {
              pid[i] = fork();
              break;
            }
          }
          if (pid[i] == 0) {
            act.sa_handler = SIG_DFL;
            sigaction(SIGTERM, &act, NULL);
            mrb_http2_worker_run(mrb, self, data->s, data->r, &app_ctx);
          } else {
            if (config->debug) {
              fprintf(stderr, "worker[%d](%d) restart\n", i, pid[i]);
            }
          }
        }
      }
    } else if (pid[i] == 0){
      mrb_http2_worker_run(mrb, self, data->s, data->r, &app_ctx);
    }
  } else {
    mrb_http2_worker_run(mrb, self, data->s, data->r, &app_ctx);
  }

  return self;
}

static mrb_value mrb_http2_server_set_map_to_storage_cb(mrb_state *mrb,
    mrb_value self)
{
  mrb_http2_data_t *data = DATA_PTR(self);
  mruby_cb_list *list = data->s->config->cb_list;
  mrb_value b;
  const char *cbid = "map_to_storage_cb";

  mrb_get_args(mrb, "&", &b);
  mrb_gc_protect(mrb, b);
  mrb_iv_set(mrb, self, mrb_intern_cstr(mrb, cbid), b);
  list->map_to_storage_cb = cbid;

  return b;
}

static mrb_value mrb_http2_server_set_access_checker_cb(mrb_state *mrb,
    mrb_value self)
{
  mrb_http2_data_t *data = DATA_PTR(self);
  mruby_cb_list *list = data->s->config->cb_list;
  mrb_value b;
  const char *cbid = "access_checker_cb";

  mrb_get_args(mrb, "&", &b);
  mrb_gc_protect(mrb, b);
  mrb_iv_set(mrb, self, mrb_intern_cstr(mrb, cbid), b);
  list->access_checker_cb = cbid;

  return b;
}

static mrb_value mrb_http2_server_set_fixups_cb(mrb_state *mrb,
    mrb_value self)
{
  mrb_http2_data_t *data = DATA_PTR(self);
  mruby_cb_list *list = data->s->config->cb_list;
  mrb_value b;
  const char *cbid = "fixups_cb";

  mrb_get_args(mrb, "&", &b);
  mrb_gc_protect(mrb, b);
  mrb_iv_set(mrb, self, mrb_intern_cstr(mrb, cbid), b);
  list->fixups_cb = cbid;

  return b;
}

static mrb_value mrb_http2_server_set_content_cb(mrb_state *mrb,
    mrb_value self)
{
  mrb_http2_data_t *data = DATA_PTR(self);
  mruby_cb_list *list = data->s->config->cb_list;
  mrb_value b;
  const char *cbid = "content_cb";

  mrb_get_args(mrb, "&", &b);
  //mrb_gc_protect(mrb, b);
  mrb_iv_set(mrb, self, mrb_intern_cstr(mrb, cbid), b);
  list->content_cb = cbid;
  TRACER;

  return b;
}

static mrb_value mrb_http2_server_set_logging_cb(mrb_state *mrb,
    mrb_value self)
{
  mrb_http2_data_t *data = DATA_PTR(self);
  mruby_cb_list *list = data->s->config->cb_list;
  mrb_value b;
  const char *cbid = "logging_cb";

  mrb_get_args(mrb, "&", &b);
  mrb_gc_protect(mrb, b);
  mrb_iv_set(mrb, self, mrb_intern_cstr(mrb, cbid), b);
  list->logging_cb = cbid;

  return b;
}

static void tune_rlimit(mrb_state *mrb, mrb_http2_config_t *config)
{
  struct rlimit r_cfg;

  if (config->rlimit_nofile == 0) {
    return;
  }

  if (config->rlimit_nofile < 0) {
    fprintf(stderr, "don't tune rlmit, rlimit_nofile=%d need positive fixnum\n",
        config->rlimit_nofile);
    return;
  }

  if (getuid() != 0) {
    fprintf(stderr, "don't tune rlmit, run with root at first. then change"
        " privilege to 'run_user' value was set in config\n");
    return;
  }

  r_cfg.rlim_cur = config->rlimit_nofile;
  r_cfg.rlim_max = config->rlimit_nofile;

  if (setrlimit(RLIMIT_NOFILE, &r_cfg) != 0) {
    int err = errno;
    mrb_raisef(mrb, E_RUNTIME_ERROR, "tune_rlimit failed: %S",
        mrb_str_new_cstr(mrb, strerror(err)));
  }
  fprintf(stderr, "tune RLIMIT_NOFILE to %d\n", config->rlimit_nofile);
}

static mrb_value mrb_http2_server_init(mrb_state *mrb, mrb_value self)
{
  mrb_http2_server_t *server;
  struct sigaction act;
  mrb_value args;
  mrb_http2_data_t *data = (mrb_http2_data_t *)mrb_malloc(mrb,
      sizeof(mrb_http2_data_t));
  memset(data, 0, sizeof(mrb_http2_data_t));

  memset(&act, 0, sizeof(struct sigaction));
  act.sa_handler = SIG_IGN;
  sigaction(SIGPIPE, &act, NULL);

  mrb_get_args(mrb, "H", &args);

  // server context
  server = (mrb_http2_server_t *)mrb_malloc(mrb, sizeof(mrb_http2_server_t));
  memset(server, 0, sizeof(mrb_http2_server_t));
  server->args = args;
  server->mrb = mrb;

  mrb_gc_protect(mrb, server->args);
  server->config = mrb_http2_s_config_init(mrb, server->args);

  data->s = server;
  data->r = mrb_http2_request_rec_init(mrb);

  tune_rlimit(mrb, server->config);

  DATA_TYPE(self) = &mrb_http2_server_type;
  DATA_PTR(self) = data;
  TRACER;

  if (server->config->daemon) {
    if (daemon(0, 0) == -1) {
      mrb_raise(mrb, E_RUNTIME_ERROR, "daemonize failed");
    }
  }

  return self;
}

static mrb_value mrb_http2_req_obj(mrb_state *mrb, mrb_value self)
{
  //return mrb_http2_class_obj(mrb, self, "request_class_obj", "Request");
  return self;
}

static mrb_value mrb_http2_conn_obj(mrb_state *mrb, mrb_value self)
{
  //return mrb_http2_class_obj(mrb, self, "request_class_obj", "Request");
  return self;
}

static mrb_value mrb_http2_server_filename(mrb_state *mrb, mrb_value self)
{
  mrb_http2_data_t *data = DATA_PTR(self);
  mrb_http2_request_rec *r = data->r;

  return mrb_str_new_cstr(mrb, r->filename);
}

static mrb_value mrb_http2_server_set_filename(mrb_state *mrb, mrb_value self)
{
  mrb_http2_data_t *data = DATA_PTR(self);
  mrb_http2_request_rec *r = data->r;
  char *filename;
  mrb_int len;
  mrb_get_args(mrb, "s", &filename, &len);
  mrb_free(mrb, r->filename);

  r->filename = mrb_http2_strcopy(mrb, filename, len);

  return self;
}

static mrb_value mrb_http2_server_uri(mrb_state *mrb, mrb_value self)
{
  mrb_http2_data_t *data = DATA_PTR(self);
  mrb_http2_request_rec *r = data->r;

  return mrb_str_new_cstr(mrb, r->uri);
}

static mrb_value mrb_http2_server_unparsed_uri(mrb_state *mrb, mrb_value self)
{
  mrb_http2_data_t *data = DATA_PTR(self);
  mrb_http2_request_rec *r = data->r;

  return mrb_str_new_cstr(mrb, r->unparsed_uri);
}

static mrb_value mrb_http2_server_percent_encode_uri(mrb_state *mrb, mrb_value self)
{
  mrb_http2_data_t *data = DATA_PTR(self);
  mrb_http2_request_rec *r = data->r;

  return mrb_str_new_cstr(mrb, r->percent_encode_uri);
}

static mrb_value mrb_http2_server_args(mrb_state *mrb, mrb_value self)
{
  mrb_http2_data_t *data = DATA_PTR(self);
  mrb_http2_request_rec *r = data->r;

  return mrb_str_new_cstr(mrb, r->args);
}

static mrb_value mrb_http2_server_method(mrb_state *mrb, mrb_value self)
{
  mrb_http2_data_t *data = DATA_PTR(self);
  mrb_http2_request_rec *r = data->r;

  return mrb_str_new_cstr(mrb, r->method);
}

static mrb_value mrb_http2_server_authority(mrb_state *mrb, mrb_value self)
{
  mrb_http2_data_t *data = DATA_PTR(self);
  mrb_http2_request_rec *r = data->r;

  return mrb_str_new_cstr(mrb, r->authority);
}

static mrb_value mrb_http2_server_scheme(mrb_state *mrb, mrb_value self)
{
  mrb_http2_data_t *data = DATA_PTR(self);
  mrb_http2_request_rec *r = data->r;

  return mrb_str_new_cstr(mrb, r->scheme);
}

static mrb_value mrb_http2_server_body(mrb_state *mrb, mrb_value self)
{
  mrb_http2_data_t *data = DATA_PTR(self);
  mrb_http2_request_rec *r = data->r;

  if (r->request_body == NULL) {
    return mrb_nil_value();
  } else {
    return mrb_str_new_cstr(mrb, r->request_body);
  }
}

static mrb_value mrb_http2_server_document_root(mrb_state *mrb, mrb_value self)
{
  mrb_http2_data_t *data = DATA_PTR(self);
  mrb_http2_config_t *config = data->s->config;

  return mrb_str_new_cstr(mrb, config->document_root);
}

static mrb_value mrb_http2_server_client_ip(mrb_state *mrb, mrb_value self)
{
  mrb_http2_data_t *data = DATA_PTR(self);
  mrb_http2_request_rec *r = data->r;

  if (!r->conn) {
    return mrb_nil_value();
  }
  return mrb_str_new_cstr(mrb, r->conn->client_ip);
}

static mrb_value mrb_http2_server_user_agent(mrb_state *mrb, mrb_value self)
{
  mrb_http2_data_t *data = DATA_PTR(self);
  mrb_http2_request_rec *r = data->r;
  int i;

  if (!data->r->reqhdr) {
    return mrb_nil_value();
  }

  i = mrb_http2_get_nv_id(r->reqhdr, r->reqhdrlen, "user-agent");
  if (i == MRB_HTTP2_HEADER_NOT_FOUND) {
    return mrb_nil_value();
  }

  return mrb_str_new(mrb, (char *)r->reqhdr[i].value, r->reqhdr[i].valuelen);
}

static mrb_value mrb_http2_server_status(mrb_state *mrb, mrb_value self)
{
  mrb_http2_data_t *data = DATA_PTR(self);

  return mrb_fixnum_value(data->r->status);
}

static mrb_value mrb_http2_server_date(mrb_state *mrb, mrb_value self)
{
  mrb_http2_data_t *data = DATA_PTR(self);

  return mrb_str_new_cstr(mrb, data->r->date);
}

static mrb_value mrb_http2_server_content_length(mrb_state *mrb, mrb_value self)
{
  mrb_http2_data_t *data = DATA_PTR(self);

  return mrb_fixnum_value(atoi(data->r->content_length));
}

static void mrb_http2_upstream_init(mrb_state *mrb, mrb_value self)
{
  mrb_http2_data_t *data = DATA_PTR(self);
  mrb_http2_request_rec *r = data->r;

  r->upstream = (mrb_http2_upstream *)mrb_malloc(mrb,
      sizeof(mrb_http2_upstream));
  memset(r->upstream, 0, sizeof(mrb_http2_upstream));

  r->upstream->uri = NULL;
  r->upstream->host = NULL;
  r->upstream->port = 80;
  r->upstream->timeout = 600;
  r->upstream->proto_major = 1;
  r->upstream->proto_minor = 1;
  r->upstream->keepalive = 1;
}

static mrb_value mrb_http2_server_set_upstream_proto_major(mrb_state *mrb,
    mrb_value self)
{
  mrb_http2_data_t *data = DATA_PTR(self);
  mrb_http2_request_rec *r = data->r;
  mrb_int major;

  mrb_get_args(mrb, "i", &major);
  if (!r->upstream) {
    mrb_http2_upstream_init(mrb, self);
  }
  // Now support HTTP/1.x only
  // TODO: support HTTP/2
  //r->upstream->proto_major = (int)major;
  r->upstream->proto_major = 1;

  return mrb_fixnum_value(r->upstream->proto_major);
}

static mrb_value mrb_http2_server_set_upstream_proto_minor(mrb_state *mrb,
    mrb_value self)
{
  mrb_http2_data_t *data = DATA_PTR(self);
  mrb_http2_request_rec *r = data->r;
  mrb_int minor;

  mrb_get_args(mrb, "i", &minor);
  if (!r->upstream) {
    mrb_http2_upstream_init(mrb, self);
  }
  // Now support HTTP/1.0 or HTTP/1.1
  // TODO: support HTTP/2
  if (minor != 0 && minor != 1) {
    // defulat HTTP/1.1
    minor = 1;
  }
  r->upstream->proto_minor = (int)minor;

  return mrb_fixnum_value(r->upstream->proto_minor);
}

static mrb_value mrb_http2_server_set_upstream_keepalive(mrb_state *mrb,
    mrb_value self)
{
  mrb_http2_data_t *data = DATA_PTR(self);
  mrb_http2_request_rec *r = data->r;
  mrb_value keepalive;

  mrb_get_args(mrb, "o", &keepalive);
  if (!r->upstream) {
    mrb_http2_upstream_init(mrb, self);
  }
  r->upstream->keepalive = mrb_bool(keepalive);

  return keepalive;
}

static mrb_value mrb_http2_server_set_upstream_timeout(mrb_state *mrb,
    mrb_value self)
{
  mrb_http2_data_t *data = DATA_PTR(self);
  mrb_http2_request_rec *r = data->r;
  mrb_int timeout;

  mrb_get_args(mrb, "i", &timeout);
  if (!r->upstream) {
    mrb_http2_upstream_init(mrb, self);
  }
  r->upstream->timeout = (int)timeout;

  return mrb_fixnum_value(timeout);
}

static mrb_value mrb_http2_server_upstream_port(mrb_state *mrb, mrb_value self)
{
  mrb_http2_data_t *data = DATA_PTR(self);
  mrb_http2_request_rec *r = data->r;

  if (!r->upstream) {
    return mrb_nil_value();
  }
  return mrb_fixnum_value(r->upstream->port);
}

static mrb_value mrb_http2_server_set_upstream_port(mrb_state *mrb, mrb_value self)
{
  mrb_http2_data_t *data = DATA_PTR(self);
  mrb_http2_request_rec *r = data->r;
  mrb_int port;

  mrb_get_args(mrb, "i", &port);
  if (!r->upstream) {
    mrb_http2_upstream_init(mrb, self);
  }
  r->upstream->port = (int)port;

  return self;
}

static mrb_value mrb_http2_server_upstream_host(mrb_state *mrb, mrb_value self)
{
  mrb_http2_data_t *data = DATA_PTR(self);
  mrb_http2_request_rec *r = data->r;

  if (!r->upstream) {
    return mrb_nil_value();
  }
  return mrb_str_new_cstr(mrb, r->upstream->host);
}

static mrb_value mrb_http2_server_set_upstream_host(mrb_state *mrb, mrb_value self)
{
  mrb_http2_data_t *data = DATA_PTR(self);
  mrb_http2_request_rec *r = data->r;
  char *host;

  if (!r->upstream) {
    mrb_http2_upstream_init(mrb, self);
  }

  mrb_get_args(mrb, "z", &host);
  //r->upstream->host = mrb_http2_strcopy(mrb, host, len);
  r->upstream->host = strdup(host);

  return self;
}

static mrb_value mrb_http2_server_upstream_uri(mrb_state *mrb, mrb_value self)
{
  mrb_http2_data_t *data = DATA_PTR(self);
  mrb_http2_request_rec *r = data->r;

  if (!r->upstream) {
    return mrb_nil_value();
  }
  return mrb_str_new_cstr(mrb, r->upstream->uri);
}

static mrb_value mrb_http2_server_set_upstream_uri(mrb_state *mrb,
    mrb_value self)
{
  mrb_http2_data_t *data = DATA_PTR(self);
  mrb_http2_request_rec *r = data->r;
  char *uri;

  mrb_get_args(mrb, "z", &uri);
  if (!r->upstream) {
    mrb_http2_upstream_init(mrb, self);
  }
  r->upstream->uri = uri;

  return self;
}

static mrb_value mrb_http2_server_total_stream_requests(mrb_state *mrb, mrb_value self)
{
  mrb_http2_data_t *data = DATA_PTR(self);
  mrb_http2_worker_t *worker = data->s->worker;

  return mrb_fixnum_value(worker->stream_requests_per_worker);
}

static mrb_value mrb_http2_server_total_session_requests(mrb_state *mrb, mrb_value self)
{
  mrb_http2_data_t *data = DATA_PTR(self);
  mrb_http2_worker_t *worker = data->s->worker;

  return mrb_fixnum_value(worker->session_requests_per_worker);
}

static mrb_value mrb_http2_server_connected_sessions(mrb_state *mrb, mrb_value self)
{
  mrb_http2_data_t *data = DATA_PTR(self);
  mrb_http2_worker_t *worker = data->s->worker;

  return mrb_fixnum_value(worker->connected_sessions);
}

static mrb_value mrb_http2_server_active_stream(mrb_state *mrb, mrb_value self)
{
  mrb_http2_data_t *data = DATA_PTR(self);
  mrb_http2_worker_t *worker = data->s->worker;

  return mrb_fixnum_value(worker->active_stream);
}

static mrb_value mrb_http2_server_enable_mruby(mrb_state *mrb, mrb_value self)
{
  mrb_http2_data_t *data = DATA_PTR(self);
  mrb_http2_request_rec *r = data->r;

  r->mruby = 1;

  return mrb_nil_value();
}

static mrb_value mrb_http2_server_enable_shared_mruby(mrb_state *mrb,
    mrb_value self)
{
  mrb_http2_data_t *data = DATA_PTR(self);
  mrb_http2_request_rec *r = data->r;

  r->shared_mruby = 1;

  return self;
}

static mrb_value mrb_http2_server_rputs(mrb_state *mrb, mrb_value self)
{
  mrb_http2_data_t *data = DATA_PTR(self);
  mrb_http2_request_rec *r = data->r;
  int write_fd = r->write_fd;
  char *msg;
  mrb_int len;
  int rv;

  mrb_get_args(mrb, "s", &msg, &len);
  rv = write(write_fd, msg, len);
  r->write_size += len;

  return mrb_fixnum_value(rv);
}

static mrb_value mrb_http2_server_echo(mrb_state *mrb, mrb_value self)
{
  mrb_http2_data_t *data = DATA_PTR(self);
  mrb_http2_request_rec *r = data->r;
  int write_fd = r->write_fd;
  mrb_value msg;
  char *str;
  mrb_int len;
  int rv;

  mrb_get_args(mrb, "o", &msg);

  str = RSTRING_PTR(mrb_str_plus(mrb, msg, mrb_str_new_lit(mrb, "\n")));
  len = RSTRING_LEN(msg) + sizeof("\n") - 1;

  rv = write(write_fd, str, len);
  r->write_size += len;

  return mrb_fixnum_value(rv);
}

static mrb_value mrb_http2_server_set_status(mrb_state *mrb, mrb_value self)
{
  mrb_http2_data_t *data = DATA_PTR(self);
  mrb_int status;

  if (data->r->phase == MRB_HTTP2_SERVER_LOGGING) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "set_status can't use at this pahse");
  }

  mrb_get_args(mrb, "i", &status);
  set_status_record(data->r, status);

  return mrb_fixnum_value(status);
}

static mrb_value mrb_http2_get_class_obj(mrb_state *mrb, mrb_value self,
    char *obj_id, char *class_name)
{
  mrb_value obj;
  struct RClass *obj_class, *http2_class;

  obj = mrb_iv_get(mrb, self, mrb_intern_cstr(mrb, obj_id));
  if (mrb_nil_p(obj)) {
    http2_class = mrb_class_get_under(mrb, mrb_module_get(mrb, "HTTP2"), "Server");
    obj_class = (struct RClass*)mrb_class_ptr(
        mrb_const_get(mrb, mrb_obj_value(http2_class),
          mrb_intern_cstr(mrb, class_name)));
    obj = mrb_obj_new(mrb, obj_class, 0, NULL);
    DATA_TYPE(obj) = &mrb_http2_server_type;
    DATA_PTR(obj) = DATA_PTR(self);
    mrb_iv_set(mrb, self, mrb_intern_cstr(mrb, obj_id), obj);
  }
  return obj;
}

static mrb_value mrb_http2_headers_out_obj(mrb_state *mrb, mrb_value self)
{
  return mrb_http2_get_class_obj(mrb, self, "headers_out_obj", "Headers_out");
}

static mrb_value mrb_http2_headers_in_obj(mrb_state *mrb, mrb_value self)
{
  return mrb_http2_get_class_obj(mrb, self, "headers_in_obj", "Headers_in");
}

static mrb_value mrb_http2_get_reqhdrs(mrb_state *mrb,
    mrb_value self)
{
  mrb_http2_data_t *data = DATA_PTR(self);
  mrb_http2_request_rec *r = data->r;
  int i;
  char *key;

  if (!data->r->reqhdr) {
    return mrb_nil_value();
  }

  mrb_get_args(mrb, "z", &key);

  i = mrb_http2_get_nv_id(r->reqhdr, r->reqhdrlen, key);
  if (i == MRB_HTTP2_HEADER_NOT_FOUND) {
    return mrb_nil_value();
  }

  return mrb_str_new(mrb, (char *)r->reqhdr[i].value, r->reqhdr[i].valuelen);
}

static mrb_value mrb_http2_get_reshdrs(mrb_state *mrb,
    mrb_value self)
{
  mrb_http2_data_t *data = DATA_PTR(self);
  mrb_http2_request_rec *r = data->r;
  int i;
  char *key;

  if (!data->r->reshdrs) {
    return mrb_nil_value();
  }

  mrb_get_args(mrb, "z", &key);

  i = mrb_http2_get_nv_id(r->reshdrs, r->reshdrslen, key);
  if (i == MRB_HTTP2_HEADER_NOT_FOUND) {
    return mrb_nil_value();
  }

  return mrb_str_new(mrb, (char *)r->reshdrs[i].value, r->reshdrs[i].valuelen);
}

static mrb_value mrb_http2_set_reshdrs(mrb_state *mrb,
    mrb_value self)
{
  mrb_http2_data_t *data = DATA_PTR(self);
  mrb_http2_request_rec *r = data->r;
  mrb_value key, val;
  int i;

  mrb_get_args(mrb, "oo", &key, &val);

  i = mrb_http2_get_nv_id(r->reshdrs, r->reshdrslen, mrb_str_to_cstr(mrb, key));
  if (i == MRB_HTTP2_HEADER_NOT_FOUND) {
    MRB_HTTP2_CREATE_NV_OBJ(mrb, &r->reshdrs[r->reshdrslen], key, val);
    r->reshdrslen += 1;
  } else {
    MRB_HTTP2_CREATE_NV_OBJ(mrb, &r->reshdrs[i], key, val);
  }

  return mrb_fixnum_value(r->reshdrslen);
}

void mrb_http2_server_class_init(mrb_state *mrb, struct RClass *http2)
{
  struct RClass *server, *hin, *hout;

  server = mrb_define_class_under(mrb, http2, "Server", mrb->object_class);
  MRB_SET_INSTANCE_TT(server, MRB_TT_DATA);

  hin = mrb_define_class_under(mrb, server, "Headers_in", mrb->object_class);
  mrb_define_method(mrb, hin, "[]", mrb_http2_get_reqhdrs, ARGS_ANY());

  mrb_define_method(mrb, server, "headers_in", mrb_http2_headers_in_obj, ARGS_NONE());
  mrb_define_method(mrb, server, "request_headers", mrb_http2_headers_in_obj, ARGS_NONE());

  hout = mrb_define_class_under(mrb, server, "Headers_out", mrb->object_class);
  mrb_define_method(mrb, hout, "[]=", mrb_http2_set_reshdrs, ARGS_ANY());
  mrb_define_method(mrb, hout, "[]", mrb_http2_get_reshdrs, ARGS_ANY());

  mrb_define_method(mrb, server, "headers_out", mrb_http2_headers_out_obj, ARGS_NONE());
  mrb_define_method(mrb, server, "response_headers", mrb_http2_headers_out_obj, ARGS_NONE());

  mrb_define_method(mrb, server, "initialize", mrb_http2_server_init, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, server, "run", mrb_http2_server_run, MRB_ARGS_NONE());
  mrb_define_method(mrb, server, "request", mrb_http2_req_obj, MRB_ARGS_NONE());
  mrb_define_method(mrb, server, "r", mrb_http2_req_obj, MRB_ARGS_NONE());
  mrb_define_method(mrb, server, "conn", mrb_http2_conn_obj, MRB_ARGS_NONE());
  mrb_define_method(mrb, server, "filename", mrb_http2_server_filename, MRB_ARGS_NONE());
  mrb_define_method(mrb, server, "filename=", mrb_http2_server_set_filename, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, server, "uri", mrb_http2_server_uri, MRB_ARGS_NONE());
  mrb_define_method(mrb, server, "unparsed_uri", mrb_http2_server_unparsed_uri, MRB_ARGS_NONE());
  mrb_define_method(mrb, server, "percent_encode_uri", mrb_http2_server_percent_encode_uri, MRB_ARGS_NONE());
  mrb_define_method(mrb, server, "args", mrb_http2_server_args, MRB_ARGS_NONE());
  mrb_define_method(mrb, server, "method", mrb_http2_server_method, MRB_ARGS_NONE());
  mrb_define_method(mrb, server, "scheme", mrb_http2_server_scheme, MRB_ARGS_NONE());
  mrb_define_method(mrb, server, "authority", mrb_http2_server_authority, MRB_ARGS_NONE());
  mrb_define_method(mrb, server, "host", mrb_http2_server_authority, MRB_ARGS_NONE());
  mrb_define_method(mrb, server, "hostname", mrb_http2_server_authority, MRB_ARGS_NONE());
  mrb_define_method(mrb, server, "body", mrb_http2_server_body, MRB_ARGS_NONE());
  mrb_define_method(mrb, server, "document_root", mrb_http2_server_document_root, MRB_ARGS_NONE());
  mrb_define_method(mrb, server, "client_ip", mrb_http2_server_client_ip, MRB_ARGS_NONE());
  mrb_define_method(mrb, server, "user_agent", mrb_http2_server_user_agent, MRB_ARGS_NONE());
  mrb_define_method(mrb, server, "status", mrb_http2_server_status, MRB_ARGS_NONE());
  mrb_define_method(mrb, server, "date", mrb_http2_server_date, MRB_ARGS_NONE());
  mrb_define_method(mrb, server, "content_length", mrb_http2_server_content_length, MRB_ARGS_NONE());

  // callbacks
  mrb_define_method(mrb, server, "set_map_to_storage_cb", mrb_http2_server_set_map_to_storage_cb, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, server, "set_access_checker_cb", mrb_http2_server_set_access_checker_cb, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, server, "set_fixups_cb", mrb_http2_server_set_fixups_cb, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, server, "set_content_cb", mrb_http2_server_set_content_cb, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, server, "set_logging_cb", mrb_http2_server_set_logging_cb, MRB_ARGS_REQ(1));

  // upstream methods
  mrb_define_method(mrb, server, "upstream_keepalive=", mrb_http2_server_set_upstream_keepalive, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, server, "upstream_proto_major=", mrb_http2_server_set_upstream_proto_major, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, server, "upstream_proto_minor=", mrb_http2_server_set_upstream_proto_minor, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, server, "upstream_timeout=", mrb_http2_server_set_upstream_timeout, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, server, "upstream_host", mrb_http2_server_upstream_host, MRB_ARGS_NONE());
  mrb_define_method(mrb, server, "upstream_host=", mrb_http2_server_set_upstream_host, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, server, "upstream_port", mrb_http2_server_upstream_port, MRB_ARGS_NONE());
  mrb_define_method(mrb, server, "upstream_port=", mrb_http2_server_set_upstream_port, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, server, "upstream_uri", mrb_http2_server_upstream_uri, MRB_ARGS_NONE());
  mrb_define_method(mrb, server, "upstream_uri=", mrb_http2_server_set_upstream_uri, MRB_ARGS_REQ(1));

  // worke status method
  mrb_define_method(mrb, server, "total_stream_requests", mrb_http2_server_total_stream_requests, MRB_ARGS_NONE());
  mrb_define_method(mrb, server, "total_session_requests", mrb_http2_server_total_session_requests, MRB_ARGS_NONE());
  mrb_define_method(mrb, server, "connected_sessions", mrb_http2_server_connected_sessions, MRB_ARGS_NONE());
  mrb_define_method(mrb, server, "active_session", mrb_http2_server_connected_sessions, MRB_ARGS_NONE());
  mrb_define_method(mrb, server, "active_stream", mrb_http2_server_active_stream, MRB_ARGS_NONE());

  // methods for mruby script
  mrb_define_method(mrb, server, "enable_mruby", mrb_http2_server_enable_mruby, MRB_ARGS_NONE());
  mrb_define_method(mrb, server, "enable_shared_mruby", mrb_http2_server_enable_shared_mruby, MRB_ARGS_NONE());
  mrb_define_method(mrb, server, "rputs", mrb_http2_server_rputs, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, server, "echo", mrb_http2_server_echo, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, server, "set_status", mrb_http2_server_set_status, MRB_ARGS_REQ(1));
  DONE;
}
