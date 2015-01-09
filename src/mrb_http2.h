/*
// mrb_http2.h - to provide http2 methods
//
// See Copyright Notice in mrb_http2.c
*/

#ifndef MRB_HTTP2_H
#define MRB_HTTP2_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
#include <assert.h>
#include <pthread.h>
#include <err.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <nghttp2/nghttp2.h>

#include "mruby.h"
#include "mruby/data.h"
#include "mruby/variable.h"
#include "mruby/array.h"
#include "mruby/hash.h"
#include "mruby/string.h"
#include "mruby/class.h"
#include "mrb_http2.h"
#include "mruby/numeric.h"

#define DONE mrb_gc_arena_restore(mrb, 0);
#define MRUBY_HTTP2_NAME "mruby-http2"
#define MRUBY_HTTP2_VERSION "0.0.1"
#define MRUBY_HTTP2_SERVER MRUBY_HTTP2_NAME "/" MRUBY_HTTP2_VERSION

#define MRB_HTTP2_HEADER_MAX 128
#define MRB_HTTP2_HEADER_NOT_FOUND -1

#define MRB_HTTP2_TRACER

#ifdef MRB_HTTP2_TRACER
#define TRACER printf("    >>>> %s:%d\n", __func__, __LINE__)
#else
#define TRACER
#endif
#define OUTPUT_WOULDBLOCK_THRESHOLD (1 << 16)
#define MRB_HTTP2_CONFIG_ENABLED 1
#define MRB_HTTP2_CONFIG_DISABLED 0
#define ARRLEN(x) (sizeof(x)/sizeof(x[0]))
#define MAKE_NV(NAME, VALUE)                                           \
  {(uint8_t*)NAME, (uint8_t*)VALUE,                                    \
    (uint16_t)(sizeof(NAME) - 1), (uint16_t)(sizeof(VALUE) - 1),       \
    NGHTTP2_NV_FLAG_NONE}
#define MAKE_NV_CS(NAME, VALUE)                                        \
  {(uint8_t*)NAME, (uint8_t*)VALUE,                                    \
    (uint16_t)(sizeof(NAME) - 1), (uint16_t)(strlen(VALUE)),           \
    NGHTTP2_NV_FLAG_NONE}

#define MRB_HTTP2_CREATE_NV_CS(MRB, NV, NAME, VALUE)                         \
  mrb_http2_create_nv(MRB, NV, (uint8_t*)NAME, (uint16_t)(sizeof(NAME) - 1), \
    (uint8_t*)VALUE,  (uint16_t)(strlen(VALUE)))

#define MRB_HTTP2_CREATE_NV_OBJ(MRB, NV, NAME, VALUE)               \
  mrb_http2_create_nv(MRB, NV, (uint8_t*)RSTRING_PTR(NAME),         \
      (uint16_t)(RSTRING_LEN(NAME)), (uint8_t*)RSTRING_PTR(VALUE),  \
      (uint16_t)(RSTRING_LEN(VALUE)))

void set_http_date_str(time_t *time, char *date);
int mrb_http2_get_nv_id(nghttp2_nv *nva, size_t nvlen, const char *key);
void mrb_http2_create_nv(mrb_state *mrb, nghttp2_nv *nv, const uint8_t *name,
    size_t namelen, const uint8_t *value, size_t valuelen);
size_t mrb_http2_add_nv(nghttp2_nv *nva, size_t nvlen, nghttp2_nv *nv);

char *mrb_http2_strcat(mrb_state *mrb, const char *s1, const char *s2);
char *mrb_http2_strcopy(mrb_state *mrb, const char *s, size_t len);
char *strcopy(const char *s, size_t len);
mrb_value mrb_http2_class_obj(mrb_state *mrb, mrb_value self,
        char *obj_id, char *class_name);
void mrb_mruby_http2_gem_init(mrb_state *mrb);

#endif
