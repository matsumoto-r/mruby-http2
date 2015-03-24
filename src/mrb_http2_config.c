/*
// mrb_http2_server.c - to provide http2 methods
//
// See Copyright Notice in mrb_http2.c
*/
#include "mrb_http2.h"
#include "mrb_http2_config.h"

#define MRB_HTTP2_CONFIG_LIT(mrb, lit) mrb_str_to_cstr(mrb, mrb_str_new_lit(mrb, lit))
#define MRB_HTTP2_CONFIG_ENABLED 1
#define MRB_HTTP2_CONFIG_DISABLED 0

#define mrb_http2_config_get_obj(mrb, args, lit) mrb_hash_get(mrb, args, \
    mrb_symbol_value(mrb_intern_lit(mrb, lit)))
#define mrb_http2_config_get_obj_cstr(mrb, args, str) mrb_hash_get(mrb, args, \
    mrb_symbol_value(mrb_intern_cstr(mrb, str)))

static mruby_cb_list *mruby_cb_list_init(mrb_state *mrb)
{
  mruby_cb_list *list = (mruby_cb_list *)mrb_malloc(mrb, sizeof(mruby_cb_list));
  memset(list, 0, sizeof(mruby_cb_list));

  list->map_to_storage_cb = NULL;
  list->access_checker_cb = NULL;
  list->fixups_cb = NULL;
  list->content_cb = NULL;
  list->logging_cb = NULL;

  return list;
}

static unsigned int mrb_http2_config_get_worker(mrb_state *mrb, mrb_value args, mrb_value w)
{
  int worker;

  // worker => fixnum or "auto"
  if (!mrb_nil_p(w)) {
    if (mrb_type(w) == MRB_TT_STRING
        && mrb_equal(mrb, w, mrb_str_new_lit(mrb, "auto"))) {
      worker = sysconf(_SC_NPROCESSORS_ONLN);
      if (worker < 0 || worker > MRB_HTTP2_WORKER_MAX) {
        mrb_raise(mrb, E_RUNTIME_ERROR, "failed sysconf(_SC_NPROCESSORS_ONLN)");
      }
    } else if (mrb_type(w) == MRB_TT_FIXNUM) {
      worker = mrb_fixnum(w);
    } else {
      mrb_raisef(mrb, E_RUNTIME_ERROR, "invalid worker parmeter: %S", w);
    }
    if (worker > MRB_HTTP2_WORKER_MAX) {
      mrb_raisef(mrb, E_RUNTIME_ERROR, "invalid worker parameter: "
          "%S > MRB_HTTP2_WORKER_MAX(%S)", mrb_fixnum_value(worker),
          mrb_fixnum_value(MRB_HTTP2_WORKER_MAX));
    }
  } else {
    worker = 0;
  }

#if !defined(__linux__) || !defined(SO_REUSEPORT)
  worker = 0;
#endif
  return worker;
}

/* // set config exmaple
static void set_callback_config(mrb_state *mrb, mrb_value args,
    mrb_http2_config_t *config, mrb_value val)
{
  if (!mrb_nil_p(val) && mrb_obj_equal(mrb, val, mrb_true_value())) {
    config->callback = MRB_HTTP2_CONFIG_ENABLED;
  } else {
   config->callback = MRB_HTTP2_CONFIG_DISABLED;
  }
}
*/

static void set_config_key(mrb_state *mrb, mrb_value args,
    mrb_http2_config_t *config, mrb_value val)
{
  if (config->tls) {
    if (mrb_nil_p(val)) {
      mrb_raise(mrb, E_RUNTIME_ERROR, "MUST set key value when using TLS");
    }
    config->key = mrb_str_to_cstr(mrb, val);
  } else {
    config->key = NULL;
  }
}

static void set_config_crt(mrb_state *mrb, mrb_value args,
    mrb_http2_config_t *config, mrb_value val)
{
  if (config->tls) {
    if (mrb_nil_p(val)) {
      mrb_raise(mrb, E_RUNTIME_ERROR, "MUST set crt value when using TLS");
    }
    config->cert = mrb_str_to_cstr(mrb, val);
  } else {
    config->cert = NULL;
  }
}

static void set_config_port(mrb_state *mrb, mrb_value args,
    mrb_http2_config_t *config, mrb_value val)
{
  config->service = mrb_str_to_cstr(mrb, mrb_fixnum_to_str(mrb, val, 10));
}

static void set_config_worker(mrb_state *mrb, mrb_value args,
    mrb_http2_config_t *config, mrb_value val)
{
  config->worker = mrb_http2_config_get_worker(mrb, args, val);
}

//
// Configuration API
//
// mrb_http2_config_define()
//  need to use setting function ptr
//
// mrb_http2_config_define_cstr()
//  string value on Ruby config or use function ptr more complex
//  :key => "string value",
//
// mrb_http2_config_define_flag()
//  true or false value on Ruby config or use function ptr more complex
//  :key => true,
//

void mrb_http2_config_define(mrb_state *mrb, mrb_value args,
    mrb_http2_config_t *config, void (*func_ptr)(), const char *key)
{
  mrb_value val = mrb_http2_config_get_obj_cstr(mrb, args, key);

  (*func_ptr)(mrb, args, config, val);

}

void mrb_http2_config_define_cstr(mrb_state *mrb, mrb_value args,
    mrb_http2_config_cstr **config_cstr, void (*func_ptr)(), const char *key)
{
  mrb_value val = mrb_http2_config_get_obj_cstr(mrb, args, key);

  if (func_ptr != NULL) {
    (*func_ptr)(mrb, args, *config_cstr, val);
  } else {
    if (!mrb_nil_p(val) && mrb_type(val) == MRB_TT_STRING) {
      *config_cstr = strdup(mrb_str_to_cstr(mrb, val));
    }
  }
}

void mrb_http2_config_define_fixnum(mrb_state *mrb, mrb_value args,
    mrb_http2_config_fixnum *config_fixnum, void (*func_ptr)(), const char *key)
{
  mrb_value val = mrb_http2_config_get_obj_cstr(mrb, args, key);

  if (func_ptr != NULL) {
    (*func_ptr)(mrb, args, *config_fixnum, val);
  } else {
    if (!mrb_nil_p(val) && mrb_type(val) == MRB_TT_FIXNUM) {
      *config_fixnum = mrb_fixnum(val);
    }
  }
}

void mrb_http2_config_define_flag(mrb_state *mrb, mrb_value args,
    mrb_http2_config_flag *config_flag, void (*func_ptr)(), const char *key)
{
  mrb_value val = mrb_http2_config_get_obj_cstr(mrb, args, key);

  if (func_ptr != NULL) {
    (*func_ptr)(mrb, args, config_flag, val);
  } else {
    if (!mrb_nil_p(val) && mrb_obj_equal(mrb, val, mrb_true_value())) {
      *config_flag = MRB_HTTP2_CONFIG_ENABLED;
    } else if (!mrb_nil_p(val) && mrb_obj_equal(mrb, val, mrb_false_value())) {
      *config_flag = MRB_HTTP2_CONFIG_DISABLED;
    }
  }
}

static void config_defualt_value(mrb_state *mrb, mrb_http2_config_t *config)
{
  config->daemon = MRB_HTTP2_CONFIG_DISABLED;
  config->debug = MRB_HTTP2_CONFIG_DISABLED;
  config->tls = MRB_HTTP2_CONFIG_ENABLED;
  config->connection_record = MRB_HTTP2_CONFIG_ENABLED;
  config->tcp_nopush = MRB_HTTP2_CONFIG_DISABLED;
  config->server_status = MRB_HTTP2_CONFIG_DISABLED;
  config->upstream = MRB_HTTP2_CONFIG_DISABLED;

  config->server_host = MRB_HTTP2_CONFIG_LIT(mrb, "0.0.0.0");
  config->server_name = MRB_HTTP2_CONFIG_LIT(mrb, MRUBY_HTTP2_SERVER);
  config->document_root = MRB_HTTP2_CONFIG_LIT(mrb, "./");
  config->run_user = NULL;
  config->dh_params_file = NULL;

  config->rlimit_nofile = 0;
  config->write_packet_buffer_expand_size = 0;
  config->write_packet_buffer_limit_size = 0;
}

mrb_http2_config_t *mrb_http2_s_config_init(mrb_state *mrb,
    mrb_value args)
{
  mrb_http2_config_t *config = (mrb_http2_config_t *)mrb_malloc(mrb,
      sizeof(mrb_http2_config_t));
  memset(config, 0, sizeof(mrb_http2_config_t));

  config_defualt_value(mrb, config);

  mrb_http2_config_define_flag(mrb, args, &config->callback, NULL, "callback");
  mrb_http2_config_define_flag(mrb, args, &config->daemon, NULL, "daemon");
  mrb_http2_config_define_flag(mrb, args, &config->debug, NULL, "debug");
  mrb_http2_config_define_flag(mrb, args, &config->tls, NULL, "tls");
  mrb_http2_config_define_flag(mrb, args, &config->connection_record, NULL, "connection_record");
  mrb_http2_config_define_flag(mrb, args, &config->tcp_nopush, NULL, "tcp_nopush");
  mrb_http2_config_define_flag(mrb, args, &config->server_status, NULL, "server_status");
  mrb_http2_config_define_flag(mrb, args, &config->upstream, NULL, "upstream");

  mrb_http2_config_define_cstr(mrb, args, &config->server_host,  NULL, "server_host");
  mrb_http2_config_define_cstr(mrb, args, &config->server_name,  NULL, "server_name");
  mrb_http2_config_define_cstr(mrb, args, &config->document_root,  NULL, "document_root");
  mrb_http2_config_define_cstr(mrb, args, &config->run_user, NULL, "run_user");
  mrb_http2_config_define_cstr(mrb, args, &config->dh_params_file, NULL, "dh_params_file");

  mrb_http2_config_define_fixnum(mrb, args, &config->rlimit_nofile, NULL, "rlimit_nofile");
  mrb_http2_config_define_fixnum(mrb, args, &config->write_packet_buffer_expand_size, NULL, "write_packet_buffer_expand_size");
  mrb_http2_config_define_fixnum(mrb, args, &config->write_packet_buffer_limit_size, NULL, "write_packet_buffer_limit_size");

  mrb_http2_config_define(mrb, args, config, set_config_port, "port");
  mrb_http2_config_define(mrb, args, config, set_config_worker, "worker");
  mrb_http2_config_define(mrb, args, config, set_config_key, "key");
  mrb_http2_config_define(mrb, args, config, set_config_crt, "crt");

  config->cb_list = mruby_cb_list_init(mrb);

  return config;
}

