#include "mrb_http2.h"
#include "mrb_http2_data.h"

void mrb_http2_request_rec_free(mrb_state *mrb, mrb_http2_request_rec *r)
{
  TRACER;
  if (r->filename != NULL) {
    mrb_free(mrb, r->filename);
    r->filename = NULL;
  }

  if (r->upstream != NULL) {
    free(r->upstream->host);
    mrb_free(mrb, r->upstream);
    r->upstream = NULL;
  }

  // disable mruby script for each request
  r->mruby = 0;
  r->shared_mruby = 0;

  // unset write fd record for each request
  r->write_fd = -1;
  r->write_size = 0;

  // for conn_rec_free when disconnected
  if (r->conn != NULL) {
    r->conn = NULL;
  }
  if (r->reqhdr != NULL) {
    mrb_http2_free_nva(mrb, r->reqhdr, r->reqhdrlen);
    r->reqhdr = NULL;
  }

  r->reqhdrlen = 0;
  // r->reshdrslen = 0;
  r->status = 0;
}

mrb_http2_request_rec *mrb_http2_request_rec_init(mrb_state *mrb)
{
  mrb_http2_request_rec *r = (mrb_http2_request_rec *)mrb_malloc(mrb,
      sizeof(mrb_http2_request_rec));
  memset(r, 0, sizeof(mrb_http2_request_rec));

  // NULL check when request_rec freed
  r->filename = NULL;
  r->uri = NULL;
  r->prev_req_time = 0;
  r->prev_last_modified = 0;
  r->reqhdr = NULL;
  r->reqhdrlen = 0;
  r->reshdrslen = 0;
  r->upstream = NULL;
  r->mruby = 0;
  r->shared_mruby = 0;
  r->write_fd = -1;
  r->status = 0;
  r->phase = MRB_HTTP2_SERVER_INIT_REQUEST;

  return r;
}

/*
 *
 * Request methods
 *
 */

static mrb_value mrb_http2_req_filename(mrb_state *mrb, mrb_value self)
{
  mrb_http2_data_t *data = DATA_PTR(self);
  mrb_http2_request_rec *r = data->r;

  return mrb_str_new_cstr(mrb, r->filename);
}

void mrb_http2_request_class_init(mrb_state *mrb, struct RClass *http2)
{
  struct RClass *req;

  req = mrb_define_class_under(mrb, http2, "Request", mrb->object_class);

  //mrb_define_method(mrb, req, "initialize", mrb_http2_req_init, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, req, "filename", mrb_http2_req_filename, MRB_ARGS_NONE());
  //mrb_define_method(mrb, req, "filename=", mrb_http2_req_get_filename, MRB_ARGS_REQ(1));

  DONE;
}

