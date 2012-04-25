// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab
/*
 * Ceph - scalable distributed file system
 *
 * Copyright (C) 2004-2006 Sage Weil <sage@newdream.net>
 *
 * This is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2.1, as published by the Free Software
 * Foundation.  See file COPYING.
 *
 */

#include "include/types.h"
#include "include/atomic.h"

#include "common/obj_bencher.h"
#include "common/config.h"
#include "common/ceph_argparse.h"
#include "global/global_init.h"

#include "libs3.h"

#include <errno.h>

#define DEFAULT_USER_AGENT "rest-bench"
#define DEFAULT_BUCKET "rest-bench-bucket"

void usage(ostream& out)
{
  out <<					\
"usage: rest_bench [options] [commands]\n"
"COMMANDS\n"
"\n";
}

static void usage_exit()
{
  usage(cerr);
  exit(1);
}

struct req_context {
  atomic_t complete;
  S3Status status;
  S3RequestContext *ctx;
  void (*cb)(void *, void *);
  void *arg;
  bufferlist *in_bl;
  bufferlist out_bl;
  uint64_t off;

  req_context() : status(S3StatusOK), ctx(NULL), cb(NULL), arg(NULL), in_bl(NULL), off(0) {}
  ~req_context() {
    if (ctx) {
      S3_destroy_request_context(ctx);
    }
  }

  int init_ctx() {
    S3Status status = S3_create_request_context(&ctx);
    if (status != S3StatusOK) {
      cerr << "failed to create context: " << S3_get_status_name(status) << std::endl;
      return -EINVAL;
    }

    return 0;
  }

  int ret() {
    if (status != S3StatusOK) {
      return -EINVAL;
    }
    return 0;
  }
};

static S3Status properties_callback(const S3ResponseProperties *properties, void *cb_data)
{
  return S3StatusOK;
}

static void complete_callback(S3Status status, const S3ErrorDetails *details, void *cb_data)
{
  if (!cb_data)
    return;

  struct req_context *ctx = (struct req_context *)cb_data;
  ctx->complete.set(1);
  ctx->status = status;

  if (ctx->cb) {
    ctx->cb((void *)ctx->cb, ctx->arg);
  }
}

static S3Status get_obj_callback(int size, const char *buf,
                                 void *cb_data)
{
  if (!cb_data)
    return S3StatusOK;

  struct req_context *ctx = (struct req_context *)cb_data;

  ctx->in_bl->append(buf, size);

  return S3StatusOK;
}

static int put_obj_callback(int size, char *buf,
                            void *cb_data)
{
  if (!cb_data)
    return 0;

  struct req_context *ctx = (struct req_context *)cb_data;

  int chunk = ctx->out_bl.length() - ctx->off;
  if (!chunk)
    return 0;

  if (chunk > size)
    chunk = size;

  memcpy(buf, ctx->out_bl.c_str() + ctx->off, chunk);

  ctx->off += chunk;

  return chunk;
}

class RESTBencher : public ObjBencher {
  struct req_context **completions;
  S3BucketContext bucket_ctx;
  string user_agent;
  string host;
  string bucket;
  S3Protocol protocol;
  string access_key;
  string secret;

  S3ResponseHandler response_handler;
  S3GetObjectHandler get_obj_handler;
  S3PutObjectHandler put_obj_handler;

protected:

  int rest_init() {
    S3Status status = S3_initialize(user_agent.c_str(), S3_INIT_ALL, host.c_str());
    if (status != S3StatusOK) {
      cerr << "failed to init: " << S3_get_status_name(status) << std::endl;
      return -EINVAL;
    }

    response_handler.propertiesCallback = properties_callback;
    response_handler.completeCallback = complete_callback;

    get_obj_handler.responseHandler = response_handler;
    get_obj_handler.getObjectDataCallback = get_obj_callback;

    put_obj_handler.responseHandler = response_handler;
    put_obj_handler.putObjectDataCallback = put_obj_callback;

    return 0;
  }


  int completions_init(int concurrentios) {
    completions = new req_context *[concurrentios];
    return 0;
  }
  void completions_done() {
    delete[] completions;
    completions = NULL;
  }
  int create_completion(int slot, void (*cb)(void *, void*), void *arg) {
    struct req_context *ctx = new req_context;
    int ret = ctx->init_ctx();
    if (ret < 0) {
      return ret;
    }

    ctx->cb = cb;
    ctx->arg = arg;

    completions[slot] = ctx;

    return 0;
  }
  void release_completion(int slot) {
    struct req_context *ctx = completions[slot];

    delete ctx;
    completions[slot] = 0;
  }

  int aio_read(const std::string& oid, int slot, bufferlist *pbl, size_t len) {
    struct req_context *ctx = completions[slot];
    ctx->in_bl = pbl;
    S3_get_object(&bucket_ctx, oid.c_str(), NULL, 0, len, ctx->ctx,
                  &get_obj_handler, ctx);

    return 0;
  }

  int aio_write(const std::string& oid, int slot, const bufferlist& bl, size_t len) {
    struct req_context *ctx = completions[slot];
    ctx->out_bl = bl;
    S3_put_object(&bucket_ctx, oid.c_str(),
                  bl.length(),
                  NULL,
                  ctx->ctx,
                  &put_obj_handler, ctx);
    return 0;
  }

  int sync_read(const std::string& oid, bufferlist& bl, size_t len) {
    struct req_context ctx;
    int ret = ctx.init_ctx();
    if (ret < 0) {
      return ret;
    }
    ctx.in_bl = &bl;
    S3_get_object(&bucket_ctx, oid.c_str(), NULL, 0, len, NULL,
                  &get_obj_handler, &ctx);

    return ctx.ret();
  }
  int sync_write(const std::string& oid, bufferlist& bl, size_t len) {
    struct req_context ctx;
    int ret = ctx.init_ctx();
    if (ret < 0) {
      return ret;
    }
    ctx.out_bl = bl;
    S3_put_object(&bucket_ctx, oid.c_str(),
                  bl.length(),
                  NULL,
                  NULL,
                  &put_obj_handler, &ctx);

    return ctx.ret();
  }

  bool completion_is_done(int slot) {
    int val = completions[slot]->complete.read();
    return (val != 0);
  }

  int completion_wait(int slot) {
  }

  int completion_ret(int slot) {
    S3Status status = completions[slot]->status;
    if (status >= 200 && status < 300)
      return 0;
    return -EIO;
  }

public:
  RESTBencher(string _bucket) : completions(NULL), bucket(_bucket) {}
  ~RESTBencher() { }

  int init(string& _agent, string& _host, string& _bucket, S3Protocol _protocol,
           string& _access_key, string& _secret) {
    user_agent = _agent;
    host = _host;
    bucket = _bucket;
    protocol = _protocol;
    access_key = _access_key;
    secret = _secret;

    bucket_ctx.hostName = host.c_str();
    bucket_ctx.bucketName = bucket.c_str();
    bucket_ctx.protocol =  protocol;
    bucket_ctx.accessKeyId = access_key.c_str();
    bucket_ctx.secretAccessKey = secret.c_str();
    
    struct req_context ctx;

    int ret = rest_init();
    if (ret < 0) {
      return ret;
    }

    ret = ctx.init_ctx();
    if (ret < 0) {
      return ret;
    }

    S3_create_bucket(protocol, access_key.c_str(), secret.c_str(), NULL,
                     bucket.c_str(), S3CannedAclPrivate,
                     NULL, /* locationConstraint */
                     NULL, /* requestContext */
                     &response_handler, /* handler */
                     (void *)&ctx  /* callbackData */);
    return 0;
  }
};

int main(int argc, const char **argv)
{
  vector<const char*> args;
  argv_to_vec(argc, argv, args);
  env_to_vec(args);

  global_init(NULL, args, CEPH_ENTITY_TYPE_CLIENT, CODE_ENVIRONMENT_UTILITY, 0);
  common_init_finish(g_ceph_context);

  std::map < std::string, std::string > opts;
  std::vector<const char*>::iterator i;
  std::string val;
  std::string host;
  std::string user_agent;
  std::string access_key;
  std::string secret;
  std::string bucket = DEFAULT_BUCKET;
  S3Protocol protocol = S3ProtocolHTTP;
  std::string proto_str;

  for (i = args.begin(); i != args.end(); ) {
    if (ceph_argparse_double_dash(args, i)) {
      break;
    } else if (ceph_argparse_flag(args, i, "-h", "--help", (char*)NULL)) {
      usage(cout);
      exit(0);
    } else if (ceph_argparse_witharg(args, i, &user_agent, "--agent", (char*)NULL)) {
      /* nothing */
    } else if (ceph_argparse_witharg(args, i, &access_key, "--access-key", (char*)NULL)) {
      /* nothing */
    } else if (ceph_argparse_witharg(args, i, &secret, "--secret", (char*)NULL)) {
      /* nothing */
    } else if (ceph_argparse_witharg(args, i, &bucket, "--bucket", (char*)NULL)) {
      /* nothing */
    } else if (ceph_argparse_witharg(args, i, &proto_str, "--protocol", (char*)NULL)) {
      if (strcasecmp(proto_str.c_str(), "http") == 0) {
        protocol = S3ProtocolHTTP;
      } else if (strcasecmp(proto_str.c_str(), "http") == 0) {
        protocol = S3ProtocolHTTPS;
      } else {
        cerr << "bad protocol" << std::endl;
        usage_exit();
      }
      /* nothing */
    } else {
      if (val[0] == '-')
        usage_exit();
      i++;
    }
  }

  host = g_conf->host;

  if (host.empty()) {
    cerr << "rest-bench: host not provided." << std::endl;
    usage_exit();
  }

  if (access_key.empty() || secret.empty()) {
    cerr << "rest-bench: access key or secret was not provided" << std::endl;
    usage_exit();
  }

  if (bucket.empty()) {
    bucket = DEFAULT_BUCKET;
  }

  if (user_agent.empty())
    user_agent = DEFAULT_USER_AGENT;

  RESTBencher bencher(bucket);

  int ret = bencher.init(user_agent, host, bucket, protocol, access_key, secret);
  if (ret < 0) {
    exit(1);
  }

  return 0;
}

