

#include "svc_meta_be.h"

#include "rgw/rgw_mdlog.h"

#define dout_subsys ceph_subsys_rgw


RGWSI_MetaBackend::Context::~Context() {} // needed, even though destructor is pure virtual
RGWSI_MetaBackend::Module::~Module() {} // ditto
RGWSI_MetaBackend::PutParams::~PutParams() {} // ...
RGWSI_MetaBackend::GetParams::~GetParams() {} // ...
RGWSI_MetaBackend::RemoveParams::~RemoveParams() {} // ...

int RGWSI_MetaBackend::pre_modify(RGWSI_MetaBackend::Context *ctx,
                                  const string& key,
                                  RGWMetadataLogData& log_data,
                                  RGWObjVersionTracker *objv_tracker,
                                  RGWMDLogStatus op_type)
{
  /* if write version has not been set, and there's a read version, set it so that we can
   * log it
   */
  if (objv_tracker &&
      objv_tracker->read_version.ver && !objv_tracker->write_version.ver) {
    objv_tracker->write_version = objv_tracker->read_version;
    objv_tracker->write_version.ver++;
  }

  return 0;
}

int RGWSI_MetaBackend::post_modify(RGWSI_MetaBackend::Context *ctx,
                                   const string& key,
                                   RGWMetadataLogData& log_data,
                                   RGWObjVersionTracker *objv_tracker, int ret)
{
  return ret;
}

int RGWSI_MetaBackend::prepare_mutate(RGWSI_MetaBackend::Context *ctx,
                                      const string& key,
                                      const real_time& mtime,
                                      RGWObjVersionTracker *objv_tracker)
{
  real_time orig_mtime;
  unique_ptr<GetParams> params(alloc_default_get_params(&orig_mtime));

  int ret = get_entry(ctx, key, *params, objv_tracker);
  if (ret < 0 && ret != -ENOENT) {
    return ret;
  }

  if (objv_tracker->write_version.tag.empty()) {
    if (objv_tracker->read_version.tag.empty()) {
      objv_tracker->generate_new_write_ver(cct);
    } else {
      objv_tracker->write_version = objv_tracker->read_version;
      objv_tracker->write_version.ver++;
    }
  }
  return 0;
}

int RGWSI_MetaBackend::mutate(RGWSI_MetaBackend::Context *ctx,
                              const string& key,
                              const ceph::real_time& mtime,
                              RGWObjVersionTracker *objv_tracker,
                              RGWMDLogStatus op_type,
                              std::function<int()> f,
                              bool generic_prepare)
{
  int ret;

  if (generic_prepare) {
    ret = prepare_mutate(ctx, key, mtime, objv_tracker);
    if (ret < 0 ||
        ret == STATUS_NO_APPLY) {
      return ret;
    }
  }

  RGWMetadataLogData log_data;
  ret = pre_modify(ctx, key, log_data, objv_tracker, op_type);
  if (ret < 0) {
    return ret;
  }

  ret = f();

  /* cascading ret into post_modify() */

  ret = post_modify(ctx, key, log_data, objv_tracker, ret);
  if (ret < 0)
    return ret;

  return 0;
}

int RGWSI_MetaBackend::get(Context *ctx,
                           const string& key,
                           GetParams& params,
                           RGWObjVersionTracker *objv_tracker)
{
  return get_entry(ctx, key, params, objv_tracker);
}

int RGWSI_MetaBackend::put(Context *ctx,
                           const string& key,
                           PutParams& params,
                           RGWObjVersionTracker *objv_tracker)
{
  std::function<int()> f = [&]() {
    return put_entry(ctx, key, params, objv_tracker);
  };

  return mutate(ctx, key, params.mtime, objv_tracker,
                MDLOG_STATUS_WRITE,
                f,
                false);
}

int RGWSI_MetaBackend::remove(Context *ctx,
                              const string& key,
                              RemoveParams& params,
                              RGWObjVersionTracker *objv_tracker)
{
  std::function<int()> f = [&]() {
    return remove_entry(ctx, key, params, objv_tracker);
  };

  return mutate(ctx, key, params.mtime, objv_tracker,
                MDLOG_STATUS_REMOVE,
                f,
                false);
}


int RGWSI_MetaBackend_Handler::call(std::function<int(Op *)> f)
{
  return be->call([&](RGWSI_MetaBackend::Context *ctx) {
    ctx->init(this);
    Op op(be, ctx);
    return f(&op);
  });
}

RGWSI_MetaBackend_Handler::Op *RGWSI_MetaBackend_Handler::alloc_op()
{
  return new Op_ManagedCtx(be);
}

RGWSI_MetaBackend_Handler::Op_ManagedCtx::Op_ManagedCtx(RGWSI_MetaBackend *_be) : Op(_be, _be->alloc_ctx())
{
  pctx.reset(ctx());
}

