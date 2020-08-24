#include "svc_account_rados.h"
#include "svc_sys_obj.h"
#include "svc_meta_be_sobj.h"
#include "svc_meta.h"
#include "rgw/rgw_account.h"
#include "rgw/rgw_tools.h"
#include "rgw/rgw_zone.h"
#include "svc_zone.h"

#define dout_subsys ceph_subsys_rgw

constexpr auto RGW_ACCOUNT_USER_OBJ_SUFFIX = ".users";

class RGWSI_Account_Module : public RGWSI_MBSObj_Handler_Module {
  RGWSI_Account_RADOS::Svc& svc;

  const string prefix;
public:
  RGWSI_Account_Module(RGWSI_Account_RADOS::Svc& _svc) : RGWSI_MBSObj_Handler_Module("account"),
                                                   svc(_svc) {}

  void get_pool_and_oid(const string& key, rgw_pool *pool, string *oid) override {
    if (pool) {
      *pool = svc.zone->get_zone_params().account_pool;
    }
    if (oid) {
      *oid = key;
    }
  }

  const string& get_oid_prefix() override {
    return prefix;
  }

  bool is_valid_oid(const string& oid) override {
    // filter out the user.buckets objects
    return !boost::algorithm::ends_with(oid, RGW_ACCOUNT_USER_OBJ_SUFFIX);
  }

  string key_to_oid(const string& key) override {
    return key;
  }

  string oid_to_key(const string& oid) override {
    return oid;
  }
};

RGWSI_Account_RADOS::RGWSI_Account_RADOS(CephContext *cct) :
  RGWSI_Account(cct) {
}

void RGWSI_Account_RADOS::init(RGWSI_Zone *_zone_svc,
                               RGWSI_Meta *_meta_svc,
                               RGWSI_MetaBackend *_meta_be_svc)
{
  svc.zone = _zone_svc;
  svc.meta = _meta_svc;
  svc.meta_be = _meta_be_svc;
}

int RGWSI_Account_RADOS::do_start()
{
  int r = svc.meta->create_be_handler(RGWSI_MetaBackend::Type::MDBE_SOBJ,
                                     &be_handler);
  if (r < 0) {
    ldout(ctx(), 0) << "ERROR: failed to create be_handler for accounts: r=" << r << dendl;
    return r;
  }

  RGWSI_MetaBackend_Handler_SObj *bh = static_cast<RGWSI_MetaBackend_Handler_SObj *>(be_handler);
  auto module = new RGWSI_Account_Module(svc);
  be_module.reset(module);
  bh->set_module(module);
  return 0;
}

int RGWSI_Account_RADOS::store_account_info(RGWSI_MetaBackend::Context *_ctx,
                                            const RGWAccountInfo& info,
                                            RGWObjVersionTracker *objv_tracker,
                                            const real_time& mtime,
                                            bool exclusive,
                                            map <string, bufferlist> *pattrs,
                                            optional_yield y)
{
  bufferlist data_bl;
  encode(info, data_bl);

  RGWSI_MBSObj_PutParams params(data_bl, pattrs, mtime, exclusive);

  int r = svc.meta_be->put(_ctx, get_meta_key(info), params, objv_tracker, y);
  if (r < 0)
    return r;
  RGWSI_MetaBackend_SObj::Context_SObj *ctx = static_cast<RGWSI_MetaBackend_SObj::Context_SObj *>(_ctx);

  auto obj_ctx = ctx->obj_ctx;
  return rgw_put_system_obj(*obj_ctx, svc.zone->get_zone_params().user_swift_pool,
                            info.get_id(), data_bl, exclusive, nullptr, real_time(), y);
}

int RGWSI_Account_RADOS::read_account_info(RGWSI_MetaBackend::Context *ctx,
                                           const std::string& account_id,
                                           RGWAccountInfo *info,
                                           RGWObjVersionTracker * const objv_tracker,
                                           real_time * const pmtime,
                                           map<std::string, bufferlist> * const pattrs,
                                           optional_yield y)
{
  bufferlist bl;
  RGWSI_MBSObj_GetParams params(&bl, pattrs, pmtime);
  int r = svc.meta_be->get_entry(ctx, account_id, params, objv_tracker, y);
  if (r < 0) {
    return r;
  }

  auto bl_iter = bl.cbegin();
  try {
    decode(*info, bl_iter);
    if (info->get_id() != account_id) {
      lderr(svc.meta_be->ctx()) << "ERROR: read_account_info account id mismatch" << info->get_id() << "!= " << account_id << dendl;
      return -EIO;
    }
  } catch (buffer::error& err) {
    ldout(svc.meta_be->ctx(), 0) << "ERROR: failed to decode account info, caught buffer::error" << dendl;
    return -EIO;
  }

  return 0;
}

int RGWSI_Account_RADOS::remove_account_info(RGWSI_MetaBackend::Context *ctx,
                                             const std::string& account_id,
                                             RGWObjVersionTracker *objv_tracker,
                                             optional_yield y)
{
  RGWSI_MBSObj_RemoveParams params;
  int ret = svc.meta_be->remove(ctx, account_id, params, objv_tracker, y);
  if (ret <0 && ret != -ENOENT && ret != -ECANCELED) {
    ldout(svc.meta_be->ctx(),0) << "ERROR: could not remove account: " << account_id << dendl;
    return ret;
  }
  return 0;
}
