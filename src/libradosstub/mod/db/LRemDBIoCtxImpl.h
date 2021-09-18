// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#pragma once

#include "LRemIoCtxImpl.h"
#include "LRemDBCluster.h"
#include "LRemDBStore.h"

namespace librados {

class LRemDBRadosClient;

class LRemDBIoCtxImpl : public LRemIoCtxImpl {
public:
  LRemDBIoCtxImpl();
  LRemDBIoCtxImpl(LRemDBRadosClient *client,
                  int64_t m_pool_id,
                  const std::string& pool_name,
                  LRemDBCluster::PoolRef pool);
  ~LRemDBIoCtxImpl() override;

  LRemIoCtxImpl *clone() override;

  int aio_append(LRemTransactionStateRef& trans, AioCompletionImpl *c,
                 const bufferlist& bl, size_t len) override;

  int aio_remove(const std::string& oid, AioCompletionImpl *c, int flags = 0) override;

  int append(LRemTransactionStateRef& trans, const bufferlist &bl,
             const SnapContext &snapc) override;

  int assert_exists(const std::string &oid, uint64_t snap_id) override;
  int assert_version(const std::string &oid, uint64_t ver) override;

  int create(const std::string& oid, bool exclusive,
             const SnapContext &snapc) override;
  int list_snaps(const std::string& o, snap_set_t *out_snaps) override;
  int omap_get_vals(const std::string& oid,
                    const std::string& start_after,
                    const std::string &filter_prefix,
                    uint64_t max_return,
                    std::map<std::string, bufferlist> *out_vals) override;
  int omap_get_vals2(const std::string& oid,
                    const std::string& start_after,
                    const std::string &filter_prefix,
                    uint64_t max_return,
                    std::map<std::string, bufferlist> *out_vals,
                    bool *pmore) override;
  int omap_get_vals_by_keys(const std::string& oid,
                            const std::set<std::string>& keys,
                            std::map<std::string, bufferlist> *vals) override;
  int omap_rm_keys(const std::string& oid,
                   const std::set<std::string>& keys) override;
  int omap_rm_range(const std::string& oid,
                    const string& key_begin,
                    const string& key_end);
  int omap_clear(const std::string& oid) override;
  int omap_set(const std::string& oid, const std::map<std::string,
               bufferlist> &map) override;
  int omap_get_header(LRemTransactionStateRef& trs,
                      bufferlist *bl) override;
  int omap_set_header(const std::string& oid,
                      const bufferlist& bl) override;
  int read(const std::string& oid, size_t len, uint64_t off,
           bufferlist *bl, uint64_t snap_id, uint64_t* objver) override;
  int remove(const std::string& oid, const SnapContext &snapc) override;
  int selfmanaged_snap_create(uint64_t *snapid) override;
  int selfmanaged_snap_remove(uint64_t snapid) override;
  int selfmanaged_snap_rollback(const std::string& oid,
                                uint64_t snapid) override;
  int set_alloc_hint(const std::string& oid, uint64_t expected_object_size,
                     uint64_t expected_write_size, uint32_t flags,
                     const SnapContext &snapc) override;
  int sparse_read(const std::string& oid, uint64_t off, uint64_t len,
                  std::map<uint64_t,uint64_t> *m, bufferlist *data_bl,
                  uint64_t snap_id) override;
  int stat2(LRemTransactionStateRef& trans, uint64_t *psize, struct timespec *pts) override;
  int mtime2(const string& oid, const struct timespec& ts,
             const SnapContext &snapc) override;
  int truncate(const std::string& oid, uint64_t size,
               const SnapContext &snapc) override;
  int write(const std::string& oid, bufferlist& bl, size_t len,
            uint64_t off, const SnapContext &snapc) override;
  int write_full(const std::string& oid, bufferlist& bl,
                 const SnapContext &snapc) override;
  int writesame(const std::string& oid, bufferlist& bl, size_t len,
                uint64_t off, const SnapContext &snapc) override;
  int cmpext(const std::string& oid, uint64_t off, bufferlist& cmp_bl,
             uint64_t snap_id) override;
  int cmpxattr_str(const std::string& oid, const char *name,
                   uint8_t op, const bufferlist& bl) override;
  int cmpxattr(const std::string& oid, const char *name,
               uint8_t op, uint64_t v) override;
  int xattr_get(LRemTransactionStateRef& trans,
                std::map<std::string, bufferlist>* attrset) override;
  int setxattr(LRemTransactionStateRef& trans, const char *name,
               bufferlist& bl) override;
  int rmxattr(LRemTransactionStateRef& trans, const char *name) override;
  int zero(const std::string& oid, uint64_t off, uint64_t len,
           const SnapContext &snapc) override;
  int get_current_ver(const std::string& oid, uint64_t *ver);

  LRemTransactionStateRef init_transaction(const std::string& oid) override;

protected:
  LRemDBCluster::PoolRef& get_pool() {
    return m_pool;
  }

private:
  LRemDBIoCtxImpl(const LRemDBIoCtxImpl&);

  LRemDBRadosClient *m_client = nullptr;
  LRemDBCluster::PoolRef m_pool;

  LRemDBStore::ClusterRef m_dbc;
  LRemDBStore::PoolRef m_pool_db;

  void append_clone(bufferlist& src, bufferlist* dest);
  size_t clip_io(size_t off, size_t len, size_t bl_len);
  void ensure_minimum_length(size_t len, bufferlist *bl);

  struct ObjFile {
    bool exists{false};
    LRemDBStore::Obj::Meta meta;
    LRemDBStore::ObjRef obj;
    LRemDBStore::OMapRef omap;

    ceph::shared_mutex *lock{nullptr};

    uint16_t flags;

    enum ModFlags {
      Meta = 0x01,
    };

    LRemDBStore::Obj::Meta& modify_meta() {
      flags |= (int)ModFlags::Meta;
      return meta;
    }

    int flush();
  };
  using ObjFileRef = std::shared_ptr<ObjFile>;

  ObjFileRef get_file(const std::string &oid, bool write,
                      uint64_t snap_id,
                      const SnapContext &snapc);
  ObjFileRef get_file_safe(LRemTransactionStateRef& trans,
                           bool write, uint64_t snap_id,
                           const SnapContext &snapc,
                           uint64_t *opt_epoch = nullptr);

  typedef boost::function<int(LRemDBCluster::PoolRef&, bool)> PoolOperation;
  int pool_op(LRemTransactionStateRef& trans,
              bool write,
              PoolOperation op);
};

} // namespace librados
