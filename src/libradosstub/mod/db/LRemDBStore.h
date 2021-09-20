// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#pragma once

#include "SQLiteCpp/SQLiteCpp.h"

#include "include/interval_set.h"

#include "LRemTransaction.h"

namespace librados {

class LRemDBOps {
  std::unique_ptr<SQLite::Database> db;

public:
  LRemDBOps(const std::string& name, int flags);

  SQLite::Database& get_db() {
    return *db;
  }

  int exec(const std::string& sql);
  int exec(SQLite::Statement& stmt);
  int exec_step(SQLite::Statement& stmt);
  int create_table(const std::string& name, const std::string& defs);


  SQLite::Statement statement(const std::string& sql);

  struct Transaction {
    int retcode{0};
    std::unique_ptr<SQLite::Transaction> trans;

    void *p{nullptr};

    Transaction(LRemDBOps& dbo);
    ~Transaction();

    void complete_op(int _r);
  };

  Transaction new_transaction();
};

using LRemDBOpsRef = std::shared_ptr<LRemDBOps>;

namespace LRemDBStore {

  class TableBase {
  protected:
    LRemDBOpsRef dbo;

    int pool_id;

    std::string table_name;

    LRemTransactionStateRef trans;

    std::string nspace;
    std::string oid;

    void init_table_name(const std::string& table_name_prefix);

  public:
    TableBase(LRemDBOpsRef& _dbo, int _pool_id,
              const std::string& table_name_prefix) : dbo(_dbo), pool_id(_pool_id) {
      init_table_name(table_name_prefix);
    }
    TableBase(LRemDBOpsRef& _dbo, int _pool_id,
              const std::string& table_name_prefix,
              LRemTransactionStateRef& _trans) : dbo(_dbo), pool_id(_pool_id), trans(_trans) {
      set_instance(trans);
      init_table_name(table_name_prefix);
    }
    virtual ~TableBase() {}

    virtual int create_table() = 0;

    void set_instance(LRemTransactionStateRef& trans) {
      nspace = trans->nspace();
      oid = trans->oid();
    }
  };

  class Obj : public TableBase {
  public:
    Obj(LRemDBOpsRef& _dbo, int _pool_id) : TableBase(_dbo, _pool_id, "obj") {}
    Obj(LRemDBOpsRef& _dbo, int _pool_id,
        LRemTransactionStateRef& trans) : TableBase(_dbo, _pool_id, "obj", trans) {}

    struct Meta {
      uint64_t size = 0;

      ceph::real_time mtime;
      uint64_t objver = 0;

      uint64_t snap_id = -1;
      std::vector<uint64_t> snaps;
      interval_set<uint64_t> snap_overlap;

      uint64_t epoch = 0;

      void touch(uint64_t epoch);
    };

    int create_table() override;

    int read_meta(LRemDBStore::Obj::Meta *pmeta);
    int write_meta(const LRemDBStore::Obj::Meta& pmeta);
    int remove_meta();

    int read_data(uint64_t ofs, uint64_t len, bufferlist *bl);
    int write_data(uint64_t ofs, uint64_t len, const bufferlist& bl);
    int remove_data();

    int write(uint64_t ofs, uint64_t len,
              const bufferlist& bl,
              uint64_t epoch);
    int write(uint64_t ofs, uint64_t len,
              const bufferlist& bl,
              LRemDBStore::Obj::Meta& meta);

    int truncate(uint64_t ofs,
                 LRemDBStore::Obj::Meta& meta);

    int append(const bufferlist& bl,
               uint64_t epoch);

    int remove();
  };
  using ObjRef = std::shared_ptr<Obj>;

  class ObjData : public TableBase {
    static constexpr int block_size = (512 * 1024);

    int write_block(int bid, bufferlist& bl);
    int read_block(int bid, bufferlist *bl);
    int truncate_block(int bid);

  public:
    ObjData(LRemDBOpsRef& _dbo, int _pool_id) : TableBase(_dbo, _pool_id, "objdata") {}
    ObjData(LRemDBOpsRef& _dbo, int _pool_id,
            LRemTransactionStateRef& trans) : TableBase(_dbo, _pool_id, "objdata", trans) {}
    int create_table() override;

    int read(uint64_t ofs, uint64_t len, bufferlist *bl);
    int write(uint64_t ofs, uint64_t len, const bufferlist& bl);
    int remove();
    int truncate(uint64_t ofs);
  };
  using ObjDataRef = std::shared_ptr<ObjData>;

  class KVTableBase : public TableBase {
  public:
    KVTableBase(LRemDBOpsRef& _dbo, int _pool_id,
                const std::string& table_name_prefix) : TableBase(_dbo, _pool_id, table_name_prefix) {}
    KVTableBase(LRemDBOpsRef& _dbo, int _pool_id,
                const std::string& table_name_prefix,
                LRemTransactionStateRef& trans) : TableBase(_dbo, _pool_id, table_name_prefix, trans) {}
    virtual ~KVTableBase() {}

    int create_table() override;

    int get_vals(const std::string& start_after,
                 const std::string &filter_prefix,
                 uint64_t max_return,
                 std::map<std::string, bufferlist> *out_vals,
                 bool *pmore);
    int get_all_vals(std::map<std::string, bufferlist> *out_vals);
    int get_vals_by_keys(const std::set<std::string>& keys,
                         std::map<std::string, bufferlist> *out_vals);
    int get_val(const std::string& key,
                bufferlist *bl);
    int rm_keys(const std::set<std::string>& keys);
    int rm_range(const string& key_begin,
                 const string& key_end);
    int clear();
    int set(const std::map<std::string, bufferlist>& m);

    int get_header(bufferlist *bl);
    int set_header(const bufferlist& bl);
  };

  class OMap : public KVTableBase {
  public:
    OMap(LRemDBOpsRef& _dbo, int _pool_id) : KVTableBase(_dbo, _pool_id, "omap") {}
    OMap(LRemDBOpsRef& _dbo, int _pool_id,
         LRemTransactionStateRef& trans) : KVTableBase(_dbo, _pool_id, "omap", trans) {}
  };
  using OMapRef = std::shared_ptr<OMap>;

  class XAttrs : public KVTableBase {
  public:
    XAttrs(LRemDBOpsRef& _dbo, int _pool_id) : KVTableBase(_dbo, _pool_id, "xattrs") {}
    XAttrs(LRemDBOpsRef& _dbo, int _pool_id,
           LRemTransactionStateRef& trans) : KVTableBase(_dbo, _pool_id, "xattrs", trans) {}
  };
  using XAttrsRef = std::shared_ptr<XAttrs>;

  class Pool {
    LRemDBOpsRef dbo;

    int id;
    std::string name;
    std::string value;

    int init_tables();

  public:
    Pool(LRemDBOpsRef& _dbo) : dbo(_dbo) {}
    Pool(LRemDBOpsRef& _dbo, int _id, std::string _name, std::string _value) : dbo(_dbo),
                                                            id(_id), name(_name), value(_value) {}

    int get_id() const {
      return id;
    }

    const std::string& get_name() const {
      return name;
    }

    int create(const std::string& _name, const std::string& _val);
    int read();

    ObjRef get_obj_handler(LRemTransactionStateRef& trans);
    XAttrsRef get_xattrs_handler(LRemTransactionStateRef& trans);
    OMapRef get_omap_handler(LRemTransactionStateRef& trans);
  };
  using PoolRef = std::shared_ptr<Pool>;

  class Cluster {
    LRemDBOpsRef dbo;

  public:
    Cluster(const std::string& cluster_name);

    int init();

    LRemDBOps::Transaction new_transaction() {
      return dbo->new_transaction();
    }

    int create_pool(const std::string& name, const std::string& val);
    int get_pool(const std::string& name, PoolRef *pool);
    int get_pool(int id, PoolRef *pool);
    int list_pools(std::map<std::string, PoolRef> *pools);
  };
  using ClusterRef = std::shared_ptr<Cluster>;

} // namespace LRemDBStore

}
