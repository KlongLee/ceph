#ifndef CEPH_RGW_ROLE_H
#define CEPH_RGW_ROLE_H

class RGWRole
{
  static const string role_name_oid_prefix;
  static const string role_oid_prefix;

  CephContext *cct;
  RGWRados *store;
  string id;
  string name;
  string path;
  string creation_date;
  string trust_policy;

  int store_info(bool exclusive);
  int store_name(bool exclusive);
  int read_id(const string& role_name, string& role_id);
  int read_name();
  int read_info();

public:
  RGWRole(CephContext *cct,
          RGWRados *store,
          string name,
          string path,
          string trust_policy)
  : cct(cct),
    store(store),
    name(std::move(name)),
    path(std::move(path)),
    trust_policy(std::move(trust_policy)) {
    if (this->path.empty())
      this->path = "/";
  }

  RGWRole(CephContext *cct,
          RGWRados *store,
          string name)
  : cct(cct),
    store(store),
    name(std::move(name)) {}

  RGWRole() {}

  ~RGWRole() = default;

  void encode(bufferlist& bl) const {
    ENCODE_START(1, 1, bl);
    ::encode(id, bl);
    ::encode(name, bl);
    ::encode(path, bl);
    ::encode(creation_date, bl);
    ::encode(trust_policy, bl);
    ENCODE_FINISH(bl);
  }

  void decode(bufferlist::iterator& bl) {
    DECODE_START(1, bl);
    ::decode(id, bl);
    ::decode(name, bl);
    ::decode(path, bl);
    ::decode(creation_date, bl);
    ::decode(trust_policy, bl);
    DECODE_FINISH(bl);
  }

  const string& get_id() const { return id; }
  const string& get_name() const { return name; }
  const string& get_path() const { return path; }
  const string& get_create_date() const { return creation_date; }

  int create(bool exclusive);
  int delete_obj();
  int get();
  void dump(Formatter *f) const;
  void decode_json(JSONObj *obj);

  static const string& get_names_oid_prefix();
  static const string& get_info_oid_prefix();
};
WRITE_CLASS_ENCODER(RGWRole)
#endif /* CEPH_RGW_ROLE_H */

