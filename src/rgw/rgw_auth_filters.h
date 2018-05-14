// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#ifndef CEPH_RGW_AUTH_FILTERS_H
#define CEPH_RGW_AUTH_FILTERS_H

#include <type_traits>

#include <boost/logic/tribool.hpp>
#include <boost/optional.hpp>

#include "rgw_common.h"
#include "rgw_auth.h"

namespace rgw {
namespace auth {

/* Abstract decorator over any implementation of rgw::auth::IdentityApplier
 * which could be provided both as a pointer-to-object or the object itself. */
template <typename DecorateeT>
class DecoratedApplier : public rgw::auth::IdentityApplier {
  typedef typename std::remove_pointer<DecorateeT>::type DerefedDecorateeT;

  static_assert(std::is_base_of<rgw::auth::IdentityApplier,
                                DerefedDecorateeT>::value,
                "DecorateeT must be a subclass of rgw::auth::IdentityApplier");

  DecorateeT decoratee;

  /* There is an indirection layer over accessing decoratee to share the same
   * code base between dynamic and static decorators. The difference is about
   * what we store internally: pointer to a decorated object versus the whole
   * object itself. Googling for "SFINAE" can help to understand the code. */
  template <typename T = void,
            typename std::enable_if<
    std::is_pointer<DecorateeT>::value, T>::type* = nullptr>
  DerefedDecorateeT& get_decoratee() {
    return *decoratee;
  }

  template <typename T = void,
            typename std::enable_if<
    ! std::is_pointer<DecorateeT>::value, T>::type* = nullptr>
  DerefedDecorateeT& get_decoratee() {
    return decoratee;
  }

  template <typename T = void,
            typename std::enable_if<
    std::is_pointer<DecorateeT>::value, T>::type* = nullptr>
  const DerefedDecorateeT& get_decoratee() const {
    return *decoratee;
  }

  template <typename T = void,
            typename std::enable_if<
    ! std::is_pointer<DecorateeT>::value, T>::type* = nullptr>
  const DerefedDecorateeT& get_decoratee() const {
    return decoratee;
  }

public:
  explicit DecoratedApplier(DecorateeT&& decoratee)
    : decoratee(std::forward<DecorateeT>(decoratee)) {
  }

  uint32_t get_perms_from_aclspec(const aclspec_t& aclspec) const override {
    return get_decoratee().get_perms_from_aclspec(aclspec);
  }

  bool is_admin_of(const rgw_user& uid) const override {
    return get_decoratee().is_admin_of(uid);
  }

  bool is_owner_of(const rgw_user& uid) const override {
    return get_decoratee().is_owner_of(uid);
  }

  uint32_t get_perm_mask() const override {
    return get_decoratee().get_perm_mask();
  }

  bool is_identity(
    const boost::container::flat_set<Principal>& ids) const override {
    return get_decoratee().is_identity(ids);
  }

  void to_str(std::ostream& out) const override {
    get_decoratee().to_str(out);
  }

  void load_acct_info(RGWUserInfo& user_info) const override {  /* out */
    return get_decoratee().load_acct_info(user_info);
  }

  void modify_request_state(req_state * s) const override {     /* in/out */
    return get_decoratee().modify_request_state(s);
  }
};


template <typename T>
class ThirdPartyAccountApplier : public DecoratedApplier<T> {
  /* const */RGWRados* const store;
  const rgw_user acct_user_override;

public:
  /* A value representing situations where there is no requested account
   * override. In other words, acct_user_override will be equal to this
   * constant where the request isn't a cross-tenant one. */
  static const rgw_user UNKNOWN_ACCT;

  template <typename U>
  ThirdPartyAccountApplier(RGWRados* const store,
                           const rgw_user &acct_user_override,
                           U&& decoratee)
    : DecoratedApplier<T>(std::move(decoratee)),
      store(store),
      acct_user_override(acct_user_override) {
  }

  void to_str(std::ostream& out) const override;
  void load_acct_info(RGWUserInfo& user_info) const override;   /* out */
};

/* static declaration: UNKNOWN_ACCT will be an empty rgw_user that is a result
 * of the default construction. */
template <typename T>
const rgw_user ThirdPartyAccountApplier<T>::UNKNOWN_ACCT;

template <typename T>
void ThirdPartyAccountApplier<T>::to_str(std::ostream& out) const
{
  out << "rgw::auth::ThirdPartyAccountApplier(" + acct_user_override.to_str() + ")"
      <<   " -> ";
  DecoratedApplier<T>::to_str(out);
}

template <typename T>
void ThirdPartyAccountApplier<T>::load_acct_info(RGWUserInfo& user_info) const
{
  if (UNKNOWN_ACCT == acct_user_override) {
    /* There is no override specified by the upper layer. This means that we'll
     * load the account owned by the authenticated identity (aka auth_user). */
    DecoratedApplier<T>::load_acct_info(user_info);
  } else if (DecoratedApplier<T>::is_owner_of(acct_user_override)) {
    /* The override has been specified but the account belongs to the authenticated
     * identity. We may safely forward the call to a next stage. */
    DecoratedApplier<T>::load_acct_info(user_info);
  } else {
    /* Compatibility mechanism for multi-tenancy. For more details refer to
     * load_acct_info method of rgw::auth::RemoteApplier. */
    if (acct_user_override.tenant.empty()) {
      const rgw_user tenanted_uid(acct_user_override.id, acct_user_override.id);

      if (rgw_get_user_info_by_uid(store, tenanted_uid, user_info) >= 0) {
        /* Succeeded. */
        return;
      }
    }

    const int ret = rgw_get_user_info_by_uid(store, acct_user_override, user_info);
    if (ret < 0) {
      /* We aren't trying to recover from ENOENT here. It's supposed that creating
       * someone else's account isn't a thing we want to support in this filter. */
      if (ret == -ENOENT) {
        throw -EACCES;
      } else {
        throw ret;
      }
    }

  }
}

template <typename T> static inline
ThirdPartyAccountApplier<T> add_3rdparty(RGWRados* const store,
                                         const rgw_user &acct_user_override,
                                         T&& t) {
  return ThirdPartyAccountApplier<T>(store, acct_user_override,
                                     std::forward<T>(t));
}


template <typename T>
class SysReqApplier : public DecoratedApplier<T> {
  CephContext* const cct;
  /*const*/ RGWRados* const store;
  const RGWHTTPArgs& args;
  mutable boost::tribool is_system;

public:
  template <typename U>
  SysReqApplier(CephContext* const cct,
                /*const*/ RGWRados* const store,
                const req_state* const s,
                U&& decoratee)
    : DecoratedApplier<T>(std::forward<T>(decoratee)),
      cct(cct),
      store(store),
      args(s->info.args),
      is_system(boost::logic::indeterminate) {
  }

  void to_str(std::ostream& out) const override;
  void load_acct_info(RGWUserInfo& user_info) const override;   /* out */
  void modify_request_state(req_state* s) const override;       /* in/out */
};

template <typename T>
void SysReqApplier<T>::to_str(std::ostream& out) const
{
  out << "rgw::auth::SysReqApplier" << " -> ";
  DecoratedApplier<T>::to_str(out);
}

template <typename T>
void SysReqApplier<T>::load_acct_info(RGWUserInfo& user_info) const
{
  DecoratedApplier<T>::load_acct_info(user_info);
  is_system = user_info.system;

  if (is_system) {
    //dout(20) << "system request" << dendl;

    rgw_user effective_uid(args.sys_get(RGW_SYS_PARAM_PREFIX "uid"));
    if (! effective_uid.empty()) {
      /* We aren't writing directly to user_info for consistency and security
       * reasons. rgw_get_user_info_by_uid doesn't trigger the operator=() but
       * calls ::decode instead. */
      RGWUserInfo euser_info;
      if (rgw_get_user_info_by_uid(store, effective_uid, euser_info) < 0) {
        //ldout(s->cct, 0) << "User lookup failed!" << dendl;
        throw -EACCES;
      }
      user_info = euser_info;
    }
  }
}

template <typename T>
void SysReqApplier<T>::modify_request_state(req_state* const s) const
{
  if (boost::logic::indeterminate(is_system)) {
    RGWUserInfo unused_info;
    load_acct_info(unused_info);
  }

  if (is_system) {
    s->info.args.set_system();
    s->system_request = true;
  }
}

template <typename T> static inline
SysReqApplier<T> add_sysreq(CephContext* const cct,
                            /* const */ RGWRados* const store,
                            const req_state* const s,
                            T&& t) {
  return SysReqApplier<T>(cct, store, s, std::forward<T>(t));
}

} /* namespace auth */
} /* namespace rgw */

#endif /* CEPH_RGW_AUTH_FILTERS_H */
