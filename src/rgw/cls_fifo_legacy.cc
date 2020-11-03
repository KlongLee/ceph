// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab
/*
 * Ceph - scalable distributed file system
 *
 * Copyright (C) 2020 Red Hat <contact@redhat.com>
 * Author: Adam C. Emerson
 *
 * This is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2.1, as published by the Free Software
 * Foundation.  See file COPYING.
 *
 */

#include <cstdint>
#include <numeric>
#include <optional>
#include <string_view>

#undef FMT_HEADER_ONLY
#define FMT_HEADER_ONLY 1
#include <fmt/format.h>

#include "include/rados/librados.hpp"

#include "include/buffer.h"

#include "common/async/yield_context.h"
#include "common/random_string.h"

#include "cls/fifo/cls_fifo_types.h"
#include "cls/fifo/cls_fifo_ops.h"

#include "librados/AioCompletionImpl.h"

#include "rgw_tools.h"

#include "cls_fifo_legacy.h"

namespace rgw::cls::fifo {
static constexpr auto dout_subsys = ceph_subsys_objclass;
namespace cb = ceph::buffer;
namespace fifo = rados::cls::fifo;

using ceph::from_error_code;

inline constexpr auto MAX_RACE_RETRIES = 10;

void create_meta(lr::ObjectWriteOperation* op,
		 std::string_view id,
		 std::optional<fifo::objv> objv,
		 std::optional<std::string_view> oid_prefix,
		 bool exclusive,
		 std::uint64_t max_part_size,
		 std::uint64_t max_entry_size)
{
  fifo::op::create_meta cm;

  cm.id = id;
  cm.version = objv;
  cm.oid_prefix = oid_prefix;
  cm.max_part_size = max_part_size;
  cm.max_entry_size = max_entry_size;
  cm.exclusive = exclusive;

  cb::list in;
  encode(cm, in);
  op->exec(fifo::op::CLASS, fifo::op::CREATE_META, in);
}

int get_meta(lr::IoCtx& ioctx, const std::string& oid,
	     std::optional<fifo::objv> objv, fifo::info* info,
	     std::uint32_t* part_header_size,
	     std::uint32_t* part_entry_overhead,
	     uint64_t tid, optional_yield y,
	     bool probe)
{
  lr::ObjectReadOperation op;
  fifo::op::get_meta gm;
  gm.version = objv;
  cb::list in;
  encode(gm, in);
  cb::list bl;

  op.exec(fifo::op::CLASS, fifo::op::GET_META, in,
	  &bl, nullptr);
  auto r = rgw_rados_operate(ioctx, oid, &op, nullptr, y);
  if (r >= 0) try {
      fifo::op::get_meta_reply reply;
      auto iter = bl.cbegin();
      decode(reply, iter);
      if (info) *info = std::move(reply.info);
      if (part_header_size) *part_header_size = reply.part_header_size;
      if (part_entry_overhead)
	*part_entry_overhead = reply.part_entry_overhead;
    } catch (const cb::error& err) {
      lderr(static_cast<CephContext*>(ioctx.cct()))
	<< __PRETTY_FUNCTION__ << ":" << __LINE__
	<< " decode failed: " << err.what()
	<< " tid=" << tid << dendl;
      r = from_error_code(err.code());
    } else if (!(probe && (r == -ENOENT || r == -ENODATA))) {
    lderr(static_cast<CephContext*>(ioctx.cct()))
      << __PRETTY_FUNCTION__ << ":" << __LINE__
      << " fifo::op::GET_META failed r=" << r << " tid=" << tid
      << dendl;
  }
  return r;
};

namespace {
void update_meta(lr::ObjectWriteOperation* op, const fifo::objv& objv,
		 const fifo::update& update)
{
  fifo::op::update_meta um;

  um.version = objv;
  um.tail_part_num = update.tail_part_num();
  um.head_part_num = update.head_part_num();
  um.min_push_part_num = update.min_push_part_num();
  um.max_push_part_num = update.max_push_part_num();
  um.journal_entries_add = std::move(update).journal_entries_add();
  um.journal_entries_rm = std::move(update).journal_entries_rm();

  cb::list in;
  encode(um, in);
  op->exec(fifo::op::CLASS, fifo::op::UPDATE_META, in);
}

void part_init(lr::ObjectWriteOperation* op, std::string_view tag,
	       fifo::data_params params)
{
  fifo::op::init_part ip;

  ip.tag = tag;
  ip.params = params;

  cb::list in;
  encode(ip, in);
  op->exec(fifo::op::CLASS, fifo::op::INIT_PART, in);
}

int push_part(lr::IoCtx& ioctx, const std::string& oid, std::string_view tag,
	      std::deque<cb::list> data_bufs, std::uint64_t tid,
	      optional_yield y)
{
  lr::ObjectWriteOperation op;
  fifo::op::push_part pp;

  pp.tag = tag;
  pp.data_bufs = data_bufs;
  pp.total_len = 0;

  for (const auto& bl : data_bufs)
    pp.total_len += bl.length();

  cb::list in;
  encode(pp, in);
  auto retval = 0;
  op.exec(fifo::op::CLASS, fifo::op::PUSH_PART, in, nullptr, &retval);
  auto r = rgw_rados_operate(ioctx, oid, &op, y, lr::OPERATION_RETURNVEC);
  if (r < 0) {
    lderr(static_cast<CephContext*>(ioctx.cct()))
      << __PRETTY_FUNCTION__ << ":" << __LINE__
      << " fifo::op::PUSH_PART failed r=" << r
      << " tid=" << tid << dendl;
    return r;
  }
  if (retval < 0) {
    lderr(static_cast<CephContext*>(ioctx.cct()))
      << __PRETTY_FUNCTION__ << ":" << __LINE__
      << " error handling response retval=" << retval
      << " tid=" << tid << dendl;
  }
  return retval;
}

void push_part(lr::IoCtx& ioctx, const std::string& oid, std::string_view tag,
	       std::deque<cb::list> data_bufs, std::uint64_t tid,
	       lr::AioCompletion* c)
{
  lr::ObjectWriteOperation op;
  fifo::op::push_part pp;

  pp.tag = tag;
  pp.data_bufs = data_bufs;
  pp.total_len = 0;

  for (const auto& bl : data_bufs)
    pp.total_len += bl.length();

  cb::list in;
  encode(pp, in);
  op.exec(fifo::op::CLASS, fifo::op::PUSH_PART, in);
  auto r = ioctx.aio_operate(oid, c, &op, lr::OPERATION_RETURNVEC);
  ceph_assert(r >= 0);
}

void trim_part(lr::ObjectWriteOperation* op,
	       std::optional<std::string_view> tag,
	       std::uint64_t ofs, bool exclusive)
{
  fifo::op::trim_part tp;

  tp.tag = tag;
  tp.ofs = ofs;
  tp.exclusive = exclusive;

  cb::list in;
  encode(tp, in);
  op->exec(fifo::op::CLASS, fifo::op::TRIM_PART, in);
}

int list_part(lr::IoCtx& ioctx, const std::string& oid,
	      std::optional<std::string_view> tag, std::uint64_t ofs,
	      std::uint64_t max_entries,
	      std::vector<fifo::part_list_entry>* entries,
	      bool* more, bool* full_part, std::string* ptag,
	      std::uint64_t tid, optional_yield y)
{
  lr::ObjectReadOperation op;
  fifo::op::list_part lp;

  lp.tag = tag;
  lp.ofs = ofs;
  lp.max_entries = max_entries;

  cb::list in;
  encode(lp, in);
  cb::list bl;
  op.exec(fifo::op::CLASS, fifo::op::LIST_PART, in, &bl, nullptr);
  auto r = rgw_rados_operate(ioctx, oid, &op, nullptr, y);
  if (r >= 0) try {
      fifo::op::list_part_reply reply;
      auto iter = bl.cbegin();
      decode(reply, iter);
      if (entries) *entries = std::move(reply.entries);
      if (more) *more = reply.more;
      if (full_part) *full_part = reply.full_part;
      if (ptag) *ptag = reply.tag;
    } catch (const cb::error& err) {
      lderr(static_cast<CephContext*>(ioctx.cct()))
	<< __PRETTY_FUNCTION__ << ":" << __LINE__
	<< " decode failed: " << err.what()
	<< " tid=" << tid << dendl;
      r = from_error_code(err.code());
    } else if (r != -ENOENT) {
    lderr(static_cast<CephContext*>(ioctx.cct()))
      << __PRETTY_FUNCTION__ << ":" << __LINE__
      << " fifo::op::LIST_PART failed r=" << r << " tid=" << tid
      << dendl;
  }
  return r;
}

struct list_entry_completion : public lr::ObjectOperationCompletion {
  CephContext* cct;
  int* r_out;
  std::vector<fifo::part_list_entry>* entries;
  bool* more;
  bool* full_part;
  std::string* ptag;
  std::uint64_t tid;

  list_entry_completion(CephContext* cct, int* r_out, std::vector<fifo::part_list_entry>* entries,
			bool* more, bool* full_part, std::string* ptag,
			std::uint64_t tid)
    : cct(cct), r_out(r_out), entries(entries), more(more),
      full_part(full_part), ptag(ptag), tid(tid) {}
  virtual ~list_entry_completion() = default;
  void handle_completion(int r, bufferlist& bl) override {
    if (r >= 0) try {
	fifo::op::list_part_reply reply;
	auto iter = bl.cbegin();
	decode(reply, iter);
	if (entries) *entries = std::move(reply.entries);
	if (more) *more = reply.more;
	if (full_part) *full_part = reply.full_part;
	if (ptag) *ptag = reply.tag;
      } catch (const cb::error& err) {
	lderr(cct)
	  << __PRETTY_FUNCTION__ << ":" << __LINE__
	  << " decode failed: " << err.what()
	  << " tid=" << tid << dendl;
	r = from_error_code(err.code());
      } else if (r < 0) {
      lderr(cct)
	<< __PRETTY_FUNCTION__ << ":" << __LINE__
	<< " fifo::op::LIST_PART failed r=" << r << " tid=" << tid
	<< dendl;
    }
    if (r_out) *r_out = r;
  }
};

lr::ObjectReadOperation list_part(CephContext* cct,
				  std::optional<std::string_view> tag,
				  std::uint64_t ofs,
				  std::uint64_t max_entries,
				  int* r_out,
				  std::vector<fifo::part_list_entry>* entries,
				  bool* more, bool* full_part,
				  std::string* ptag, std::uint64_t tid)
{
  lr::ObjectReadOperation op;
  fifo::op::list_part lp;

  lp.tag = tag;
  lp.ofs = ofs;
  lp.max_entries = max_entries;

  cb::list in;
  encode(lp, in);
  op.exec(fifo::op::CLASS, fifo::op::LIST_PART, in,
	  new list_entry_completion(cct, r_out, entries, more, full_part,
				    ptag, tid));
  return op;
}

int get_part_info(lr::IoCtx& ioctx, const std::string& oid,
		  fifo::part_header* header,
		  std::uint64_t tid, optional_yield y)
{
  lr::ObjectReadOperation op;
  fifo::op::get_part_info gpi;

  cb::list in;
  cb::list bl;
  encode(gpi, in);
  op.exec(fifo::op::CLASS, fifo::op::GET_PART_INFO, in, &bl, nullptr);
  auto r = rgw_rados_operate(ioctx, oid, &op, nullptr, y);
  if (r >= 0) try {
      fifo::op::get_part_info_reply reply;
      auto iter = bl.cbegin();
      decode(reply, iter);
      if (header) *header = std::move(reply.header);
    } catch (const cb::error& err) {
      lderr(static_cast<CephContext*>(ioctx.cct()))
	<< __PRETTY_FUNCTION__ << ":" << __LINE__
	<< " decode failed: " << err.what()
	<< " tid=" << tid << dendl;
      r = from_error_code(err.code());
    } else {
    lderr(static_cast<CephContext*>(ioctx.cct()))
      << __PRETTY_FUNCTION__ << ":" << __LINE__
      << " fifo::op::GET_PART_INFO failed r=" << r << " tid=" << tid
      << dendl;
  }
  return r;
}

struct partinfo_completion : public lr::ObjectOperationCompletion {
  CephContext* cct;
  int* rp;
  fifo::part_header* h;
  std::uint64_t tid;
  partinfo_completion(CephContext* cct, int* rp, fifo::part_header* h,
		      std::uint64_t tid) :
    cct(cct), rp(rp), h(h), tid(tid) {
  }
  virtual ~partinfo_completion() = default;
  void handle_completion(int r, bufferlist& bl) override {
    if (r >= 0) try {
	fifo::op::get_part_info_reply reply;
	auto iter = bl.cbegin();
	decode(reply, iter);
	if (h) *h = std::move(reply.header);
      } catch (const cb::error& err) {
	r = from_error_code(err.code());
	lderr(cct) << __PRETTY_FUNCTION__ << ":" << __LINE__
		   << " decode failed: " << err.what()
		   << " tid=" << tid << dendl;
      } else {
      lderr(cct) << __PRETTY_FUNCTION__ << ":" << __LINE__
		 << " fifo::op::GET_PART_INFO failed r=" << r << " tid=" << tid
		 << dendl;
    }
    if (rp) {
      *rp = r;
    }
  }
};

template<typename T>
struct Completion {
private:
  lr::AioCompletion* _cur = nullptr;
  lr::AioCompletion* _super;
public:

  using Ptr = std::unique_ptr<T>;

  lr::AioCompletion* cur() const {
    return _cur;
  }
  lr::AioCompletion* super() const {
    return _super;
  }

  Completion(lr::AioCompletion* super) : _super(super) {
    super->pc->get();
  }

  ~Completion() {
    if (_super) {
      _super->pc->put();
    }
    if (_cur)
      _cur->release();
    _super = nullptr;
    _cur = nullptr;
  }

  // The only times that aio_operate can return an error are:
  // 1. The completion contains a null pointer. This should just
  //    crash, and in our case it does.
  // 2. An attempt is made to write to a snapshot. RGW doesn't use
  //    snapshots, so we don't care.
  //
  // So we will just assert that initiating an Aio operation succeeds
  // and not worry about recovering.
  static lr::AioCompletion* call(Ptr&& p) {
    p->_cur = lr::Rados::aio_create_completion(static_cast<void*>(p.get()),
					       &cb);
    auto c = p->_cur;
    p.release();
    return c;
  }
  static void complete(Ptr&& p, int r) {
    auto c = p->_super->pc;
    p->_super = nullptr;
    c->lock.lock();
    c->rval = r;
    c->complete = true;
    c->lock.unlock();

    auto cb_complete = c->callback_complete;
    auto cb_complete_arg = c->callback_complete_arg;
    if (cb_complete)
      cb_complete(c, cb_complete_arg);

    auto cb_safe = c->callback_safe;
    auto cb_safe_arg = c->callback_safe_arg;
    if (cb_safe)
      cb_safe(c, cb_safe_arg);

    c->lock.lock();
    c->callback_complete = nullptr;
    c->callback_safe = nullptr;
    c->cond.notify_all();
    c->put_unlock();
  }

  static void cb(lr::completion_t, void* arg) {
    auto t = static_cast<T*>(arg);
    auto r = t->_cur->get_return_value();
    t->_cur->release();
    t->_cur = nullptr;
    t->handle(Ptr(t), r);
  }
};

lr::ObjectReadOperation get_part_info(CephContext* cct,
				      fifo::part_header* header,
				      std::uint64_t tid, int* r = 0)
{
  lr::ObjectReadOperation op;
  fifo::op::get_part_info gpi;

  cb::list in;
  cb::list bl;
  encode(gpi, in);
  op.exec(fifo::op::CLASS, fifo::op::GET_PART_INFO, in,
	  new partinfo_completion(cct, r, header, tid));
  return op;
}
}

std::optional<marker> FIFO::to_marker(std::string_view s)
{
  marker m;
  if (s.empty()) {
    m.num = info.tail_part_num;
    m.ofs = 0;
    return m;
  }

  auto pos = s.find(':');
  if (pos == string::npos) {
    return std::nullopt;
  }

  auto num = s.substr(0, pos);
  auto ofs = s.substr(pos + 1);

  auto n = ceph::parse<decltype(m.num)>(num);
  if (!n) {
    return std::nullopt;
  }
  m.num = *n;
  auto o = ceph::parse<decltype(m.ofs)>(ofs);
  if (!o) {
    return std::nullopt;
  }
  m.ofs = *o;
  return m;
}

std::string FIFO::generate_tag() const
{
  static constexpr auto HEADER_TAG_SIZE = 16;
  return gen_rand_alphanumeric_plain(static_cast<CephContext*>(ioctx.cct()),
				     HEADER_TAG_SIZE);
}


int FIFO::apply_update(fifo::info* info,
		       const fifo::objv& objv,
		       const fifo::update& update,
		       std::uint64_t tid)
{
  ldout(cct, 20) << __PRETTY_FUNCTION__ << ":" << __LINE__
		 << " entering: tid=" << tid << dendl;
  std::unique_lock l(m);
  if (objv != info->version) {
    lderr(cct) << __PRETTY_FUNCTION__ << ":" << __LINE__
	       << " version mismatch, canceling: tid=" << tid << dendl;
    return -ECANCELED;
  }
  auto err = info->apply_update(update);
  if (err) {
    lderr(cct) << __PRETTY_FUNCTION__ << ":" << __LINE__
	       << " error applying update: " << *err << " tid=" << tid << dendl;
    return -ECANCELED;
  }

  ++info->version.ver;

  return {};
}

int FIFO::_update_meta(const fifo::update& update,
		       fifo::objv version, bool* pcanceled,
		       std::uint64_t tid, optional_yield y)
{
  ldout(cct, 20) << __PRETTY_FUNCTION__ << ":" << __LINE__
		 << " entering: tid=" << tid << dendl;
  lr::ObjectWriteOperation op;
  bool canceled = false;
  update_meta(&op, info.version, update);
  auto r = rgw_rados_operate(ioctx, oid, &op, y);
  if (r >= 0 || r == -ECANCELED) {
    canceled = (r == -ECANCELED);
    if (!canceled) {
      r = apply_update(&info, version, update, tid);
      if (r < 0) canceled = true;
    }
    if (canceled) {
      r = read_meta(tid, y);
      canceled = r < 0 ? false : true;
    }
  }
  if (pcanceled) *pcanceled = canceled;
  if (canceled) {
    ldout(cct, 20) << __PRETTY_FUNCTION__ << ":" << __LINE__
		   << " canceled: tid=" << tid << dendl;
  }
  if (r < 0) {
    lderr(cct) << __PRETTY_FUNCTION__ << ":" << __LINE__
	       << " returning error: r=" << r << " tid=" << tid << dendl;
  }
  return r;
}

struct Updater : public Completion<Updater> {
  FIFO* fifo;
  fifo::update update;
  fifo::objv version;
  bool reread = false;
  bool* pcanceled = nullptr;
  std::uint64_t tid;
  Updater(FIFO* fifo, lr::AioCompletion* super,
	  const fifo::update& update, fifo::objv version,
	  bool* pcanceled, std::uint64_t tid)
    : Completion(super), fifo(fifo), update(update), version(version),
      pcanceled(pcanceled) {}

  void handle(Ptr&& p, int r) {
    ldout(fifo->cct, 20) << __PRETTY_FUNCTION__ << ":" << __LINE__
			 << " entering: tid=" << tid << dendl;
    if (reread)
      handle_reread(std::move(p), r);
    else
      handle_update(std::move(p), r);
  }

  void handle_update(Ptr&& p, int r) {
    ldout(fifo->cct, 20) << __PRETTY_FUNCTION__ << ":" << __LINE__
			 << " handling async update_meta: tid="
			 << tid << dendl;
    if (r < 0 && r != -ECANCELED) {
      lderr(fifo->cct) << __PRETTY_FUNCTION__ << ":" << __LINE__
		 << " update failed: r=" << r << " tid=" << tid << dendl;
      complete(std::move(p), r);
      return;
    }
    bool canceled = (r == -ECANCELED);
    if (!canceled) {
      int r = fifo->apply_update(&fifo->info, version, update, tid);
      if (r < 0) {
	ldout(fifo->cct, 20) << __PRETTY_FUNCTION__ << ":" << __LINE__
			     << " update failed, marking canceled: r=" << r
			     << " tid=" << tid << dendl;
	canceled = true;
      }
    }
    if (canceled) {
      reread = true;
      fifo->read_meta(tid, call(std::move(p)));
      return;
    }
    if (pcanceled)
      *pcanceled = false;
    ldout(fifo->cct, 20) << __PRETTY_FUNCTION__ << ":" << __LINE__
			 << " completing: tid=" << tid << dendl;
    complete(std::move(p), 0);
  }

  void handle_reread(Ptr&& p, int r) {
    ldout(fifo->cct, 20) << __PRETTY_FUNCTION__ << ":" << __LINE__
			 << " handling async read_meta: tid="
			 << tid << dendl;
    if (r < 0 && pcanceled) {
      *pcanceled = false;
    } else if (r >= 0 && pcanceled) {
      *pcanceled = true;
    }
    if (r < 0) {
      lderr(fifo->cct) << __PRETTY_FUNCTION__ << ":" << __LINE__
		       << " failed dispatching read_meta: r=" << r << " tid="
		       << tid << dendl;
    } else {
      ldout(fifo->cct, 20) << __PRETTY_FUNCTION__ << ":" << __LINE__
			   << " completing: tid=" << tid << dendl;
    }
    complete(std::move(p), r);
  }
};

void FIFO::_update_meta(const fifo::update& update,
			fifo::objv version, bool* pcanceled,
			std::uint64_t tid, lr::AioCompletion* c)
{
  ldout(cct, 20) << __PRETTY_FUNCTION__ << ":" << __LINE__
		 << " entering: tid=" << tid << dendl;
  lr::ObjectWriteOperation op;
  update_meta(&op, info.version, update);
  auto updater = std::make_unique<Updater>(this, c, update, version, pcanceled,
					   tid);
  auto r = ioctx.aio_operate(oid, Updater::call(std::move(updater)), &op);
  assert(r >= 0);
}

int FIFO::create_part(int64_t part_num, std::string_view tag, std::uint64_t tid,
		      optional_yield y)
{
  ldout(cct, 20) << __PRETTY_FUNCTION__ << ":" << __LINE__
		 << " entering: tid=" << tid << dendl;
  lr::ObjectWriteOperation op;
  op.create(false); /* We don't need exclusivity, part_init ensures
		       we're creating from the  same journal entry. */
  std::unique_lock l(m);
  part_init(&op, tag, info.params);
  auto oid = info.part_oid(part_num);
  l.unlock();
  auto r = rgw_rados_operate(ioctx, oid, &op, y);
  if (r < 0) {
    lderr(cct) << __PRETTY_FUNCTION__ << ":" << __LINE__
	       << " part_init failed: r=" << r << " tid="
	       << tid << dendl;
  }
  return r;
}

int FIFO::remove_part(int64_t part_num, std::string_view tag, std::uint64_t tid,
		      optional_yield y)
{
  ldout(cct, 20) << __PRETTY_FUNCTION__ << ":" << __LINE__
		 << " entering: tid=" << tid << dendl;
  lr::ObjectWriteOperation op;
  op.remove();
  std::unique_lock l(m);
  auto oid = info.part_oid(part_num);
  l.unlock();
  auto r = rgw_rados_operate(ioctx, oid, &op, y);
  if (r < 0) {
    lderr(cct) << __PRETTY_FUNCTION__ << ":" << __LINE__
	       << " remove failed: r=" << r << " tid="
	       << tid << dendl;
  }
  return r;
}

int FIFO::process_journal(std::uint64_t tid, optional_yield y)
{
  ldout(cct, 20) << __PRETTY_FUNCTION__ << ":" << __LINE__
		 << " entering: tid=" << tid << dendl;
  std::vector<fifo::journal_entry> processed;

  std::unique_lock l(m);
  auto tmpjournal = info.journal;
  auto new_tail = info.tail_part_num;
  auto new_head = info.head_part_num;
  auto new_max = info.max_push_part_num;
  l.unlock();

  int r = 0;
  for (auto& [n, entry] : tmpjournal) {
    ldout(cct, 20) << __PRETTY_FUNCTION__ << ":" << __LINE__
		   << " processing entry: entry=" << entry << " tid=" << tid
		   << dendl;
    switch (entry.op) {
    case fifo::journal_entry::Op::create:
      r = create_part(entry.part_num, entry.part_tag, tid, y);
      if (entry.part_num > new_max) {
	new_max = entry.part_num;
      }
      break;
    case fifo::journal_entry::Op::set_head:
      r = 0;
      if (entry.part_num > new_head) {
	new_head = entry.part_num;
      }
      break;
    case fifo::journal_entry::Op::remove:
      r = remove_part(entry.part_num, entry.part_tag, tid, y);
      if (r == -ENOENT) r = 0;
      if (entry.part_num >= new_tail) {
	new_tail = entry.part_num + 1;
      }
      break;
    default:
      lderr(cct) << __PRETTY_FUNCTION__ << ":" << __LINE__
		 << " unknown journaled op: entry=" << entry << " tid="
		 << tid << dendl;
      return -EIO;
    }

    if (r < 0) {
      lderr(cct) << __PRETTY_FUNCTION__ << ":" << __LINE__
		 << " processing entry failed: entry=" << entry
		 << " r=" << r << " tid=" << tid << dendl;
      return -r;
    }

    processed.push_back(std::move(entry));
  }

  // Postprocess
  bool canceled = true;

  for (auto i = 0; canceled && i < MAX_RACE_RETRIES; ++i) {
    ldout(cct, 20) << __PRETTY_FUNCTION__ << ":" << __LINE__
		   << " postprocessing: i=" << i << " tid=" << tid << dendl;

    std::optional<int64_t> tail_part_num;
    std::optional<int64_t> head_part_num;
    std::optional<int64_t> max_part_num;

    std::unique_lock l(m);
    auto objv = info.version;
    if (new_tail > tail_part_num) tail_part_num = new_tail;
    if (new_head > info.head_part_num) head_part_num = new_head;
    if (new_max > info.max_push_part_num) max_part_num = new_max;
    l.unlock();

    if (processed.empty() &&
	!tail_part_num &&
	!max_part_num) {
      ldout(cct, 20) << __PRETTY_FUNCTION__ << ":" << __LINE__
		     << " nothing to update any more: i=" << i << " tid="
		     << tid << dendl;
      canceled = false;
      break;
    }
    auto u = fifo::update().tail_part_num(tail_part_num)
      .head_part_num(head_part_num).max_push_part_num(max_part_num)
      .journal_entries_rm(processed);
    r = _update_meta(u, objv, &canceled, tid, y);
    if (r < 0) {
      lderr(cct) << __PRETTY_FUNCTION__ << ":" << __LINE__
		 << " _update_meta failed: update=" << u
		 << " r=" << r << " tid=" << tid << dendl;
      break;
    }

    if (canceled) {
      std::vector<fifo::journal_entry> new_processed;
      std::unique_lock l(m);
      ldout(cct, 20) << __PRETTY_FUNCTION__ << ":" << __LINE__
		     << " update canceled, retrying: i=" << i << " tid="
		     << tid << dendl;
      for (auto& e : processed) {
	auto jiter = info.journal.find(e.part_num);
	/* journal entry was already processed */
	if (jiter == info.journal.end() ||
	    !(jiter->second == e)) {
	  continue;
	}
	new_processed.push_back(e);
      }
      processed = std::move(new_processed);
    }
  }
  if (r == 0 && canceled) {
    lderr(cct) << __PRETTY_FUNCTION__ << ":" << __LINE__
	       << " canceled too many times, giving up: tid=" << tid << dendl;
    r = -ECANCELED;
  }
  if (r < 0) {
    lderr(cct) << __PRETTY_FUNCTION__ << ":" << __LINE__
	       << " failed, r=: " << r << " tid=" << tid << dendl;
  }
  return r;
}

int FIFO::_prepare_new_part(bool is_head, std::uint64_t tid, optional_yield y)
{
  ldout(cct, 20) << __PRETTY_FUNCTION__ << ":" << __LINE__
		 << " entering: tid=" << tid << dendl;
  std::unique_lock l(m);
  std::vector jentries = { info.next_journal_entry(generate_tag()) };
  if (info.journal.find(jentries.front().part_num) != info.journal.end()) {
    l.unlock();
    ldout(cct, 5) << __PRETTY_FUNCTION__ << ":" << __LINE__
		  << " new part journaled, but not processed: tid="
		  << tid << dendl;
    auto r = process_journal(tid, y);
    if (r < 0) {
      lderr(cct) << __PRETTY_FUNCTION__ << ":" << __LINE__
		 << " process_journal failed: r=" << r << " tid=" << tid << dendl;
    }
    return r;
  }
  std::int64_t new_head_part_num = info.head_part_num;
  auto version = info.version;

  if (is_head) {
    ldout(cct, 20) << __PRETTY_FUNCTION__ << ":" << __LINE__
		   << " needs new head: tid=" << tid << dendl;
    auto new_head_jentry = jentries.front();
    new_head_jentry.op = fifo::journal_entry::Op::set_head;
    new_head_part_num = jentries.front().part_num;
    jentries.push_back(std::move(new_head_jentry));
  }
  l.unlock();

  int r = 0;
  bool canceled = true;
  for (auto i = 0; canceled && i < MAX_RACE_RETRIES; ++i) {
    canceled = false;
    ldout(cct, 20) << __PRETTY_FUNCTION__ << ":" << __LINE__
		   << " updating metadata: i=" << i << " tid=" << tid << dendl;
    auto u = fifo::update{}.journal_entries_add(jentries);
    r = _update_meta(u, version, &canceled, tid, y);
    if (r >= 0 && canceled) {
      std::unique_lock l(m);
      auto found = (info.journal.find(jentries.front().part_num) !=
		    info.journal.end());
      if ((info.max_push_part_num >= jentries.front().part_num &&
	   info.head_part_num >= new_head_part_num)) {
	ldout(cct, 20) << __PRETTY_FUNCTION__ << ":" << __LINE__
		       << " raced, but journaled and processed: i=" << i
		       << " tid=" << tid << dendl;
	return 0;
      }
      if (found) {
	ldout(cct, 20) << __PRETTY_FUNCTION__ << ":" << __LINE__
		       << " raced, journaled but not processed: i=" << i
		       << " tid=" << tid << dendl;
	canceled = false;
      }
      l.unlock();
    }
    if (r < 0) {
      lderr(cct) << __PRETTY_FUNCTION__ << ":" << __LINE__
		 << " _update_meta failed: update=" << u << " r=" << r
		 << " tid=" << tid << dendl;
      return r;
    }
  }
  if (canceled) {
    lderr(cct) << __PRETTY_FUNCTION__ << ":" << __LINE__
	       << " canceled too many times, giving up: tid=" << tid << dendl;
    return -ECANCELED;
  }
  r = process_journal(tid, y);
  if (r < 0) {
    lderr(cct) << __PRETTY_FUNCTION__ << ":" << __LINE__
	       << " process_journal failed: r=" << r << " tid=" << tid << dendl;
  }
  return r;
}

int FIFO::_prepare_new_head(std::uint64_t tid, optional_yield y)
{
  ldout(cct, 20) << __PRETTY_FUNCTION__ << ":" << __LINE__
		 << " entering: tid=" << tid << dendl;
  std::unique_lock l(m);
  std::int64_t new_head_num = info.head_part_num + 1;
  auto max_push_part_num = info.max_push_part_num;
  auto version = info.version;
  l.unlock();

  int r = 0;
  if (max_push_part_num < new_head_num) {
    ldout(cct, 20) << __PRETTY_FUNCTION__ << ":" << __LINE__
		   << " need new part: tid=" << tid << dendl;
    r = _prepare_new_part(true, tid, y);
    if (r < 0) {
      lderr(cct) << __PRETTY_FUNCTION__ << ":" << __LINE__
		 << " _prepare_new_part failed: r=" << r
		 << " tid=" << tid << dendl;
      return r;
    }
    std::unique_lock l(m);
    if (info.max_push_part_num < new_head_num) {
      lderr(cct) << __PRETTY_FUNCTION__ << ":" << __LINE__
		 << " inconsistency, push part less than head part: "
		 << " tid=" << tid << dendl;
      return -EIO;
    }
    l.unlock();
    return 0;
  }

  bool canceled = true;
  for (auto i = 0; canceled && i < MAX_RACE_RETRIES; ++i) {
    ldout(cct, 20) << __PRETTY_FUNCTION__ << ":" << __LINE__
		   << " updating head: i=" << i << " tid=" << tid << dendl;
    auto u = fifo::update{}.head_part_num(new_head_num);
    r = _update_meta(u, version, &canceled, tid, y);
    if (r < 0) {
      lderr(cct) << __PRETTY_FUNCTION__ << ":" << __LINE__
		 << " _update_meta failed: update=" << u << " r=" << r
		 << " tid=" << tid << dendl;
      return r;
    }
    std::unique_lock l(m);
    auto head_part_num = info.head_part_num;
    version = info.version;
    l.unlock();
    if (canceled && (head_part_num >= new_head_num)) {
      ldout(cct, 20) << __PRETTY_FUNCTION__ << ":" << __LINE__
		     << " raced, but completed by the other caller: i=" << i
		     << " tid=" << tid << dendl;
      canceled = false;
    }
  }
  if (canceled) {
    lderr(cct) << __PRETTY_FUNCTION__ << ":" << __LINE__
	       << " canceled too many times, giving up: tid=" << tid << dendl;
    return -ECANCELED;
  }
  return 0;
}

struct NewPartPreparer : public Completion<NewPartPreparer> {
  FIFO* f;
  std::vector<fifo::journal_entry> jentries;
  int i = 0;
  std::int64_t new_head_part_num;
  bool canceled = false;
  uint64_t tid;

  NewPartPreparer(FIFO* f, lr::AioCompletion* super,
		  std::vector<fifo::journal_entry> jentries,
		  std::int64_t new_head_part_num,
		  std::uint64_t tid)
    : Completion(super), f(f), jentries(std::move(jentries)),
      new_head_part_num(new_head_part_num), tid(tid) {}

  void handle(Ptr&& p, int r) {
    ldout(f->cct, 20) << __PRETTY_FUNCTION__ << ":" << __LINE__
		      << " entering: tid=" << tid << dendl;
    if (r < 0) {
      lderr(f->cct) << __PRETTY_FUNCTION__ << ":" << __LINE__
		    << " _update_meta failed:  r=" << r
		    << " tid=" << tid << dendl;
      complete(std::move(p), r);
      return;
    }

    if (canceled) {
      std::unique_lock l(f->m);
      auto iter = f->info.journal.find(jentries.front().part_num);
      auto max_push_part_num = f->info.max_push_part_num;
      auto head_part_num = f->info.head_part_num;
      auto version = f->info.version;
      auto found = (iter != f->info.journal.end());
      l.unlock();
      if ((max_push_part_num >= jentries.front().part_num &&
	   head_part_num >= new_head_part_num)) {
	ldout(f->cct, 20) << __PRETTY_FUNCTION__ << ":" << __LINE__
			  << " raced, but journaled and processed: i=" << i
			  << " tid=" << tid << dendl;
	complete(std::move(p), 0);
	return;
      }
      if (i >= MAX_RACE_RETRIES) {
	complete(std::move(p), -ECANCELED);
	return;
      }
      if (!found) {
	++i;
	f->_update_meta(fifo::update{}
			.journal_entries_add(jentries),
                        version, &canceled, tid, call(std::move(p)));
	return;
      } else {
	ldout(f->cct, 20) << __PRETTY_FUNCTION__ << ":" << __LINE__
			  << " raced, journaled but not processed: i=" << i
			  << " tid=" << tid << dendl;
	canceled = false;
      }
      // Fall through. We still need to process the journal.
    }
    f->process_journal(tid, super());
    return;
  }
};

void FIFO::_prepare_new_part(bool is_head, std::uint64_t tid,
			     lr::AioCompletion* c)
{
  std::unique_lock l(m);
  std::vector jentries = { info.next_journal_entry(generate_tag()) };
  if (info.journal.find(jentries.front().part_num) != info.journal.end()) {
    l.unlock();
    ldout(cct, 5) << __PRETTY_FUNCTION__ << ":" << __LINE__
		  << " new part journaled, but not processed: tid="
		  << tid << dendl;
    process_journal(tid, c);
    return;
  }
  std::int64_t new_head_part_num = info.head_part_num;
  auto version = info.version;

  if (is_head) {
    auto new_head_jentry = jentries.front();
    new_head_jentry.op = fifo::journal_entry::Op::set_head;
    new_head_part_num = jentries.front().part_num;
    jentries.push_back(std::move(new_head_jentry));
  }
  l.unlock();

  auto n = std::make_unique<NewPartPreparer>(this, c, jentries,
					     new_head_part_num, tid);
  auto np = n.get();
  _update_meta(fifo::update{}.journal_entries_add(jentries), version,
	       &np->canceled, tid, NewPartPreparer::call(std::move(n)));
}

struct NewHeadPreparer : public Completion<NewHeadPreparer> {
  FIFO* f;
  int i = 0;
  bool newpart;
  std::int64_t new_head_num;
  bool canceled = false;
  std::uint64_t tid;

  NewHeadPreparer(FIFO* f, lr::AioCompletion* super,
		  bool newpart, std::int64_t new_head_num, std::uint64_t tid)
    : Completion(super), f(f), newpart(newpart), new_head_num(new_head_num),
      tid(tid) {}

  void handle(Ptr&& p, int r) {
    if (newpart)
      handle_newpart(std::move(p), r);
    else
      handle_update(std::move(p), r);
  }

  void handle_newpart(Ptr&& p, int r) {
    if (r < 0) {
      lderr(f->cct) << __PRETTY_FUNCTION__ << ":" << __LINE__
		    << " _prepare_new_part failed: r=" << r
		    << " tid=" << tid << dendl;
      complete(std::move(p), r);
      return;
    }
    std::unique_lock l(f->m);
    if (f->info.max_push_part_num < new_head_num) {
      l.unlock();
      lderr(f->cct) << __PRETTY_FUNCTION__ << ":" << __LINE__
		    << " _prepare_new_part failed: r=" << r
		    << " tid=" << tid << dendl;
      complete(std::move(p), -EIO);
    } else {
      l.unlock();
      complete(std::move(p), 0);
    }
  }

  void handle_update(Ptr&& p, int r) {
    std::unique_lock l(f->m);
    auto head_part_num = f->info.head_part_num;
    auto version = f->info.version;
    l.unlock();

    if (r < 0) {
      lderr(f->cct) << __PRETTY_FUNCTION__ << ":" << __LINE__
		    << " _update_meta failed: r=" << r
		    << " tid=" << tid << dendl;
      complete(std::move(p), r);
      return;
    }
    if (canceled) {
      if (i >= MAX_RACE_RETRIES) {
	lderr(f->cct) << __PRETTY_FUNCTION__ << ":" << __LINE__
		      << " canceled too many times, giving up: tid=" << tid << dendl;
	complete(std::move(p), -ECANCELED);
	return;
      }

      // Raced, but there's still work to do!
      if (head_part_num < new_head_num) {
	canceled = false;
	++i;
	ldout(f->cct, 20) << __PRETTY_FUNCTION__ << ":" << __LINE__
			  << " updating head: i=" << i << " tid=" << tid << dendl;
	f->_update_meta(fifo::update{}.head_part_num(new_head_num),
			version, &this->canceled, tid, call(std::move(p)));
	return;
      }
    }
    ldout(f->cct, 20) << __PRETTY_FUNCTION__ << ":" << __LINE__
		   << " succeeded : i=" << i << " tid=" << tid << dendl;
    complete(std::move(p), 0);
    return;
  }
};

void FIFO::_prepare_new_head(std::uint64_t tid, lr::AioCompletion* c)
{
  ldout(cct, 20) << __PRETTY_FUNCTION__ << ":" << __LINE__
		 << " entering: tid=" << tid << dendl;
  std::unique_lock l(m);
  int64_t new_head_num = info.head_part_num + 1;
  auto max_push_part_num = info.max_push_part_num;
  auto version = info.version;
  l.unlock();

  if (max_push_part_num < new_head_num) {
    ldout(cct, 20) << __PRETTY_FUNCTION__ << ":" << __LINE__
		   << " need new part: tid=" << tid << dendl;
    auto n = std::make_unique<NewHeadPreparer>(this, c, true, new_head_num,
					       tid);
    _prepare_new_part(true, tid, NewHeadPreparer::call(std::move(n)));
  } else {
    ldout(cct, 20) << __PRETTY_FUNCTION__ << ":" << __LINE__
		   << " updating head: tid=" << tid << dendl;
    auto n = std::make_unique<NewHeadPreparer>(this, c, false, new_head_num,
					       tid);
    auto np = n.get();
    _update_meta(fifo::update{}.head_part_num(new_head_num), version,
		 &np->canceled, tid, NewHeadPreparer::call(std::move(n)));
  }
}

int FIFO::push_entries(const std::deque<cb::list>& data_bufs,
		       std::uint64_t tid, optional_yield y)
{
  ldout(cct, 20) << __PRETTY_FUNCTION__ << ":" << __LINE__
		 << " entering: tid=" << tid << dendl;
  std::unique_lock l(m);
  auto head_part_num = info.head_part_num;
  auto tag = info.head_tag;
  const auto part_oid = info.part_oid(head_part_num);
  l.unlock();

  auto r = push_part(ioctx, part_oid, tag, data_bufs, tid, y);
  if (r < 0) {
    lderr(cct) << __PRETTY_FUNCTION__ << ":" << __LINE__
	       << " push_part failed: r=" << r << " tid=" << tid << dendl;
  }
  return r;
}

void FIFO::push_entries(const std::deque<cb::list>& data_bufs,
			std::uint64_t tid, lr::AioCompletion* c)
{
  std::unique_lock l(m);
  auto head_part_num = info.head_part_num;
  auto tag = info.head_tag;
  const auto part_oid = info.part_oid(head_part_num);
  l.unlock();

  push_part(ioctx, part_oid, tag, data_bufs, tid, c);
}

int FIFO::trim_part(int64_t part_num, uint64_t ofs,
		    std::optional<std::string_view> tag,
		    bool exclusive, std::uint64_t tid,
		    optional_yield y)
{
  ldout(cct, 20) << __PRETTY_FUNCTION__ << ":" << __LINE__
		 << " entering: tid=" << tid << dendl;
  lr::ObjectWriteOperation op;
  std::unique_lock l(m);
  const auto part_oid = info.part_oid(part_num);
  l.unlock();
  rgw::cls::fifo::trim_part(&op, tag, ofs, exclusive);
  auto r = rgw_rados_operate(ioctx, part_oid, &op, y);
  if (r < 0) {
    lderr(cct) << __PRETTY_FUNCTION__ << ":" << __LINE__
	       << " trim_part failed: r=" << r << " tid=" << tid << dendl;
  }
  return 0;
}

void FIFO::trim_part(int64_t part_num, uint64_t ofs,
		     std::optional<std::string_view> tag,
		     bool exclusive, std::uint64_t tid,
		     lr::AioCompletion* c)
{
  ldout(cct, 20) << __PRETTY_FUNCTION__ << ":" << __LINE__
		 << " entering: tid=" << tid << dendl;
  lr::ObjectWriteOperation op;
  std::unique_lock l(m);
  const auto part_oid = info.part_oid(part_num);
  l.unlock();
  rgw::cls::fifo::trim_part(&op, tag, ofs, exclusive);
  auto r = ioctx.aio_operate(part_oid, c, &op);
  ceph_assert(r >= 0);
}

int FIFO::open(lr::IoCtx ioctx, std::string oid, std::unique_ptr<FIFO>* fifo,
	       optional_yield y, std::optional<fifo::objv> objv,
	       bool probe)
{
  auto cct = static_cast<CephContext*>(ioctx.cct());
  ldout(cct, 20)
    << __PRETTY_FUNCTION__ << ":" << __LINE__
    << " entering" << dendl;
  fifo::info info;
  std::uint32_t size;
  std::uint32_t over;
  int r = get_meta(ioctx, std::move(oid), objv, &info, &size, &over, 0, y,
		   probe);
  if (r < 0) {
    if (!(probe && (r == -ENOENT || r == -ENODATA))) {
      lderr(cct) << __PRETTY_FUNCTION__ << ":" << __LINE__
		 << " get_meta failed: r=" << r << dendl;
    }
    return r;
  }
  std::unique_ptr<FIFO> f(new FIFO(std::move(ioctx), oid));
  f->info = info;
  f->part_header_size = size;
  f->part_entry_overhead = over;
  // If there are journal entries, process them, in case
  // someone crashed mid-transaction.
  if (!info.journal.empty()) {
    ldout(cct, 20)
      << __PRETTY_FUNCTION__ << ":" << __LINE__
      << " processing leftover journal" << dendl;
    r = f->process_journal(0, y);
    if (r < 0) {
      lderr(cct) << __PRETTY_FUNCTION__ << ":" << __LINE__
		 << " process_journal failed: r=" << r << dendl;
      return r;
    }
  }
  *fifo = std::move(f);
  return 0;
}

int FIFO::create(lr::IoCtx ioctx, std::string oid, std::unique_ptr<FIFO>* fifo,
		 optional_yield y, std::optional<fifo::objv> objv,
		 std::optional<std::string_view> oid_prefix,
		 bool exclusive, std::uint64_t max_part_size,
		 std::uint64_t max_entry_size)
{
  auto cct = static_cast<CephContext*>(ioctx.cct());
  ldout(cct, 20)
    << __PRETTY_FUNCTION__ << ":" << __LINE__
    << " entering" << dendl;
  lr::ObjectWriteOperation op;
  create_meta(&op, oid, objv, oid_prefix, exclusive, max_part_size,
	      max_entry_size);
  auto r = rgw_rados_operate(ioctx, oid, &op, y);
  if (r < 0) {
    lderr(cct) << __PRETTY_FUNCTION__ << ":" << __LINE__
	       << " create_meta failed: r=" << r << dendl;
    return r;
  }
  r = open(std::move(ioctx), std::move(oid), fifo, y, objv);
  return r;
}

int FIFO::read_meta(std::uint64_t tid, optional_yield y) {
  ldout(cct, 20) << __PRETTY_FUNCTION__ << ":" << __LINE__
		 << " entering: tid=" << tid << dendl;
  fifo::info _info;
  std::uint32_t _phs;
  std::uint32_t _peo;

  auto r = get_meta(ioctx, oid, nullopt, &_info, &_phs, &_peo, tid, y);
  if (r < 0) {
    lderr(cct) << __PRETTY_FUNCTION__ << ":" << __LINE__
	       << " get_meta failed: r=" << r << " tid=" << tid << dendl;
    return r;
  }
  std::unique_lock l(m);
  // We have a newer version already!
  if (_info.version.same_or_later(this->info.version)) {
    info = std::move(_info);
    part_header_size = _phs;
    part_entry_overhead = _peo;
  }
  return 0;
}

int FIFO::read_meta(optional_yield y) {
  std::unique_lock l(m);
  auto tid = ++next_tid;
  l.unlock();
  return read_meta(tid, y);
}

struct Reader : public Completion<Reader> {
  FIFO* fifo;
  cb::list bl;
  std::uint64_t tid;
  Reader(FIFO* fifo, lr::AioCompletion* super, std::uint64_t tid)
    : Completion(super), fifo(fifo), tid(tid) {}

  void handle(Ptr&& p, int r) {
    auto cct = fifo->cct;
    ldout(cct, 20) << __PRETTY_FUNCTION__ << ":" << __LINE__
		   << " entering: tid=" << tid << dendl;
    if (r >= 0) try {
	fifo::op::get_meta_reply reply;
	auto iter = bl.cbegin();
	decode(reply, iter);
	std::unique_lock l(fifo->m);
	if (reply.info.version.same_or_later(fifo->info.version)) {
	  fifo->info = std::move(reply.info);
	  fifo->part_header_size = reply.part_header_size;
	  fifo->part_entry_overhead = reply.part_entry_overhead;
	}
      } catch (const cb::error& err) {
	lderr(cct) << __PRETTY_FUNCTION__ << ":" << __LINE__
		   << " failed to decode response err=" << err.what()
		   << " tid=" << tid << dendl;
	r = from_error_code(err.code());
      } else {
      lderr(cct) << __PRETTY_FUNCTION__ << ":" << __LINE__
		 << " read_meta failed r=" << r
		 << " tid=" << tid << dendl;
    }
    complete(std::move(p), r);
  }
};

void FIFO::read_meta(std::uint64_t tid, lr::AioCompletion* c)
{
  ldout(cct, 20) << __PRETTY_FUNCTION__ << ":" << __LINE__
		 << " entering: tid=" << tid << dendl;
  lr::ObjectReadOperation op;
  fifo::op::get_meta gm;
  cb::list in;
  encode(gm, in);
  auto reader = std::make_unique<Reader>(this, c, tid);
  auto rp = reader.get();
  auto r = ioctx.aio_exec(oid, Reader::call(std::move(reader)), fifo::op::CLASS,
			  fifo::op::GET_META, in, &rp->bl);
  assert(r >= 0);
}

const fifo::info& FIFO::meta() const {
  return info;
}

std::pair<std::uint32_t, std::uint32_t> FIFO::get_part_layout_info() const {
  return {part_header_size, part_entry_overhead};
}

int FIFO::push(const cb::list& bl, optional_yield y) {
  return push(std::vector{ bl }, y);
}

void FIFO::push(const cb::list& bl, lr::AioCompletion* c) {
  push(std::vector{ bl }, c);
}

int FIFO::push(const std::vector<cb::list>& data_bufs, optional_yield y)
{
  std::unique_lock l(m);
  auto tid = ++next_tid;
  auto max_entry_size = info.params.max_entry_size;
  auto need_new_head = info.need_new_head();
  l.unlock();
  ldout(cct, 20) << __PRETTY_FUNCTION__ << ":" << __LINE__
		 << " entering: tid=" << tid << dendl;
  if (data_bufs.empty()) {
    ldout(cct, 20) << __PRETTY_FUNCTION__ << ":" << __LINE__
		   << " empty push, returning success tid=" << tid << dendl;
    return 0;
  }

  // Validate sizes
  for (const auto& bl : data_bufs) {
    if (bl.length() > max_entry_size) {
      lderr(cct) << __PRETTY_FUNCTION__ << ":" << __LINE__
		 << " entry bigger than max_entry_size tid=" << tid << dendl;
      return -E2BIG;
    }
  }

  int r = 0;
  if (need_new_head) {
    ldout(cct, 20) << __PRETTY_FUNCTION__ << ":" << __LINE__
		   << " need new head tid=" << tid << dendl;
    r = _prepare_new_head(tid, y);
    if (r < 0) {
      lderr(cct) << __PRETTY_FUNCTION__ << ":" << __LINE__
		 << " _prepare_new_head failed: r=" << r
		 << " tid=" << tid << dendl;
      return r;
    }
  }

  std::deque<cb::list> remaining(data_bufs.begin(), data_bufs.end());
  std::deque<cb::list> batch;

  uint64_t batch_len = 0;
  auto retries = 0;
  bool canceled = true;
  while ((!remaining.empty() || !batch.empty()) &&
	 (retries <= MAX_RACE_RETRIES)) {
    ldout(cct, 20) << __PRETTY_FUNCTION__ << ":" << __LINE__
		   << " preparing push: remaining=" << remaining.size()
		   << " batch=" << batch.size() << " retries=" << retries
		   << " tid=" << tid << dendl;
    std::unique_lock l(m);
    auto max_part_size = info.params.max_part_size;
    auto overhead = part_entry_overhead;
    l.unlock();

    while (!remaining.empty() &&
	   (remaining.front().length() + batch_len <= max_part_size)) {
      /* We can send entries with data_len up to max_entry_size,
	 however, we want to also account the overhead when
	 dealing with multiple entries. Previous check doesn't
	 account for overhead on purpose. */
      batch_len += remaining.front().length() + overhead;
      batch.push_back(std::move(remaining.front()));
      remaining.pop_front();
    }
    ldout(cct, 20) << __PRETTY_FUNCTION__ << ":" << __LINE__
		   << " prepared push: remaining=" << remaining.size()
		   << " batch=" << batch.size() << " retries=" << retries
		   << " batch_len=" << batch_len
		   << " tid=" << tid << dendl;

    auto r = push_entries(batch, tid, y);
    if (r == -ERANGE) {
      canceled = true;
      ++retries;
      ldout(cct, 20) << __PRETTY_FUNCTION__ << ":" << __LINE__
		     << " need new head tid=" << tid << dendl;
      r = _prepare_new_head(tid, y);
      if (r < 0) {
	lderr(cct) << __PRETTY_FUNCTION__ << ":" << __LINE__
		   << " prepare_new_head failed: r=" << r
		   << " tid=" << tid << dendl;
	return r;
      }
      r = 0;
      continue;
    }
    if (r < 0) {
      lderr(cct) << __PRETTY_FUNCTION__ << ":" << __LINE__
		 << " push_entries failed: r=" << r
		 << " tid=" << tid << dendl;
      return r;
    }
    // Made forward progress!
    canceled = false;
    retries = 0;
    batch_len = 0;
    if (static_cast<unsigned>(r) == batch.size()) {
      batch.clear();
    } else  {
      batch.erase(batch.begin(), batch.begin() + r);
      for (const auto& b : batch) {
	batch_len +=  b.length() + part_entry_overhead;
      }
    }
  }
  if (canceled) {
    lderr(cct) << __PRETTY_FUNCTION__ << ":" << __LINE__
	       << " canceled too many times, giving up: tid=" << tid << dendl;
    return -ECANCELED;
  }
  return 0;
}

struct Pusher : public Completion<Pusher> {
  FIFO* f;
  std::deque<cb::list> remaining;
  std::deque<cb::list> batch;
  int i = 0;
  std::uint64_t tid;
  bool new_heading = false;

  void prep_then_push(Ptr&& p, const unsigned successes) {
    std::unique_lock l(f->m);
    auto max_part_size = f->info.params.max_part_size;
    auto part_entry_overhead = f->part_entry_overhead;
    l.unlock();

    ldout(f->cct, 20) << __PRETTY_FUNCTION__ << ":" << __LINE__
		      << " preparing push: remaining=" << remaining.size()
		      << " batch=" << batch.size() << " i=" << i
		      << " tid=" << tid << dendl;

    uint64_t batch_len = 0;
    if (successes > 0) {
      if (successes == batch.size()) {
	batch.clear();
      } else  {
	batch.erase(batch.begin(), batch.begin() + successes);
	for (const auto& b : batch) {
	  batch_len +=  b.length() + part_entry_overhead;
	}
      }
    }

    if (batch.empty() && remaining.empty()) {
      complete(std::move(p), 0);
      return;
    }

    while (!remaining.empty() &&
	   (remaining.front().length() + batch_len <= max_part_size)) {

      /* We can send entries with data_len up to max_entry_size,
	 however, we want to also account the overhead when
	 dealing with multiple entries. Previous check doesn't
	 account for overhead on purpose. */
      batch_len += remaining.front().length() + part_entry_overhead;
      batch.push_back(std::move(remaining.front()));
      remaining.pop_front();
    }
    ldout(f->cct, 20) << __PRETTY_FUNCTION__ << ":" << __LINE__
		      << " prepared push: remaining=" << remaining.size()
		      << " batch=" << batch.size() << " i=" << i
		      << " batch_len=" << batch_len
		      << " tid=" << tid << dendl;
    push(std::move(p));
  }

  void push(Ptr&& p) {
    f->push_entries(batch, tid, call(std::move(p)));
  }

  void new_head(Ptr&& p) {
    new_heading = true;
    f->_prepare_new_head(tid, call(std::move(p)));
  }

  void handle(Ptr&& p, int r) {
    if (!new_heading) {
      if (r == -ERANGE) {
	ldout(f->cct, 20) << __PRETTY_FUNCTION__ << ":" << __LINE__
		       << " need new head tid=" << tid << dendl;
	new_head(std::move(p));
	return;
      }
      if (r < 0) {
	lderr(f->cct) << __PRETTY_FUNCTION__ << ":" << __LINE__
		      << " push_entries failed: r=" << r
		      << " tid=" << tid << dendl;
	complete(std::move(p), r);
	return;
      }
      i = 0; // We've made forward progress, so reset the race counter!
      prep_then_push(std::move(p), r);
    } else {
      if (r < 0) {
	lderr(f->cct) << __PRETTY_FUNCTION__ << ":" << __LINE__
		      << " prepare_new_head failed: r=" << r
		      << " tid=" << tid << dendl;
	complete(std::move(p), r);
	return;
      }
      new_heading = false;
      handle_new_head(std::move(p), r);
    }
  }

  void handle_new_head(Ptr&& p, int r) {
    if (r == -ECANCELED) {
      if (p->i == MAX_RACE_RETRIES) {
	lderr(f->cct) << __PRETTY_FUNCTION__ << ":" << __LINE__
		      << " canceled too many times, giving up: tid=" << tid << dendl;
	complete(std::move(p), -ECANCELED);
	return;
      }
      ++p->i;
    } else if (r) {
      complete(std::move(p), r);
      return;
    }

    if (p->batch.empty()) {
      prep_then_push(std::move(p), 0);
      return;
    } else {
      push(std::move(p));
      return;
    }
  }

  Pusher(FIFO* f, std::deque<cb::list>&& remaining,
	 std::uint64_t tid, lr::AioCompletion* super)
    : Completion(super), f(f), remaining(std::move(remaining)),
      tid(tid) {}
};

void FIFO::push(const std::vector<cb::list>& data_bufs,
		lr::AioCompletion* c)
{
  std::unique_lock l(m);
  auto tid = ++next_tid;
  auto max_entry_size = info.params.max_entry_size;
  auto need_new_head = info.need_new_head();
  l.unlock();
  ldout(cct, 20) << __PRETTY_FUNCTION__ << ":" << __LINE__
		 << " entering: tid=" << tid << dendl;
  auto p = std::make_unique<Pusher>(this, std::deque<cb::list>(data_bufs.begin(), data_bufs.end()),
				    tid, c);
  // Validate sizes
  for (const auto& bl : data_bufs) {
    if (bl.length() > max_entry_size) {
      lderr(cct) << __PRETTY_FUNCTION__ << ":" << __LINE__
		 << " entry bigger than max_entry_size tid=" << tid << dendl;
      Pusher::complete(std::move(p), -E2BIG);
      return;
    }
  }

  if (data_bufs.empty() ) {
    ldout(cct, 20) << __PRETTY_FUNCTION__ << ":" << __LINE__
		   << " empty push, returning success tid=" << tid << dendl;
    Pusher::complete(std::move(p), 0);
    return;
  }

  if (need_new_head) {
    ldout(cct, 20) << __PRETTY_FUNCTION__ << ":" << __LINE__
		   << " need new head tid=" << tid << dendl;
    p->new_head(std::move(p));
  } else {
    p->prep_then_push(std::move(p), 0);
  }
}

int FIFO::list(int max_entries,
	       std::optional<std::string_view> markstr,
	       std::vector<list_entry>* presult, bool* pmore,
	       optional_yield y)
{
  std::unique_lock l(m);
  auto tid = ++next_tid;
  std::int64_t part_num = info.tail_part_num;
  l.unlock();
  ldout(cct, 20) << __PRETTY_FUNCTION__ << ":" << __LINE__
		 << " entering: tid=" << tid << dendl;
  std::uint64_t ofs = 0;
  if (markstr) {
    auto marker = to_marker(*markstr);
    if (!marker) {
      lderr(cct) << __PRETTY_FUNCTION__ << ":" << __LINE__
		 << " invalid marker string: " << markstr
		 << " tid= "<< tid << dendl;
      return -EINVAL;
    }
    part_num = marker->num;
    ofs = marker->ofs;
  }

  std::vector<list_entry> result;
  result.reserve(max_entries);
  bool more = false;

  std::vector<fifo::part_list_entry> entries;
  int r = 0;
  while (max_entries > 0) {
    ldout(cct, 20) << __PRETTY_FUNCTION__ << ":" << __LINE__
		   << " max_entries=" << max_entries << " tid=" << tid << dendl;
    bool part_more = false;
    bool part_full = false;

    std::unique_lock l(m);
    auto part_oid = info.part_oid(part_num);
    l.unlock();

    r = list_part(ioctx, part_oid, {}, ofs, max_entries, &entries,
		  &part_more, &part_full, nullptr, tid, y);
    if (r == -ENOENT) {
      ldout(cct, 20) << __PRETTY_FUNCTION__ << ":" << __LINE__
		     << " missing part, rereading metadata"
		     << " tid= "<< tid << dendl;
      r = read_meta(tid, y);
      if (r < 0) {
	lderr(cct) << __PRETTY_FUNCTION__ << ":" << __LINE__
		   << " read_meta failed: r=" << r
		   << " tid= "<< tid << dendl;
	return r;
      }
      if (part_num < info.tail_part_num) {
	/* raced with trim? restart */
	ldout(cct, 20) << __PRETTY_FUNCTION__ << ":" << __LINE__
		       << " raced with trim, restarting: tid=" << tid << dendl;
	max_entries += result.size();
	result.clear();
	std::unique_lock l(m);
	part_num = info.tail_part_num;
	l.unlock();
	ofs = 0;
	continue;
      }
      ldout(cct, 20) << __PRETTY_FUNCTION__ << ":" << __LINE__
		     << " assuming part was not written yet, so end of data: "
		     << "tid=" << tid << dendl;
      more = false;
      r = 0;
      break;
    }
    if (r < 0) {
      lderr(cct) << __PRETTY_FUNCTION__ << ":" << __LINE__
		 << " list_entries failed: r=" << r
		 << " tid= "<< tid << dendl;
      return r;
    }
    more = part_full || part_more;
    for (auto& entry : entries) {
      list_entry e;
      e.data = std::move(entry.data);
      e.marker = marker{part_num, entry.ofs}.to_string();
      e.mtime = entry.mtime;
      result.push_back(std::move(e));
      --max_entries;
      if (max_entries == 0)
	break;
    }
    entries.clear();
    if (max_entries > 0 &&
	part_more) {
    }

    if (!part_full) {
      ldout(cct, 20) << __PRETTY_FUNCTION__ << ":" << __LINE__
		     << " head part is not full, so we can assume we're done: "
		     << "tid=" << tid << dendl;
      break;
    }
    if (!part_more) {
      ++part_num;
      ofs = 0;
    }
  }
  if (presult)
    *presult = std::move(result);
  if (pmore)
    *pmore =  more;
  return 0;
}

int FIFO::trim(std::string_view markstr, bool exclusive, optional_yield y)
{
  auto marker = to_marker(markstr);
  if (!marker) {
    return -EINVAL;
  }
  auto part_num = marker->num;
  auto ofs = marker->ofs;
  std::unique_lock l(m);
  auto tid = ++next_tid;
  auto pn = info.tail_part_num;
  l.unlock();
  ldout(cct, 20) << __PRETTY_FUNCTION__ << ":" << __LINE__
		 << " entering: tid=" << tid << dendl;

  int r = 0;
  while (pn < part_num) {
    ldout(cct, 20) << __PRETTY_FUNCTION__ << ":" << __LINE__
		   << " pn=" << pn << " tid=" << tid << dendl;
    std::unique_lock l(m);
    auto max_part_size = info.params.max_part_size;
    l.unlock();
    r = trim_part(pn, max_part_size, std::nullopt, false, tid, y);
    if (r < 0 && r == -ENOENT) {
      lderr(cct) << __PRETTY_FUNCTION__ << ":" << __LINE__
		 << " trim_part failed: r=" << r
		 << " tid= "<< tid << dendl;
      return r;
    }
    ++pn;
  }
  r = trim_part(part_num, ofs, std::nullopt, exclusive, tid, y);
  if (r < 0 && r != -ENOENT) {
    lderr(cct) << __PRETTY_FUNCTION__ << ":" << __LINE__
	       << " trim_part failed: r=" << r
	       << " tid= "<< tid << dendl;
    return r;
  }

  l.lock();
  auto tail_part_num = info.tail_part_num;
  auto objv = info.version;
  l.unlock();
  bool canceled = tail_part_num < part_num;
  int retries = 0;
  while ((tail_part_num < part_num) &&
	 canceled &&
	 (retries <= MAX_RACE_RETRIES)) {
    r = _update_meta(fifo::update{}.tail_part_num(part_num), objv, &canceled,
		     tid, y);
    if (r < 0) {
      lderr(cct) << __PRETTY_FUNCTION__ << ":" << __LINE__
		 << " _update_meta failed: r=" << r
		 << " tid= "<< tid << dendl;
      return r;
    }
    if (canceled) {
      ldout(cct, 20) << __PRETTY_FUNCTION__ << ":" << __LINE__
		     << " canceled: retries=" << retries
		     << " tid=" << tid << dendl;
      l.lock();
      tail_part_num = info.tail_part_num;
      objv = info.version;
      l.unlock();
      ++retries;
    }
  }
  if (canceled) {
    lderr(cct) << __PRETTY_FUNCTION__ << ":" << __LINE__
	       << " canceled too many times, giving up: tid=" << tid << dendl;
    return -EIO;
  }
  return 0;
}

struct Trimmer : public Completion<Trimmer> {
  FIFO* fifo;
  std::int64_t part_num;
  std::uint64_t ofs;
  std::int64_t pn;
  bool exclusive;
  std::uint64_t tid;
  bool update = false;
  bool canceled = false;
  int retries = 0;

  Trimmer(FIFO* fifo, std::int64_t part_num, std::uint64_t ofs, std::int64_t pn,
	  bool exclusive, lr::AioCompletion* super, std::uint64_t tid)
    : Completion(super), fifo(fifo), part_num(part_num), ofs(ofs), pn(pn),
      exclusive(exclusive), tid(tid) {}

  void handle(Ptr&& p, int r) {
    auto cct = fifo->cct;
    ldout(cct, 20) << __PRETTY_FUNCTION__ << ":" << __LINE__
		   << " entering: tid=" << tid << dendl;
    if (r == -ENOENT) {
      r = 0;
    }

    if (r < 0) {
      lderr(cct) << __PRETTY_FUNCTION__ << ":" << __LINE__
		 << (update ? " update_meta " : " trim ") << "failed: r="
		 << r << " tid=" << tid << dendl;
      complete(std::move(p), r);
      return;
    }

    if (!update) {
      ldout(cct, 20) << __PRETTY_FUNCTION__ << ":" << __LINE__
		     << " handling preceding trim callback: tid=" << tid << dendl;
      retries = 0;
      if (pn < part_num) {
	ldout(cct, 20) << __PRETTY_FUNCTION__ << ":" << __LINE__
		       << " pn=" << pn << " tid=" << tid << dendl;
	std::unique_lock l(fifo->m);
	const auto max_part_size = fifo->info.params.max_part_size;
	l.unlock();
	fifo->trim_part(pn++, max_part_size, std::nullopt,
			false, tid, call(std::move(p)));
	return;
      }

      std::unique_lock l(fifo->m);
      const auto tail_part_num = fifo->info.tail_part_num;
      l.unlock();
      update = true;
      canceled = tail_part_num < part_num;
      fifo->trim_part(part_num, ofs, std::nullopt, exclusive, tid,
		      call(std::move(p)));
      return;
    }

    ldout(cct, 20) << __PRETTY_FUNCTION__ << ":" << __LINE__
		   << " handling update-needed callback: tid=" << tid << dendl;
    std::unique_lock l(fifo->m);
    auto tail_part_num = fifo->info.tail_part_num;
    auto objv = fifo->info.version;
    l.unlock();
    if ((tail_part_num < part_num) &&
	canceled) {
      if (retries > MAX_RACE_RETRIES) {
	lderr(cct) << __PRETTY_FUNCTION__ << ":" << __LINE__
		   << " canceled too many times, giving up: tid=" << tid << dendl;
	complete(std::move(p), -EIO);
	return;
      }
      ++retries;
      fifo->_update_meta(fifo::update{}
			 .tail_part_num(part_num), objv, &canceled,
                         tid, call(std::move(p)));
    } else {
      complete(std::move(p), 0);
    }
  }
};

void FIFO::trim(std::string_view markstr, bool exclusive,
		lr::AioCompletion* c) {
  auto marker = to_marker(markstr);
  auto realmark = marker.value_or(::rgw::cls::fifo::marker{});
  std::unique_lock l(m);
  const auto max_part_size = info.params.max_part_size;
  const auto pn = info.tail_part_num;
  const auto part_oid = info.part_oid(pn);
  auto tid = ++next_tid;
  l.unlock();
  ldout(cct, 20) << __PRETTY_FUNCTION__ << ":" << __LINE__
		 << " entering: tid=" << tid << dendl;
  auto trimmer = std::make_unique<Trimmer>(this, realmark.num, realmark.ofs,
					   pn, exclusive, c, tid);
  if (!marker) {
    Trimmer::complete(std::move(trimmer), -EINVAL);
  }
  ++trimmer->pn;
  auto ofs = marker->ofs;
  if (pn < marker->num) {
    ldout(cct, 20) << __PRETTY_FUNCTION__ << ":" << __LINE__
		   << " pn=" << pn << " tid=" << tid << dendl;
    ofs = max_part_size;
  } else {
    trimmer->update = true;
  }
  trim_part(pn, ofs, std::nullopt, exclusive,
	    tid, Trimmer::call(std::move(trimmer)));
}

int FIFO::get_part_info(int64_t part_num,
			fifo::part_header* header,
			optional_yield y)
{
  std::unique_lock l(m);
  const auto part_oid = info.part_oid(part_num);
  auto tid = ++next_tid;
  l.unlock();
  auto r = rgw::cls::fifo::get_part_info(ioctx, part_oid, header, tid, y);
  if (r < 0) {
    lderr(cct) << __PRETTY_FUNCTION__ << ":" << __LINE__
	       << " get_part_info failed: r="
	       << r << " tid=" << tid << dendl;
  }
  return r;
}

void FIFO::get_part_info(int64_t part_num,
			 fifo::part_header* header,
			 lr::AioCompletion* c)
{
  std::unique_lock l(m);
  const auto part_oid = info.part_oid(part_num);
  auto tid = ++next_tid;
  l.unlock();
  auto op = rgw::cls::fifo::get_part_info(cct, header, tid);
  auto r = ioctx.aio_operate(part_oid, c, &op, nullptr);
  ceph_assert(r >= 0);
}

struct InfoGetter : Completion<InfoGetter> {
  FIFO* fifo;
  fifo::part_header header;
  fu2::function<void(int r, fifo::part_header&&)> f;
  std::uint64_t tid;
  bool headerread = false;

  InfoGetter(FIFO* fifo, fu2::function<void(int r, fifo::part_header&&)> f,
	     std::uint64_t tid, lr::AioCompletion* super)
    : Completion(super), fifo(fifo), f(std::move(f)), tid(tid) {}
  void handle(Ptr&& p, int r) {
    if (!headerread) {
      if (r < 0) {
	lderr(fifo->cct) << __PRETTY_FUNCTION__ << ":" << __LINE__
			 << " read_meta failed: r="
			 << r << " tid=" << tid << dendl;
	if (f)
	  f(r, {});
	complete(std::move(p), r);
	return;
      }

      auto info = fifo->meta();
      auto hpn = info.head_part_num;
      if (hpn < 0) {
	ldout(fifo->cct, 20) << __PRETTY_FUNCTION__ << ":" << __LINE__
			     << " no head, returning empty partinfo r="
			     << r << " tid=" << tid << dendl;
	if (f)
	  f(0, {});
	complete(std::move(p), r);
	return;
      }
      headerread = true;
      auto op = rgw::cls::fifo::get_part_info(fifo->cct, &header, tid);
      std::unique_lock l(fifo->m);
      auto oid = fifo->info.part_oid(hpn);
      l.unlock();
      r = fifo->ioctx.aio_operate(oid, call(std::move(p)), &op,
				  nullptr);
      ceph_assert(r >= 0);
      return;
    }

    if (r < 0) {
      lderr(fifo->cct) << __PRETTY_FUNCTION__ << ":" << __LINE__
		       << " get_part_info failed: r="
		       << r << " tid=" << tid << dendl;
    }

    if (f)
      f(r, std::move(header));
    complete(std::move(p), r);
    return;
  }
};

void FIFO::get_head_info(fu2::unique_function<void(int r,
						   fifo::part_header&&)> f,
			 lr::AioCompletion* c)
{
  std::unique_lock l(m);
  auto tid = ++next_tid;
  l.unlock();
  auto ig = std::make_unique<InfoGetter>(this, std::move(f), tid, c);
  read_meta(tid, InfoGetter::call(std::move(ig)));
}

struct JournalProcessor : public Completion<JournalProcessor> {
private:
  FIFO* const fifo;

  std::vector<fifo::journal_entry> processed;
  std::multimap<std::int64_t, fifo::journal_entry> journal;
  std::multimap<std::int64_t, fifo::journal_entry>::iterator iter;
  std::int64_t new_tail;
  std::int64_t new_head;
  std::int64_t new_max;
  int race_retries = 0;
  bool first_pp = true;
  bool canceled = false;
  std::uint64_t tid;

  enum {
    entry_callback,
    pp_callback,
  } state;

  void create_part(Ptr&& p, int64_t part_num,
		   std::string_view tag) {
    ldout(fifo->cct, 20) << __PRETTY_FUNCTION__ << ":" << __LINE__
			 << " entering: tid=" << tid << dendl;
    state = entry_callback;
    lr::ObjectWriteOperation op;
    op.create(false); /* We don't need exclusivity, part_init ensures
			 we're creating from the  same journal entry. */
    std::unique_lock l(fifo->m);
    part_init(&op, tag, fifo->info.params);
    auto oid = fifo->info.part_oid(part_num);
    l.unlock();
    auto r = fifo->ioctx.aio_operate(oid, call(std::move(p)), &op);
    ceph_assert(r >= 0);
    return;
  }

  void remove_part(Ptr&& p, int64_t part_num,
		   std::string_view tag) {
    ldout(fifo->cct, 20) << __PRETTY_FUNCTION__ << ":" << __LINE__
			 << " entering: tid=" << tid << dendl;
    state = entry_callback;
    lr::ObjectWriteOperation op;
    op.remove();
    std::unique_lock l(fifo->m);
    auto oid = fifo->info.part_oid(part_num);
    l.unlock();
    auto r = fifo->ioctx.aio_operate(oid, call(std::move(p)), &op);
    ceph_assert(r >= 0);
    return;
  }

  void finish_je(Ptr&& p, int r,
		 const fifo::journal_entry& entry) {
    ldout(fifo->cct, 20) << __PRETTY_FUNCTION__ << ":" << __LINE__
			 << " entering: tid=" << tid << dendl;

    ldout(fifo->cct, 20) << __PRETTY_FUNCTION__ << ":" << __LINE__
			 << " finishing entry: entry=" << entry
			 << " tid=" << tid << dendl;

    if (entry.op == fifo::journal_entry::Op::remove && r == -ENOENT)
      r = 0;

    if (r < 0) {
      lderr(fifo->cct) << __PRETTY_FUNCTION__ << ":" << __LINE__
		       << " processing entry failed: entry=" << entry
		       << " r=" << r << " tid=" << tid << dendl;
      complete(std::move(p), r);
      return;
    } else {
      switch (entry.op) {
      case fifo::journal_entry::Op::unknown:
      case fifo::journal_entry::Op::set_head:
	// Can't happen. Filtered out in process.
	complete(std::move(p), -EIO);
	return;

      case fifo::journal_entry::Op::create:
	if (entry.part_num > new_max) {
	  new_max = entry.part_num;
	}
	break;
      case fifo::journal_entry::Op::remove:
	if (entry.part_num >= new_tail) {
	  new_tail = entry.part_num + 1;
	}
	break;
      }
      processed.push_back(entry);
    }
    ++iter;
    process(std::move(p));
  }

  void postprocess(Ptr&& p) {
    ldout(fifo->cct, 20) << __PRETTY_FUNCTION__ << ":" << __LINE__
			 << " entering: tid=" << tid << dendl;
    if (processed.empty()) {
      ldout(fifo->cct, 20) << __PRETTY_FUNCTION__ << ":" << __LINE__
			   << " nothing to update any more: race_retries="
			   << race_retries << " tid=" << tid << dendl;
      complete(std::move(p), 0);
      return;
    }
    pp_run(std::move(p), 0, false);
  }

public:

  JournalProcessor(FIFO* fifo, std::uint64_t tid, lr::AioCompletion* super)
    : Completion(super), fifo(fifo), tid(tid) {
    std::unique_lock l(fifo->m);
    journal = fifo->info.journal;
    iter = journal.begin();
    new_tail = fifo->info.tail_part_num;
    new_head = fifo->info.head_part_num;
    new_max = fifo->info.max_push_part_num;
  }

  void pp_run(Ptr&& p, int r, bool canceled) {
    ldout(fifo->cct, 20) << __PRETTY_FUNCTION__ << ":" << __LINE__
			 << " entering: tid=" << tid << dendl;
    std::optional<int64_t> tail_part_num;
    std::optional<int64_t> head_part_num;
    std::optional<int64_t> max_part_num;

    if (r < 0) {
      lderr(fifo->cct) << __PRETTY_FUNCTION__ << ":" << __LINE__
		       << " failed, r=: " << r << " tid=" << tid << dendl;
      complete(std::move(p), r);
    }


    ldout(fifo->cct, 20) << __PRETTY_FUNCTION__ << ":" << __LINE__
			 << " postprocessing: race_retries="
			 << race_retries << " tid=" << tid << dendl;

    if (!first_pp && r == 0 && !canceled) {
      ldout(fifo->cct, 20) << __PRETTY_FUNCTION__ << ":" << __LINE__
			   << " nothing to update any more: race_retries="
			   << race_retries << " tid=" << tid << dendl;
      complete(std::move(p), 0);
      return;
    }

    first_pp = false;

    if (canceled) {
      if (race_retries >= MAX_RACE_RETRIES) {
	lderr(fifo->cct) << __PRETTY_FUNCTION__ << ":" << __LINE__
			 << " canceled too many times, giving up: tid="
			 << tid << dendl;
	complete(std::move(p), -ECANCELED);
	return;
      }
      ldout(fifo->cct, 20) << __PRETTY_FUNCTION__ << ":" << __LINE__
			   << " update canceled, retrying: race_retries="
			   << race_retries << " tid=" << tid << dendl;

      ++race_retries;

      std::vector<fifo::journal_entry> new_processed;
      std::unique_lock l(fifo->m);
      for (auto& e : processed) {
	auto jiter = fifo->info.journal.find(e.part_num);
	/* journal entry was already processed */
	if (jiter == fifo->info.journal.end() ||
	    !(jiter->second == e)) {
	  continue;
	}
	new_processed.push_back(e);
      }
      processed = std::move(new_processed);
    }

    std::unique_lock l(fifo->m);
    auto objv = fifo->info.version;
    if (new_tail > fifo->info.tail_part_num) {
      tail_part_num = new_tail;
    }

    if (new_head > fifo->info.head_part_num) {
      head_part_num = new_head;
    }

    if (new_max > fifo->info.max_push_part_num) {
      max_part_num = new_max;
    }
    l.unlock();

    if (processed.empty() &&
	!tail_part_num &&
	!max_part_num) {
      /* nothing to update anymore */
      ldout(fifo->cct, 20) << __PRETTY_FUNCTION__ << ":" << __LINE__
			   << " nothing to update any more: race_retries="
			   << race_retries << " tid=" << tid << dendl;
      complete(std::move(p), 0);
      return;
    }
    state = pp_callback;
    fifo->_update_meta(fifo::update{}
		       .tail_part_num(tail_part_num)
		       .head_part_num(head_part_num)
		       .max_push_part_num(max_part_num)
		       .journal_entries_rm(processed),
                       objv, &this->canceled, tid, call(std::move(p)));
    return;
  }

  JournalProcessor(const JournalProcessor&) = delete;
  JournalProcessor& operator =(const JournalProcessor&) = delete;
  JournalProcessor(JournalProcessor&&) = delete;
  JournalProcessor& operator =(JournalProcessor&&) = delete;

  void process(Ptr&& p) {
    ldout(fifo->cct, 20) << __PRETTY_FUNCTION__ << ":" << __LINE__
			 << " entering: tid=" << tid << dendl;
    while (iter != journal.end()) {
      ldout(fifo->cct, 20) << __PRETTY_FUNCTION__ << ":" << __LINE__
			   << " processing entry: entry=" << *iter
			   << " tid=" << tid << dendl;
      const auto entry = iter->second;
      switch (entry.op) {
      case fifo::journal_entry::Op::create:
	create_part(std::move(p), entry.part_num, entry.part_tag);
	return;
      case fifo::journal_entry::Op::set_head:
	if (entry.part_num > new_head) {
	  new_head = entry.part_num;
	}
	processed.push_back(entry);
	++iter;
	continue;
      case fifo::journal_entry::Op::remove:
	remove_part(std::move(p), entry.part_num, entry.part_tag);
	return;
      default:
	lderr(fifo->cct) << __PRETTY_FUNCTION__ << ":" << __LINE__
			 << " unknown journaled op: entry=" << entry << " tid="
			 << tid << dendl;
	complete(std::move(p), -EIO);
	return;
      }
    }
    postprocess(std::move(p));
    return;
  }

  void handle(Ptr&& p, int r) {
    ldout(fifo->cct, 20) << __PRETTY_FUNCTION__ << ":" << __LINE__
			 << " entering: tid=" << tid << dendl;
    switch (state) {
    case entry_callback:
      finish_je(std::move(p), r, iter->second);
      return;
    case pp_callback:
      auto c = canceled;
      canceled = false;
      pp_run(std::move(p), r, c);
      return;
    }

    abort();
  }

};

void FIFO::process_journal(std::uint64_t tid, lr::AioCompletion* c) {
  auto p = std::make_unique<JournalProcessor>(this, tid, c);
  p->process(std::move(p));
}

struct Lister : Completion<Lister> {
  FIFO* f;
  std::vector<list_entry> result;
  bool more = false;
  std::int64_t part_num;
  std::uint64_t ofs;
  int max_entries;
  int r_out = 0;
  std::vector<fifo::part_list_entry> entries;
  bool part_more = false;
  bool part_full = false;
  std::vector<list_entry>* entries_out;
  bool* more_out;
  std::uint64_t tid;

  bool read = false;

  void complete(Ptr&& p, int r) {
    if (r >= 0) {
      if (more_out) *more_out = more;
      if (entries_out) *entries_out = std::move(result);
    }
    Completion::complete(std::move(p), r);
  }

public:
  Lister(FIFO* f, std::int64_t part_num, std::uint64_t ofs, int max_entries,
	 std::vector<list_entry>* entries_out, bool* more_out,
	 std::uint64_t tid, lr::AioCompletion* super)
    : Completion(super), f(f), part_num(part_num), ofs(ofs), max_entries(max_entries),
      entries_out(entries_out), more_out(more_out), tid(tid) {
    result.reserve(max_entries);
  }

  Lister(const Lister&) = delete;
  Lister& operator =(const Lister&) = delete;
  Lister(Lister&&) = delete;
  Lister& operator =(Lister&&) = delete;

  void handle(Ptr&& p, int r) {
    if (read)
      handle_read(std::move(p), r);
    else
      handle_list(std::move(p), r);
  }

  void list(Ptr&& p) {
    if (max_entries > 0) {
      part_more = false;
      part_full = false;
      entries.clear();

      std::unique_lock l(f->m);
      auto part_oid = f->info.part_oid(part_num);
      l.unlock();

      read = false;
      auto op = list_part(f->cct, {}, ofs, max_entries, &r_out,
			  &entries, &part_more, &part_full,
			  nullptr, tid);
      f->ioctx.aio_operate(part_oid, call(std::move(p)), &op, nullptr);
    } else {
      complete(std::move(p), 0);
    }
  }

  void handle_read(Ptr&& p, int r) {
    read = false;
    if (r >= 0) r = r_out;
    r_out = 0;

    if (r < 0) {
      complete(std::move(p), r);
      return;
    }

    if (part_num < f->info.tail_part_num) {
      /* raced with trim? restart */
      max_entries += result.size();
      result.clear();
      part_num = f->info.tail_part_num;
      ofs = 0;
      list(std::move(p));
      return;
    }
    /* assuming part was not written yet, so end of data */
    more = false;
    complete(std::move(p), 0);
    return;
  }

  void handle_list(Ptr&& p, int r) {
    if (r >= 0) r = r_out;
    r_out = 0;
    std::unique_lock l(f->m);
    auto part_oid = f->info.part_oid(part_num);
    l.unlock();
    if (r == -ENOENT) {
      read = true;
      f->read_meta(tid, call(std::move(p)));
      return;
    }
    if (r < 0) {
      complete(std::move(p), r);
      return;
    }

    more = part_full || part_more;
    for (auto& entry : entries) {
      list_entry e;
      e.data = std::move(entry.data);
      e.marker = marker{part_num, entry.ofs}.to_string();
      e.mtime = entry.mtime;
      result.push_back(std::move(e));
    }
    max_entries -= entries.size();
    entries.clear();
    if (max_entries > 0 && part_more) {
      list(std::move(p));
      return;
    }

    if (!part_full) { /* head part is not full */
      complete(std::move(p), 0);
      return;
    }
    ++part_num;
    ofs = 0;
    list(std::move(p));
  }
};

void FIFO::list(int max_entries,
		std::optional<std::string_view> markstr,
		std::vector<list_entry>* out,
		bool* more,
		lr::AioCompletion* c) {
  std::unique_lock l(m);
  auto tid = ++next_tid;
  std::int64_t part_num = info.tail_part_num;
  l.unlock();
  std::uint64_t ofs = 0;
  std::optional<::rgw::cls::fifo::marker> marker;

  if (markstr) {
    marker = to_marker(*markstr);
    if (marker) {
      part_num = marker->num;
      ofs = marker->ofs;
    }
  }

  auto ls = std::make_unique<Lister>(this, part_num, ofs, max_entries, out,
				     more, tid, c);
  if (markstr && !marker) {
    auto l = ls.get();
    l->complete(std::move(ls), -EINVAL);
  } else {
    ls->list(std::move(ls));
  }
}
}
