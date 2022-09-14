/*
 * Ceph - scalable distributed file system
 *
 * Copyright (C) 2018 Intel Corporation
 *
 * Author: Qiaowei Ren <qiaowei.ren@intel.com>
 *
 * This is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2.1, as published by the Free Software
 * Foundation.  See file COPYING.
 *
 */

#include <qatzip.h>

extern "C" {
#include "icp_sal_user.h"
}

#include "common/ceph_context.h"
#include "common/common_init.h"
#include "common/debug.h"
#include "common/dout.h"
#include "common/errno.h"
#include "QatAccel.h"


// -----------------------------------------------------------------------------
#define dout_context g_ceph_context
#define dout_subsys ceph_subsys_compressor
#undef dout_prefix
#define dout_prefix _prefix(_dout)

static std::ostream& _prefix(std::ostream* _dout)
{
  return *_dout << "QatAccel: ";
}
// -----------------------------------------------------------------------------
// default window size for Zlib 1.2.8, negated for raw deflate
#define ZLIB_DEFAULT_WIN_SIZE -15
#define QAT_SECTION_NAME_SIZE 32

/* Estimate data expansion after decompression */
static const unsigned int expansion_ratio[] = {5, 20, 50, 100, 200, 1000, 10000};

void QzSessionDeleter::operator() (struct QzSession_S *session) {
  qzTeardownSession(session);
  delete session;
}

const char *g_dev_tag = "SHIM";
static Cpa16U get_instance_num(void)
{
    int len;
    char *section_name;
    Cpa16U num_instances;
    CpaStatus status;
#if __GLIBC_PREREQ(2, 17)
    section_name = secure_getenv("QAT_SECTION_NAME");
#else
    section_name = getenv("QAT_SECTION_NAME");
#endif

    if (!section_name || !(len = strlen(section_name))) {
        section_name = (char *)g_dev_tag;
    } else if (len >= QAT_SECTION_NAME_SIZE) {
        dout(1) << "The length of QAT_SECTION_NAME exceeds the limit." << dendl;
        return -1;
    }

    status = icp_sal_userStart(section_name);
    if (CPA_STATUS_SUCCESS != status) {
        dout(1) << "Error userStartMultiProcess" << status
                << "switch to SW if permitted" << dendl;
        return -1;
    }

    status = cpaDcGetNumInstances(&num_instances);
    if (CPA_STATUS_SUCCESS != status) {
        dout(1) << "Error in cpaDcGetNumInstances status = " << status << dendl;
        return -1;
    }
    dout(1) << "Number of instance: " << num_instances << dendl;
    icp_sal_userStop();
    return num_instances;
}

static bool get_qz_params(const std::string &alg, QzSessionParams_T &params) {
  int rc;
  rc = qzGetDefaults(&params);
  if (rc != QZ_OK)
    return false;
  params.direction = QZ_DIR_BOTH;
  params.is_busy_polling = false;
  if (alg == "zlib") {
    params.comp_algorithm = QZ_DEFLATE;
    params.data_fmt = QZ_DEFLATE_RAW;
    params.comp_lvl = g_ceph_context->_conf->compressor_zlib_level;
  }
  else {
    // later, there also has lz4.
    return false;
  }

  rc = qzSetDefaults(&params);
  if (rc != QZ_OK)
      return false;
  return true;
}

static bool setup_session(QatAccel::session_ptr &session, QzSessionParams_T &params) {
  int rc;
  rc = qzInit(session.get(), QZ_SW_BACKUP_DEFAULT);
  if (rc != QZ_OK && rc != QZ_DUPLICATE)
    return false;
  rc = qzSetupSession(session.get(), &params);
  if (rc != QZ_OK) {
    return false;
  }
  return true;
}

// put the session back to the session pool in a RAII manner
struct cached_session_t {
  cached_session_t(QatAccel* accel, QatAccel::session_ptr&& sess)
    : accel{accel}, session{std::move(sess)} {}

  ~cached_session_t() {
    // All session is put into accel->sessions.
    std::scoped_lock lock{accel->mutex};
    accel->sessions.push_back(std::move(session));
    accel->cond.notify_one();
  }

  struct QzSession_S* get() {
    assert(static_cast<bool>(session));
    return session.get();
  }

  QatAccel* accel;
  QatAccel::session_ptr session;
};

QatAccel::session_ptr QatAccel::get_session() {
  std::unique_lock lock{mutex};
  cond.wait(lock, [this](){return !sessions.empty();});

  auto session = std::move(sessions.back());
  sessions.pop_back();
  return session;
}

QatAccel::QatAccel() {}

QatAccel::~QatAccel() {
  // First, we should uninitialize all QATzip session that disconnects all session
  // from a hardware instance and deallocates buffers.
  sessions.clear();
  // Then we close the connection with QAT.
  // where the value of the parameter passed to qzClose() does not matter. as long as
  // it is not nullptr.
  qzClose((QzSession_T*)1);
}

bool QatAccel::init(const std::string &alg) {
  std::scoped_lock lock(mutex);
  if (!alg_name.empty()) {
    return true;
  }

  dout(15) << "First use for QAT compressor" << dendl;
  if (alg != "zlib") {
    return false;
  }

  alg_name = alg;

  Cpa16U sessions_num = get_instance_num();
  for (Cpa16U i = 0; i < sessions_num; i++) {
    QzSessionParams_T params = {(QzHuffmanHdr_T)0,};
    session_ptr session(new struct QzSession_S());
    memset(session.get(), 0, sizeof(struct QzSession_S));
    if (get_qz_params(alg_name, params) && setup_session(session, params)) {
      sessions.push_back(std::move(session));
    } else {
      dout(1) << "init session failed " << dendl;
      return false;
    }
  }

  return true;
}

int QatAccel::compress(const bufferlist &in, bufferlist &out, std::optional<int32_t> &compressor_message) {
  auto s = get_session(); // get a session from the pool
  if (!s) {
    return -1; // session initialization failed
  }
  auto session = cached_session_t{this, std::move(s)}; // returns to the session pool on destruction
  compressor_message = ZLIB_DEFAULT_WIN_SIZE;
  int begin = 1;
  for (auto &i : in.buffers()) {
    const unsigned char* c_in = (unsigned char*) i.c_str();
    unsigned int len = i.length();
    unsigned int out_len = qzMaxCompressedLength(len, session.get()) + begin;

    bufferptr ptr = buffer::create_small_page_aligned(out_len);
    unsigned char* c_out = (unsigned char*)ptr.c_str() + begin;
    int rc = qzCompress(session.get(), c_in, &len, c_out, &out_len, 1);
    if (rc != QZ_OK)
      return -1;
    if (begin) {
      // put a compressor variation mark in front of compressed stream, not used at the moment
      ptr.c_str()[0] = 0;
      out_len += begin;
      begin = 0;
    }
    out.append(ptr, 0, out_len);

  }

  return 0;
}

int QatAccel::decompress(const bufferlist &in, bufferlist &out, std::optional<int32_t> compressor_message) {
  auto i = in.begin();
  return decompress(i, in.length(), out, compressor_message);
}

int QatAccel::decompress(bufferlist::const_iterator &p,
		 size_t compressed_len,
		 bufferlist &dst,
		 std::optional<int32_t> compressor_message) {
  auto s = get_session(); // get a session from the pool
  if (!s) {
    return -1; // session initialization failed
  }
  auto session = cached_session_t{this, std::move(s)}; // returns to the session pool on destruction
  int begin = 1;

  int rc = 0;
  bufferlist tmp;
  size_t remaining = std::min<size_t>(p.get_remaining(), compressed_len);

  while (remaining) {
    unsigned int ratio_idx = 0;
    const char* c_in = nullptr;
    unsigned int len = p.get_ptr_and_advance(remaining, &c_in);
    remaining -= len;
    len -= begin;
    c_in += begin;
    begin = 0;
    unsigned int out_len = QZ_HW_BUFF_SZ;

    bufferptr ptr;
    do {
      while (out_len <= len * expansion_ratio[ratio_idx]) {
        out_len *= 2;
      }

      ptr = buffer::create_small_page_aligned(out_len);
      rc = qzDecompress(session.get(), (const unsigned char*)c_in, &len, (unsigned char*)ptr.c_str(), &out_len);
      ratio_idx++;
    } while (rc == QZ_BUF_ERROR && ratio_idx < std::size(expansion_ratio));

    if (rc == QZ_OK) {
      dst.append(ptr, 0, out_len);
    } else if (rc == QZ_DATA_ERROR) {
      dout(1) << "QAT compressor DATA ERROR" << dendl;
      return -1;
    } else if (rc == QZ_BUF_ERROR) {
      dout(1) << "QAT compressor BUF ERROR" << dendl;
      return -1;
    } else if (rc != QZ_OK) {
      dout(1) << "QAT compressor NOT OK" << dendl;
      return -1;
    }
  }

  return 0;
}
