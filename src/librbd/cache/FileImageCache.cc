// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#include "FileImageCache.h"
#include "include/buffer.h"
#include "include/Context.h"
#include "common/dout.h"
#include "common/errno.h"
#include "common/WorkQueue.h"
#include "librbd/ImageCtx.h"
#include "librbd/cache/file/ImageStore.h"
#include "librbd/cache/file/JournalStore.h"
#include "librbd/cache/file/MetaStore.h"
#include "librbd/cache/file/StupidPolicy.h"
#include <map>
#include <vector>

#define dout_subsys ceph_subsys_rbd
#undef dout_prefix
#define dout_prefix *_dout << "librbd::cache::FileImageCache: " << this << " " \
                           <<  __func__ << ": "

namespace librbd {
namespace cache {

using namespace librbd::cache::file;

namespace {

typedef std::map<uint64_t, bufferlist> ExtentBuffers;
typedef std::function<void(uint64_t)> ReleaseBlock;

static const uint32_t BLOCK_SIZE = 4096;

bool is_block_aligned(const ImageCache::Extents &image_extents) {
  for (auto &extent : image_extents) {
    if (extent.first % BLOCK_SIZE != 0 || extent.second % BLOCK_SIZE != 0) {
      return false;
    }
  }
  return true;
}

struct C_BlockIORequest : public Context {
  CephContext *cct;
  C_BlockIORequest *next_block_request;

  C_BlockIORequest(CephContext *cct, C_BlockIORequest *next_block_request)
    : cct(cct), next_block_request(next_block_request) {
  }

  virtual void finish(int r) override {
    ldout(cct, 20) << "(" << get_name() << "): r=" << r << dendl;

    if (r < 0) {
      // abort the chain of requests upon failure
      next_block_request->complete(r);
    } else {
      // execute next request in chain
      next_block_request->send();
    }
  }

  virtual void send() = 0;
  virtual const char *get_name() const = 0;
};

struct C_ReleaseBlockGuard : public C_BlockIORequest {
  uint64_t block;
  ReleaseBlock &release_block;
  BlockGuard::C_BlockRequest *block_request;

  C_ReleaseBlockGuard(CephContext *cct, uint64_t block,
                      ReleaseBlock &release_block,
                      BlockGuard::C_BlockRequest *block_request)
    : C_BlockIORequest(cct, nullptr), block(block),
      release_block(release_block), block_request(block_request) {
  }

  virtual void send() override {
    complete(0);
  }
  virtual const char *get_name() const override {
    return "C_ReleaseBlockGuard";
  }

  virtual void finish(int r) override {
    ldout(cct, 20) << "(" << get_name() << "): r=" << r << dendl;

    // IO operation finished -- release guard
    release_block(block);

    // complete block request
    block_request->complete_request(r);
  }
};

template <typename I>
struct C_PromoteToCache : public C_BlockIORequest {
  ImageStore<I> &image_store;
  uint64_t block;
  const bufferlist &bl;

  C_PromoteToCache(CephContext *cct, ImageStore<I> &image_store, uint64_t block,
                   const bufferlist &bl, C_BlockIORequest *next_block_request)
    : C_BlockIORequest(cct, next_block_request),
      image_store(image_store), block(block), bl(bl) {
  }

  virtual void send() override {
    ldout(cct, 20) << "(" << get_name() << "): "
                   << "block=" << block << dendl;
    // promote the clean block to the cache
    bufferlist sub_bl;
    sub_bl.append(bl);
    image_store.write_block(block, {{0, BLOCK_SIZE}}, std::move(sub_bl),
                            this);
  }
  virtual const char *get_name() const override {
    return "C_PromoteToCache";
  }
};

template <typename I>
struct C_DemoteFromCache : public C_BlockIORequest {
  ImageStore<I> &image_store;
  ReleaseBlock &release_block;
  uint64_t block;

  C_DemoteFromCache(CephContext *cct, ImageStore<I> &image_store,
                    ReleaseBlock &release_block, uint64_t block,
                    C_BlockIORequest *next_block_request)
    : C_BlockIORequest(cct, next_block_request),
      image_store(image_store), release_block(release_block), block(block) {
  }

  virtual void send() override {
    ldout(cct, 20) << "(" << get_name() << "): "
                   << "block=" << block << dendl;
    image_store.discard_block(block, this);
  }
  virtual const char *get_name() const override {
    return "C_DemoteFromCache";
  }

  virtual void finish(int r) {
    // IO against the demote block was detained -- release
    release_block(block);

    C_BlockIORequest::finish(r);
  }
};

template <typename I>
struct C_ReadFromCacheRequest : public C_BlockIORequest {
  ImageStore<I> &image_store;
  BlockGuard::BlockIO block_io;
  ExtentBuffers *extent_buffers;

  C_ReadFromCacheRequest(CephContext *cct, ImageStore<I> &image_store,
                         BlockGuard::BlockIO &&block_io,
                         ExtentBuffers *extent_buffers,
                         C_BlockIORequest *next_block_request)
    : C_BlockIORequest(cct, next_block_request),
      image_store(image_store), block_io(block_io),
      extent_buffers(extent_buffers) {
  }

  virtual void send() override {
    ldout(cct, 20) << "(" << get_name() << "): "
                   << "block_io=[" << block_io << "]" << dendl;
    C_Gather *ctx = new C_Gather(cct, this);
    for (auto &extent : block_io.extents) {
      image_store.read_block(block_io.block,
                             {{extent.block_offset, extent.block_length}},
                             &(*extent_buffers)[extent.buffer_offset],
                             ctx->new_sub());
    }
    ctx->activate();
  }
  virtual const char *get_name() const override {
    return "C_ReadFromCacheRequest";
  }
};

template <typename I>
struct C_ReadFromImageRequest : public C_BlockIORequest {
  ImageWriteback<I> &image_writeback;
  BlockGuard::BlockIO block_io;
  ExtentBuffers *extent_buffers;

  C_ReadFromImageRequest(CephContext *cct, ImageWriteback<I> &image_writeback,
                         BlockGuard::BlockIO &&block_io,
                         ExtentBuffers *extent_buffers,
                         C_BlockIORequest *next_block_request)
    : C_BlockIORequest(cct, next_block_request),
      image_writeback(image_writeback), block_io(block_io),
      extent_buffers(extent_buffers) {
  }

  virtual void send() override {
    ldout(cct, 20) << "(" << get_name() << "): "
                   << "block_io=[" << block_io << "]" << dendl;

    // TODO improve scatter/gather to include buffer offsets
    uint64_t image_offset = block_io.block * BLOCK_SIZE;
    C_Gather *ctx = new C_Gather(cct, this);
    for (auto &extent : block_io.extents) {
      image_writeback.aio_read({{image_offset + extent.block_offset,
                                 extent.block_length}},
                               &(*extent_buffers)[extent.buffer_offset],
                               0, ctx->new_sub());
    }
    ctx->activate();
  }
  virtual const char *get_name() const override {
    return "C_ReadFromImageRequest";
  }
};

template <typename I>
struct C_ReadBlockFromImageRequest : public C_BlockIORequest {
  ImageWriteback<I> &image_writeback;
  uint64_t block;
  bufferlist *block_bl;

  C_ReadBlockFromImageRequest(CephContext *cct,
                              ImageWriteback<I> &image_writeback,
                              uint64_t block, bufferlist *block_bl,
                              C_BlockIORequest *next_block_request)
    : C_BlockIORequest(cct, next_block_request),
      image_writeback(image_writeback), block(block), block_bl(block_bl) {
  }

  virtual void send() override {
    ldout(cct, 20) << "(" << get_name() << "): "
                   << "block=" << block << dendl;

    uint64_t image_offset = block * BLOCK_SIZE;
    image_writeback.aio_read({{image_offset, BLOCK_SIZE}}, block_bl, 0, this);
  }
  virtual const char *get_name() const override {
    return "C_ReadBlockFromImageRequest";
  }
};

struct C_CopyFromBlockBuffer : public C_BlockIORequest {
  BlockGuard::BlockIO block_io;
  const bufferlist &block_bl;
  ExtentBuffers *extent_buffers;

  C_CopyFromBlockBuffer(CephContext *cct, const BlockGuard::BlockIO &block_io,
                        const bufferlist &block_bl,
                        ExtentBuffers *extent_buffers,
                        C_BlockIORequest *next_block_request)
    : C_BlockIORequest(cct, next_block_request),
      block_io(block_io), block_bl(block_bl), extent_buffers(extent_buffers) {
  }

  virtual void send() override {
    ldout(cct, 20) << "(" << get_name() << "): "
                   << "block_io=[" << block_io << dendl;

    for (auto &extent : block_io.extents) {
      bufferlist &sub_bl = (*extent_buffers)[extent.buffer_offset];
      sub_bl.substr_of(block_bl, extent.block_offset, extent.block_length);
    }
    complete(0);
  }
  virtual const char *get_name() const override {
    return "C_CopyFromBlockBuffer";
  }
};

template <typename I>
struct C_ReadBlockRequest : public BlockGuard::C_BlockRequest {
  typedef std::list<bufferlist> Buffers;

  I &image_ctx;
  ImageWriteback<I> &image_writeback;
  ImageStore<I> &image_store;
  ReleaseBlock &release_block;
  bufferlist *bl;

  ExtentBuffers extent_buffers;
  Buffers promote_buffers;

  C_ReadBlockRequest(I &image_ctx,
                     ImageWriteback<I> &image_writeback,
                     ImageStore<I> &image_store,
                     ReleaseBlock &release_block, bufferlist *bl,
                     Context *on_finish)
    : C_BlockRequest(on_finish), image_ctx(image_ctx),
      image_writeback(image_writeback), image_store(image_store),
      release_block(release_block), bl(bl) {
  }

  virtual void remap(PolicyMapResult policy_map_result,
                     BlockGuard::BlockIO &&block_io) {
    CephContext *cct = image_ctx.cct;

    // TODO: consolidate multiple reads into a single request (i.e. don't
    // have 1024 4K requests to read a single object)

    // NOTE: block guard active -- must be released after IO completes
    C_BlockIORequest *req = new C_ReleaseBlockGuard(cct, block_io.block,
                                                         release_block, this);
    switch (policy_map_result) {
    case POLICY_MAP_RESULT_HIT:
      req = new C_ReadFromCacheRequest<I>(cct, image_store, std::move(block_io),
                                          &extent_buffers, req);
      break;
    case POLICY_MAP_RESULT_MISS:
      req = new C_ReadFromImageRequest<I>(cct, image_writeback,
                                          std::move(block_io), &extent_buffers,
                                          req);
      break;
    case POLICY_MAP_RESULT_NEW:
    case POLICY_MAP_RESULT_REPLACE:
      promote_buffers.emplace_back();
      req = new C_CopyFromBlockBuffer(cct, block_io, promote_buffers.back(),
                                      &extent_buffers, req);
      req = new C_PromoteToCache<I>(cct, image_store, block_io.block,
                                    promote_buffers.back(), req);
      req = new C_ReadBlockFromImageRequest<I>(cct, image_writeback,
                                               block_io.block,
                                               &promote_buffers.back(), req);
      if (policy_map_result == POLICY_MAP_RESULT_REPLACE) {
        req = new C_DemoteFromCache<I>(cct, image_store, release_block,
                                       block_io.block, req);
      }
      break;
    default:
      assert(false);
    }
    req->send();
  }

  virtual void finish(int r) override {
    CephContext *cct = image_ctx.cct;
    ldout(cct, 20) << "(C_ReadBlockRequest): r=" << r << dendl;

    if (r < 0) {
      C_BlockRequest::finish(r);
      return;
    }

    ldout(cct, 20) << "assembling read extents" << dendl;
    for (auto &extent_bl : extent_buffers) {
      ldout(cct, 20) << extent_bl.first << "~" << extent_bl.second.length()
                     << dendl;
      bl->claim_append(extent_bl.second);
    }
    C_BlockRequest::finish(0);
  }
};

} // anonymous namespace

template <typename I>
FileImageCache<I>::FileImageCache(ImageCtx &image_ctx)
  : m_image_ctx(image_ctx), m_image_writeback(image_ctx),
    m_block_guard(image_ctx.cct, 256, BLOCK_SIZE),
    m_policy(new StupidPolicy<I>(m_image_ctx, m_block_guard)),
    m_release_block(std::bind(&FileImageCache<I>::release_block, this,
                              std::placeholders::_1)),
    m_lock("librbd::cache::FileImageCache::m_lock") {
}

template <typename I>
FileImageCache<I>::~FileImageCache() {
  delete m_policy;
}

template <typename I>
void FileImageCache<I>::aio_read(Extents &&image_extents, bufferlist *bl,
                                 int fadvise_flags, Context *on_finish) {
  CephContext *cct = m_image_ctx.cct;
  ldout(cct, 20) << "image_extents=" << image_extents << ", "
                 << "on_finish=" << on_finish << dendl;

  // TODO handle fadvise flags
  BlockGuard::C_BlockRequest *req = new C_ReadBlockRequest<I>(
    m_image_ctx, m_image_writeback, *m_image_store, m_release_block, bl,
    on_finish);
  map_blocks(IO_TYPE_READ, std::move(image_extents), req);
}

template <typename I>
void FileImageCache<I>::aio_write(Extents &&image_extents,
                                  bufferlist&& bl,
                                  int fadvise_flags,
                                  Context *on_finish) {
  CephContext *cct = m_image_ctx.cct;
  ldout(cct, 20) << "image_extents=" << image_extents << ", "
                 << "on_finish=" << on_finish << dendl;

  if (!is_block_aligned(image_extents)) {
    // For clients that don't use LBA extents, re-align the write request
    // to work with the cache
    ldout(cct, 20) << "aligning write to block size" << dendl;

    // TODO: for non-aligned extents, invalidate the associated block-aligned
    // regions in the cache (if any), send the aligned extents to the cache
    // and the un-aligned extents directly to back to librbd
  }

  // TODO invalidate written blocks until writethrough/back support added
  C_Gather *ctx = new C_Gather(cct, on_finish);
  Extents invalidate_extents(image_extents);
  invalidate(std::move(invalidate_extents), ctx->new_sub());

  m_image_writeback.aio_write(std::move(image_extents), std::move(bl),
                              fadvise_flags, ctx->new_sub());
  ctx->activate();
}

template <typename I>
void FileImageCache<I>::aio_discard(uint64_t offset, uint64_t length,
                                    bool skip_partial_discard, Context *on_finish) {
  CephContext *cct = m_image_ctx.cct;
  ldout(cct, 20) << "offset=" << offset << ", "
                 << "length=" << length << ", "
                 << "on_finish=" << on_finish << dendl;

  if (!is_block_aligned({{offset, length}})) {
    // For clients that don't use LBA extents, re-align the discard request
    // to work with the cache
    ldout(cct, 20) << "aligning discard to block size" << dendl;

    // TODO: for non-aligned extents, invalidate the associated block-aligned
    // regions in the cache (if any), send the aligned extents to the cache
    // and the un-aligned extents directly to back to librbd
  }

  // TODO invalidate discard blocks until writethrough/back support added
  C_Gather *ctx = new C_Gather(cct, on_finish);
  invalidate({{offset, length}}, ctx->new_sub());

  m_image_writeback.aio_discard(offset, length, skip_partial_discard, ctx->new_sub());

  ctx->activate();

  Context *invalidate_ctx = new FunctionContext(
    [this, offset, length, invalidate_done_ctx](int r) {
      invalidate({{offset, length}}, invalidate_done_ctx);
    });
  flush(invalidate_ctx);
}

template <typename I>
void FileImageCache<I>::aio_flush(Context *on_finish) {
  CephContext *cct = m_image_ctx.cct;
  ldout(cct, 20) << "on_finish=" << on_finish << dendl;

  m_image_writeback.aio_flush(on_finish);
}

template <typename I>
void FileImageCache<I>::aio_writesame(uint64_t offset, uint64_t length,
                                             bufferlist&& bl, int fadvise_flags,
                                             Context *on_finish) {
  CephContext *cct = m_image_ctx.cct;
  ldout(cct, 20) << "offset=" << offset << ", "
                 << "length=" << length << ", "
                 << "data_len=" << bl.length() << ", "
                 << "on_finish=" << on_finish << dendl;

  m_image_writeback.aio_writesame(offset, length, std::move(bl), fadvise_flags,
                                  on_finish);
}

template <typename I>
void FileImageCache<I>::aio_compare_and_write(Extents &&image_extents,
                                                     bufferlist&& cmp_bl,
                                                     bufferlist&& bl,
                                                     uint64_t *mismatch_offset,
                                                     int fadvise_flags,
                                                     Context *on_finish) {
  CephContext *cct = m_image_ctx.cct;
  ldout(cct, 20) << "image_extents=" << image_extents << ", "
                 << "on_finish=" << on_finish << dendl;

  m_image_writeback.aio_compare_and_write(
    std::move(image_extents), std::move(cmp_bl), std::move(bl), mismatch_offset,
    fadvise_flags, on_finish);
}

template <typename I>
void FileImageCache<I>::init(Context *on_finish) {
  CephContext *cct = m_image_ctx.cct;
  ldout(cct, 20) << dendl;

  // chain the initialization of the meta, image, and journal stores
  Context *ctx = new FunctionContext(
    [this, on_finish](int r) {
      if (r >= 0) {
        // TODO need to support dynamic image resizes
        m_policy->set_block_count(
          m_meta_store->offset_to_block(m_image_ctx.size));
      }
      on_finish->complete(r);
    });
  ctx = new FunctionContext(
    [this, ctx](int r) {
      if (r < 0) {
        ctx->complete(r);
        return;
      }

      // TODO: do not enable journal store if writeback disabled
      m_journal_store = new JournalStore<I>(m_image_ctx, *m_meta_store);
      m_journal_store->init(ctx);
    });
  ctx = new FunctionContext(
    [this, ctx](int r) {
      if (r < 0) {
        ctx->complete(r);
        return;
      }

      m_image_store = new ImageStore<I>(m_image_ctx, *m_meta_store);
      m_image_store->init(ctx);
    });
  m_meta_store = new MetaStore<I>(m_image_ctx, BLOCK_SIZE);
  m_meta_store->init(ctx);
}

template <typename I>
void FileImageCache<I>::shut_down(Context *on_finish) {
  CephContext *cct = m_image_ctx.cct;
  ldout(cct, 20) << dendl;

  // TODO flush all in-flight IO and pending writeback prior to shut down

  // chain the shut down of the journal, image, and meta stores
  Context *ctx = new FunctionContext(
    [this, on_finish](int r) {
      delete m_journal_store;
      delete m_image_store;
      delete m_meta_store;
      on_finish->complete(r);
    });
  ctx = new FunctionContext(
    [this, ctx](int r) {
      Context *next_ctx = ctx;
      if (r < 0) {
        next_ctx = new FunctionContext(
          [r, ctx](int _r) {
            ctx->complete(r);
          });
      }
      m_meta_store->shut_down(next_ctx);
    });
  ctx = new FunctionContext(
    [this, ctx](int r) {
      Context *next_ctx = ctx;
      if (r < 0) {
        next_ctx = new FunctionContext(
          [r, ctx](int _r) {
            ctx->complete(r);
          });
      }
      m_image_store->shut_down(next_ctx);
    });
  ctx = new FunctionContext(
    [this, ctx](int r) {
      m_journal_store->shut_down(ctx);
    });

  {
    Mutex::Locker locker(m_lock);
    assert(m_on_shutdown == nullptr);
    if (m_wake_up_scheduled) {
      // wake for wake-up thread to complete
      m_on_shutdown = ctx;
      return;
    }
  }

  ctx->complete(0);
}

template <typename I>
void FileImageCache<I>::invalidate(Context *on_finish) {
  CephContext *cct = m_image_ctx.cct;
  ldout(cct, 20) << dendl;

  // TODO
  invalidate({{0, m_image_ctx.size}}, on_finish);
}

template <typename I>
void FileImageCache<I>::map_blocks(IOType io_type, Extents &&image_extents,
                                   BlockGuard::C_BlockRequest *block_request) {
  CephContext *cct = m_image_ctx.cct;
  ldout(cct, 20) << dendl;

  BlockGuard::BlockIOs block_ios;
  m_block_guard.create_block_ios(io_type, image_extents, &block_ios,
                                 block_request);

  // map block IO requests to the cache or backing image based upon policy
  for (auto &block_io : block_ios) {
    map_block(true, std::move(block_io));
  }

  // advance the policy statistics
  m_policy->tick();
  block_request->activate();
}

template <typename I>
void FileImageCache<I>::map_block(bool detain_block,
                                  BlockGuard::BlockIO &&block_io) {
  CephContext *cct = m_image_ctx.cct;
  ldout(cct, 20) << "block_io=[" << block_io << "]" << dendl;

  int r;
  if (detain_block) {
    r = m_block_guard.detain(block_io.block, &block_io);
    if (r < 0) {
      Mutex::Locker locker(m_lock);
      ldout(cct, 20) << "block guard full -- deferring block IO" << dendl;
      m_deferred_block_ios.emplace_back(std::move(block_io));
      return;
    } else if (r > 0) {
      ldout(cct, 20) << "block already detained" << dendl;
      return;
    }
  }

  bool partial_block = (block_io.extents.size() != 1 ||
                        block_io.extents.front().block_offset != 0 ||
                        block_io.extents.front().block_length != BLOCK_SIZE);

  PolicyMapResult policy_map_result;
  uint64_t replace_cache_block;
  r = m_policy->map(block_io.io_type, block_io.block, partial_block,
                    &policy_map_result, &replace_cache_block);
  if (r < 0) {
    // fail this IO and release any detained IOs to the block
    lderr(cct) << "failed to map block via cache policy: " << cpp_strerror(r)
               << dendl;
    block_io.block_request->fail(r);
    release_block(block_io.block);
    return;
  }

  block_io.block_request->remap(policy_map_result, std::move(block_io));
}

template <typename I>
void FileImageCache<I>::release_block(uint64_t block) {
  CephContext *cct = m_image_ctx.cct;
  ldout(cct, 20) << "block=" << block << dendl;

  Mutex::Locker locker(m_lock);
  m_block_guard.release(block, &m_deferred_detained_block_ios);
  wake_up();
}

template <typename I>
void FileImageCache<I>::wake_up() {
  assert(m_lock.is_locked());
  if (m_wake_up_scheduled || m_on_shutdown != nullptr) {
    return;
  }

  CephContext *cct = m_image_ctx.cct;
  ldout(cct, 20) << dendl;

  m_wake_up_scheduled = true;
  m_image_ctx.op_work_queue->queue(new FunctionContext(
    [this](int r) {
      process_work();
    }), 0);
}

template <typename I>
void FileImageCache<I>::process_work() {
  CephContext *cct = m_image_ctx.cct;
  ldout(cct, 20) << dendl;

  BlockGuard::BlockIOs deferred_detained_block_ios;
  BlockGuard::BlockIOs deferred_block_ios;
  Context *on_shutdown = nullptr;
  {
    Mutex::Locker locker(m_lock);
    std::swap(deferred_detained_block_ios, m_deferred_detained_block_ios);
    std::swap(deferred_block_ios, m_deferred_block_ios);

    // TODO while doing work ensure a flush cannot complete

    std::swap(on_shutdown, m_on_shutdown);
    m_wake_up_scheduled = false;
  }

  ldout(cct, 20) << "deferred_detained_block_ios="
                 << deferred_detained_block_ios.size() << ", "
                 << "deferred_block_ios=" << deferred_block_ios.size() << dendl;
  for (auto &block_io : deferred_detained_block_ios) {
    map_block(false, std::move(block_io));
  }
  for (auto &block_io : deferred_block_ios) {
    map_block(true, std::move(block_io));
  }

  if (on_shutdown != nullptr) {
    on_shutdown->complete(0);
  }
}

template <typename I>
void FileImageCache<I>::invalidate(Extents&& image_extents,
                                   Context *on_finish) {
  CephContext *cct = m_image_ctx.cct;
  ldout(cct, 20) << "image_extents=" << image_extents << dendl;

  // TODO
  for (auto &extent : image_extents) {
    uint64_t image_offset = extent.first;
    uint64_t image_length = extent.second;
    while (image_length > 0) {
      uint64_t block = m_meta_store->offset_to_block(image_offset);
      uint32_t block_start_offset = image_offset % BLOCK_SIZE;
      uint32_t block_end_offset = MIN(block_start_offset + image_length,
                                      BLOCK_SIZE);
      uint32_t block_length = block_end_offset - block_start_offset;

      m_policy->invalidate(block);

      image_offset += block_length;
      image_length -= block_length;
    }
  }

  // dump specific extents within the cache
  on_finish->complete(0);
}

template <typename I>
void FileImageCache<I>::flush(Context *on_finish) {
  CephContext *cct = m_image_ctx.cct;
  ldout(cct, 20) << dendl;

  // TODO

  // internal flush -- nothing to writeback but make sure
  // in-flight IO is flushed
  aio_flush(on_finish);
}

} // namespace cache
} // namespace librbd

template class librbd::cache::FileImageCache<librbd::ImageCtx>;
