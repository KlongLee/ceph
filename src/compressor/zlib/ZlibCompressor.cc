/*
 * Ceph - scalable distributed file system
 *
 * Copyright (C) 2015 Mirantis, Inc.
 *
 * Author: Alyona Kiseleva <akiselyova@mirantis.com>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 */

// -----------------------------------------------------------------------------
#include "common/debug.h"
#include "ZlibCompressor.h"
#include "osd/osd_types.h"
#include "isa-l/include/igzip_lib.h"
// -----------------------------------------------------------------------------

#include <zlib.h>

// -----------------------------------------------------------------------------
#define dout_subsys ceph_subsys_compressor
#undef dout_prefix
#define dout_prefix _prefix(_dout)
// -----------------------------------------------------------------------------

// -----------------------------------------------------------------------------

static ostream&
_prefix(std::ostream* _dout)
{
  return *_dout << "ZlibCompressor: ";
}
// -----------------------------------------------------------------------------

const long unsigned int max_len = 2048;

int ZlibCompressor::zlib_compress(const bufferlist &in, bufferlist &out)
{
  int ret;
  unsigned have;
  z_stream strm;
  unsigned char* c_in;
  int level = 5;
  int begin = 1;

  /* allocate deflate state */
  strm.zalloc = Z_NULL;
  strm.zfree = Z_NULL;
  strm.opaque = Z_NULL;
  ret = deflateInit(&strm, level);
  if (ret != Z_OK) {
    dout(1) << "Compression init error: init return "
         << ret << " instead of Z_OK" << dendl;
    return -1;
  }

  for (std::list<buffer::ptr>::const_iterator i = in.buffers().begin();
      i != in.buffers().end();) {

    c_in = (unsigned char*) (*i).c_str();
    long unsigned int len = (*i).length();
    ++i;

    strm.avail_in = len;
    int flush = i != in.buffers().end() ? Z_NO_FLUSH : Z_FINISH;

    strm.next_in = c_in;

    do {
      strm.avail_out = max_len;
      bufferptr ptr = buffer::create_page_aligned(max_len);
      strm.next_out = (unsigned char*)ptr.c_str() + begin;
      if (begin) {
        ptr.c_str()[0] = 0;
        begin = 0;
      }
      ret = deflate(&strm, flush);    /* no bad return value */
      if (ret == Z_STREAM_ERROR) {
         dout(1) << "Compression error: compress return Z_STREAM_ERROR("
              << ret << ")" << dendl;
         deflateEnd(&strm);
         return -1;
      }
      have = max_len - strm.avail_out;
      out.append(ptr, 0, have);
    } while (strm.avail_out == 0);
    if (strm.avail_in != 0) {
      dout(10) << "Compression error: unused input" << dendl;
      deflateEnd(&strm);
      return -1;
    }
  }

  deflateEnd(&strm);
  return 0;
}

#if __x86_64__ && defined(HAVE_BETTER_YASM_ELF64)
int ZlibCompressor::isal_compress(const bufferlist &in, bufferlist &out)
{
  int ret;
  unsigned have;
  isal_zstream strm;
  unsigned char* c_in;
  int begin = 1;

  /* allocate deflate state */
  isal_deflate_init(&strm);
  strm.end_of_stream = 0;

  for (std::list<buffer::ptr>::const_iterator i = in.buffers().begin();
      i != in.buffers().end();) {

    c_in = (unsigned char*) (*i).c_str();
    long unsigned int len = (*i).length();
    ++i;

    strm.avail_in = len;
    strm.end_of_stream = (i == in.buffers().end());
    strm.flush = FINISH_FLUSH;

    strm.next_in = c_in;

    do {
      strm.avail_out = max_len;
      bufferptr ptr = buffer::create_page_aligned(max_len);
      strm.next_out = (unsigned char*)ptr.c_str() + begin;
      if (begin) {
        ptr.c_str()[0] = 1;
        begin = 0;
      }
      ret = isal_deflate(&strm);
      if (ret != COMP_OK) {
         dout(1) << "Compression error: isal_deflate return error ("
              << ret << ")" << dendl;
         return -1;
      }
      have = max_len - strm.avail_out;
      out.append(ptr, 0, have);
    } while (strm.avail_out == 0);
    if (strm.avail_in != 0) {
      dout(10) << "Compression error: unused input" << dendl;
      return -1;
    }
  }

  return 0;  
}
#endif

int ZlibCompressor::compress(const bufferlist &in, bufferlist &out)
{
#if __x86_64__ && defined(HAVE_BETTER_YASM_ELF64)
  if (isal_enabled)
    return isal_compress(in, out);
  else
    return zlib_compress(in, out);
#else
  return zlib_compress(in, out);
#endif
}

int ZlibCompressor::decompress(bufferlist::iterator &p, size_t compressed_size, bufferlist &out)
{
  int ret;
  unsigned have;
  z_stream strm;
  const char* c_in;
  int begin = 1;

  /* allocate inflate state */
  strm.zalloc = Z_NULL;
  strm.zfree = Z_NULL;
  strm.opaque = Z_NULL;
  strm.avail_in = 0;
  strm.next_in = Z_NULL;
  if (*p == 1)
    ret = inflateInit2(&strm, -HIST_SIZE);
  else
    ret = inflateInit(&strm);
  if (ret != Z_OK) {
    dout(1) << "Decompression init error: init return "
         << ret << " instead of Z_OK" << dendl;
    return -1;
  }

  size_t remaining = MIN(p.get_remaining(), compressed_size);
  while(remaining) {

    long unsigned int len = p.get_ptr_and_advance(remaining, &c_in);
    remaining -= len;
    strm.avail_in = len;
    strm.next_in = (unsigned char*)c_in + begin;
    begin = 0;

    do {
      strm.avail_out = max_len;
      bufferptr ptr = buffer::create_page_aligned(max_len);
      strm.next_out = (unsigned char*)ptr.c_str();
      ret = inflate(&strm, Z_NO_FLUSH);
      if (ret != Z_OK && ret != Z_STREAM_END && ret != Z_BUF_ERROR) {
       dout(1) << "Decompression error: decompress return "
            << ret << dendl;
       inflateEnd(&strm);
       return -1;
      }
      have = max_len - strm.avail_out;
      out.append(ptr, 0, have);
    } while (strm.avail_out == 0);

  }

  /* clean up and return */
  (void)inflateEnd(&strm);
  return 0;
}

int ZlibCompressor::decompress(const bufferlist &in, bufferlist &out)
{
  bufferlist::iterator i = const_cast<bufferlist&>(in).begin();
  return decompress(i, in.length(), out);
}
