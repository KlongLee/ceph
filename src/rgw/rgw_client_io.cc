// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include "rgw_client_io.h"

#define dout_subsys ceph_subsys_rgw

void RGWClientIO::init(CephContext *cct) {
  engine->init_env(cct);

  if (cct->_conf->subsys.should_gather(ceph_subsys_rgw, 20)) {
    std::map<string, string, ltstr_nocase>& env_map = \
        engine->get_env().get_map();
    std::map<string, string, ltstr_nocase>::iterator iter = env_map.begin();

    for (iter = env_map.begin(); iter != env_map.end(); ++iter) {
      ldout(cct, 20) << iter->first << "=" << iter->second << dendl;
    }
  }
}


int RGWClientIO::print(const char *format, ...)
{
#define LARGE_ENOUGH 128
  int size = LARGE_ENOUGH;

  va_list ap;

  while(1) {
    char buf[size];
    va_start(ap, format);
    int ret = vsnprintf(buf, size, format, ap);
    va_end(ap);

    if (ret >= 0 && ret < size) {
      return write(buf, ret);
    }

    if (ret >= 0) {
      size = ret + 1;
    } else {
      size *= 2;
    }
  }

  /* not reachable */
}

int RGWClientIO::write(const char *buf, int len)
{
  int ret = engine->write_data(buf, len);
  if (ret < 0) {
    return ret;
  }

  if (account) {
    bytes_sent += ret;
  }

  if (ret < len) {
    /* sent less than tried to send, error out */
    return -EIO;
  }

  return 0;
}


int RGWClientIO::read(char *buf, int max, int *actual)
{
  int ret = engine->read_data(buf, max);
  if (ret < 0) {
    return ret;
  }

  *actual = ret;

  bytes_received += *actual;

  return 0;
}


int RGWClientIOEngineReorderer::write_data(const char * const buf, const int len)
{
  switch (phase) {
  case ReorderState::RGW_EARLY_HEADERS:
    early_header_data.append(buf, len);
    return len;
  case ReorderState::RGW_STATUS_SEEN:
    header_data.append(buf, len);
    return len;
  case ReorderState::RGW_DATA:
    /* FALL THROUGH */;
  }

  return RGWClientIOEngineDecorator::write_data(buf, len);
}

int RGWClientIOEngineReorderer::send_status(RGWClientIO& controller,
                                            const char * const status,
                                            const char * const status_name)
{
  phase = ReorderState::RGW_STATUS_SEEN;

  return RGWClientIOEngineDecorator::send_status(controller, status,
          status_name);
}

int RGWClientIOEngineReorderer::send_100_continue(RGWClientIO& controller)
{
  auto prev = phase;
  phase = ReorderState::RGW_STATUS_SEEN;

  auto ret = RGWClientIOEngineDecorator::send_100_continue(controller);
  phase = prev;

  return ret;
}

int RGWClientIOEngineReorderer::complete_header(RGWClientIO& controller)
{
  /* Change state in order to immediately send everything we get. */
  phase = ReorderState::RGW_DATA;

  /* Header data in buffers are already counted. */
  if (header_data.length()) {
    ssize_t rc = write_data(header_data.c_str(), header_data.length());
    if (rc < 0) {
      return rc;
    }
    header_data.clear();
  }

  if (early_header_data.length()) {
    ssize_t rc = write_data(early_header_data.c_str(),
            early_header_data.length());
    if (rc < 0) {
      return rc;
    }
    early_header_data.clear();
  }

  return RGWClientIOEngineDecorator::complete_header(controller);
}
