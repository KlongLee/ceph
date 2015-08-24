// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab
/*
 * Ceph - scalable distributed file system
 *
 * Copyright (C) 2011 New Dream Network
 *
 * This is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2.1, as published by the Free Software
 * Foundation.  See file COPYING.
 *
 */

#define LARGE_SIZE 1024

#include "include/int_types.h"

#include "assert.h"
#include "Formatter.h"
#include "HTMLFormatter.h"
#include "XMLFormatter.h"
#include "common/escape.h"

#include <iostream>
#include <sstream>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <vector>
#include <string>
#include <set>
#include <boost/format.hpp>

// -----------------------
namespace ceph {

HTMLFormatter::HTMLFormatter(bool pretty)
: XMLFormatter(pretty)
{
}

template <typename T>
void HTMLFormatter::dump_template(const char *name, T arg)
{
  print_spaces();
  m_ss << "<li>" << name << ": " << arg << "</li>";
  if (m_pretty)
    m_ss << "\n";
}

void HTMLFormatter::dump_unsigned(const char *name, uint64_t u)
{
  dump_template(name, u);
}

void HTMLFormatter::dump_int(const char *name, int64_t u)
{
  dump_template(name, u);
}

void HTMLFormatter::dump_float(const char *name, double d)
{
  dump_template(name, d);
}

void HTMLFormatter::dump_string(const char *name, const std::string& s)
{
  dump_template(name, escape_xml_str(s.c_str()));
}

void HTMLFormatter::dump_string_with_attrs(const char *name, const std::string& s, const FormatterAttrs& attrs)
{
  std::string e(name);
  std::string attrs_str;
  get_attrs_str(&attrs, attrs_str);
  print_spaces();
  m_ss << "<li>" << e << ": " << escape_xml_str(s.c_str()) << attrs_str << "</li>";
  if (m_pretty)
    m_ss << "\n";
}

std::ostream& HTMLFormatter::dump_stream(const char *name)
{
  print_spaces();
  m_pending_string_name = "li";
  m_ss << "<li>" << name << ": ";
  return m_pending_string;
}

void HTMLFormatter::dump_format_va(const char* name, const char *ns, bool quoted, const char *fmt, va_list ap)
{
  char buf[LARGE_SIZE];
  vsnprintf(buf, LARGE_SIZE, fmt, ap);

  std::string e(name);
  print_spaces();
  if (ns) {
    m_ss << "<li xmlns=\"" << ns << "\">" << e << ": " << escape_xml_str(buf) << "</li>";
  } else {
    m_ss << "<li>" << e << ": " << escape_xml_str(buf) << "</li>";
  }

  if (m_pretty)
    m_ss << "\n";
}


} // namespace ceph
