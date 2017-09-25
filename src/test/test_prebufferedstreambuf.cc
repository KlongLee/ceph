// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#include "common/PrebufferedStreambuf.h"
#include "gtest/gtest.h"

TEST(PrebufferedStreambuf, Empty)
{
  char buf[10];
  prebuffered_data data(buf, sizeof(buf));
  PrebufferedStreambuf& sb = *PrebufferedStreambuf::get_streambuf(&data);

  std::istream is(&sb);
  std::string out;
  getline(is, out);
  ASSERT_EQ("", out);
}

TEST(PrebufferedStreambuf, Simple)
{
  char buf[10];
  prebuffered_data data(buf, sizeof(buf));
  PrebufferedStreambuf& sb = *PrebufferedStreambuf::get_streambuf(&data);

  std::ostream os(&sb);
  os << "test";

  std::istream is(&sb);
  std::string out;
  getline(is, out);
  ASSERT_EQ("test", out);
}

TEST(PrebufferedStreambuf, Multiline)
{
  char buf[10];
  prebuffered_data data(buf, sizeof(buf));
  PrebufferedStreambuf& sb = *PrebufferedStreambuf::get_streambuf(&data);

  std::ostream os(&sb);
  const char *s = "this is a line\nanother line\nand a third\nwhee!\n";
  os << s;

  std::istream is(&sb);
  std::string out;
  getline(is, out, is.widen(0));
  ASSERT_EQ(s, out);
}

TEST(PrebufferedStreambuf, Withnull)
{
  char buf[10];
  prebuffered_data data(buf, sizeof(buf));
  PrebufferedStreambuf& sb = *PrebufferedStreambuf::get_streambuf(&data);

  std::ostream os(&sb);
  std::string s("null \0 and more", 15);
  os << s;

  std::istream is(&sb);
  std::string out;
  getline(is, out);
  ASSERT_EQ(s, out);
}

TEST(PrebufferedStreambuf, SimpleOverflow)
{
  char buf[10];
  prebuffered_data data(buf, sizeof(buf));
  PrebufferedStreambuf& sb = *PrebufferedStreambuf::get_streambuf(&data);

  std::ostream os(&sb);
  const char *s = "hello, this is longer than buf[10]";
  os << s;
  std::cout << "a" << std::endl;
  //sb.finish();
  ASSERT_EQ(s, sb.get_str());
  std::cout << "b" << std::endl;

  std::istream is(&sb);
  std::cout << "c" << std::endl;
  std::string out;
  std::cout << "d" << std::endl;

  getline(is, out);
  std::cout << "d" << std::endl;

  ASSERT_EQ(s, out);
}

TEST(PrebufferedStreambuf, ManyOverflow)
{
  char buf[10];
  prebuffered_data data(buf, sizeof(buf));
  PrebufferedStreambuf& sb = *PrebufferedStreambuf::get_streambuf(&data);

  std::ostream os(&sb);
  const char *s = "hello, this way way way way way way way way way way way way way way way way way way way way way way way way way _way_ longer than buf[10]";
  os << s;

  ASSERT_EQ(s, sb.get_str());

  std::istream is(&sb);
  std::string out;
  getline(is, out);
  ASSERT_EQ(s, out);
}

