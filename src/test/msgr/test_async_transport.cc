// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab
/*
 * Ceph - scalable distributed file system
 *
 * Copyright (C) 2016 XSky <haomai@xsky.com>
 *
 * Author: Haomai Wang <haomaiwang@gmail.com>
 *
 * This is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2.1, as published by the Free Software
 * Foundation.  See file COPYING.
 *
 */

#include <algorithm>
#include <atomic>
#include <iostream>
#include <string>
#include <set>
#include <thread>
#include <vector>
#include <gtest/gtest.h>

#include "acconfig.h"
#include "include/Context.h"
#include "common/ceph_argparse.h"
#include "global/global_init.h"

#include "msg/async/Event.h"
#include "msg/async/GenericSocket.h"
#include "msg/async/dpdk/Packet.h"

#if GTEST_HAS_PARAM_TEST

class TransportTest : public ::testing::TestWithParam<const char*> {
  struct StackThread {
    CephContext *cct;
    std::thread thread;
    EventCenter center;
    std::unique_ptr<NetworkStack> transport;
    unsigned idx;
    bool done = false;
    bool init_done = false;

    StackThread(CephContext *c, unsigned i): cct(c), center(cct), idx(i) {}
    void start(const char *type) {
      center.init(1000);
      if (idx) {
        thread = std::thread(&StackThread::worker, this, type);
      } else {
        center.set_owner(idx);
        transport = NetworkStack::create(cct, type, &center);
        transport->initialize();
        init_done = true;
      }
    }

    void stop() {
      done = true;
      if (idx)
        thread.join();
      transport.reset();
    }

    void ready() {
      while (!init_done)
        usleep(100);
    }

    void worker(const char *type) {
      center.set_owner(idx);
      transport = NetworkStack::create(cct, type, &center);
      transport->initialize();
      init_done = true;
      while (!done) {
        center.process_events(0);
      }
      usleep(100);
    }
  };

  int count_one_bits(unsigned value) {
    int ones = 0;
    for (; value != 0; value = value >> 1)
      if (value % 2 != 0)
          ones = ones + 1;
    return ones;
  }

 public:
  std::vector<StackThread*> stacks;
  string addr, port_addr;

  TransportTest() {}
  virtual void SetUp() {
    cerr << __func__ << " start set up " << GetParam() << std::endl;
    if (strncmp(GetParam(), "dpdk", 4)) {
      g_ceph_context->_conf->set_val("ms_dpdk_enable", "false");
      addr = "127.0.0.1:15000";
      port_addr = "127.0.0.1:15001";
    } else {
      g_ceph_context->_conf->set_val("ms_dpdk_enable", "true");
      g_ceph_context->_conf->set_val("ms_dpdk_coremask", "3", false, false);
      g_ceph_context->_conf->set_val("ms_dpdk_host_ipv4_addr", "172.16.218.199", false, false);
      g_ceph_context->_conf->set_val("ms_dpdk_gateway_ipv4_addr", "172.16.218.2", false, false);
      g_ceph_context->_conf->set_val("ms_dpdk_netmask_ipv4_addr", "255.255.255.0", false, false);
      addr = "172.16.218.199:15000";
      port_addr = "172.16.218.199:15001";
    }
    g_ceph_context->_conf->apply_changes(nullptr);
    unsigned x;
    std::stringstream ss;
    ss << std::dec << g_ceph_context->_conf->ms_dpdk_coremask;
    ss >> x;
    x = count_one_bits(x);
    stacks.resize(x);
    for (unsigned i = x; i > 0; --i) {
       StackThread *t = new StackThread(g_ceph_context, i-1);
       stacks[i-1] = t;
       t->start(GetParam());
    }
    for (auto &&t : stacks)
       t->ready();
  }
  virtual void TearDown() {
    for (auto &&t : stacks) {
      t->stop();
      delete t;
    }
    stacks.clear();
  }
  string get_addr() const {
    return addr;
  }
  string get_ip_different_port() const {
    return port_addr;
  }
  string get_different_ip() const {
    return "10.0.123.100:4323";
  }
  EventCenter *get_center(unsigned i) {
    return &stacks[i]->center;
  }
  NetworkStack *get_transport(unsigned i) {
    return stacks[i]->transport.get();
  }
};

class C_poll : public EventCallback {
  EventCenter *center;
  std::atomic<bool> wakeuped;
  static const int sleepus = 500;
  Mutex *lock;

 public:
  C_poll(EventCenter *c, Mutex *l=nullptr): center(c), wakeuped(false), lock(l) {}
  void do_request(int r) {
    wakeuped = true;
  }
  bool poll(int milliseconds) {
    auto start = ceph::coarse_real_clock::now(g_ceph_context);
    while (!wakeuped) {
      if (lock)
        lock->Lock();
      center->process_events(sleepus);
      if (lock)
        lock->Unlock();
      usleep(sleepus);
      auto r = std::chrono::duration_cast<std::chrono::milliseconds>(
              ceph::coarse_real_clock::now(g_ceph_context) - start);
      if (r >= std::chrono::milliseconds(milliseconds))
        break;
    }
    return wakeuped;
  }
  void reset() {
    wakeuped = false;
  }
};

TEST_P(TransportTest, SimpleTest) {
  entity_addr_t bind_addr, cli_addr;
  ASSERT_EQ(bind_addr.parse(get_addr().c_str()), true);
  SocketOptions options;
  ServerSocket bind_socket;
  NetworkStack *transport = get_transport(0);
  EventCenter *center = get_center(0);
  ssize_t r = transport->listen(bind_addr, options, &bind_socket);
  ASSERT_EQ(r, 0);
  ConnectedSocket cli_socket, srv_socket;
  r = transport->connect(bind_addr, options, &cli_socket);
  ASSERT_EQ(r, 0);

  {
    C_poll cb(center);
    center->create_file_event(bind_socket.fd(), EVENT_READABLE, &cb);
    ASSERT_EQ(cb.poll(500), true);
    center->delete_file_event(bind_socket.fd(), EVENT_READABLE);
  }

  r = bind_socket.accept(&srv_socket, &cli_addr);
  ASSERT_EQ(r, 0);
  ASSERT_TRUE(srv_socket.fd() > 0);

  {
    C_poll cb(center);
    center->create_file_event(cli_socket.fd(), EVENT_READABLE, &cb);
    r = cli_socket.is_connected();
    if (r == 0) {
      ASSERT_EQ(cb.poll(500), true);
      r = cli_socket.is_connected();
    }
    ASSERT_EQ(r, 1);
    center->delete_file_event(cli_socket.fd(), EVENT_READABLE);
  }

  const char *message = "this is a new message";
  int len = strlen(message);
  bufferlist bl;
  bl.append(message, len);
  r = cli_socket.send(bl, false);
  ASSERT_EQ(r, len);

  char buf[1024];
  C_poll cb(center);
  center->create_file_event(srv_socket.fd(), EVENT_READABLE, &cb);
  {
    r = srv_socket.read(buf, sizeof(buf));
    if (r == -EAGAIN) {
      ASSERT_EQ(cb.poll(500), true);
      r = srv_socket.read(buf, sizeof(buf));
    }
    ASSERT_EQ(r, len);
    ASSERT_EQ(0, memcmp(buf, message, len));
  }
  bind_socket.abort_accept();
  cli_socket.shutdown();

  bl.clear();
  bl.append(message, len);
  r = cli_socket.send(bl, false);
  ASSERT_EQ(r, -EPIPE);
  {
    cb.reset();
    ASSERT_EQ(cb.poll(500), true);
    r = srv_socket.read(buf, sizeof(buf));
    ASSERT_EQ(r, 0);
    bl.clear();
    bl.append(message, len);
    r = srv_socket.send(bl, false);
    ASSERT_EQ(r, len);
  }
  center->delete_file_event(srv_socket.fd(), EVENT_READABLE);

  srv_socket.close();
}

TEST_P(TransportTest, ConnectFailedTest) {
  NetworkStack *transport = get_transport(0);
  EventCenter *center = get_center(0);
  entity_addr_t bind_addr, cli_addr;
  ASSERT_EQ(bind_addr.parse(get_addr().c_str()), true);
  ASSERT_EQ(cli_addr.parse(get_ip_different_port().c_str()), true);
  SocketOptions options;
  ServerSocket bind_socket;
  int r = transport->listen(bind_addr, options, &bind_socket);
  ASSERT_EQ(r, 0);

  ConnectedSocket cli_socket1, cli_socket2;
  r = transport->connect(cli_addr, options, &cli_socket1);
  ASSERT_EQ(r, 0);

  {
    C_poll cb(center);
    center->create_file_event(cli_socket1.fd(), EVENT_READABLE, &cb);
    r = cli_socket1.is_connected();
    if (r == 0) {
      ASSERT_EQ(cb.poll(500), true);
      r = cli_socket1.is_connected();
    }
    ASSERT_TRUE(r == -ECONNREFUSED || r == -ECONNRESET);
  }

  ASSERT_EQ(cli_addr.parse(get_different_ip().c_str()), true);
  r = transport->connect(cli_addr, options, &cli_socket2);
  ASSERT_EQ(r, 0);

  {
    C_poll cb(center);
    center->create_file_event(cli_socket2.fd(), EVENT_READABLE, &cb);
    r = cli_socket2.is_connected();
    if (r == 0) {
      ASSERT_EQ(cb.poll(500), false);
      r = cli_socket2.is_connected();
    }
    ASSERT_TRUE(r != 1);
    center->delete_file_event(cli_socket2.fd(), EVENT_READABLE);
  }
}

TEST_P(TransportTest, ListenTest) {
  NetworkStack *transport = get_transport(0);
  entity_addr_t bind_addr;
  ASSERT_EQ(bind_addr.parse(get_addr().c_str()), true);
  SocketOptions options;
  ServerSocket bind_socket1, bind_socket2;
  int r = transport->listen(bind_addr, options, &bind_socket1);
  ASSERT_EQ(r, 0);

  r = transport->listen(bind_addr, options, &bind_socket2);
  ASSERT_EQ(r, -EADDRINUSE);
}

TEST_P(TransportTest, AcceptAndCloseTest) {
  NetworkStack *transport = get_transport(0);
  EventCenter *center = get_center(0);
  entity_addr_t bind_addr, cli_addr;
  ASSERT_EQ(bind_addr.parse(get_addr().c_str()), true);
  SocketOptions options;
  int r = 0;
  {
    ServerSocket bind_socket;
    r = transport->listen(bind_addr, options, &bind_socket);
    ASSERT_EQ(r, 0);

    ConnectedSocket srv_socket, cli_socket;
    r = bind_socket.accept(&srv_socket, &cli_addr);
    ASSERT_EQ(r, -EAGAIN);

    C_poll cb(center);
    center->create_file_event(bind_socket.fd(), EVENT_READABLE, &cb);
    r = transport->connect(bind_addr, options, &cli_socket);
    ASSERT_EQ(r, 0);
    ASSERT_EQ(cb.poll(500), true);

    {
      ConnectedSocket srv_socket2;
      r = bind_socket.accept(&srv_socket2, &cli_addr);
      ASSERT_EQ(r, 0);
      ASSERT_TRUE(srv_socket2.fd() > 0);

      // srv_socket2 closed
    }
    center->delete_file_event(bind_socket.fd(), EVENT_READABLE);

    char buf[100];
    cb.reset();
    center->create_file_event(cli_socket.fd(), EVENT_READABLE, &cb);
    int i = 3;
    while (!i--) {
      ASSERT_EQ(cb.poll(500), true);
      r = cli_socket.read(buf, sizeof(buf));
      if (r == 0)
        break;
    }
    ASSERT_EQ(r, 0);
    center->delete_file_event(cli_socket.fd(), EVENT_READABLE);

    cb.reset();
    center->create_file_event(bind_socket.fd(), EVENT_READABLE, &cb);
    r = transport->connect(bind_addr, options, &cli_socket);
    ASSERT_EQ(r, 0);

    ASSERT_EQ(cb.poll(500), true);
    center->delete_file_event(cli_socket.fd(), EVENT_READABLE);
    cli_socket.close();
    r = bind_socket.accept(&srv_socket, &cli_addr);
    ASSERT_EQ(r, 0);
    center->delete_file_event(bind_socket.fd(), EVENT_READABLE);
    // unbind
  }

  ConnectedSocket cli_socket;
  r = transport->connect(bind_addr, options, &cli_socket);
  ASSERT_EQ(r, 0);
  {
    C_poll cb(center);
    center->create_file_event(cli_socket.fd(), EVENT_READABLE, &cb);
    r = cli_socket.is_connected();
    if (r == 0) {
      ASSERT_EQ(cb.poll(500), true);
      r = cli_socket.is_connected();
    }
    ASSERT_TRUE(r == -ECONNREFUSED || r == -ECONNRESET);
  }
}

TEST_P(TransportTest, ComplexTest) {
  NetworkStack *transport = get_transport(0);
  EventCenter *center = get_center(0);
  entity_addr_t bind_addr, cli_addr;
  ASSERT_EQ(bind_addr.parse(get_addr().c_str()), true);
  SocketOptions options;
  ServerSocket bind_socket;
  int r = transport->listen(bind_addr, options, &bind_socket);
  ASSERT_EQ(r, 0);
  ConnectedSocket cli_socket, srv_socket;
  r = transport->connect(bind_addr, options, &cli_socket);
  ASSERT_EQ(r, 0);

  {
    C_poll cb(center);
    center->create_file_event(bind_socket.fd(), EVENT_READABLE, &cb);
    ASSERT_EQ(cb.poll(500), true);
    center->delete_file_event(bind_socket.fd(), EVENT_READABLE);
  }

  r = bind_socket.accept(&srv_socket, &cli_addr);
  ASSERT_EQ(r, 0);
  ASSERT_TRUE(srv_socket.fd() > 0);

  {
    C_poll cb(center);
    center->create_file_event(cli_socket.fd(), EVENT_READABLE, &cb);
    r = cli_socket.is_connected();
    if (r == 0) {
      ASSERT_EQ(cb.poll(500), true);
      r = cli_socket.is_connected();
    }
    ASSERT_EQ(r, 1);
    center->delete_file_event(cli_socket.fd(), EVENT_READABLE);
  }

  const size_t message_size = 10240;
  size_t count = 100;
  string message(message_size, '!');
  for (size_t i = 0; i < message_size; i += 100)
    message[i] = ',';
  auto cli_fd = cli_socket.fd();
  bool done = false;
  size_t len = message_size * count;
  Mutex lock("test_async_transport::lock");
  std::thread t([len, cli_fd, count](EventCenter *center, ConnectedSocket &cli_socket, const string &message, Mutex &lock, bool &done) {
    bool first = true;
   again:
    bufferlist bl;
    for (size_t i = 0; i < count; ++i)
      bl.push_back(bufferptr((char*)message.data(), message_size));

    ASSERT_TRUE(center->get_owner());
    C_poll cb(center, &lock);
    center->create_file_event(cli_fd, EVENT_WRITABLE, &cb);
    ssize_t r = 0;
    size_t left = len;
    usleep(100);
    while (left > 0) {
      lock.Lock();
      r = cli_socket.send(bl, false);
      lock.Unlock();
      ASSERT_TRUE(r > 0 || r == -EAGAIN);
      if (r > 0)
        left -= r;
      if (left == 0)
        break;
      cb.reset();
      ASSERT_EQ(cb.poll(500), true);
    }
    if (first) {
      first = false;
      goto again;
    }
    while (!done)
      usleep(100);
    center->delete_file_event(cli_fd, EVENT_WRITABLE);
    usleep(100);
  }, center, std::ref(cli_socket), std::ref(message), std::ref(lock), std::ref(done));

  char buf[1000];
  C_poll cb(center, &lock);
  center->create_file_event(srv_socket.fd(), EVENT_READABLE, &cb);
  string read_string;
  len *= 2;
  while (len > 0) {
    lock.Lock();
    r = srv_socket.read(buf, sizeof(buf));
    lock.Unlock();
    ASSERT_TRUE(r > 0 || r == -EAGAIN);
    if (r > 0) {
      read_string.append(buf, r);
      len -= r;
    }
    if (r == -EAGAIN) {
      ASSERT_EQ(cb.poll(500), true);
      cb.reset();
    }
  }
  center->delete_file_event(srv_socket.fd(), EVENT_READABLE);
  done = true;
  t.join();
  for (size_t i = 0; i < read_string.size(); i += message_size)
    ASSERT_EQ(memcmp(read_string.c_str()+i, message.c_str(), message_size), 0);

  center->delete_file_event(bind_socket.fd(), EVENT_READABLE);
  bind_socket.abort_accept();
  srv_socket.close();
  cli_socket.close();
}

class StressFactory {
  struct RandomString {
    size_t slen;
    vector<std::string> strs;
    std::random_device rd;
    std::default_random_engine rng;

    RandomString(size_t s): slen(s), rng(rd()) {}
    void prepare(size_t n) {
      static const char alphabet[] =
          "abcdefghijklmnopqrstuvwxyz"
          "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
          "0123456789";

      std::uniform_int_distribution<> dist(
              0, sizeof(alphabet) / sizeof(*alphabet) - 2);

      strs.reserve(n);
      std::generate_n(
        std::back_inserter(strs), strs.capacity(), [&] {
          std::string str;
          str.reserve(slen);
          std::generate_n(std::back_inserter(str), slen, [&]() {
            return alphabet[dist(rng)];
          });
         return str;
        }
      );
    }
    std::string &get_random_string() {
      std::uniform_int_distribution<> dist(
              0, strs.size() - 1);
      return strs[dist(rng)];
    }
  };
  struct Message {
    size_t idx;
    size_t len;
    std::string content;

    explicit Message(RandomString &rs, size_t i, size_t l): idx(i) {
      size_t slen = rs.slen;
      len = std::max(slen, l);

      std::vector<std::string> strs;
      strs.reserve(len / slen);
      std::generate_n(
        std::back_inserter(strs), strs.capacity(), [&] {
          return rs.get_random_string();
        }
      );
      len = slen * strs.size();
      content.reserve(len);
      for (auto &&s : strs)
        content.append(s);
    }
    bool verify(const char *b, size_t len = 0) const {
      return content.compare(0, len, b, 0, len) == 0;
    }
  };

  template <typename T>
  class C_delete : public EventCallback {
    T *ctxt;
   public:
    C_delete(T *c): ctxt(c) {}
    void do_request(int id) {
      delete ctxt;
      delete this;
    }
  };

  class Client {
    StressFactory *factory;
    ConnectedSocket socket;
    std::deque<StressFactory::Message*> acking;
    std::deque<StressFactory::Message*> writings;
    std::string buffer;
    bufferlist buf_bl;
    size_t index = 0;
    size_t left;
    bool write_enabled = false;
    size_t read_offset = 0, write_offset = 0;
    bool first = true;
    bool dead = false;
    StressFactory::Message homeless_message;

    class Client_read_handle : public EventCallback {
      Client *c;
     public:
      Client_read_handle(Client *_c): c(_c) {}
      void do_request(int id) {
        c->do_read_request();
      }
    } read_ctxt;

    class Client_write_handle : public EventCallback {
      Client *c;
     public:
      Client_write_handle(Client *_c): c(_c) {}
      void do_request(int id) {
        c->do_write_request();
      }
    } write_ctxt;

   public:
    Client(StressFactory *f, ConnectedSocket s, size_t c)
        : factory(f), socket(std::move(s)), left(c), homeless_message(factory->rs, -1, 1024),
          read_ctxt(this), write_ctxt(this) {
      factory->center->create_file_event(
              socket.fd(), EVENT_READABLE, &read_ctxt);
      factory->center->dispatch_event_external(&read_ctxt);
    }
    void close() {
      ASSERT_FALSE(write_enabled);
      dead = true;
      socket.shutdown();
      factory->center->delete_file_event(socket.fd(), EVENT_READABLE);
      factory->center->dispatch_event_external(new C_delete<Client>(this));
    }

    void do_read_request() {
      if (dead)
        return ;
      ASSERT_TRUE(socket.is_connected() >= 0);
      if (!socket.is_connected())
        return ;
      ASSERT_TRUE(!acking.empty() || first);
      if (first) {
        first = false;
        factory->center->dispatch_event_external(&write_ctxt);
        if (acking.empty())
          return ;
      }
      StressFactory::Message *m = acking.front();
      int r = 0;
      if (buffer.empty())
        buffer.resize(m->len);
      bool must_no = false;
      while (true) {
        if (factory->zero_copy_read) {
          r = socket.zero_copy_read(m->len - read_offset, buf_bl);
        } else {
          r = socket.read((char*)buffer.data() + read_offset,
                          m->len - read_offset);
        }

        ASSERT_TRUE(r == -EAGAIN || r > 0);
        if (r == -EAGAIN)
          break;
        std::cerr << " client " << this << " receive " << m->idx << " len " << r << " content: "  << std::endl;
        ASSERT_FALSE(must_no);
        read_offset += r;
        if ((m->len - read_offset) == 0) {
          if (factory->zero_copy_read)
            ASSERT_TRUE(m->verify(buf_bl.c_str(), 0));
          else
            ASSERT_TRUE(m->verify(buffer.data(), 0));
          delete m;
          acking.pop_front();
          read_offset = 0;
          buffer.clear();
          buf_bl.clear();
          if (acking.empty()) {
            m = &homeless_message;
            must_no = true;
          } else {
            m = acking.front();
            buffer.resize(m->len);
          }
        }
      }
      if (acking.empty()) {
        factory->center->dispatch_event_external(&write_ctxt);
        return ;
      }
    }

    void do_write_request() {
      if (dead)
        return ;
      ASSERT_TRUE(socket.is_connected() > 0);

      while (left > 0 && factory->queue_depth > writings.size() + acking.size()) {
        StressFactory::Message *m = new StressFactory::Message(
                factory->rs, ++index,
                factory->rd() % factory->max_message_length);
        std::cerr << " client " << this << " generate message " << m->idx << " length " << m->len << std::endl;
        ASSERT_EQ(m->len, m->content.size());
        writings.push_back(m);
        --left;
        --factory->message_left;
      }

      while (!writings.empty()) {
        StressFactory::Message *m = writings.front();
        bufferlist bl;
        bl.append(m->content.data() + write_offset, m->content.size() - write_offset);
        ssize_t r = socket.send(bl, false);
        if (r == -EAGAIN)
          break;
        std::cerr << " client " << this << " send " << m->idx << " len " << r << " content: " << std::endl;
        ASSERT_TRUE(r >= 0);
        write_offset += r;
        if (write_offset == m->content.size()) {
          write_offset = 0;
          writings.pop_front();
          acking.push_back(m);
        }
      }
      if (writings.empty() && write_enabled) {
        factory->center->delete_file_event(socket.fd(), EVENT_WRITABLE);
        write_enabled = false;
      } else if (!writings.empty() && !write_enabled) {
        ASSERT_EQ(factory->center->create_file_event(
                  socket.fd(), EVENT_WRITABLE, &write_ctxt), 0);
        write_enabled = true;
      }
    }

    bool finish() const {
      return left == 0 && acking.empty() && writings.empty();
    }
  };
  friend class Client;

  class Server {
    StressFactory *factory;
    ConnectedSocket socket;
    std::deque<std::string> buffers;
    bool write_enabled = false;
    bool dead = false;

    class Server_read_handle : public EventCallback {
      Server *s;
     public:
      Server_read_handle(Server *_s): s(_s) {}
      void do_request(int id) {
        s->do_read_request();
      }
    } read_ctxt;

    class Server_write_handle : public EventCallback {
      Server *s;
     public:
      Server_write_handle(Server *_s): s(_s) {}
      void do_request(int id) {
        s->do_write_request();
      }
    } write_ctxt;

   public:
    Server(StressFactory *f, ConnectedSocket s):
        factory(f), socket(std::move(s)), read_ctxt(this), write_ctxt(this) {
      factory->center->create_file_event(socket.fd(), EVENT_READABLE, &read_ctxt);
      factory->center->dispatch_event_external(&read_ctxt);
    }
    void close() {
      ASSERT_FALSE(write_enabled);
      socket.shutdown();
      factory->center->delete_file_event(socket.fd(), EVENT_READABLE);
      factory->center->dispatch_event_external(new C_delete<Server>(this));
    }
    void do_read_request() {
      if (dead)
        return ;
      int r = 0;
      while (true) {
        char buf[4096];
        bufferlist data;
        if (factory->zero_copy_read) {
          r = socket.zero_copy_read(sizeof(buf), data);
        } else {
          r = socket.read(buf, sizeof(buf));
        }
        ASSERT_TRUE(r == -EAGAIN || (r >= 0 && (size_t)r <= sizeof(buf)));
        if (r == 0) {
          ASSERT_TRUE(buffers.empty());
          dead = true;
          return ;
        } else if (r == -EAGAIN)
          break;
        if (factory->zero_copy_read) {
          buffers.emplace_back(data.c_str(), 0, r);
        } else {
          buffers.emplace_back(buf, 0, r);
        }
        std::cerr << " server " << this << " receive " << r << " content: " << std::endl;
      }
      if (!buffers.empty() && !write_enabled)
        factory->center->dispatch_event_external(&write_ctxt);
    }

    void do_write_request() {
      if (dead)
        return ;

      ASSERT_TRUE(!buffers.empty());
      while (!buffers.empty()) {
        bufferlist bl;
        auto it = buffers.begin();
        for (size_t i = 0; i < buffers.size(); ++i) {
          bl.push_back(bufferptr((char*)it->data(), it->size()));
          ++it;
        }

        ssize_t r = socket.send(bl, false);
        std::cerr << " server " << this << " send " << r << std::endl;
        if (r == -EAGAIN)
          break;
        ASSERT_TRUE(r >= 0);
        while (r > 0) {
          ASSERT_TRUE(!buffers.empty());
          string &buffer = buffers.front();
          if (r >= (int)buffer.size()) {
            r -= (int)buffer.size();
            buffers.pop_front();
          } else {
           std::cerr << " server " << this << " sent " << r << std::endl;
            buffer = buffer.substr(r, buffer.size());
            break;
          }
        }
      }
      if (buffers.empty()) {
        if (write_enabled) {
          factory->center->delete_file_event(socket.fd(), EVENT_WRITABLE);
          write_enabled = false;
        }
      } else if (!write_enabled) {
        ASSERT_EQ(factory->center->create_file_event(
                  socket.fd(), EVENT_WRITABLE, &write_ctxt), 0);
        write_enabled = true;
      }
    }

    bool finish() {
     return dead;
    }
  };
  friend class Server;

  class C_accept : public EventCallback {
    StressFactory *factory;
    ServerSocket bind_socket;

   public:
    C_accept(StressFactory *f, ServerSocket s)
        : factory(f), bind_socket(std::move(s)) {}
    void do_request(int id) {
      while (true) {
        entity_addr_t cli_addr;
        ConnectedSocket srv_socket;
        int r = bind_socket.accept(&srv_socket, &cli_addr);
        if (r == -EAGAIN) {
          break;
        }
        ASSERT_EQ(r, 0);
        ASSERT_TRUE(srv_socket.fd() > 0);
        Server *cb = new Server(factory, std::move(srv_socket));
        factory->servers.insert(cb);
      }
    }
  };
  friend class C_accept;

  static const size_t min_client_send_messages = 100;
  static const size_t max_client_send_messages = 1000;
  NetworkStack *stack;
  EventCenter *center;
  RandomString rs;
  std::random_device rd;
  const size_t client_num, queue_depth, max_message_length;
  size_t message_count, message_left;
  entity_addr_t bind_addr;
  std::set<Client*> clients;
  std::set<Server*> servers;
  SocketOptions options;
  bool zero_copy_read;

 public:
  explicit StressFactory(NetworkStack *_stack, EventCenter *c,
                         const string &addr,
                         size_t cli, size_t qd, size_t mc, size_t l)
      : stack(_stack), center(c), rs(128), client_num(cli), queue_depth(qd),
        max_message_length(l), message_count(mc), message_left(mc),
        zero_copy_read(stack->support_zero_copy_read()) {
    bind_addr.parse(addr.c_str());
    rs.prepare(100);
  }
  ~StressFactory() {
    for (auto && i : clients)
      delete i;
    for (auto && i : servers)
      delete i;
  }

  void add_client() {
    ConnectedSocket sock;
    int r = stack->connect(bind_addr, options, &sock);
    std::default_random_engine rng(rd());
    std::uniform_int_distribution<> dist(
            min_client_send_messages, max_client_send_messages);
    ASSERT_EQ(r, 0);
    size_t c = dist(rng);
    c = std::min(c, message_count);
    Client *cb = new Client(this, std::move(sock), c);
    clients.insert(cb);
    message_count -= c;
  }

  void drop_client(Client *c) {
    c->close();
    ASSERT_EQ(clients.erase(c), 1U);
  }

  void drop_server(Server *s) {
    s->close();
    ASSERT_EQ(servers.erase(s), 1U);
  }

  void start() {
    ServerSocket bind_socket;
    int r = stack->listen(bind_addr, options, &bind_socket);
    ASSERT_EQ(r, 0);
    auto bind_fd = bind_socket.fd();
    C_accept accept_handler(this, std::move(bind_socket));
    ASSERT_EQ(center->create_file_event(
                bind_fd, EVENT_READABLE, &accept_handler), 0);

    size_t echo_throttle = message_count;
    while (message_count > 0 || !clients.empty() || !servers.empty()) {
      if (message_count > 0  && clients.size() < client_num && servers.size() < client_num)
        add_client();
      for (auto &&c : clients) {
        if (c->finish()) {
          drop_client(c);
          break;
        }
      }
      for (auto &&s : servers) {
        if (s->finish()) {
          drop_server(s);
          break;
        }
      }

      center->process_events(1);
      if (echo_throttle > message_left) {
        std::cerr << " clients " << clients.size() << " servers " << servers.size()
                  << " message count " << message_left << std::endl;
        echo_throttle -= 100;
      }
    }
    center->delete_file_event(bind_fd, EVENT_READABLE);
    ASSERT_EQ(message_left, 0U);
    while (center->exist_pending_event())
      center->process_events(0);
  }
};

TEST_P(TransportTest, StressTest) {
  StressFactory factory(get_transport(0), get_center(0), get_addr(),
                        16, 16, 10000, 1024);
  factory.start();
}


INSTANTIATE_TEST_CASE_P(
  NetworkStack,
  TransportTest,
  ::testing::Values(
#ifdef HAVE_DPDK
    "dpdk",
#endif
    "posix"
  )
);

#else

// Google Test may not support value-parameterized tests with some
// compilers. If we use conditional compilation to compile out all
// code referring to the gtest_main library, MSVC linker will not link
// that library at all and consequently complain about missing entry
// point defined in that library (fatal error LNK1561: entry point
// must be defined). This dummy test keeps gtest_main linked in.
TEST(DummyTest, ValueParameterizedTestsAreNotSupportedOnThisPlatform) {}

#endif


int main(int argc, char **argv) {
  vector<const char*> args;
  argv_to_vec(argc, (const char **)argv, args);

  global_init(NULL, args, CEPH_ENTITY_TYPE_CLIENT, CODE_ENVIRONMENT_UTILITY, 0);
  common_init_finish(g_ceph_context);

  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}

/*
 * Local Variables:
 * compile-command: "cd ../.. ; make ceph_test_async_transport &&
 *    ./ceph_test_async_transport
 *
 * End:
 */
