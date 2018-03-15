// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab
/*
 * Ceph - scalable distributed file system
 *
 * Copyright (C) 2018 Red Hat, Inc.
 *
 * This is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2.1, as published by the Free Software
 * Foundation. See file COPYING.
 *
 */

#ifndef RGW_DMCLOCK_QUEUE_H
#define RGW_DMCLOCK_QUEUE_H

#include <boost/asio.hpp>
#include "common/ceph_time.h"
#include "common/async/completion.h"
#include "rgw_dmclock.h"

namespace rgw::dmclock {

namespace async = ceph::async;

/// A dmclock request scheduling service for use with boost::asio.
class PriorityQueue {
 public:
  template <typename ...Args> // args forwarded to PullPriorityQueue ctor
  PriorityQueue(boost::asio::io_context& context, Args&& ...args)
    : queue(std::forward<Args>(args)...),
      timer(context)
  {}

  ~PriorityQueue() {
    cancel();
  }

  using executor_type = boost::asio::io_context::executor_type;

  /// return the default executor for async_request() callbacks
  executor_type get_executor() noexcept {
    return timer.get_executor();
  }

  /// submit an async request for dmclock scheduling. the given completion
  /// handler will be invoked with (error_code, PhaseType) when the request
  /// is ready or canceled
  template <typename CompletionToken>
  auto async_request(const client_id& client, const ReqParams& params,
                     const Time& time, Cost cost, CompletionToken&& token);

  /// cancel all queued requests, invoking their completion handlers with an
  /// operation_aborted error and default-constructed result
  void cancel();

  /// cancel all queued requests for a given client, invoking their completion
  /// handler with an operation_aborted error and default-constructed result
  void cancel(const client_id& client);

 private:
  struct Request {}; // empty request type
  using Queue = crimson::dmclock::PullPriorityQueue<client_id, Request>;
  using RequestRef = typename Queue::RequestRef;
  Queue queue; //< dmclock priority queue

  using Signature = void(boost::system::error_code, PhaseType);
  using Completion = async::Completion<Signature, async::AsBase<Request>>;

  using Clock = ceph::coarse_real_clock;
  using Timer = boost::asio::basic_waitable_timer<Clock>;
  Timer timer; //< timer for the next scheduled request

  /// set a timer to process the next request
  void schedule(const Time& time);

  /// process ready requests, then schedule the next pending request
  void process(const Time& now);
};

template <typename CompletionToken>
auto PriorityQueue::async_request(const client_id& client,
                                  const ReqParams& params,
                                  const Time& time, double cost,
                                  CompletionToken&& token)
{
  boost::asio::async_completion<CompletionToken, Signature> init(token);

  auto ex1 = get_executor();
  auto& handler = init.completion_handler;

  // allocate the request and add it to the queue
  auto req = Completion::create(ex1, std::move(handler));
  queue.add_request(std::move(req), client, params, time, cost);

  // schedule an immediate call to process() on the executor
  schedule(crimson::dmclock::TimeZero);

  return init.result.get();
}

} // namespace rgw::dmclock

#endif // RGW_DMCLOCK_QUEUE_H
