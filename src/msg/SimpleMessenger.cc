// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*- 
// vim: ts=8 sw=2 smarttab
/*
 * Ceph - scalable distributed file system
 *
 * Copyright (C) 2004-2006 Sage Weil <sage@newdream.net>
 *
 * This is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2.1, as published by the Free Software 
 * Foundation.  See file COPYING.
 * 
 */

#include <errno.h>
#include <iostream>
#include <fstream>


#include "SimpleMessenger.h"

#include "common/config.h"
#include "common/Timer.h"
#include "common/errno.h"

#define dout_subsys ceph_subsys_ms
#undef dout_prefix
#define dout_prefix _prefix(_dout, msgr)
static ostream& _prefix(std::ostream *_dout, SimpleMessenger *msgr) {
  return *_dout << "-- " << msgr->get_myaddr() << " ";
}


/*******************
 * SimpleMessenger
 */

SimpleMessenger::SimpleMessenger(CephContext *cct, entity_name_t name,
				 string mname, uint64_t _nonce)
  : Messenger(cct, name),
    accepter(this),
    dispatch_queue(cct, this),
    reaper_thread(this),
    my_type(name.type()),
    nonce(_nonce),
    lock("SimpleMessenger::lock"), need_addr(true), did_bind(false),
    global_seq(0),
    cluster_protocol(0),
    dispatch_throttler(cct, string("msgr_dispatch_throttler-") + mname, cct->_conf->ms_dispatch_throttle_bytes),
    reaper_started(false), reaper_stop(false),
    timeout(0),
    local_connection(new Connection),
    msgr(this)
{
  pthread_spin_init(&global_seq_lock, PTHREAD_PROCESS_PRIVATE);
  init_local_connection();
}

/**
 * Destroy the SimpleMessenger. Pretty simple since all the work is done
 * elsewhere.
 */
SimpleMessenger::~SimpleMessenger()
{
  assert(!did_bind); // either we didn't bind or we shut down the Accepter
  assert(rank_pipe.empty()); // we don't have any running Pipes.
  assert(reaper_stop && !reaper_started); // the reaper thread is stopped
}

void SimpleMessenger::ready()
{
  ldout(cct,10) << "ready " << get_myaddr() << dendl;
  dispatch_queue.start();
}


int SimpleMessenger::shutdown()
{
  ldout(cct,10) << "shutdown " << get_myaddr() << dendl;
  dispatch_queue.shutdown();
  mark_down_all();
  return 0;
}

int SimpleMessenger::_send_message(Message *m, const entity_inst_t& dest,
                                   bool lazy)
{
  // set envelope
  m->get_header().src = get_myname();

  if (!m->get_priority()) m->set_priority(get_default_send_priority());
 
  ldout(cct,1) << (lazy ? "lazy " : "") <<"--> " << dest.name << " "
          << dest.addr << " -- " << *m
    	  << " -- ?+" << m->get_data().length()
	  << " " << m 
	  << dendl;

  if (dest.addr == entity_addr_t()) {
    ldout(cct,0) << (lazy ? "lazy_" : "") << "send_message message " << *m
                 << " with empty dest " << dest.addr << dendl;
    m->put();
    return -EINVAL;
  }

  lock.Lock();
  Pipe *pipe = rank_pipe.count(dest.addr) ? rank_pipe[ dest.addr ] : NULL;
  submit_message(m, (pipe ? pipe->connection_state : NULL),
                 dest.addr, dest.name.type(), lazy);
  lock.Unlock();
  return 0;
}

int SimpleMessenger::_send_message(Message *m, Connection *con, bool lazy)
{
  //set envelope
  m->get_header().src = get_myname();

  if (!m->get_priority()) m->set_priority(get_default_send_priority());

  ldout(cct,1) << (lazy ? "lazy " : "") << "--> " << con->get_peer_addr()
      << " -- " << *m
      << " -- ?+" << m->get_data().length()
      << " " << m << " con " << con
      << dendl;

  lock.Lock();
  submit_message(m, con, con->get_peer_addr(), con->get_peer_type(), lazy);
  lock.Unlock();
  return 0;
}

/**
 * If my_inst.addr doesn't have an IP set, this function
 * will fill it in from the passed addr. Otherwise it does nothing and returns.
 */
void SimpleMessenger::set_addr_unknowns(entity_addr_t &addr)
{
  if (my_inst.addr.is_blank_ip()) {
    int port = my_inst.addr.get_port();
    my_inst.addr.addr = addr.addr;
    my_inst.addr.set_port(port);
  }
}

int SimpleMessenger::get_proto_version(int peer_type, bool connect)
{
  // set reply protocol version
  if (peer_type == my_type) {
    // internal
    return cluster_protocol;
  } else {
    // public
    if (connect) {
      switch (peer_type) {
      case CEPH_ENTITY_TYPE_OSD: return CEPH_OSDC_PROTOCOL;
      case CEPH_ENTITY_TYPE_MDS: return CEPH_MDSC_PROTOCOL;
      case CEPH_ENTITY_TYPE_MON: return CEPH_MONC_PROTOCOL;
      }
    } else {
      switch (my_type) {
      case CEPH_ENTITY_TYPE_OSD: return CEPH_OSDC_PROTOCOL;
      case CEPH_ENTITY_TYPE_MDS: return CEPH_MDSC_PROTOCOL;
      case CEPH_ENTITY_TYPE_MON: return CEPH_MONC_PROTOCOL;
      }
    }
  }
  return 0;
}







/********************************************
 * SimpleMessenger
 */
#undef dout_prefix
#define dout_prefix _prefix(_dout, this)

void SimpleMessenger::dispatch_throttle_release(uint64_t msize)
{
  if (msize) {
    ldout(cct,10) << "dispatch_throttle_release " << msize << " to dispatch throttler "
	    << msgr->dispatch_throttler.get_current() << "/"
	    << msgr->dispatch_throttler.get_max() << dendl;
    dispatch_throttler.put(msize);
  }
}

void SimpleMessenger::reaper_entry()
{
  ldout(cct,10) << "reaper_entry start" << dendl;
  lock.Lock();
  while (!reaper_stop) {
    reaper();
    reaper_cond.Wait(lock);
  }
  lock.Unlock();
  ldout(cct,10) << "reaper_entry done" << dendl;
}

/*
 * note: assumes lock is held
 */
void SimpleMessenger::reaper()
{
  ldout(cct,10) << "reaper" << dendl;
  assert(lock.is_locked());

  while (!pipe_reap_queue.empty()) {
    Pipe *p = pipe_reap_queue.front();
    pipe_reap_queue.pop_front();
    ldout(cct,10) << "reaper reaping pipe " << p << " " << p->get_peer_addr() << dendl;
    p->pipe_lock.Lock();
    p->discard_queue();
    p->pipe_lock.Unlock();
    p->unregister_pipe();
    assert(pipes.count(p));
    pipes.erase(p);
    p->join();
    if (p->sd >= 0)
      ::close(p->sd);
    ldout(cct,10) << "reaper reaped pipe " << p << " " << p->get_peer_addr() << dendl;
    if (p->connection_state)
      p->connection_state->clear_pipe(p);
    p->put();
    ldout(cct,10) << "reaper deleted pipe " << p << dendl;
  }
  ldout(cct,10) << "reaper done" << dendl;
}

void SimpleMessenger::queue_reap(Pipe *pipe)
{
  ldout(cct,10) << "queue_reap " << pipe << dendl;
  lock.Lock();
  pipe_reap_queue.push_back(pipe);
  reaper_cond.Signal();
  lock.Unlock();
}



int SimpleMessenger::bind(entity_addr_t bind_addr)
{
  lock.Lock();
  if (started) {
    ldout(cct,10) << "rank.bind already started" << dendl;
    lock.Unlock();
    return -1;
  }
  ldout(cct,10) << "rank.bind " << bind_addr << dendl;
  lock.Unlock();

  // bind to a socket
  int r = accepter.bind(bind_addr);
  if (r >= 0)
    msgr->did_bind = true;
  return r;
}

int SimpleMessenger::rebind(int avoid_port)
{
  ldout(cct,1) << "rebind avoid " << avoid_port << dendl;
  mark_down_all();
  assert(did_bind);
  return accepter.rebind(avoid_port);
}

int SimpleMessenger::start()
{
  lock.Lock();
  ldout(cct,1) << "messenger.start" << dendl;

  // register at least one entity, first!
  assert(my_type >= 0);

  assert(!started);
  started = true;

  if (!did_bind)
    my_inst.addr.nonce = nonce;

  lock.Unlock();

  if (did_bind)
    accepter.start();

  reaper_started = true;
  reaper_thread.create();
  return 0;
}

Pipe *SimpleMessenger::add_accept_pipe(int sd)
{
  lock.Lock();
  Pipe *p = new Pipe(this, Pipe::STATE_ACCEPTING, NULL);
  p->sd = sd;
  p->pipe_lock.Lock();
  p->start_reader();
  p->pipe_lock.Unlock();
  msgr->pipes.insert(p);
  lock.Unlock();
  return p;
}

/* connect_rank
 * NOTE: assumes messenger.lock held.
 */
Pipe *SimpleMessenger::connect_rank(const entity_addr_t& addr,
				    int type,
				    Connection *con)
{
  assert(lock.is_locked());
  assert(addr != my_inst.addr);
  
  ldout(cct,10) << "connect_rank to " << addr << ", creating pipe and registering" << dendl;
  
  // create pipe
  Pipe *pipe = new Pipe(this, Pipe::STATE_CONNECTING, con);
  pipe->pipe_lock.Lock();
  pipe->set_peer_type(type);
  pipe->set_peer_addr(addr);
  pipe->policy = get_policy(type);
  pipe->start_writer();
  pipe->pipe_lock.Unlock();
  pipe->register_pipe();
  pipes.insert(pipe);

  return pipe;
}






AuthAuthorizer *SimpleMessenger::get_authorizer(int peer_type, bool force_new)
{
  return ms_deliver_get_authorizer(peer_type, force_new);
}

bool SimpleMessenger::verify_authorizer(Connection *con, int peer_type,
					int protocol, bufferlist& authorizer, bufferlist& authorizer_reply,
					bool& isvalid)
{
  return ms_deliver_verify_authorizer(con, peer_type, protocol, authorizer, authorizer_reply, isvalid);
}

Connection *SimpleMessenger::get_connection(const entity_inst_t& dest)
{
  Mutex::Locker l(lock);
  if (my_inst.addr == dest.addr) {
    // local
    return (Connection *)local_connection->get();
  } else {
    // remote
    Pipe *pipe = NULL;
    hash_map<entity_addr_t, Pipe*>::iterator p = rank_pipe.find(dest.addr);
    if (p != rank_pipe.end()) {
      pipe = p->second;
      pipe->pipe_lock.Lock();
      if (pipe->state == Pipe::STATE_CLOSED) {
	pipe->unregister_pipe();
	pipe->pipe_lock.Unlock();
	pipe = 0;
      } else {
	pipe->pipe_lock.Unlock();
      }
    }
    if (!pipe) {
      pipe = connect_rank(dest.addr, dest.name.type(), NULL);
    }
    return (Connection *)pipe->connection_state->get();
  }
}


void SimpleMessenger::submit_message(Message *m, Connection *con, const entity_addr_t& dest_addr, int dest_type, bool lazy)
{
  Pipe *pipe = NULL;
  if (con) {
    pipe = con ? (Pipe *)con->pipe : NULL;
    // we don't want to deal with ref-counting here, so we don't use get_pipe()
    con->get();
  }

  // local?
  if (!pipe && my_inst.addr == dest_addr) {
    // local
    ldout(cct,20) << "submit_message " << *m << " local" << dendl;
    dispatch_queue.local_delivery(m, m->get_priority());
  } else {
    // remote pipe.
    if (pipe) {
      pipe->pipe_lock.Lock();
      if (pipe->state == Pipe::STATE_CLOSED) {
        ldout(cct,0) << "submit_message " << *m << " remote, " << dest_addr << ", ignoring closed pipe, dropping message " << m << dendl;
        pipe->unregister_pipe();
        pipe->pipe_lock.Unlock();
        pipe = 0;
	assert(con);
	con->put();
	return;
      } else {
        ldout(cct,20) << "submit_message " << *m << " remote, " << dest_addr << ", have pipe." << dendl;

        pipe->_send(m);
        pipe->pipe_lock.Unlock();
      }
    }
    if (!pipe) {
      const Policy& policy = get_policy(dest_type);
      if (policy.server) {
        ldout(cct,20) << "submit_message " << *m << " remote, " << dest_addr << ", lossy server for target type "
            << ceph_entity_type_name(dest_type) << ", no session, dropping." << dendl;
        m->put();
      } else if (lazy) {
        ldout(cct,20) << "submit_message " << *m << " remote, " << dest_addr << ", lazy, dropping." << dendl;
        m->put();
      } else {
        ldout(cct,20) << "submit_message " << *m << " remote, " << dest_addr << ", new pipe." << dendl;
        // not connected.
        pipe = connect_rank(dest_addr, dest_type, con);
        pipe->send(m);
      }
    }
  }
  if (con) {
    con->put();
  }
}

int SimpleMessenger::send_keepalive(const entity_inst_t& dest)
{
  const entity_addr_t dest_addr = dest.addr;
  entity_addr_t dest_proc_addr = dest_addr;
  int ret = 0;

  lock.Lock();
  {
    // local?
    if (my_inst.addr != dest_addr) {
      // remote.
      Pipe *pipe = 0;
      if (rank_pipe.count( dest_proc_addr )) {
        // connected?
        pipe = rank_pipe[ dest_proc_addr ];
	pipe->pipe_lock.Lock();
	if (pipe->state == Pipe::STATE_CLOSED) {
	  ldout(cct,20) << "send_keepalive remote, " << dest_addr << ", ignoring old closed pipe." << dendl;
	  pipe->unregister_pipe();
	  pipe->pipe_lock.Unlock();
	  pipe = 0;
	  ret = -EPIPE;
	} else {
	  ldout(cct,20) << "send_keepalive remote, " << dest_addr << ", have pipe." << dendl;
	  pipe->_send_keepalive();
	  pipe->pipe_lock.Unlock();
	}
      } else {
        ret = -EINVAL;
      }
      if (!pipe) {
	ldout(cct,20) << "send_keepalive no pipe for " << dest_addr << ", doing nothing." << dendl;
      }
    }
  }
  lock.Unlock();
  return ret;
}

int SimpleMessenger::send_keepalive(Connection *con)
{
  int ret = 0;
  Pipe *pipe = (Pipe *)con->get_pipe();
  if (pipe) {
    ldout(cct,20) << "send_keepalive con " << con << ", have pipe." << dendl;
    assert(pipe->msgr == this);
    pipe->pipe_lock.Lock();
    pipe->_send_keepalive();
    pipe->pipe_lock.Unlock();
    pipe->put();
  } else {
    ldout(cct,0) << "send_keepalive con " << con << ", no pipe." << dendl;
    ret = -EPIPE;
  }
  return ret;
}



void SimpleMessenger::wait()
{
  lock.Lock();
  if (!started) {
    lock.Unlock();
    return;
  }
  lock.Unlock();

  ldout(cct,10) << "wait: waiting for dispatch queue" << dendl;
  dispatch_queue.wait();
  ldout(cct,10) << "wait: dispatch queue is stopped" << dendl;
  
  // done!  clean up.
  if (did_bind) {
    ldout(cct,20) << "wait: stopping accepter thread" << dendl;
    accepter.stop();
    did_bind = false;
    ldout(cct,20) << "wait: stopped accepter thread" << dendl;
  }

  if (reaper_started) {
    ldout(cct,20) << "wait: stopping reaper thread" << dendl;
    lock.Lock();
    reaper_cond.Signal();
    reaper_stop = true;
    lock.Unlock();
    reaper_thread.join();
    reaper_started = false;
    ldout(cct,20) << "wait: stopped reaper thread" << dendl;
  }

  // close+reap all pipes
  lock.Lock();
  {
    ldout(cct,10) << "wait: closing pipes" << dendl;

    while (!rank_pipe.empty()) {
      Pipe *p = rank_pipe.begin()->second;
      p->unregister_pipe();
      p->pipe_lock.Lock();
      p->stop();
      p->pipe_lock.Unlock();
    }

    reaper();
    ldout(cct,10) << "wait: waiting for pipes " << pipes << " to close" << dendl;
    while (!pipes.empty()) {
      reaper_cond.Wait(lock);
      reaper();
    }

    dispatch_queue.local_queue.discard_queue();
  }
  lock.Unlock();

  ldout(cct,10) << "wait: done." << dendl;
  ldout(cct,1) << "shutdown complete." << dendl;
  started = false;
  my_type = -1;
}


void SimpleMessenger::mark_down_all()
{
  ldout(cct,1) << "mark_down_all" << dendl;
  lock.Lock();
  while (!rank_pipe.empty()) {
    hash_map<entity_addr_t,Pipe*>::iterator it = rank_pipe.begin();
    Pipe *p = it->second;
    ldout(cct,5) << "mark_down_all " << it->first << " " << p << dendl;
    rank_pipe.erase(it);
    p->unregister_pipe();
    p->pipe_lock.Lock();
    p->stop();
    p->pipe_lock.Unlock();
  }
  lock.Unlock();
}

void SimpleMessenger::mark_down(const entity_addr_t& addr)
{
  lock.Lock();
  if (rank_pipe.count(addr)) {
    Pipe *p = rank_pipe[addr];
    ldout(cct,1) << "mark_down " << addr << " -- " << p << dendl;
    p->unregister_pipe();
    p->pipe_lock.Lock();
    p->stop();
    p->pipe_lock.Unlock();
  } else {
    ldout(cct,1) << "mark_down " << addr << " -- pipe dne" << dendl;
  }
  lock.Unlock();
}

void SimpleMessenger::mark_down(Connection *con)
{
  lock.Lock();
  Pipe *p = (Pipe *)con->get_pipe();
  if (p) {
    ldout(cct,1) << "mark_down " << con << " -- " << p << dendl;
    assert(p->msgr == this);
    p->unregister_pipe();
    p->pipe_lock.Lock();
    p->stop();
    p->pipe_lock.Unlock();
    p->put();
  } else {
    ldout(cct,1) << "mark_down " << con << " -- pipe dne" << dendl;
  }
  lock.Unlock();
}

void SimpleMessenger::mark_down_on_empty(Connection *con)
{
  lock.Lock();
  Pipe *p = (Pipe *)con->get_pipe();
  if (p) {
    assert(p->msgr == this);
    p->pipe_lock.Lock();
    p->unregister_pipe();
    if (p->out_q.empty()) {
      ldout(cct,1) << "mark_down_on_empty " << con << " -- " << p << " closing (queue is empty)" << dendl;
      p->stop();
    } else {
      ldout(cct,1) << "mark_down_on_empty " << con << " -- " << p << " marking (queue is not empty)" << dendl;
      p->close_on_empty = true;
    }
    p->pipe_lock.Unlock();
    p->put();
  } else {
    ldout(cct,1) << "mark_down_on_empty " << con << " -- pipe dne" << dendl;
  }
  lock.Unlock();
}

void SimpleMessenger::mark_disposable(Connection *con)
{
  lock.Lock();
  Pipe *p = (Pipe *)con->get_pipe();
  if (p) {
    ldout(cct,1) << "mark_disposable " << con << " -- " << p << dendl;
    assert(p->msgr == this);
    p->pipe_lock.Lock();
    p->policy.lossy = true;
    p->pipe_lock.Unlock();
    p->put();
  } else {
    ldout(cct,1) << "mark_disposable " << con << " -- pipe dne" << dendl;
  }
  lock.Unlock();
}

void SimpleMessenger::learned_addr(const entity_addr_t &peer_addr_for_me)
{
  // be careful here: multiple threads may block here, and readers of
  // my_inst.addr do NOT hold any lock.
  lock.Lock();
  if (need_addr) {
    entity_addr_t t = peer_addr_for_me;
    t.set_port(my_inst.addr.get_port());
    my_inst.addr.addr = t.addr;
    ldout(cct,1) << "learned my addr " << my_inst.addr << dendl;
    need_addr = false;
    init_local_connection();
  }
  lock.Unlock();
}

void SimpleMessenger::init_local_connection()
{
  local_connection->peer_addr = msgr->my_inst.addr;
  local_connection->peer_type = msgr->my_type;
}
