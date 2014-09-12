// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*- 
// vim: ts=8 sw=2 smarttab
#ifndef CEPH_MSG_EVENTEPOLL_H
#define CEPH_MSG_EVENTEPOLL_H

#include <unistd.h>
#include <sys/epoll.h>

#include "Event.h"

class EpollDriver : public EventDriver {
  int epfd;
  // map "fd" to the pos of "events"
  map<int, int> fds;
  // used to store the deleted position
  list<int> deleted_fds;
  int next_pos;
  struct epoll_event *events;
  CephContext *cct;

 public:
  EpollDriver(CephContext *c): epfd(-1), next_pos(0), events(NULL), cct(c) {}
  virtual ~EpollDriver() {
    if (epfd != -1)
      close(epfd);

    if (events)
      free(events);
  }

  int init(int nevent);
  int add_event(int fd, int cur_mask, int add_mask);
  void del_event(int fd, int cur_mask, int del_mask);
  int resize_events(int newsize);
  int event_wait(vector<FiredFileEvent> &fired_events, struct timeval *tp);
};

#endif
