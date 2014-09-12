// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*- 
// vim: ts=8 sw=2 smarttab
#include <time.h>

#include "common/errno.h"
#include "Event.h"

#ifdef HAVE_EPOLL
#include "EventEpoll.h"
#else
#ifdef HAVE_KQUEUE
#include "EventKqueue.h"
#else
#include "EventSelect.h"
#endif
#endif

int EventCenter::init(int n)
{
  // can't init multi times
  assert(nevent == 0);
#ifdef HAVE_EPOLL
  driver = new EpollDriver(cct);
#else
#ifdef HAVE_KQUEUE
  driver = new KqueueDriver(cct);
#else
  driver = new SelectDriver(cct);
#endif
#endif

  if (!driver) {
    lderr(cct) << __func__ << " failed to create event driver " << dendl;
    return -1;
  }

  int r = driver->init(n);
  if (r < 0) {
    lderr(cct) << __func__ << " failed to init event driver." << dendl;
    return r;
  }

  nevent = n;
  event_tp.start();
  return 0;
}

EventCenter::~EventCenter()
{
  if (driver)
    delete driver;
}

int EventCenter::create_file_event(int fd, int mask, EventCallback *ctxt)
{
  int r;
  Mutex::Locker l(lock);
  if (events.size() > nevent) {
    int new_size = nevent << 2;
    ldout(cct, 10) << __func__ << " event count exceed " << nevent << ", expand to " << new_size << dendl;
    r = driver->resize_events(new_size);
    if (r < 0) {
      lderr(cct) << __func__ << " event count is exceed." << dendl;
      return -ERANGE;
    }
    nevent = new_size;
  }

  EventCenter::FileEvent *event = _get_file_event(fd);

  r = driver->add_event(fd, event ? event->mask: EVENT_NONE, mask);
  if (r < 0)
    return r;

  if (!event) {
    events[fd] = EventCenter::FileEvent();
    event = &events[fd];
  }

  event->mask |= mask;
  if (mask & EVENT_READABLE) {
    if (event->read_cb)
      delete event->read_cb;
    event->read_cb = ctxt;
  }
  if (mask & EVENT_WRITABLE) {
    if (event->write_cb)
      delete event->write_cb;
    event->write_cb = ctxt;
  }
  return 0;
}

void EventCenter::delete_file_event(int fd, int mask)
{
  Mutex::Locker l(lock);

  EventCenter::FileEvent *event = _get_file_event(fd);
  driver->del_event(fd, event ? event->mask: EVENT_NONE, mask);
  if (!event) {
    events[fd] = EventCenter::FileEvent();
    event = &events[fd];
  }

  if (event->read_cb)
    delete event->read_cb;
  if (event->write_cb)
    delete event->write_cb;

  event->mask = event->mask & (~mask);
  if (event->mask == EVENT_NONE)
    events.erase(fd);
}


uint64_t EventCenter::create_time_event(uint64_t milliseconds, EventCallback *ctxt)
{
  Mutex::Locker l(lock);
  uint64_t id = eventLoop->timeEventNextId++;
  EventCenter::TimeEvent event;
  utime_t expire;
  struct timeval tv;

  expire = ceph_clock_now(cct);
  expire.copy_to_timeval(&tv);
  tv.tv_sec = expire.tv_sec + milliseconds / 1000;
  tv.tv_usec = expire.tv_usec + milliseconds * 1000;
  expire.set_from_timeval(&tv);

  event.id = id;
  event.time_cb = ctxt;
  time_events[expire] = event;

  return id;
}

void EventCenter::delete_time_event(uint64_t id)
{
  Mutex::Locker l(lock);
  for (map<utime_t, TimeEvent>::iterator it = time_events.begin();
       it != time_events.end(); it++) {
    if (it->second.id == id) {
      time_events.erase(it);
      return ;
    }
  }
}

int EventCenter::_process_time_events()
{
  int processed = 0;
  time_t now = time(NULL);
  utime_t cur = ceph_clock_now(cct);

  /* If the system clock is moved to the future, and then set back to the
   * right value, time events may be delayed in a random way. Often this
   * means that scheduled operations will not be performed soon enough.
   *
   * Here we try to detect system clock skews, and force all the time
   * events to be processed ASAP when this happens: the idea is that
   * processing events earlier is less dangerous than delaying them
   * indefinitely, and practice suggests it is. */
  if (now < last_time) {
    for (map<utime_t, TimeEvent>::iterator it = time_events.begin();
          it != time_events.end(); ++it) {
      it->first = utime_t();
    }
  }
  last_time = now;

  map<utime_t, TimeEvent>::iterator prev;
  for (map<utime_t, TimeEvent>::iterator it = time_events.begin();
       it != time_events.end(); ) {
    prev = it;
    if (cur >= it->first) {
      FiredEvent event;
      e.time_event.id = it->second.id;
      e.time_event.time_cb = it->second.time_cb;
      e.is_file = false;
      event_wq.queue(e);
      processed++;
      ++it;
      time_events.erase(prev);
    } else {
      break;
    }
  }

  return processed;
}

int EventCenter::process_events(int timeout_millionseconds)
{
  struct timeval tv;
  int numevents;
  bool trigger_time = false;

  if (timeout_millionseconds > 0) {
    tv.tv_sec = timeout_millionseconds / 1000;
    tv.tv_usec = (timeout_millionseconds % 1000) * 1000;
  }
  else {
    tv.tv_sec = 0;
    tv.tv_usec = 0;
  }

  Mutex::Locker l(lock);
  utime_t shortest = utime_t(&tv);
  for (map<utime_t, TimeEvent>::iterator it = time_events.begin();
        it != time_events.end(); ++it) {
    if (shortes > it->first) {
      shortest = it->first;
      trigger_time = true;
      break;
    }
  }
  shortes.copy_to_timeval(&tv);

  vector<FiredFileEvent> fired_events;
  numevents = driver->event_wait(fired_events, &tv);
  for (int j = 0; j < numevents; j++) {
    FiredEvent e;
    e.file_event = fired_events[j];
    e.is_file = true
    event_wq.queue(e);
  }

  if (trigger_time)
    numevents += _process_time_events(shortest);

  return numevents;
}
