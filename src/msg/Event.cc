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

#define dout_subsys ceph_subsys_ms

#undef dout_prefix
#define dout_prefix *_dout << "Event "

class C_handle_notify : public EventCallback {
 public:
  C_handle_notify() {}
  void do_request(int fd_or_id) {
  }
};

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

  int fds[2];
  if (pipe(fds) < 0) {
    lderr(cct) << __func__ << " can't create notify pipe" << dendl;
    return -1;
  }

  notify_receive_fd = fds[0];
  notify_send_fd = fds[1];

  nevent = n;
  create_file_event(notify_receive_fd, EVENT_READABLE, EventCallbackRef(new C_handle_notify()));
  return 0;
}

EventCenter::~EventCenter()
{
  if (driver)
    delete driver;

  if (notify_receive_fd > 0)
    ::close(notify_receive_fd);
  if (notify_send_fd > 0)
    ::close(notify_send_fd);
}

int EventCenter::create_file_event(int fd, int mask, EventCallbackRef ctxt)
{
  int r;
  if (file_events.size() > nevent) {
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
    file_events[fd] = EventCenter::FileEvent();
    event = &file_events[fd];
  }

  event->mask |= mask;
  if (mask & EVENT_READABLE) {
    event->read_cb = ctxt;
  }
  if (mask & EVENT_WRITABLE) {
    event->write_cb = ctxt;
  }
  ldout(cct, 10) << __func__ << " create event fd=" << fd << " mask=" << mask
                 << " now mask is " << event->mask << dendl;
  return 0;
}

void EventCenter::delete_file_event(int fd, int mask)
{
  EventCenter::FileEvent *event = _get_file_event(fd);
  if (!event)
    return ;

  driver->del_event(fd, event->mask, mask);

  if (mask & EVENT_READABLE && event->read_cb) {
    event->read_cb.reset();
  }
  if (mask & EVENT_WRITABLE && event->write_cb) {
    event->write_cb.reset();
  }

  event->mask = event->mask & (~mask);
  if (event->mask == EVENT_NONE)
    file_events.erase(fd);
  ldout(cct, 10) << __func__ << " delete fd=" << fd << " mask=" << mask
                 << " now mask is " << event->mask << dendl;
}

uint64_t EventCenter::create_time_event(uint64_t milliseconds, EventCallbackRef ctxt)
{
  uint64_t id = time_event_next_id++;

  ldout(cct, 10) << __func__ << " id=" << id << " expire time=" << milliseconds << dendl;
  EventCenter::TimeEvent event;
  utime_t expire;
  struct timeval tv;

  expire = ceph_clock_now(cct);
  expire.copy_to_timeval(&tv);
  tv.tv_sec += milliseconds / 1000;
  tv.tv_usec += (milliseconds % 1000) * 1000;
  expire.set_from_timeval(&tv);

  event.id = id;
  event.time_cb = ctxt;
  time_to_ids[expire] = id;
  time_events[id] = event;

  if (expire < next_wake) {
    wakeup();
  }
  return id;
}

void EventCenter::delete_time_event(uint64_t id)
{
  for (map<utime_t, uint64_t>::iterator it = time_to_ids.begin();
       it != time_to_ids.end(); it++) {
    if (it->second == id) {
      time_to_ids.erase(it);
      time_events.erase(id);
      ldout(cct, 10) << __func__ << " id=" << id << dendl;
      return ;
    }
  }
}

void EventCenter::wakeup()
{
  ldout(cct, 1) << __func__ << dendl;
  char buf[1];
  buf[0] = 'c';
  // wake up "event_wait"
  int n = write(notify_send_fd, buf, 1);
  // FIXME ?
  assert(n == 1);
}

int EventCenter::process_time_events()
{
  int processed = 0;
  time_t now = time(NULL);
  utime_t cur = ceph_clock_now(cct);
  ldout(cct, 10) << __func__ << " cur time is " << cur << dendl;

  /* If the system clock is moved to the future, and then set back to the
   * right value, time events may be delayed in a random way. Often this
   * means that scheduled operations will not be performed soon enough.
   *
   * Here we try to detect system clock skews, and force all the time
   * events to be processed ASAP when this happens: the idea is that
   * processing events earlier is less dangerous than delaying them
   * indefinitely, and practice suggests it is. */
  if (now < last_time) {
    map<utime_t, uint64_t> changed;
    for (map<utime_t, uint64_t>::iterator it = time_to_ids.begin();
          it != time_to_ids.end(); ++it) {
      changed[utime_t()] = it->second;
    }
    time_to_ids.swap(changed);
  }
  last_time = now;

  map<utime_t, uint64_t>::iterator prev;
  for (map<utime_t, uint64_t>::iterator it = time_to_ids.begin();
       it != time_to_ids.end(); ) {
    prev = it;
    if (cur >= it->first) {
      ldout(cct, 10) << __func__ << " queue time event: id=" << it->second << " time is "
                     << it->first << dendl;
      time_events[it->second].time_cb->do_request(it->first);
      processed++;
      ++it;
      time_to_ids.erase(prev);
      time_events.erase(prev->second);
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

  utime_t period, shortest, now = ceph_clock_now(cct);
  now.copy_to_timeval(&tv);
  if (timeout_millionseconds > 0) {
    tv.tv_sec += timeout_millionseconds / 1000;
    tv.tv_usec += (timeout_millionseconds % 1000) * 1000;
  }
  shortest.set_from_timeval(&tv);

  {
    map<utime_t, uint64_t>::iterator it = time_to_ids.begin();
    if (it != time_to_ids.end() && shortest > it->first) {
      ldout(cct, 10) << __func__ << " shortest is " << shortest << " it->first is " << it->first << dendl;
      shortest = it->first;
      trigger_time = true;
      period = now - shortest;
      period.copy_to_timeval(&tv);
    } else {
      tv.tv_sec = timeout_millionseconds / 1000;
      tv.tv_usec = (timeout_millionseconds % 1000) * 1000;
    }

    next_wake = shortest;
  }

  ldout(cct, 10) << __func__ << " wait second " << tv.tv_sec << " usec " << tv.tv_usec << dendl;
  vector<FiredFileEvent> fired_events;
  numevents = driver->event_wait(fired_events, &tv);
  for (int j = 0; j < numevents; j++) {
    int rfired = 0;
    FileEvent *event = _get_file_event(fired_events[j].fd);
    if (!event)
      continue;

    /* note the event->mask & mask & ... code: maybe an already processed
    * event removed an element that fired and we still didn't
    * processed, so we check if the event is still valid. */
    if (event->mask & fired_events[j].mask & EVENT_READABLE) {
      rfired = 1;
      event->read_cb->do_request(fired_events[j].fd);
    }
    event = _get_file_event(fired_events[j].fd);
    if (!event)
      continue;

    if (event->mask & fired_events[j].mask & EVENT_WRITABLE) {
      if (!rfired || event->read_cb != event->write_cb)
        event->write_cb->do_request(fired_events[j].fd);
    }

    ldout(cct, 20) << __func__ << " event_wq process is " << fired_events[j].fd << " mask is " << fired_events[j].mask << dendl;
  }

  if (trigger_time)
    numevents += process_time_events();

  {
    lock.Lock();
    while (!external_events.empty()) {
      EventCallbackRef e = external_events.front();
      external_events.pop_front();
      lock.Unlock();
      e->do_request(0);
      lock.Lock();
    }
    lock.Unlock();
  }
  return numevents;
}

void EventCenter::dispatch_event_external(EventCallbackRef e)
{
  lock.Lock();
  external_events.push_back(e);
  lock.Unlock();
  wakeup();
}
