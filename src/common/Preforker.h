// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab
#ifndef CEPH_COMMON_PREFORKER_H
#define CEPH_COMMON_PREFORKER_H

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#ifdef WITH_LTTNG
#include <lttng/ust.h>
#endif
#include "include/assert.h"
#include "common/safe_io.h"
#include "common/errno.h"

/**
 * pre-fork fork/daemonize helper class
 *
 * Hide the details of letting a process fork early, do a bunch of
 * initialization work that may spam stdout or exit with an error, and
 * then daemonize.  The exit() method will either exit directly (if we
 * haven't forked) or pass a message to the parent with the error if
 * we have.
 */
class Preforker {
  pid_t childpid;
  bool forked;
  int fd[2];  // parent's, child's
#ifdef WITH_LTTNG
    sigset_t sigset;
#endif

public:
  Preforker()
    : childpid(0),
      forked(false)
  {}

  void prefork() {
    assert(!forked);
    int r = socketpair(AF_UNIX, SOCK_STREAM, 0, fd);
    if (r < 0) {
      cerr << "[" << getpid() << "]: unable to create socketpair: " << cpp_strerror(errno) << std::endl;
      exit(errno);
    }

#ifdef WITH_LTTNG
    ust_before_fork(&sigset);
#endif

    forked = true;

    childpid = fork();
    if (childpid == 0) {
      child_after_fork();
    } else {
      parent_after_fork();
    }
  }

  bool is_child() {
    return childpid == 0;
  }

  bool is_parent() {
    return childpid != 0;
  }

  int parent_wait() {
    assert(forked);

    int r = -1;
    int err = safe_read_exact(fd[0], &r, sizeof(r));
    if (err == 0 && r == -1) {
      // daemonize
      ::close(0);
      ::close(1);
      ::close(2);
      r = 0;
    } else if (err) {
      cerr << "[" << getpid() << "]: " << cpp_strerror(err) << std::endl;
    } else {
      // wait for child to exit
      r = waitpid(childpid, NULL, 0);
    }
    return r;
  }

  int signal_exit(int r) {
    if (forked) {
      // tell parent.  this shouldn't fail, but if it does, pass the
      // error back to the parent.
      int ret = safe_write(fd[1], &r, sizeof(r));
      if (ret <= 0)
	return ret;
    }
    return r;
  }
  void exit(int r) {
    signal_exit(r);
    ::exit(r);
  }

  void daemonize() {
    assert(forked);
    static int r = -1;
    int r2 = ::write(fd[1], &r, sizeof(r));
    r += r2;  // make the compiler shut up about the unused return code from ::write(2).
  }
  
private:
  void child_after_fork() {
#ifdef WITH_LTTNG
    ust_after_fork_child(&sigset);
#endif
    ::close(fd[0]);
  }

  void parent_after_fork() {
#ifdef WITH_LTTNG
    ust_after_fork_parent(&sigset);
#endif
    ::close(fd[1]);
  }
};

#endif
