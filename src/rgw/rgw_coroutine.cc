

#include "rgw_coroutine.h"

#include <boost/asio/coroutine.hpp>
#include <boost/asio/yield.hpp>

#define dout_subsys ceph_subsys_rgw



RGWCoroutinesStack::RGWCoroutinesStack(CephContext *_cct, RGWCoroutinesManager *_ops_mgr, RGWCoroutine *start) : cct(_cct), ops_mgr(_ops_mgr),
                                                                                                         done_flag(false), error_flag(false), blocked_flag(false),
                                                                                                         sleep_flag(false),
													 retcode(0),
													 env(NULL)
{
  if (start) {
    ops.push_back(start);
  }
  pos = ops.begin();
}

int RGWCoroutinesStack::operate(RGWCoroutinesEnv *_env)
{
  env = _env;
  RGWCoroutine *op = *pos;
  op->stack = this;
  int r = op->operate();
  if (r < 0) {
    ldout(cct, 0) << "ERROR: op->operate() returned r=" << r << dendl;
  }

  error_flag = op->is_error();
  blocked_flag = op->is_io_blocked();
  sleep_flag = op->is_sleeping();

  if (op->is_done()) {
    int op_retcode = op->get_ret_status();
    op->put();
    r = unwind(r);
    done_flag = (pos == ops.end());
    if (done_flag) {
      retcode = op_retcode;
    }
    return r;
  }

  /* should r ever be negative at this point? */
  assert(r >= 0);

  return 0;
}

string RGWCoroutinesStack::error_str()
{
  if (pos != ops.end()) {
    return (*pos)->error_str();
  }
  return string();
}

int RGWCoroutinesStack::call(RGWCoroutine *next_op, int ret) {
  ops.push_back(next_op);
  if (pos != ops.end()) {
    ++pos;
  } else {
    pos = ops.begin();
  }
  return ret;
}

void RGWCoroutinesStack::spawn(RGWCoroutine *op, bool wait)
{
  op->get();

  RGWCoroutinesStack *stack = env->manager->allocate_stack();
  spawned_stacks.push_back(stack);

  stack->get(); /* we'll need to collect the stack */
  int r = stack->call(op, 0);
  assert(r == 0);

  env->stacks->push_back(stack);

  if (wait) {
    set_blocked_by(stack);
  }
}

int RGWCoroutinesStack::unwind(int retcode)
{
  if (pos == ops.begin()) {
    pos = ops.end();
    return retcode;
  }

  --pos;
  ops.pop_back();
  RGWCoroutine *op = *pos;
  op->set_retcode(retcode);
  return 0;
}

void RGWCoroutinesStack::set_io_blocked(bool flag)
{
  blocked_flag = flag;
  if (pos != ops.end()) {
    (*pos)->set_io_blocked(flag);
  }
}

int RGWCoroutinesStack::complete_spawned()
{
  int ret = 0;
  for (list<RGWCoroutinesStack *>::iterator iter = spawned_stacks.begin(); iter != spawned_stacks.end(); ++iter) {
    int r = (*iter)->get_ret_status();
    if (r < 0) {
      ret = r;
    }

    (*iter)->put();
  }
  spawned_stacks.clear();
  return ret;
}

static void _aio_completion_notifier_cb(librados::completion_t cb, void *arg);

static void _aio_completion_notifier_cb(librados::completion_t cb, void *arg)
{
  ((RGWAioCompletionNotifier *)arg)->cb();
}

RGWAioCompletionNotifier::RGWAioCompletionNotifier(RGWCompletionManager *_mgr, void *_user_data) : completion_mgr(_mgr), user_data(_user_data) {
  c = librados::Rados::aio_create_completion((void *)this, _aio_completion_notifier_cb, NULL);
}

RGWAioCompletionNotifier *RGWCoroutinesStack::create_completion_notifier()
{
  return ops_mgr->create_completion_notifier(this);
}

RGWCompletionManager *RGWCoroutinesStack::get_completion_mgr()
{
  return ops_mgr->get_completion_mgr();
}

bool RGWCoroutinesStack::unblock_stack(RGWCoroutinesStack **s)
{
  if (blocking_stacks.empty()) {
    return false;
  }

  set<RGWCoroutinesStack *>::iterator iter = blocking_stacks.begin();
  *s = *iter;
  blocking_stacks.erase(iter);
  (*s)->blocked_by_stack.erase(this);

  return true;
}

void RGWCoroutinesManager::report_error(RGWCoroutinesStack *op)
{
#warning need to have error logging infrastructure that logs on backend
  lderr(cct) << "ERROR: failed operation: " << op->error_str() << dendl;
}

void RGWCoroutinesManager::handle_unblocked_stack(list<RGWCoroutinesStack *>& stacks, RGWCoroutinesStack *stack, int *blocked_count)
{
  --(*blocked_count);
  stack->set_io_blocked(false);
  if (!stack->is_done()) {
    stacks.push_back(stack);
  } else {
    stack->put();
  }
}

int RGWCoroutinesManager::run(list<RGWCoroutinesStack *>& stacks)
{
  int blocked_count = 0;
  RGWCoroutinesEnv env;

  env.manager = this;
  env.stacks = &stacks;

  for (list<RGWCoroutinesStack *>::iterator iter = stacks.begin(); iter != stacks.end();) {
    RGWCoroutinesStack *stack = *iter;
    env.stack = stack;
    int ret = stack->operate(&env);
    if (ret < 0) {
      ldout(cct, 0) << "ERROR: stack->operate() returned ret=" << ret << dendl;
    }

    if (stack->is_error()) {
      report_error(stack);
    }

    if (stack->is_blocked_by_stack() || stack->is_sleeping()) {
      /* do nothing, we'll re-add the stack when the blocking stack is done,
       * or when we're awaken
       */
    } else if (stack->is_io_blocked()) {
      blocked_count++;
    } else if (stack->is_done()) {
      RGWCoroutinesStack *s;
      while (stack->unblock_stack(&s)) {
	if (!s->is_blocked_by_stack() && !s->is_done()) {
	  if (s->is_io_blocked()) {
	    blocked_count++;
	  } else {
	    stacks.push_back(s);
	  }
	}
      }
      stack->put();
    } else {
      stacks.push_back(stack);
    }

    RGWCoroutinesStack *blocked_stack;
    while (completion_mgr.try_get_next((void **)&blocked_stack)) {
      handle_unblocked_stack(stacks, blocked_stack, &blocked_count);
    }

    if (blocked_count >= ops_window) {
      int ret = completion_mgr.get_next((void **)&blocked_stack);
      if (ret < 0) {
	ldout(cct, 0) << "ERROR: failed to clone shard, completion_mgr.get_next() returned ret=" << ret << dendl;
      }
      handle_unblocked_stack(stacks, blocked_stack, &blocked_count);
    }

    ++iter;
    stacks.pop_front();
    while (iter == stacks.end() && blocked_count > 0) {
      int ret = completion_mgr.get_next((void **)&blocked_stack);
      if (ret < 0) {
	ldout(cct, 0) << "ERROR: failed to clone shard, completion_mgr.get_next() returned ret=" << ret << dendl;
      }
      handle_unblocked_stack(stacks, blocked_stack, &blocked_count);
      iter = stacks.begin();
    }
  }

  return 0;
}

int RGWCoroutinesManager::run(RGWCoroutine *op)
{
  list<RGWCoroutinesStack *> stacks;
  RGWCoroutinesStack *stack = allocate_stack();
  op->get();
  int r = stack->call(op);
  if (r < 0) {
    ldout(cct, 0) << "ERROR: stack->call() returned r=" << r << dendl;
    return r;
  }

  stacks.push_back(stack);

  r = run(stacks);
  if (r < 0) {
    ldout(cct, 0) << "ERROR: run(stacks) returned r=" << r << dendl;
  }

  r = op->get_ret_status();
  op->put();

  return r;
}

RGWAioCompletionNotifier *RGWCoroutinesManager::create_completion_notifier(RGWCoroutinesStack *stack)
{
  return new RGWAioCompletionNotifier(&completion_mgr, (void *)stack);
}

void RGWCoroutine::call(RGWCoroutine *op)
{
  int r = stack->call(op, 0);
  assert(r == 0);
}

void RGWCoroutine::spawn(RGWCoroutine *op, bool wait)
{
  stack->spawn(op, wait);
}

int RGWSimpleCoroutine::operate()
{
  reenter(this) {
    yield return state_init();
    yield return state_send_request();
    yield return state_request_complete();
    yield return state_all_complete();
  }

  return set_state(RGWCoroutine_Done);
}

int RGWSimpleCoroutine::state_init()
{
  int ret = init();
  if (ret < 0) {
    return set_state(RGWCoroutine_Error, ret);
  }
  return 0;
}

int RGWSimpleCoroutine::state_send_request()
{
  int ret = send_request();
  if (ret < 0) {
    return set_state(RGWCoroutine_Error, ret);
  }
  return io_block(0);
}

int RGWSimpleCoroutine::state_request_complete()
{
  int ret = request_complete();
  if (ret < 0) {
    return set_state(RGWCoroutine_Error, ret);
  }
  return 0;
}

int RGWSimpleCoroutine::state_all_complete()
{
  int ret = finish();
  if (ret < 0) {
    return set_state(RGWCoroutine_Error, ret);
  }
  return 0;
}


