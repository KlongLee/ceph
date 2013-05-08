#include <errno.h>

#include "include/types.h"
#include "cls/log/cls_log_ops.h"
#include "include/rados/librados.hpp"


using namespace librados;



void cls_log_add(librados::ObjectWriteOperation& op, list<cls_log_entry>& entries)
{
  bufferlist in;
  cls_log_add_op call;
  call.entries = entries;
  ::encode(call, in);
  op.exec("log", "add", in);
}

void cls_log_add(librados::ObjectWriteOperation& op, cls_log_entry& entry)
{
  bufferlist in;
  cls_log_add_op call;
  call.entries.push_back(entry);
  ::encode(call, in);
  op.exec("log", "add", in);
}

void cls_log_add_prepare_entry(cls_log_entry& entry, const utime_t& timestamp,
                 const string& section, const string& name, bufferlist& bl)
{
  entry.timestamp = timestamp;
  entry.section = section;
  entry.name = name;
  entry.data = bl;
}

void cls_log_add(librados::ObjectWriteOperation& op, const utime_t& timestamp,
                 const string& section, const string& name, bufferlist& bl)
{
  cls_log_entry entry;

  cls_log_add_prepare_entry(entry, timestamp, section, name, bl);
  cls_log_add(op, entry);
}

void cls_log_trim(librados::ObjectWriteOperation& op, utime_t& from, utime_t& to)
{
  bufferlist in;
  cls_log_trim_op call;
  call.from_time = from;
  call.to_time = to;
  ::encode(call, in);
  op.exec("log", "trim", in);
}

int cls_log_trim(librados::IoCtx& io_ctx, const string& oid, utime_t& from, utime_t& to)
{
  bool done = false;

  do {
    ObjectWriteOperation op;

    cls_log_trim(op, from, to);

    int r = io_ctx.operate(oid, &op);
    if (r == -ENODATA)
      done = true;
    else if (r < 0)
      return r;

  } while (!done);


  return 0;
}

class LogListCtx : public ObjectOperationCompletion {
  list<cls_log_entry> *entries;
  string *marker;
  bool *truncated;
public:
  LogListCtx(list<cls_log_entry> *_entries, string *_marker, bool *_truncated) :
                                      entries(_entries), marker(_marker), truncated(_truncated) {}
  void handle_completion(int r, bufferlist& outbl) {
    if (r >= 0) {
      cls_log_list_ret ret;
      try {
        bufferlist::iterator iter = outbl.begin();
        ::decode(ret, iter);
        if (entries)
	  *entries = ret.entries;
        if (truncated)
          *truncated = ret.truncated;
        if (marker)
          *marker = ret.marker;
      } catch (buffer::error& err) {
        // nothing we can do about it atm
      }
    }
  }
};

void cls_log_list(librados::ObjectReadOperation& op, utime_t& from, utime_t& to,
                  string& in_marker, int max_entries, list<cls_log_entry>& entries,
                  string *out_marker, bool *truncated)
{
  bufferlist inbl;
  cls_log_list_op call;
  call.from_time = from;
  call.to_time = to;
  call.marker = in_marker;
  call.max_entries = max_entries;

  ::encode(call, inbl);

  op.exec("log", "list", inbl, new LogListCtx(&entries, out_marker, truncated));
}

