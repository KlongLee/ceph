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
#include <string>

#include "common/ceph_argparse.h"
#include "common/errno.h"

#include "global/global_init.h"
#include "include/str_list.h"
#include "mon/MonMap.h"


void usage()
{
  cout << " usage: [--print] [--create [--clobber][--fsid uuid]]\n"
       << "        [--generate] [--set-initial-members]\n"
       << "        [--add name 1.2.3.4:567] [--rm name]\n"
       << "        [--feature-list [plain|parseable]]\n"
       << "        [--feature-set <value> [--optional|--persistent]]\n"
       << "        [--feature-unset <value> [--optional|--persistent]] "
       << "<mapfilename>"
       << std::endl;
  exit(1);
}

struct feature_op_t {
  enum type_t {
    PERSISTENT,
    OPTIONAL,
    PLAIN,
    PARSEABLE,
    NONE
  };

  enum op_t {
    OP_SET,
    OP_UNSET,
    OP_LIST
  };

  op_t op;
  type_t type;
  mon_feature_t feature;

  feature_op_t() : op(OP_LIST), type(NONE) { }
  // default to 'persistent' feature if not specified
  feature_op_t(op_t o) : op(o), type(PERSISTENT) { }
  feature_op_t(op_t o, type_t t) : op(o), type(t) { }
  feature_op_t(op_t o, type_t t, mon_feature_t &f) :
    op(o), type(t), feature(t) { }

  void set_optional() {
    type = OPTIONAL;
  }
  void set_persistent() {
    type = PERSISTENT;
  }
  bool parse_value(string &s, ostream *errout = NULL) {

    feature = ceph::features::mon::get_feature_by_name(s);
    if (feature != ceph::features::mon::FEATURE_NONE) {
      return true;
    }

    // try parsing as numerical value
    uint64_t feature_val;
    string interr;
    feature_val = strict_strtoll(s.c_str(), 10, &interr);
    if (!interr.empty()) {
      if (errout) {
        *errout << "unknown features name '" << s
                << "' or unable to parse value: " << interr << std::endl;
      }
      return false;
    }
    feature = mon_feature_t(feature_val);
    return true;
  }
};

void features_list(feature_op_t &f, MonMap &m)
{
  if (f.type == feature_op_t::type_t::PLAIN) {

    cout << "MONMAP FEATURES:" << std::endl;
    cout << "    persistent: ";
    m.persistent_features.print_with_value(cout);
    cout << std::endl;
    cout << "    optional:   ";
    m.optional_features.print_with_value(cout);
    cout << std::endl;
    cout << "    required:   ";
    m.get_required_features().print_with_value(cout);
    cout << std::endl;

    cout << std::endl;
    cout << "AVAILABLE FEATURES:" << std::endl;
    cout << "    supported:  ";
    ceph::features::mon::get_supported().print_with_value(cout);
    cout << std::endl;
    cout << "    persistent: ";
    ceph::features::mon::get_persistent().print_with_value(cout);
    cout << std::endl;
  } else if (f.type == feature_op_t::type_t::PARSEABLE) {

    cout << "monmap:persistent:";
    m.persistent_features.print_with_value(cout);
    cout << std::endl;
    cout << "monmap:optional:";
    m.optional_features.print_with_value(cout);
    cout << std::endl;
    cout << "monmap:required:";
    m.get_required_features().print_with_value(cout);
    cout << std::endl;
    cout << "available:supported:";
    ceph::features::mon::get_supported().print_with_value(cout);
    cout << std::endl;
    cout << "available:persistent:";
    ceph::features::mon::get_persistent().print_with_value(cout);
    cout << std::endl;
  }
}

bool handle_features(list<feature_op_t>& lst, MonMap &m)
{
  if (lst.empty())
    return false;

  bool modified = false;

  for (auto &f : lst) {
    if (f.op == feature_op_t::op_t::OP_LIST) {
      features_list(f, m);
    } else if (f.op == feature_op_t::op_t::OP_SET ||
               f.op == feature_op_t::op_t::OP_UNSET) {

      modified = true;

      mon_feature_t &target =
        ( f.type == feature_op_t::type_t::OPTIONAL ?
            m.optional_features : m.persistent_features );

      if (f.op == feature_op_t::op_t::OP_SET) {
        target.set_feature(f.feature);
      } else {
        target.unset_feature(f.feature);
      }
    } else {
      cerr << "unknow feature operation type '" << f.op << "'" << std::endl; 
    }
  }
  return modified;
}

int main(int argc, const char **argv)
{
  vector<const char*> args;
  argv_to_vec(argc, argv, args);

  const char *me = argv[0];

  std::string fn;
  bool print = false;
  bool create = false;
  bool clobber = false;
  bool modified = false;
  bool show_features = false;
  bool generate = false;
  bool filter = false;
  map<string,entity_addr_t> add;
  list<string> rm;
  list<feature_op_t> features;

  auto cct = global_init(NULL, args, CEPH_ENTITY_TYPE_CLIENT,
			 CODE_ENVIRONMENT_UTILITY,
			 CINIT_FLAG_NO_DEFAULT_CONFIG_FILE);
  common_init_finish(g_ceph_context);
  std::string val;
  for (std::vector<const char*>::iterator i = args.begin(); i != args.end(); ) {
    if (ceph_argparse_double_dash(args, i)) {
      break;
    } else if (ceph_argparse_flag(args, i, "-h", "--help", (char*)NULL)) {
      usage();
    } else if (ceph_argparse_flag(args, i, "-p", "--print", (char*)NULL)) {
      print = true;
    } else if (ceph_argparse_flag(args, i, "--create", (char*)NULL)) {
      create = true;
    } else if (ceph_argparse_flag(args, i, "--clobber", (char*)NULL)) {
      clobber = true;
    } else if (ceph_argparse_flag(args, i, "--generate", (char*)NULL)) {
      generate = true;
    } else if (ceph_argparse_flag(args, i, "--set-initial-members", (char*)NULL)) {
      filter = true;
    } else if (ceph_argparse_flag(args, i, "--add", (char*)NULL)) {
      string name = *i;
      i = args.erase(i);
      if (i == args.end())
	usage();
      entity_addr_t addr;
      if (!addr.parse(*i)) {
	cerr << me << ": invalid ip:port '" << *i << "'" << std::endl;
	return -1;
      }
      if (addr.get_port() == 0)
	addr.set_port(CEPH_MON_PORT);
      add[name] = addr;
      modified = true;
      i = args.erase(i);
    } else if (ceph_argparse_witharg(args, i, &val, "--rm", (char*)NULL)) {
      rm.push_back(val);
      modified = true;
    } else if (ceph_argparse_flag(args, i, "--feature-list", (char*)NULL)) {
      string format = *i;
      if (format == "plain" || format == "parseable") {
        i = args.erase(i);
      } else {
        format = "plain";
      }

      feature_op_t f(feature_op_t::op_t::OP_LIST,
                   feature_op_t::type_t::PLAIN);

      if (format == "parseable") {
        f.type = feature_op_t::type_t::PARSEABLE;
      } else if (format != "plain") {
        cerr << "invalid format type for list: '" << val << "'" << std::endl;
        usage();
      }

      features.push_back(f);
      show_features = true;
    } else if (ceph_argparse_witharg(args, i, &val,
                                     "--feature-set", (char*)NULL)) {
      // parse value
      feature_op_t f(feature_op_t::op_t::OP_SET);
      if (!f.parse_value(val, &cerr)) {
        usage();
      }
      features.push_back(f);

    } else if (ceph_argparse_witharg(args, i, &val,
                                     "--feature-unset", (char*)NULL)) {
      // parse value
      feature_op_t f(feature_op_t::op_t::OP_UNSET);
      if (!f.parse_value(val, &cerr)) {
        usage();
      }
      features.push_back(f);
    } else if (ceph_argparse_flag(args, i, "--optional", (char*)NULL)) {
      if (features.empty()) {
        usage();
      }
      features.back().set_optional();
    } else if (ceph_argparse_flag(args, i, "--persistent", (char*)NULL)) {
      if (features.empty()) {
        usage();
      }
      features.back().set_persistent();
    } else {
      ++i;
    }
  }
  if (args.empty()) {
    cerr << me << ": must specify monmap filename" << std::endl;
    usage();
  }
  else if (args.size() > 1) {
    cerr << me << ": too many arguments" << std::endl;
    usage();
  }
  fn = args[0];
  
  MonMap monmap;

  cout << me << ": monmap file " << fn << std::endl;

  int r = 0;
  if (!(create && clobber)) {
    try {
      r = monmap.read(fn.c_str());
    } catch (...) {
      cerr << me << ": unable to read monmap file" << std::endl;
      return -1;
    }
  }

  if (!create && r < 0) {
    cerr << me << ": couldn't open " << fn << ": " << cpp_strerror(r) << std::endl;
    return -1;
  }    
  else if (create && !clobber && r == 0) {
    cerr << me << ": " << fn << " exists, --clobber to overwrite" << std::endl;
    return -1;
  }

  if (create) {
    monmap.epoch = 0;
    monmap.created = ceph_clock_now();
    monmap.last_changed = monmap.created;
    srand(getpid() + time(0));
    if (g_conf->get_val<uuid_d>("fsid").is_zero()) {
      monmap.generate_fsid();
      cout << me << ": generated fsid " << monmap.fsid << std::endl;
    }
    modified = true;
  }

  if (generate) {
    int r = monmap.build_initial(g_ceph_context, cerr);
    if (r < 0)
      return r;
  }

  if (filter) {
    // apply initial members
    list<string> initial_members;
    get_str_list(g_conf->mon_initial_members, initial_members);
    if (!initial_members.empty()) {
      cout << "initial_members " << initial_members << ", filtering seed monmap" << std::endl;
      set<entity_addr_t> removed;
      monmap.set_initial_members(g_ceph_context, initial_members,
				 string(), entity_addr_t(),
				 &removed);
      cout << "removed " << removed << std::endl;
    }
    modified = true;
  }

  if (!g_conf->get_val<uuid_d>("fsid").is_zero()) {
    monmap.fsid = g_conf->get_val<uuid_d>("fsid");
    cout << me << ": set fsid to " << monmap.fsid << std::endl;
    modified = true;
  }

  for (map<string,entity_addr_t>::iterator p = add.begin(); p != add.end(); ++p) {
    if (monmap.contains(p->first)) {
      cerr << me << ": map already contains mon." << p->first << std::endl;
      usage();
    }
    if (monmap.contains(p->second)) {
      cerr << me << ": map already contains " << p->second << std::endl;
      usage();
    }
    monmap.add(p->first, p->second);
  }
  for (list<string>::iterator p = rm.begin(); p != rm.end(); ++p) {
    cout << me << ": removing " << *p << std::endl;
    if (!monmap.contains(*p)) {
      cerr << me << ": map does not contain " << *p << std::endl;
      usage();
    }
    monmap.remove(*p);
  }

  if (handle_features(features, monmap)) {
    modified = true;
  }

  if (!print && !modified && !show_features)
    usage();

  if (print) 
    monmap.print(cout);

  if (modified) {
    // write it out
    cout << me << ": writing epoch " << monmap.epoch
	 << " to " << fn
	 << " (" << monmap.size() << " monitors)" 
	 << std::endl;
    int r = monmap.write(fn.c_str());
    if (r < 0) {
      cerr << "monmaptool: error writing to '" << fn << "': " << cpp_strerror(r) << std::endl;
      return 1;
    }
  }
  

  return 0;
}
