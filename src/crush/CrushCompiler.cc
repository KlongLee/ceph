
#include "CrushCompiler.h"

#if defined(_AIX)
#define EBADE ECORRUPT
#endif

#ifndef EBADE
#define EBADE EFTYPE
#endif

#include <iostream>
#include <stack>
#include <functional>
#include <string>
#include <stdexcept>
#include <map>
#include <cctype>

#include <typeinfo>
#include "common/errno.h"
#include <boost/algorithm/string.hpp>

// -------------

static void print_type_name(ostream& out, int t, CrushWrapper &crush)
{
  const char *name = crush.get_type_name(t);
  if (name)
    out << name;
  else if (t == 0)
    out << "device";
  else
    out << "type" << t;
}

static void print_item_name(ostream& out, int t, CrushWrapper &crush)
{
  const char *name = crush.get_item_name(t);
  if (name)
    out << name;
  else if (t >= 0)
    out << "device" << t;
  else
    out << "bucket" << (-1-t);
}

static void print_rule_name(ostream& out, int t, CrushWrapper &crush)
{
  const char *name = crush.get_rule_name(t);
  if (name)
    out << name;
  else
    out << "rule" << t;
}

static void print_fixedpoint(ostream& out, int i)
{
  char s[20];
  snprintf(s, sizeof(s), "%.3f", (float)i / (float)0x10000);
  out << s;
}

int CrushCompiler::decompile_bucket_impl(int i, ostream &out)
{
  int type = crush.get_bucket_type(i);
  print_type_name(out, type, crush);
  out << " ";
  print_item_name(out, i, crush);
  out << " {\n";
  out << "\tid " << i << "\t\t# do not change unnecessarily\n";

  out << "\t# weight ";
  print_fixedpoint(out, crush.get_bucket_weight(i));
  out << "\n";

  int n = crush.get_bucket_size(i);

  int alg = crush.get_bucket_alg(i);
  out << "\talg " << crush_bucket_alg_name(alg);

  // notate based on alg type
  bool dopos = false;
  switch (alg) {
  case CRUSH_BUCKET_UNIFORM:
    out << "\t# do not change bucket size (" << n << ") unnecessarily";
    dopos = true;
    break;
  case CRUSH_BUCKET_LIST:
    out << "\t# add new items at the end; do not change order unnecessarily";
    break;
  case CRUSH_BUCKET_TREE:
    out << "\t# do not change pos for existing items unnecessarily";
    dopos = true;
    break;
  }
  out << "\n";

  int hash = crush.get_bucket_hash(i);
  out << "\thash " << hash << "\t# " << crush_hash_name(hash) << "\n";

  for (int j=0; j<n; j++) {
    int item = crush.get_bucket_item(i, j);
    int w = crush.get_bucket_item_weight(i, j);
    out << "\titem ";
    print_item_name(out, item, crush);
    out << " weight ";
    print_fixedpoint(out, w);
    if (dopos) 
      out << " pos " << j;
    
    out << "\n";
  }
  out << "}\n";
  return 0;
}

/* Basically, we just descend recursively into all of the buckets,
 * executing a depth-first traversal of the graph. Since the buckets form a
 * directed acyclic graph, this should work just fine. The graph isn't
 * necessarily a tree, so we have to keep track of what buckets we already
 * outputted. We don't want to output anything twice. We also keep track of
 * what buckets are in progress so that we can detect cycles. These can
 * arise through user error.
 */
int CrushCompiler::decompile_bucket(int cur,
				    std::map<int, dcb_state_t>& dcb_states,
				    ostream &out)
{
  if ((cur == 0) || (!crush.bucket_exists(cur)))
    return 0;

  std::map<int, dcb_state_t>::iterator c = dcb_states.find(cur);
  if (c == dcb_states.end()) {
    // Mark this bucket as "in progress."
    std::map<int, dcb_state_t>::value_type val(cur, DCB_STATE_IN_PROGRESS);
    std::pair <std::map<int, dcb_state_t>::iterator, bool> rval
      (dcb_states.insert(val));
    assert(rval.second);
    c = rval.first;
  }
  else if (c->second == DCB_STATE_DONE) {
    // We already did this bucket.
    return 0;
  }
  else if (c->second == DCB_STATE_IN_PROGRESS) {
    err << "decompile_crush_bucket: logic error: tried to decompile "
	"a bucket that is already being decompiled" << std::endl;
    return -EBADE;
  }
  else {
    err << "decompile_crush_bucket: logic error: illegal bucket state! "
	 << c->second << std::endl;
    return -EBADE;
  }

  int bsize = crush.get_bucket_size(cur);
  for (int i = 0; i < bsize; ++i) {
    int item = crush.get_bucket_item(cur, i);
    std::map<int, dcb_state_t>::iterator d = dcb_states.find(item);
    if (d == dcb_states.end()) {
      int ret = decompile_bucket(item, dcb_states, out);
      if (ret)
	return ret;
    }
    else if (d->second == DCB_STATE_IN_PROGRESS) {
      err << "decompile_crush_bucket: error: while trying to output bucket "
	   << cur << ", we found out that it contains one of the buckets that "
	   << "contain it. This is not allowed. The buckets must form a "
	   <<  "directed acyclic graph." << std::endl;
      return -EINVAL;
    }
    else if (d->second != DCB_STATE_DONE) {
      err << "decompile_crush_bucket: logic error: illegal bucket state "
	   << d->second << std::endl;
      return -EBADE;
    }
  }
  decompile_bucket_impl(cur, out);
  c->second = DCB_STATE_DONE;
  return 0;
}

int CrushCompiler::decompile(ostream &out)
{
  out << "# begin crush map\n";

  // only dump tunables if they differ from the defaults
  if (crush.get_choose_local_tries() != 2)
    out << "tunable choose_local_tries " << crush.get_choose_local_tries() << "\n";
  if (crush.get_choose_local_fallback_tries() != 5)
    out << "tunable choose_local_fallback_tries " << crush.get_choose_local_fallback_tries() << "\n";
  if (crush.get_choose_total_tries() != 19)
    out << "tunable choose_total_tries " << crush.get_choose_total_tries() << "\n";
  if (crush.get_chooseleaf_descend_once() != 0)
    out << "tunable chooseleaf_descend_once " << crush.get_chooseleaf_descend_once() << "\n";
  if (crush.get_chooseleaf_vary_r() != 0)
    out << "tunable chooseleaf_vary_r " << crush.get_chooseleaf_vary_r() << "\n";
  if (crush.get_chooseleaf_stable() != 0)
    out << "tunable chooseleaf_stable " << crush.get_chooseleaf_stable() << "\n";
  if (crush.get_straw_calc_version() != 0)
    out << "tunable straw_calc_version " << crush.get_straw_calc_version() << "\n";
  if (crush.get_allowed_bucket_algs() != CRUSH_LEGACY_ALLOWED_BUCKET_ALGS)
    out << "tunable allowed_bucket_algs " << crush.get_allowed_bucket_algs()
	<< "\n";

  out << "\n# devices\n";
  for (int i=0; i<crush.get_max_devices(); i++) {
    out << "device " << i << " ";
    print_item_name(out, i, crush);
    out << "\n";
  }
  
  out << "\n# types\n";
  int n = crush.get_num_type_names();
  for (int i=0; n; i++) {
    const char *name = crush.get_type_name(i);
    if (!name) {
      if (i == 0) out << "type 0 osd\n";
      continue;
    }
    n--;
    out << "type " << i << " " << name << "\n";
  }

  out << "\n# buckets\n";
  std::map<int, dcb_state_t> dcb_states;
  for (int bucket = -1; bucket > -1-crush.get_max_buckets(); --bucket) {
    int ret = decompile_bucket(bucket, dcb_states, out);
    if (ret)
      return ret;
  }

  out << "\n# rules\n";
  for (int i=0; i<crush.get_max_rules(); i++) {
    if (!crush.rule_exists(i))
      continue;
    out << "rule ";
    if (crush.get_rule_name(i))
      print_rule_name(out, i, crush);
    out << " {\n";
    out << "\truleset " << crush.get_rule_mask_ruleset(i) << "\n";

    switch (crush.get_rule_mask_type(i)) {
    case CEPH_PG_TYPE_REPLICATED:
      out << "\ttype replicated\n";
      break;
    case CEPH_PG_TYPE_ERASURE:
      out << "\ttype erasure\n";
      break;
    default:
      out << "\ttype " << crush.get_rule_mask_type(i) << "\n";
    }

    out << "\tmin_size " << crush.get_rule_mask_min_size(i) << "\n";
    out << "\tmax_size " << crush.get_rule_mask_max_size(i) << "\n";

    for (int j=0; j<crush.get_rule_len(i); j++) {
      switch (crush.get_rule_op(i, j)) {
      case CRUSH_RULE_NOOP:
	out << "\tstep noop\n";
	break;
      case CRUSH_RULE_TAKE:
	out << "\tstep take ";
	print_item_name(out, crush.get_rule_arg1(i, j), crush);
	out << "\n";
	break;
      case CRUSH_RULE_EMIT:
	out << "\tstep emit\n";
	break;
      case CRUSH_RULE_SET_CHOOSE_TRIES:
	out << "\tstep set_choose_tries " << crush.get_rule_arg1(i, j)
	    << "\n";
	break;
      case CRUSH_RULE_SET_CHOOSE_LOCAL_TRIES:
	out << "\tstep set_choose_local_tries " << crush.get_rule_arg1(i, j)
	    << "\n";
	break;
      case CRUSH_RULE_SET_CHOOSE_LOCAL_FALLBACK_TRIES:
	out << "\tstep set_choose_local_fallback_tries " << crush.get_rule_arg1(i, j)
	    << "\n";
	break;
      case CRUSH_RULE_SET_CHOOSELEAF_TRIES:
	out << "\tstep set_chooseleaf_tries " << crush.get_rule_arg1(i, j)
	    << "\n";
	break;
      case CRUSH_RULE_SET_CHOOSELEAF_VARY_R:
	out << "\tstep set_chooseleaf_vary_r " << crush.get_rule_arg1(i, j)
	    << "\n";
	break;
      case CRUSH_RULE_SET_CHOOSELEAF_STABLE:
	out << "\tstep set_chooseleaf_stable " << crush.get_rule_arg1(i, j)
	    << "\n";
	break;
      case CRUSH_RULE_CHOOSE_FIRSTN:
	out << "\tstep choose firstn "
	    << crush.get_rule_arg1(i, j) 
	    << " type ";
	print_type_name(out, crush.get_rule_arg2(i, j), crush);
	out << "\n";
	break;
      case CRUSH_RULE_CHOOSE_INDEP:
	out << "\tstep choose indep "
	    << crush.get_rule_arg1(i, j) 
	    << " type ";
	print_type_name(out, crush.get_rule_arg2(i, j), crush);
	out << "\n";
	break;
      case CRUSH_RULE_CHOOSELEAF_FIRSTN:
	out << "\tstep chooseleaf firstn "
	    << crush.get_rule_arg1(i, j) 
	    << " type ";
	print_type_name(out, crush.get_rule_arg2(i, j), crush);
	out << "\n";
	break;
      case CRUSH_RULE_CHOOSELEAF_INDEP:
	out << "\tstep chooseleaf indep "
	    << crush.get_rule_arg1(i, j) 
	    << " type ";
	print_type_name(out, crush.get_rule_arg2(i, j), crush);
	out << "\n";
	break;
      }
    }
    out << "}\n";
  }
  out << "\n# end crush map" << std::endl;
  return 0;
}


// ================================================================

string CrushCompiler::string_node(node_t &node)
{
  return boost::trim_copy(string(node.value.begin(), node.value.end()));
}

int CrushCompiler::int_node(node_t &node) 
{
  string str = string_node(node);
  return strtol(str.c_str(), 0, 10);
}

float CrushCompiler::float_node(node_t &node)
{
  string s = string_node(node);
  return strtof(s.c_str(), 0);
}

int CrushCompiler::parse_device(iter_t const& i)
{
  int id = int_node(i->children[1]);

  string name = string_node(i->children[2]);
  crush.set_item_name(id, name.c_str());
  if (item_id.count(name)) {
    err << "item " << name << " defined twice" << std::endl;
    return -1;
  }    
  item_id[name] = id;//
  id_item[id] = name;

  if (verbose) err << "device " << id << " '" << name << "'" << std::endl;
  return 0;
}

int CrushCompiler::parse_tunable(iter_t const& i)
{
  string name = string_node(i->children[1]);
  int val = int_node(i->children[2]);

  if (name == "choose_local_tries")
    crush.set_choose_local_tries(val);
  else if (name == "choose_local_fallback_tries")
    crush.set_choose_local_fallback_tries(val);
  else if (name == "choose_total_tries")
    crush.set_choose_total_tries(val);
  else if (name == "chooseleaf_descend_once")
    crush.set_chooseleaf_descend_once(val);
  else if (name == "chooseleaf_vary_r")
    crush.set_chooseleaf_vary_r(val);
  else if (name == "chooseleaf_stable")
    crush.set_chooseleaf_stable(val);
  else if (name == "straw_calc_version")
    crush.set_straw_calc_version(val);
  else if (name == "allowed_bucket_algs")
    crush.set_allowed_bucket_algs(val);
  else {
    err << "tunable " << name << " not recognized" << std::endl;
    return -1;
  }

  /*

    current crop of tunables are all now "safe".  re-enable this when we
    add new ones that are ... new.

  if (!unsafe_tunables) {
    err << "tunables are NOT FULLY IMPLEMENTED; enable with --enable-unsafe-tunables to enable this feature" << std::endl;
    return -1;
  }
  */

  if (verbose) err << "tunable " << name << " " << val << std::endl;
  return 0;
}

int CrushCompiler::parse_bucket_type(iter_t const& i)
{
  int id = int_node(i->children[1]);
  string name = string_node(i->children[2]);
  if (verbose) err << "type " << id << " '" << name << "'" << std::endl;
  type_id[name] = id;
  crush.set_type_name(id, name.c_str());
  return 0;
}

//bucket = name >> name >> '{' >> !bucket_id >> bucket_alg >> *bucket_hash >> *bucket_item >> '}'
int CrushCompiler::parse_bucket(iter_t const& i)
{
  string tname = string_node(i->children[0]);//桶类型名称
  if (!type_id.count(tname)) {
    err << "bucket type '" << tname << "' is not defined" << std::endl;
    return -1;
  }
  int type = type_id[tname];

  string name = string_node(i->children[1]);//桶名称不能是device已定义的名称.桶名不能是之前已定义的桶名称
  if (item_id.count(name)) {
    err << "bucket or device '" << name << "' is already defined" << std::endl;
    return -1;
  }

  int id = 0;  // none, yet!
  int alg = -1;
  int hash = 0;
  set<int> used_items;
  int size = 0;
  
  //bucket_id = str_p("id") >> negint;
  //bucket_alg = str_p("alg") >> name;
  //bucket_hash = str_p("hash") >> ( integer | str_p("rjenkins1") );
  //bucket_item = str_p("item") >> name >> !( str_p("weight") >> real_p ) >> !( str_p("pos") >> posint );
  //pos关键字用于定义位置
  for (unsigned p=3; p<i->children.size()-1; p++) {
    iter_t sub = i->children.begin() + p;
    string tag = string_node(sub->children[0]);
    //err << "tag " << tag << std::endl;
    if (tag == "id") //桶的id字段
      id = int_node(sub->children[1]);//处理bucket_id
    else if (tag == "alg") {//桶的算法字段
      string a = string_node(sub->children[1]);//处理bucket_alg
      if (a == "uniform")
	alg = CRUSH_BUCKET_UNIFORM;
      else if (a == "list")
	alg = CRUSH_BUCKET_LIST;
      else if (a == "tree")
	alg = CRUSH_BUCKET_TREE;
      else if (a == "straw")
	alg = CRUSH_BUCKET_STRAW;
      else if (a == "straw2")
	alg = CRUSH_BUCKET_STRAW2;
      else {
	err << "unknown bucket alg '" << a << "'" << std::endl << std::endl;
	return -EINVAL;
      }
    }
    else if (tag == "hash") {//处理bucket　hash字段
      string a = string_node(sub->children[1]);
      if (a == "rjenkins1")
	hash = CRUSH_HASH_RJENKINS1;//注：rjenkins1与a=='0'是等价的
      else
	hash = atoi(a.c_str());
    }
    else if (tag == "item") {//处理bucket_item（处理桶的子项）
    	//但这里我们仅关注pos格式的情况
      // first, just determine which item pos's are already used
      size++;//对item数进行计数。
      for (unsigned q = 2; q < sub->children.size(); q++) {
	string tag = string_node(sub->children[q++]);
	if (tag == "pos") {//仅考虑pos情况
	  int pos = int_node(sub->children[q]);
	  if (used_items.count(pos)) {
	    err << "item '" << string_node(sub->children[1]) << "' in bucket '" << name << "' has explicit pos " << pos << ", which is occupied" << std::endl;
	    return -1;
	  }
	  used_items.insert(pos);
	}
      }
    }
    else ceph_abort();
  }

  // now do the items.
  if (!used_items.empty())
    size = MAX(size, *used_items.rbegin());
  vector<int> items(size);
  vector<int> weights(size);

  int curpos = 0;
  unsigned bucketweight = 0;
  bool have_uniform_weight = false;
  unsigned uniform_weight = 0;
  for (unsigned p=3; p<i->children.size()-1; p++) {
	  //仅处理bucket_item = str_p("item") >> name >> !( str_p("weight") >> real_p ) >> !( str_p("pos") >> posint );情况
    iter_t sub = i->children.begin() + p;
    string tag = string_node(sub->children[0]);
    if (tag == "item") {

      string iname = string_node(sub->children[1]);//取出子项的名称（bucket或device中已定义）
      if (!item_id.count(iname)) {//规则需要保证item指定的项已定义。所以bucket,device在定义时需要与树根方向反着定义。
	err << "item '" << iname << "' in bucket '" << name << "' is not defined" << std::endl;
	return -1;
      }
      int itemid = item_id[iname];//item <item_name>　//找出子项对应的id

      unsigned weight = 0x10000;//默认权重
      if (item_weight.count(itemid))//取出子项指定的权重
	weight = item_weight[itemid];//如果item_weight已有权重，否则默认为0x10000（这种事先为子项配置了权重）

      int pos = -1;
      for (unsigned q = 2; q < sub->children.size(); q++) {//完成bucket_item解析
	string tag = string_node(sub->children[q++]);
	if (tag == "weight") {//weight配置
	  weight = float_node(sub->children[q]) * (float)0x10000;//配置的值不能超过１００（这里更改了子项的权重）
	  if (weight > CRUSH_MAX_DEVICE_WEIGHT && itemid >= 0) {//weight过大（device　id均为>=0)
	    err << "device weight limited to " << CRUSH_MAX_DEVICE_WEIGHT / 0x10000 << std::endl;
	    return -ERANGE;
	  }
	  else if (weight > CRUSH_MAX_BUCKET_WEIGHT && itemid < 0) {//bucket　id均为<0，权重不得大于１００
	    err << "bucket weight limited to " << CRUSH_MAX_BUCKET_WEIGHT / 0x10000
	        << " to prevent overflow" << std::endl;
	    return -ERANGE;
	  }
	}
	else if (tag == "pos") 
	  pos = int_node(sub->children[q]);
	else
	  ceph_abort();

      }//一行item解析完成
      if (alg == CRUSH_BUCKET_UNIFORM) {//uniform要求多个item的权重是相同的
	if (!have_uniform_weight) {
	  have_uniform_weight = true;
	  uniform_weight = weight;
	} else {
	  if (uniform_weight != weight) {
	    err << "item '" << iname << "' in uniform bucket '" << name << "' has weight " << weight
		<< " but previous item(s) have weight " << (float)uniform_weight/(float)0x10000
		<< "; uniform bucket items must all have identical weights." << std::endl;
	    return -1;
	  }
	}
      }

      if (pos >= size) {//pos指定超过size值，说明定位有误（pos不能大于等于item的数目)
	err << "item '" << iname << "' in bucket '" << name << "' has pos " << pos << " >= size " << size << std::endl;
	return -1;
      }
      if (pos < 0) {
	while (used_items.count(curpos)) curpos++;
	pos = curpos++;
      }
      //err << " item " << iname << " (" << itemid << ") pos " << pos << " weight " << weight << std::endl;
      items[pos] = itemid;
      weights[pos] = weight;//记录每一个item的weights

      if (crush_addition_is_unsafe(bucketweight, weight)) {//检查bucketweight 加上weight后是否会发生uint32溢出
        err << "oh no! our bucket weights are overflowing all over the place, better lower the item weights" << std::endl;
        return -ERANGE;//将发生溢出
      }

      bucketweight += weight;//计算桶出权重数
    }
  }//第二次处理item完成

  if (id == 0) {
    for (id=-1; id_item.count(id); id--) ;//如果id设置为０，则为bucket探测id
    //err << "assigned id " << id << std::endl;
  }

  if (verbose) err << "bucket " << name << " (" << id << ") " << size << " items and weight "
		   << (float)bucketweight / (float)0x10000 << std::endl;//显示bucket名称，id,item数目，item总权重
  id_item[id] = name;
  item_id[name] = id;//填充item
  item_weight[id] = bucketweight;
  
  assert(id != 0);
  int r = crush.add_bucket(id, alg, hash, type, size, &items[0], &weights[0], NULL);//添加桶（size是item的大小，items中记录各item数据，weights记录各item对应权重）
  if (r < 0) {
    if (r == -EEXIST)
      err << "Duplicate bucket id " << id << std::endl;
    else
      err << "add_bucket failed " << cpp_strerror(r) << std::endl;
    return r;
  }
  r = crush.set_item_name(id, name.c_str());
  return r;
}

//规则解析
int CrushCompiler::parse_rule(iter_t const& i)
{
  int start;  // rule name is optional!
 
  string rname = string_node(i->children[1]);//取名称
  if (rname != "{") {//有名称的规则
    if (rule_id.count(rname)) {
      err << "rule name '" << rname << "' already defined\n" << std::endl;
      return -1;
    }
    start = 4;
  } else {//无名称的规则
    rname = string();
    start = 3;
  }

  //ruleset　id值的位置按有名称与无名称偏移量不同
  int ruleset = int_node(i->children[start]);

  string tname = string_node(i->children[start+2]);//适用范围（副本，纠错码）
  int type;
  if (tname == "replicated")
    type = CEPH_PG_TYPE_REPLICATED;
  else if (tname == "erasure")
    type = CEPH_PG_TYPE_ERASURE;
  else 
    ceph_abort();

  int minsize = int_node(i->children[start+4]);//最小值
  int maxsize = int_node(i->children[start+6]);//最大值
  
  int steps = i->children.size() - start - 8;//steps是语法树上'step'需要解析大小。我们一会就会解析这段数据
  //err << "num steps " << steps << std::endl;
  
  //这里应该用for循环处理下steps的size数再传入，作者这样处理太简洁，size过大。
  int ruleno = crush.add_rule(steps, ruleset, type, minsize, maxsize, -1);//提前告诉rule,我们后面最多有steps个step{最大值,肯定不超过这个值}
  if (rname.length()) {//有名称的规则
    crush.set_rule_name(ruleno, rname.c_str());//设置规则名称
    rule_id[rname] = ruleno;
  }

  //解析step对应的数据,给规则添加step操作
  int step = 0;
  for (iter_t p = i->children.begin() + start + 7; step < steps; p++) {
    iter_t s = p->children.begin() + 1;
    int stepid = s->value.id().to_long();
    switch (stepid) {
    case crush_grammar::_step_take: //处理take子规则，step_take = str_p("take") >> name;
      {
	string item = string_node(s->children[1]);
	if (!item_id.count(item)) {
	  err << "in rule '" << rname << "' item '" << item << "' not defined" << std::endl;
	  return -1;
	}
	crush.set_rule_step_take(ruleno, step++, item_id[item]);//这里将item转为id号
      }
      break;

    case crush_grammar::_step_set_choose_tries://处理choose子规则，step_set_choose_tries = str_p("set_choose_tries") >> posint;
      {
	int val = int_node(s->children[1]);
	crush.set_rule_step_set_choose_tries(ruleno, step++, val);
      }
      break;

    case crush_grammar::_step_set_choose_local_tries://step_set_choose_local_tries = str_p("set_choose_local_tries") >> posint;
      {
	int val = int_node(s->children[1]);
	crush.set_rule_step_set_choose_local_tries(ruleno, step++, val);
      }
      break;

    case crush_grammar::_step_set_choose_local_fallback_tries://str_p("set_choose_local_fallback_tries") >> posint
      {
	int val = int_node(s->children[1]);
	crush.set_rule_step_set_choose_local_fallback_tries(ruleno, step++, val);
      }
      break;

    case crush_grammar::_step_set_chooseleaf_tries://str_p("set_chooseleaf_tries") >> posint;
      {
	int val = int_node(s->children[1]);
	crush.set_rule_step_set_chooseleaf_tries(ruleno, step++, val);
      }
      break;

    case crush_grammar::_step_set_chooseleaf_vary_r://str_p("set_chooseleaf_vary_r") >> posint;
      {
	int val = int_node(s->children[1]);
	crush.set_rule_step_set_chooseleaf_vary_r(ruleno, step++, val);
      }
      break;

    case crush_grammar::_step_set_chooseleaf_stable://str_p("set_chooseleaf_stable") >> posint;
      {
	int val = int_node(s->children[1]);
	crush.set_rule_step_set_chooseleaf_stable(ruleno, step++, val);
      }
      break;

    case crush_grammar::_step_choose://str_p("choose") >> ( str_p("indep") | str_p("firstn") )
									 // >> integer >> str_p("type") >> name;
    case crush_grammar::_step_chooseleaf:  //str_p("chooseleaf") >> ( str_p("indep") | str_p("firstn") )
    								// >> integer >> str_p("type") >> name;
      {
	string type = string_node(s->children[4]);
	if (!type_id.count(type)) {
	  err << "in rule '" << rname << "' type '" << type << "' not defined" << std::endl;
	  return -1;
	}
	string choose = string_node(s->children[0]);//那种choose,{choose,chooseleaf}
	string mode = string_node(s->children[1]);//那种模式 {'indep','firstn'}
	if (choose == "choose") {
	  if (mode == "firstn")
	    crush.set_rule_step_choose_firstn(ruleno, step++, int_node(s->children[2]), type_id[type]);
	  else if (mode == "indep")
	    crush.set_rule_step_choose_indep(ruleno, step++, int_node(s->children[2]), type_id[type]);
	  else ceph_abort();
	} else if (choose == "chooseleaf") {
	  if (mode == "firstn") 
	    crush.set_rule_step_choose_leaf_firstn(ruleno, step++, int_node(s->children[2]), type_id[type]);
	  else if (mode == "indep")
	    crush.set_rule_step_choose_leaf_indep(ruleno, step++, int_node(s->children[2]), type_id[type]);
	  else ceph_abort();
	} else ceph_abort();
      }
      break;

    case crush_grammar::_step_emit://step_emit = str_p("emit");
      crush.set_rule_step_emit(ruleno, step++);
      break;

    default:
      err << "bad crush step " << stepid << std::endl;
      return -1;
    }
  }
  assert(step == steps);
  return 0;
}

void CrushCompiler::find_used_bucket_ids(iter_t const& i)
{
  for (iter_t p = i->children.begin(); p != i->children.end(); p++) {
    if ((int)p->value.id().to_long() == crush_grammar::_bucket) {
      iter_t firstline = p->children.begin() + 3;
      string tag = string_node(firstline->children[0]);
      if (tag == "id") {
	int id = int_node(firstline->children[1]);
	//err << "saw bucket id " << id << std::endl;
	id_item[id] = string();
      }
    }
  }
}

/*
 *
device 0 osd.0
device 1 osd.1
device 2 osd.2
device 3 osd.3
device 4 osd.4
device 5 osd.5
device 6 osd.6
device 7 osd.7

      host ceph-osd-ssd-server-1 {
              id -1
              alg straw
              hash 0
              item osd.0 weight 1.00
              item osd.1 weight 1.00
      }

      host ceph-osd-ssd-server-2 {
              id -2
              alg straw
              hash 0
              item osd.2 weight 1.00
              item osd.3 weight 1.00
      }

      host ceph-osd-platter-server-1 {
              id -3
              alg straw
              hash 0
              item osd.4 weight 1.00
              item osd.5 weight 1.00
      }

      host ceph-osd-platter-server-2 {
              id -4
              alg straw
              hash 0
              item osd.6 weight 1.00
              item osd.7 weight 1.00
      }

      root platter {
              id -5
              alg straw
              hash 0
              item ceph-osd-platter-server-1 weight 2.00
              item ceph-osd-platter-server-2 weight 2.00
      }

      root ssd {
              id -6
              alg straw
              hash 0
              item ceph-osd-ssd-server-1 weight 2.00
              item ceph-osd-ssd-server-2 weight 2.00
      }

      rule data {
              ruleset 0
              type replicated
              min_size 2
              max_size 2
              step take platter
              step chooseleaf firstn 0 type host
              step emit
      }

      rule metadata {
              ruleset 1
              type replicated
              min_size 0
              max_size 10
              step take platter
              step chooseleaf firstn 0 type host
              step emit
      }

      rule rbd {
              ruleset 2
              type replicated
              min_size 0
              max_size 10
              step take platter
              step chooseleaf firstn 0 type host
              step emit
      }

      rule platter {
              ruleset 3
              type replicated
              min_size 0
              max_size 10
              step take platter
              step chooseleaf firstn 0 type host
              step emit
      }

      rule ssd {
              ruleset 4
              type replicated
              min_size 0
              max_size 4
              step take ssd
              step chooseleaf firstn 0 type host
              step emit
      }

      rule ssd-primary {
              ruleset 5
              type replicated
              min_size 5
              max_size 10
              step take ssd
              step chooseleaf firstn 1 type host
              step emit
              step take platter
              step chooseleaf firstn -1 type host
              step emit
      }
 */
int CrushCompiler::parse_crush(iter_t const& i) 
{ 
  find_used_bucket_ids(i);

  for (iter_t p = i->children.begin(); p != i->children.end(); p++) {
    int r = 0;
    switch (p->value.id().to_long()) {
    case crush_grammar::_tunable:
      r = parse_tunable(p);//定义可调整的一些参数“实际上没有必要，这些不可以做为配置项吗？
      break;
    case crush_grammar::_device: //device = str_p("device") >> posint >> name;
      r = parse_device(p);//定义device项，起提前声明作用,用于说明哪些是osd
      break;
    case crush_grammar::_bucket_type: //bucket_type = str_p("type") >> posint >> name;
      r = parse_bucket_type(p);//定义type项，起提前声明作用
      break;
    case crush_grammar::_bucket: //bucket = name >> name >> '{' >> !bucket_id >> bucket_alg >> *bucket_hash >> *bucket_item >> '}';
      r = parse_bucket(p);
      break;
    case crush_grammar::_crushrule: //rule <name> { .* }
      r = parse_rule(p);//分析rule
      break;
    default:
      ceph_abort();
    }
    if (r < 0) {
      return r;
    }
  }

  //err << "max_devices " << crush.get_max_devices() << std::endl;
  crush.finalize();
  
  return 0;
} 

// squash runs of whitespace to one space, excepting newlines
string CrushCompiler::consolidate_whitespace(string in)
{
  string out;

  bool white = false;
  for (unsigned p=0; p<in.length(); p++) {
    if (isspace(in[p]) && in[p] != '\n') {
      if (white)
	continue;
      white = true;
    } else {
      if (white) {
	if (out.length()) out += " ";
	white = false;
      }
      out += in[p];
    }
  }
  if (verbose > 3)
    err << " \"" << in << "\" -> \"" << out << "\"" << std::endl;
  return out;
}

void CrushCompiler::dump(iter_t const& i, int ind) 
{
  err << "dump"; 
  for (int j=0; j<ind; j++)
    cout << "\t"; 
  long id = i->value.id().to_long();
  err << id << "\t"; 
  err << "'" << string(i->value.begin(), i->value.end())  
      << "' " << i->children.size() << " children" << std::endl; 
  for (unsigned int j = 0; j < i->children.size(); j++)  
    dump(i->children.begin() + j, ind+1); 
}

/**
*  This function fix the problem like below
*   rack using_foo { item foo }  
*   host foo { ... }
*
*  if an item being used by a bucket is defined after that bucket. 
*  CRUSH compiler will create a map by which we can 
*  not identify that item when selecting in that bucket.
**/
int CrushCompiler::adjust_bucket_item_place(iter_t const &i)
{
  map<string,set<string> > bucket_items;
  map<string,iter_t> bucket_itrer;
  vector<string> buckets;
  for (iter_t p = i->children.begin(); p != i->children.end(); ++p) {
    if ((int)p->value.id().to_long() == crush_grammar::_bucket) {
      string name = string_node(p->children[1]);
      buckets.push_back(name);
      bucket_itrer[name] = p;
      //skip non-bucket-item children in the bucket's parse tree
      for (unsigned q=3; q < p->children.size()-1; ++q) {
        iter_t sub = p->children.begin() + q;
        if ((int)sub->value.id().to_long() 
          == crush_grammar::_bucket_item) {
          string iname = string_node(sub->children[1]);
          bucket_items[name].insert(iname);
        }         
      }       
    }     
  }
  
  //adjust the bucket
  for (unsigned i=0; i < buckets.size(); ++i) { 
    for (unsigned j=i+1; j < buckets.size(); ++j) {
      if (bucket_items[buckets[i]].count(buckets[j])) {
        if (bucket_items[buckets[j]].count(buckets[i])) {
          err << "bucket  '" <<  buckets[i] << "' and bucket '"
          << buckets[j] << "' are included each other" << std::endl;
          return -1; 
        } else {  
	   std::iter_swap(bucket_itrer[buckets[i]], bucket_itrer[buckets[j]]);
        } 
      } 
    }
  }
	
  return 0;
}

int CrushCompiler::compile(istream& in, const char *infn)
{
  if (!infn)
    infn = "<input>";

  // always start with legacy tunables, so that the compiled result of
  // a given crush file is fixed for all time.
  crush.set_tunables_legacy();

  string big;
  string str;
  int line = 1;
  map<int,int> line_pos;  // pos -> line
  map<int,string> line_val;
  while (getline(in, str)) {
    // remove newline
    int l = str.length();
    if (l && str[l - 1] == '\n')
      str.erase(l-1, 1);

    line_val[line] = str;

    // strip comment
    int n = str.find("#");
    if (n >= 0)
      str.erase(n, str.length()-n);
    
    if (verbose>1) err << line << ": " << str << std::endl;

    // work around spirit crankiness by removing extraneous
    // whitespace.  there is probably a more elegant solution, but
    // this only broke with the latest spirit (with the switchover to
    // "classic"), i don't want to spend too much time figuring it
    // out.
    string stripped = consolidate_whitespace(str);
    if (stripped.length() && big.length() && big[big.length()-1] != ' ') big += " ";

    line_pos[big.length()] = line;
    line++;
    big += stripped;
  }
  
  if (verbose > 2) err << "whole file is: \"" << big << "\"" << std::endl;
  
  crush_grammar crushg;
  const char *start = big.c_str();
  //tree_parse_info<const char *> info = ast_parse(start, crushg, space_p);
  tree_parse_info<> info = ast_parse(start, crushg, space_p);
  
  // parse error?
  if (!info.full) {
    int cpos = info.stop - start;
    //out << "cpos " << cpos << std::endl;
    //out << " linemap " << line_pos << std::endl;
    assert(!line_pos.empty());
    map<int,int>::iterator p = line_pos.upper_bound(cpos);
    if (p != line_pos.begin())
      --p;
    int line = p->second;
    int pos = cpos - p->first;
    err << infn << ":" << line //<< ":" << (pos+1)
	<< " error: parse error at '" << line_val[line].substr(pos) << "'" << std::endl;
    return -1;
  }
  
  int r = adjust_bucket_item_place(info.trees.begin());
  if (r < 0) {
    return r;
  }
  //out << "parsing succeeded\n";
  //dump(info.trees.begin());
  return parse_crush(info.trees.begin());
}
