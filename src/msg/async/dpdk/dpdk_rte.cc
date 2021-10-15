/*
 * This file is open source software, licensed to you under the terms
 * of the Apache License, Version 2.0 (the "License").  See the NOTICE file
 * distributed with this work for additional information regarding copyright
 * ownership.  You may not use this file except in compliance with the License.
 *
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

#include <bitset>

#include <rte_config.h>
#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_version.h>

#include "DPDK.h"
#include "dpdk_rte.h"

namespace dpdk {

  static inline std::vector<char> string2vector(std::string str) {
    auto v = std::vector<char>(str.begin(), str.end());
    v.push_back('\0');
    return v;
  }

  bool eal::initialized = false;
  std::thread eal::t;
  std::mutex eal::lock;
  std::condition_variable eal::cond;
  std::list<std::function<void()>> eal::funcs;

  static int bitcount(unsigned long long n)
  {
    return std::bitset<CHAR_BIT * sizeof(n)>{n}.count();
  }

  static int hex2bitcount(unsigned char c)
  {
    int val;

    if (isdigit(c))
      val = c - '0';
    else if (isupper(c))
      val = c - 'A' + 10;
    else
      val = c - 'a' + 10;
    return bitcount(val);
  }

  static int coremask_bitcount(const char *buf)
  {
    int count = 0;

    if (buf[0] == '0' && 
        ((buf[1] == 'x') || (buf[1] == 'X')))
      buf += 2;

    for (int i = 0; buf[i] != '\0'; i++) {
      char c = buf[i];
      if (isxdigit(c) == 0)
        return -EINVAL;
      count += hex2bitcount(c);
    }
    return count;
  }

  int eal::init(CephContext *c)
  {
    if (initialized) {
      return 1;
    }

    bool done = false;
    auto coremask = c->_conf.get_val<std::string>("ms_dpdk_coremask");
    int coremaskbit = coremask_bitcount(coremask.c_str());

    if (coremaskbit <= 0
        || static_cast<uint64_t>(coremaskbit) < c->_conf->ms_async_op_threads)
      return -EINVAL;

    t = std::thread([&]() {
      // TODO: Inherit these from the app parameters - "opts"
      std::vector<std::vector<char>> args {
          string2vector("ceph"),
          string2vector("-c"), string2vector(c->_conf.get_val<std::string>("ms_dpdk_coremask")),
          string2vector("-n"), string2vector(c->_conf->ms_dpdk_memory_channel),
      };

      std::optional<std::string> hugepages_path;
      if (!c->_conf->ms_dpdk_hugepages.empty()) {
        hugepages_path.emplace(c->_conf->ms_dpdk_hugepages);
      }

      // If "hugepages" is not provided and DPDK PMD drivers mode is requested -
      // use the default DPDK huge tables configuration.
      if (hugepages_path) {
        args.push_back(string2vector("--huge-dir"));
        args.push_back(string2vector(*hugepages_path));

        //
        // We don't know what is going to be our networking configuration so we
        // assume there is going to be a queue per-CPU. Plus we'll give a DPDK
        // 64MB for "other stuff".
        //
        unsigned int x;
        std::stringstream ss;
        ss << std::hex << "fffefffe";
        ss >> x;
        size_t size_MB = mem_size(bitcount(x)) >> 20;
        std::stringstream size_MB_str;
        size_MB_str << size_MB;

        args.push_back(string2vector("-m"));
        args.push_back(string2vector(size_MB_str.str()));
      } else if (!c->_conf->ms_dpdk_pmd.empty()) {
        args.push_back(string2vector("--no-huge"));
      }

      std::optional<std::string> port_list;
      if (!c->_conf->ms_dpdk_port_list.empty()) {
	port_list.emplace(c->_conf->ms_dpdk_port_list);
      }
      if (port_list) {
	char *port = strtok(const_cast<char *>(port_list->c_str()), ",");
	while(port) {
	  args.push_back(string2vector("--pci-whitelist"));
	  args.push_back(string2vector(port));
	  port = strtok(NULL, ",");
	}
      }

      std::string rte_file_prefix;
      rte_file_prefix = "rte_";
      rte_file_prefix += c->_conf->name.to_str();
      args.push_back(string2vector("--file-prefix"));
      args.push_back(string2vector(rte_file_prefix));

      std::vector<char*> cargs;

      for (auto&& a: args) {
        cargs.push_back(a.data());
      }
      /* initialise the EAL for all */
      int ret = rte_eal_init(cargs.size(), cargs.data());
      if (ret < 0)
        return ret;

      std::unique_lock<std::mutex> l(lock);
      initialized = true;
      done = true;
      cond.notify_all();
      while (true) {
        if (!funcs.empty()) {
          auto f = std::move(funcs.front());
          funcs.pop_front();
          f();
          cond.notify_all();
        } else {
          cond.wait(l);
        }
      }
    });
    t.detach();
    std::unique_lock<std::mutex> l(lock);
    while (!done)
      cond.wait(l);
    return 0;
  }

  size_t eal::mem_size(int num_cpus)
  {
    size_t memsize = 0;
    //
    // PMD mempool memory:
    //
    // We don't know what is going to be our networking configuration so we
    // assume there is going to be a queue per-CPU.
    //
    memsize += num_cpus * qp_mempool_obj_size();

    // Plus we'll give a DPDK 64MB for "other stuff".
    memsize += (64UL << 20);

    return memsize;
  }

} // namespace dpdk
