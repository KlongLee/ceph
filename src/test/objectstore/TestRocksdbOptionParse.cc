#include <gtest/gtest.h>
#include "include/Context.h"
#include "common/ceph_argparse.h"
#include "global/global_init.h"
#include "rocksdb/db.h"
#include "rocksdb/env.h"
#include "rocksdb/thread_status.h"
#include "kv/RocksDBStore.h"
#include <iostream>
using namespace std;

const string dir("store_test_temp_dir");

TEST(RocksDBOption, simple) {
  rocksdb::Options options;
  rocksdb::Status status;
  RocksDBStore *db = new RocksDBStore(g_ceph_context, dir);
  string options_string = ""
			  "write_buffer_size=536870912;"
			  "create_if_missing=true;"
			  "max_write_buffer_number=4;"
			  "max_background_compactions=4;"
			  "stats_dump_period_sec = 5;"
			  "min_write_buffer_number_to_merge = 2;"
			  "level0_file_num_compaction_trigger = 4;"
			  "max_bytes_for_level_base = 104857600;"
			  "target_file_size_base = 10485760;"
			  "num_levels = 3;"
			  "compression = kNoCompression;"
			  "disable_data_sync = false;";
  int r = db->ParseOptionsFromString(options_string, options);
  ASSERT_EQ(0, r);
  ASSERT_EQ(536870912, options.write_buffer_size);
  ASSERT_EQ(4, options.max_write_buffer_number);
  ASSERT_EQ(4, options.max_background_compactions);
  ASSERT_EQ(5, options.stats_dump_period_sec);
  ASSERT_EQ(2, options.min_write_buffer_number_to_merge);
  ASSERT_EQ(4, options.level0_file_num_compaction_trigger);
  ASSERT_EQ(104857600, options.max_bytes_for_level_base);
  ASSERT_EQ(10485760, options.target_file_size_base);
  ASSERT_EQ(3, options.num_levels);
  ASSERT_FALSE(options.disableDataSync);
 // ASSERT_EQ("none", options.compression);
}
TEST(RocksDBOption, interpret) {
  rocksdb::Options options;
  rocksdb::Status status;
  RocksDBStore *db = new RocksDBStore(g_ceph_context, dir);
  string options_string = "compact_on_mount = true; compaction_threads=10;flusher_threads=5;";
  
  int r = db->ParseOptionsFromString(options_string, options);
  ASSERT_EQ(0, r);
  ASSERT_TRUE(db->compact_on_mount);
  //check thread pool setting
  options.env->SleepForMicroseconds(100000);
  std::vector<rocksdb::ThreadStatus> thread_list;
  status = options.env->GetThreadList(&thread_list);
  ASSERT_TRUE(status.ok());

  int num_high_pri_threads = 0;
  int num_low_pri_threads = 0;
  for (vector<rocksdb::ThreadStatus>::iterator it = thread_list.begin();
	it!= thread_list.end();
	++it) {
    if (it->thread_type == rocksdb::ThreadStatus::HIGH_PRIORITY)
      num_high_pri_threads++;
    if (it->thread_type == rocksdb::ThreadStatus::LOW_PRIORITY)
      num_low_pri_threads++;
  }
  ASSERT_EQ(15, thread_list.size());
  //low pri threads is compaction_threads
  ASSERT_EQ(10, num_low_pri_threads);
  //high pri threads is flusher_threads
  ASSERT_EQ(5, num_high_pri_threads);
}

int main(int argc, char **argv) {
  vector<const char*> args;
  argv_to_vec(argc, (const char **)argv, args);
  env_to_vec(args);
  global_init(NULL, args, CEPH_ENTITY_TYPE_CLIENT, CODE_ENVIRONMENT_UTILITY, 0);
  common_init_finish(g_ceph_context);
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
