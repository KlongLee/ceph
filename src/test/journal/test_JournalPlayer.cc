// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#include "journal/JournalPlayer.h"
#include "journal/Entry.h"
#include "journal/JournalMetadata.h"
#include "journal/ReplayHandler.h"
#include "include/stringify.h"
#include "common/Cond.h"
#include "common/Mutex.h"
#include "gtest/gtest.h"
#include "test/journal/RadosTestFixture.h"
#include <list>
#include <boost/assign/list_of.hpp>

class TestJournalPlayer : public RadosTestFixture {
public:
  typedef std::list<journal::Entry> Entries;

  struct ReplayHandler : public journal::ReplayHandler {
    Mutex lock;
    Cond cond;
    bool entries_available;
    bool error_occurred;

    ReplayHandler()
      : lock("lock"), entries_available(false), error_occurred(false) {}

    virtual bool filter_entry(const std::string &tag) {
      return false;
    }

    virtual void handle_entries_available() {
      Mutex::Locker locker(lock);
      entries_available = true;
      cond.Signal();
    }

    virtual void handle_error(int r) {
      error_occurred = true;
    }
  };

  int create(const std::string &oid) {
    return RadosTestFixture::create(oid, 14, 2);
  }

  int client_register(const std::string &oid) {
    return RadosTestFixture::client_register(oid, "client", "");
  }

  int client_commit(const std::string &oid,
                    journal::JournalPlayer::ObjectSetPosition position) {
    return RadosTestFixture::client_commit(oid, "client", position);
  }

  journal::Entry create_entry(const std::string &tag, uint64_t tid) {
    bufferlist payload_bl;
    payload_bl.append("playload");
    return journal::Entry(tag, tid, payload_bl);
  }

  journal::JournalMetadataPtr create_metadata(const std::string &oid) {
    journal::JournalMetadataPtr metadata(new journal::JournalMetadata(
      m_ioctx, oid, "client"));
    return metadata;
  }

  journal::JournalPlayerPtr create_player(const std::string &oid,
                                          const journal::JournalMetadataPtr &metadata) {
    journal::JournalPlayerPtr player(new journal::JournalPlayer(
      m_ioctx, oid + ".", metadata, &m_replay_hander));
    return player;
  }

  bool wait_for_entries(journal::JournalPlayerPtr player, uint32_t count,
                        Entries *entries) {
    entries->clear();
    while (entries->size() < count) {
      journal::Entry entry;
      journal::JournalPlayer::ObjectSetPosition object_set_position;
      while (entries->size() < count &&
             player->try_pop_front(&entry, &object_set_position)) {
        entries->push_back(entry);
      }
      if (entries->size() == count) {
        break;
      }

      Mutex::Locker locker(m_replay_hander.lock);
      if (m_replay_hander.entries_available) {
        m_replay_hander.entries_available = false;
      } else if (m_replay_hander.cond.WaitInterval(
          reinterpret_cast<CephContext*>(m_ioctx.cct()),
          m_replay_hander.lock, utime_t(10, 0)) != 0) {
        break;
      }
    }
    return entries->size() == count;
  }

  int write_entry(const std::string &oid, uint64_t object_num,
                  const std::string &tag, uint64_t tid) {
    bufferlist bl;
    ::encode(create_entry(tag, tid), bl);
    return append(oid + "." + stringify(object_num), bl);
  }

  ReplayHandler m_replay_hander;
};

TEST_F(TestJournalPlayer, Prefetch) {
  std::string oid = get_temp_oid();

  journal::JournalPlayer::EntryPositions positions;
  positions = boost::assign::list_of(
    cls::journal::EntryPosition("tag1", 122));
  cls::journal::ObjectSetPosition commit_position(0, positions);

  ASSERT_EQ(0, create(oid));
  ASSERT_EQ(0, client_register(oid));
  ASSERT_EQ(0, client_commit(oid, commit_position));

  journal::JournalMetadataPtr metadata = create_metadata(oid);
  ASSERT_EQ(0, metadata->init());

  journal::JournalPlayerPtr player = create_player(oid, metadata);

  ASSERT_EQ(0, write_entry(oid, 0, "tag1", 122));
  ASSERT_EQ(0, write_entry(oid, 1, "tag1", 123));
  ASSERT_EQ(0, write_entry(oid, 0, "tag1", 124));
  ASSERT_EQ(0, write_entry(oid, 1, "tag1", 125));

  player->prefetch();

  Entries entries;
  ASSERT_TRUE(wait_for_entries(player, 3, &entries));

  Entries expected_entries;
  expected_entries = boost::assign::list_of(
    create_entry("tag1", 123))(
    create_entry("tag1", 124))(
    create_entry("tag1", 125));
  ASSERT_EQ(expected_entries, entries);

  uint64_t last_tid;
  ASSERT_TRUE(metadata->get_last_allocated_tid("tag1", &last_tid));
  ASSERT_EQ(125U, last_tid);
}

TEST_F(TestJournalPlayer, PrefetchWithoutCommit) {
  std::string oid = get_temp_oid();

  cls::journal::ObjectSetPosition commit_position;

  ASSERT_EQ(0, create(oid));
  ASSERT_EQ(0, client_register(oid));
  ASSERT_EQ(0, client_commit(oid, commit_position));

  journal::JournalMetadataPtr metadata = create_metadata(oid);
  ASSERT_EQ(0, metadata->init());

  journal::JournalPlayerPtr player = create_player(oid, metadata);

  ASSERT_EQ(0, write_entry(oid, 0, "tag1", 122));
  ASSERT_EQ(0, write_entry(oid, 1, "tag1", 123));

  player->prefetch();

  Entries entries;
  ASSERT_TRUE(wait_for_entries(player, 2, &entries));

  Entries expected_entries;
  expected_entries = boost::assign::list_of(
    create_entry("tag1", 122))(
    create_entry("tag1", 123));
  ASSERT_EQ(expected_entries, entries);
}

TEST_F(TestJournalPlayer, PrefetchMultipleTags) {
  std::string oid = get_temp_oid();

  journal::JournalPlayer::EntryPositions positions;
  positions = boost::assign::list_of(
    cls::journal::EntryPosition("tag1", 122))(
    cls::journal::EntryPosition("tag2", 1));
  cls::journal::ObjectSetPosition commit_position(0, positions);

  ASSERT_EQ(0, create(oid));
  ASSERT_EQ(0, client_register(oid));
  ASSERT_EQ(0, client_commit(oid, commit_position));

  journal::JournalMetadataPtr metadata = create_metadata(oid);
  ASSERT_EQ(0, metadata->init());

  journal::JournalPlayerPtr player = create_player(oid, metadata);

  ASSERT_EQ(0, write_entry(oid, 0, "tag1", 120));
  ASSERT_EQ(0, write_entry(oid, 0, "tag2", 0));
  ASSERT_EQ(0, write_entry(oid, 1, "tag1", 121));
  ASSERT_EQ(0, write_entry(oid, 1, "tag2", 1));
  ASSERT_EQ(0, write_entry(oid, 0, "tag1", 122));
  ASSERT_EQ(0, write_entry(oid, 1, "tag1", 123));
  ASSERT_EQ(0, write_entry(oid, 0, "tag1", 124));
  ASSERT_EQ(0, write_entry(oid, 0, "tag2", 2));

  player->prefetch();

  Entries entries;
  ASSERT_TRUE(wait_for_entries(player, 3, &entries));

  uint64_t last_tid;
  ASSERT_TRUE(metadata->get_last_allocated_tid("tag1", &last_tid));
  ASSERT_EQ(124U, last_tid);
  ASSERT_TRUE(metadata->get_last_allocated_tid("tag2", &last_tid));
  ASSERT_EQ(2U, last_tid);
}

TEST_F(TestJournalPlayer, PrefetchCorruptSequence) {
  std::string oid = get_temp_oid();

  cls::journal::ObjectSetPosition commit_position;

  ASSERT_EQ(0, create(oid));
  ASSERT_EQ(0, client_register(oid));
  ASSERT_EQ(0, client_commit(oid, commit_position));

  journal::JournalMetadataPtr metadata = create_metadata(oid);
  ASSERT_EQ(0, metadata->init());

  journal::JournalPlayerPtr player = create_player(oid, metadata);

  ASSERT_EQ(0, write_entry(oid, 0, "tag1", 120));
  ASSERT_EQ(0, write_entry(oid, 0, "tag2", 0));
  ASSERT_EQ(0, write_entry(oid, 1, "tag1", 121));
  ASSERT_EQ(0, write_entry(oid, 0, "tag1", 124));

  player->prefetch();
  Entries entries;
  ASSERT_TRUE(wait_for_entries(player, 3, &entries));

  journal::Entry entry;
  cls::journal::ObjectSetPosition object_set_position;
  ASSERT_FALSE(player->try_pop_front(&entry, &object_set_position));
  ASSERT_TRUE(m_replay_hander.error_occurred);
}

TEST_F(TestJournalPlayer, PrefetchAndWatch) {
  std::string oid = get_temp_oid();

  journal::JournalPlayer::EntryPositions positions;
  positions = boost::assign::list_of(
    cls::journal::EntryPosition("tag1", 122));
  cls::journal::ObjectSetPosition commit_position(0, positions);

  ASSERT_EQ(0, create(oid));
  ASSERT_EQ(0, client_register(oid));
  ASSERT_EQ(0, client_commit(oid, commit_position));

  journal::JournalMetadataPtr metadata = create_metadata(oid);
  ASSERT_EQ(0, metadata->init());

  journal::JournalPlayerPtr player = create_player(oid, metadata);

  ASSERT_EQ(0, write_entry(oid, 0, "tag1", 122));

  player->prefetch_and_watch(0.25);

  Entries entries;
  ASSERT_EQ(0, write_entry(oid, 1, "tag1", 123));
  ASSERT_TRUE(wait_for_entries(player, 1, &entries));

  Entries expected_entries;
  expected_entries = boost::assign::list_of(create_entry("tag1", 123));
  ASSERT_EQ(expected_entries, entries);

  ASSERT_EQ(0, write_entry(oid, 0, "tag1", 124));
  ASSERT_TRUE(wait_for_entries(player, 1, &entries));

  expected_entries = boost::assign::list_of(create_entry("tag1", 124));
  ASSERT_EQ(expected_entries, entries);
}
