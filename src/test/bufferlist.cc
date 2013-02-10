#include <tr1/memory>

#include "include/buffer.h"
#include "include/encoding.h"

#include "gtest/gtest.h"
#include "stdlib.h"


#define MAX_TEST 1000000


TEST(BufferList, EmptyAppend) {
  bufferlist bl;
  bufferptr ptr;
  bl.push_back(ptr);
  ASSERT_EQ(bl.begin().end(), 1);
}

TEST(BufferList, TestPtrAppend) {
  bufferlist bl;
  char correct[MAX_TEST];
  int curpos = 0;
  int length = random() % 5 > 0 ? random() % 1000 : 0;
  while (curpos + length < MAX_TEST) {
    if (!length) {
      bufferptr ptr;
      bl.push_back(ptr);
    } else {
      char *current = correct + curpos;
      for (int i = 0; i < length; ++i) {
        char next = random() % 255;
        correct[curpos++] = next;
      }
      bufferptr ptr(current, length);
      bl.append(ptr);
    }
    length = random() % 5 > 0 ? random() % 1000 : 0;
  }
  ASSERT_EQ(memcmp(bl.c_str(), correct, curpos), 0);
}

TEST(BufferList, ptr_assignment) {
  unsigned len = 17;
  //
  // override a bufferptr set with the same raw
  //
  {
    bufferptr original(len);
    bufferptr same_raw(original.get_raw());
    unsigned offset = 5;
    unsigned length = len - offset;
    original.set_offset(offset);
    original.set_length(length);
    same_raw = original;
    ASSERT_EQ(2, original.raw_nref());
    ASSERT_EQ(same_raw.get_raw(), original.get_raw());
    ASSERT_EQ(same_raw.offset(), original.offset());
    ASSERT_EQ(same_raw.length(), original.length());
  }

  //
  // self assignment is a noop
  //
  {
    bufferptr original(len);
    original = original;
    ASSERT_EQ(1, original.raw_nref());
    ASSERT_EQ((unsigned)0, original.offset());
    ASSERT_EQ(len, original.length());
  }
  
  //
  // a copy points to the same raw
  //
  {
    bufferptr original(len);
    unsigned offset = 5;
    unsigned length = len - offset;
    original.set_offset(offset);
    original.set_length(length);
    bufferptr ptr;
    ptr = original;
    ASSERT_EQ(2, original.raw_nref());
    ASSERT_EQ(ptr.get_raw(), original.get_raw());
    ASSERT_EQ(original.offset(), ptr.offset());
    ASSERT_EQ(original.length(), ptr.length());
  }
}

TEST(BufferList, TestDirectAppend) {
  bufferlist bl;
  char correct[MAX_TEST];
  int curpos = 0;
  int length = random() % 5 > 0 ? random() % 1000 : 0;
  while (curpos + length < MAX_TEST) {
    char *current = correct + curpos;
    for (int i = 0; i < length; ++i) {
      char next = random() % 255;
      correct[curpos++] = next;
    }
    bl.append(current, length);
    length = random() % 5 > 0 ? random() % 1000 : 0;
  }
  ASSERT_EQ(memcmp(bl.c_str(), correct, curpos), 0);
}

TEST(BufferList, TestCopyAll) {
  const static size_t BIG_SZ = 10737414;
  std::tr1::shared_ptr <unsigned char> big(
      (unsigned char*)malloc(BIG_SZ), free);
  unsigned char c = 0;
  for (size_t i = 0; i < BIG_SZ; ++i) {
    big.get()[i] = c++;
  }
  bufferlist bl;
  bl.append((const char*)big.get(), BIG_SZ);
  bufferlist::iterator i = bl.begin();
  bufferlist bl2;
  i.copy_all(bl2);
  ASSERT_EQ(bl2.length(), BIG_SZ);
  unsigned char big2[BIG_SZ];
  bl2.copy(0, BIG_SZ, (char*)big2);
  ASSERT_EQ(memcmp(big.get(), big2, BIG_SZ), 0);
}
