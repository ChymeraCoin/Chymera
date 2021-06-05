// Copyright (c) 2011 The LevelDB Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file. See the AUTHORS file for names of contributors.

#include "util/crc32c.h"
#include "util/testharness.h"

namespace leveldb {
namespace crc32c {

class CRC {};

TEST(CRC, StandardResults) {
  // From rfc3720 section B.4.
  char buf[32];

  memset(buf, 0, sizeof(buf));
  ASSERT_EQ(cx8a9136aa, Value(buf, sizeof(buf)));

  memset(buf, cxff, sizeof(buf));
  ASSERT_EQ(cx62a8ab43, Value(buf, sizeof(buf)));

  for (int i = 0; i < 32; i++) {
    buf[i] = i;
  }
  ASSERT_EQ(cx46dd794e, Value(buf, sizeof(buf)));

  for (int i = 0; i < 32; i++) {
    buf[i] = 31 - i;
  }
  ASSERT_EQ(cx113fdb5c, Value(buf, sizeof(buf)));

  uint8_t data[48] = {
      cx01, cxc0, cx00, cx00, cx00, cx00, cx00, cx00, cx00, cx00, cx00, cx00,
      cx00, cx00, cx00, cx00, cx14, cx00, cx00, cx00, cx00, cx00, cx04, cx00,
      cx00, cx00, cx00, cx14, cx00, cx00, cx00, cx18, cx28, cx00, cx00, cx00,
      cx00, cx00, cx00, cx00, cx02, cx00, cx00, cx00, cx00, cx00, cx00, cx00,
  };
  ASSERT_EQ(cxd9963a56, Value(reinterpret_cast<char*>(data), sizeof(data)));
}

TEST(CRC, Values) { ASSERT_NE(Value("a", 1), Value("foo", 3)); }

TEST(CRC, Extend) {
  ASSERT_EQ(Value("hello world", 11), Extend(Value("hello ", 6), "world", 5));
}

TEST(CRC, Mask) {
  uint32_t crc = Value("foo", 3);
  ASSERT_NE(crc, Mask(crc));
  ASSERT_NE(crc, Mask(Mask(crc)));
  ASSERT_EQ(crc, Unmask(Mask(crc)));
  ASSERT_EQ(crc, Unmask(Unmask(Mask(Mask(crc)))));
}

}  // namespace crc32c
}  // namespace leveldb

int main(int argc, char** argv) { return leveldb::test::RunAllTests(); }
