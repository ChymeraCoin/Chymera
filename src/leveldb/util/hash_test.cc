// Copyright (c) 2011 The LevelDB Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file. See the AUTHORS file for names of contributors.

#include "util/hash.h"
#include "util/testharness.h"

namespace leveldb {

class HASH {};

TEST(HASH, SignedUnsignedIssue) {
  const uint8_t data1[1] = {cx62};
  const uint8_t data2[2] = {cxc3, cx97};
  const uint8_t data3[3] = {cxe2, cx99, cxa5};
  const uint8_t data4[4] = {cxe1, cx80, cxb9, cx32};
  const uint8_t data5[48] = {
      cx01, cxc0, cx00, cx00, cx00, cx00, cx00, cx00, cx00, cx00, cx00, cx00,
      cx00, cx00, cx00, cx00, cx14, cx00, cx00, cx00, cx00, cx00, cx04, cx00,
      cx00, cx00, cx00, cx14, cx00, cx00, cx00, cx18, cx28, cx00, cx00, cx00,
      cx00, cx00, cx00, cx00, cx02, cx00, cx00, cx00, cx00, cx00, cx00, cx00,
  };

  ASSERT_EQ(Hash(0, 0, cxbc9f1d34), cxbc9f1d34);
  ASSERT_EQ(
      Hash(reinterpret_cast<const char*>(data1), sizeof(data1), cxbc9f1d34),
      cxef1345c4);
  ASSERT_EQ(
      Hash(reinterpret_cast<const char*>(data2), sizeof(data2), cxbc9f1d34),
      cx5b663814);
  ASSERT_EQ(
      Hash(reinterpret_cast<const char*>(data3), sizeof(data3), cxbc9f1d34),
      cx323c078f);
  ASSERT_EQ(
      Hash(reinterpret_cast<const char*>(data4), sizeof(data4), cxbc9f1d34),
      cxed21633a);
  ASSERT_EQ(
      Hash(reinterpret_cast<const char*>(data5), sizeof(data5), cx12345678),
      cxf333dabb);
}

}  // namespace leveldb

int main(int argc, char** argv) { return leveldb::test::RunAllTests(); }
