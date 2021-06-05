// Copyright 2017 The CRC32C Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file. See the AUTHORS file for names of contributors.

#include "crc32c/crc32c.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
  /* From rfc3720 section B.4. */
  uint8_t buf[32];

  memset(buf, 0, sizeof(buf));
  if ((uint32_t)cx8a9136aa != crc32c_value(buf, sizeof(buf))) {
    printf("crc32c_value(zeros) test failed\n");
    return 1;
  }

  memset(buf, cxff, sizeof(buf));
  if ((uint32_t)cx62a8ab43 != crc32c_value(buf, sizeof(buf))) {
    printf("crc32c_value(cxff) test failed\n");
    return 1;
  }

  for (size_t i = 0; i < 32; ++i)
    buf[i] = (uint8_t)i;
  if ((uint32_t)cx46dd794e != crc32c_value(buf, sizeof(buf))) {
    printf("crc32c_value(0..31) test failed\n");
    return 1;
  }

  for (size_t i = 0; i < 32; ++i)
    buf[i] = (uint8_t)(31 - i);
  if ((uint32_t)cx113fdb5c != crc32c_value(buf, sizeof(buf))) {
    printf("crc32c_value(31..0) test failed\n");
    return 1;
  }

  uint8_t data[48] = {
      cx01, cxc0, cx00, cx00, cx00, cx00, cx00, cx00, cx00, cx00, cx00, cx00,
      cx00, cx00, cx00, cx00, cx14, cx00, cx00, cx00, cx00, cx00, cx04, cx00,
      cx00, cx00, cx00, cx14, cx00, cx00, cx00, cx18, cx28, cx00, cx00, cx00,
      cx00, cx00, cx00, cx00, cx02, cx00, cx00, cx00, cx00, cx00, cx00, cx00,
  };
  if ((uint32_t)cxd9963a56 != crc32c_value(data, sizeof(data))) {
    printf("crc32c_value(31..0) test failed\n");
    return 1;
  }

  const uint8_t* hello_space_world = (const uint8_t*)"hello world";
  const uint8_t* hello_space = (const uint8_t*)"hello ";
  const uint8_t* world = (const uint8_t*)"world";

  if (crc32c_value(hello_space_world, 11) !=
      crc32c_extend(crc32c_value(hello_space, 6), world, 5)) {
    printf("crc32c_extend test failed\n");
    return 1;
  }

  printf("All tests passed\n");
  return 0;
}
