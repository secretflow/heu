// Copyright 2022 Ant Group Co., Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "coding.h"

#include <cstring>

namespace {

inline bool IsLittleEndian() {
  int i = 1;
  char* p = (char*)&i;

  if (p[0] == 1) {
    return true;
  }
  return false;
}

}  // namespace

namespace heu::lib::phe {

void EncodeFixed32(char* str, uint32_t value) {
  auto* const buf = reinterpret_cast<uint8_t*>(str);

  if (IsLittleEndian()) {
    std::memcpy(buf, &value, sizeof(uint32_t));
    return;
  }

  buf[0] = static_cast<uint8_t>(value);
  buf[1] = static_cast<uint8_t>(value >> 8);
  buf[2] = static_cast<uint8_t>(value >> 16);
  buf[3] = static_cast<uint8_t>(value >> 24);
}

void PutFixed32(std::string* str, uint32_t value) {
  char buf[sizeof(value)];
  EncodeFixed32(buf, value);
  str->append(buf, sizeof(buf));
}

uint32_t DecodeFixed32(const char* data) {
  const auto* const buf = reinterpret_cast<const uint8_t*>(data);

  if (IsLittleEndian()) {
    uint32_t result;
    std::memcpy(&result, buf, sizeof(uint32_t));
    return result;
  }

  return (static_cast<uint32_t>(buf[0])) |
         (static_cast<uint32_t>(buf[1]) << 8) |
         (static_cast<uint32_t>(buf[2]) << 16) |
         (static_cast<uint32_t>(buf[3]) << 24);
}

}  // namespace heu::lib::phe