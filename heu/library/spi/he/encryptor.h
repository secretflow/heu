// Copyright 2024 Ant Group Co., Ltd.
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

#pragma once

#include <cstddef>
#include <cstdint>

#include "heu/library/spi/he/base.h"

namespace heu::lib::spi {

class Encryptor {
 public:
  // message is encoded plaintext or plaintext array
  // For all HE schema, plaintext is a custom type defined by underlying lib
  // For 1bit-boolean-FHE, plaintext can be bool or custom type
  // PT -> CT
  // PTs -> CTs
  virtual Item Encrypt(const Item &plaintext) const = 0;
  virtual void Encrypt(const Item &plaintext, Item *out) const = 0;

  virtual Item EncryptZero(const Item &plaintext) const = 0;

  // encrypt and serialize to buffer
  virtual yacl::Buffer EncryptToBin(const Item &plaintext) const = 0;
  virtual size_t EncryptToBin(const Item &plaintext, uint8_t *buf,
                              size_t buf_len) const = 0;

  // Encrypt plaintext and record all pseudorandom data for audit.
  //
  // Due to security and audit requirements, the random numbers used in the
  // encryption process need to be recorded so that the entire calculation
  // process can be reproduced later. `audit_out` stores all random numbers used
  // in the encryption process. There are no requirements for its format and can
  // be customized by each library. You only need to ensure that the information
  // inside is complete.
  // 因安全和审计要求，加密过程的随机数需要记录下来，以便后续整个计算过程可（人工）复盘。
  // `audit_out` 记录了所有加密用到的随机数，其格式没有规定，可由每个库自定义
  // 库开发者只需要保证记录在 `audit_out` 中的信息是全的，没有遗留即可。
  virtual void EncryptWithAudit(const Item &plaintext, Item *ct_out,
                                std::string *audit_out) const = 0;
};

}  // namespace heu::lib::spi
