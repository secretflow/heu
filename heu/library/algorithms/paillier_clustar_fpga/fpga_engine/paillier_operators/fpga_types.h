// Copyright 2023 Clustar Technology Co., Ltd.
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

namespace heu::lib::algorithms::paillier_clustar_fpga::fpga_engine {

// Monostate-class to define FPGA types
class CFPGATypes {
 public:
  CFPGATypes() = default;
  ~CFPGATypes() = default;

 public:
  // This is determined by FATE + FPGA
  static constexpr unsigned MAX_NUMBER_BITS = 64;
  static constexpr unsigned CIPHER_BITS =
      2048;  // varies according to key length
  static constexpr unsigned PLAIN_BITS =
      2048;  // varies according to key length
  static constexpr unsigned BYTE_LEN = 8;
  static constexpr unsigned CIPHER_BYTE =
      CFPGATypes::CIPHER_BITS /
      CFPGATypes::BYTE_LEN;  // varies according to key length
  static constexpr unsigned PLAIN_BYTE =
      CFPGATypes::PLAIN_BITS /
      CFPGATypes::BYTE_LEN;  // varies according to key length

  static constexpr unsigned U_INT32_BYTE = 4;
  static constexpr unsigned INT64_BYTE = 8;
  static constexpr unsigned DOUBLE_BYTE = 8;

  static constexpr unsigned ENCR_RANDOM_BIT_LEN =
      1024;  // varies according to key length
  static constexpr unsigned ENCR_RANDOM_BYTE =
      CFPGATypes::ENCR_RANDOM_BIT_LEN /
      CFPGATypes::BYTE_LEN;  // varies according to key length

  static constexpr unsigned CIPHER_BASE =
      16;  // used in encoded format, hard code to 16 in FPGA case
};

class CKeyLenConfig {
 public:
  CKeyLenConfig(size_t key_len);
  ~CKeyLenConfig() = default;

 private:
  // Config key length related parameters
  void Config();

  void ConfigKeyLen512();
  void ConfigKeyLen1024();
  void ConfigKeyLen2048();

 public:
  size_t key_len_;  // options: 512, 1024, 2048

  unsigned cipher_bits_;
  unsigned cipher_byte_;

  unsigned plain_bits_;
  unsigned plain_byte_;

  unsigned encr_random_bit_len_;
  unsigned encr_random_byte_;
};

}  // namespace heu::lib::algorithms::paillier_clustar_fpga::fpga_engine
