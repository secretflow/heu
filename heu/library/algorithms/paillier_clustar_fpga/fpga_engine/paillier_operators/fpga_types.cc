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

#include "fpga_types.h"

namespace heu::lib::algorithms::paillier_clustar_fpga::fpga_engine {

CKeyLenConfig::CKeyLenConfig(size_t key_len) : key_len_(key_len) { Config(); }

void CKeyLenConfig::Config() {
  if (key_len_ == 0) {
    // TODO: give a warning later
    return;
  }

  if (key_len_ == 512) {
    ConfigKeyLen512();
  } else if (key_len_ == 1024) {
    ConfigKeyLen1024();
  } else if (key_len_ == 2048) {
    ConfigKeyLen2048();
  }
}

void CKeyLenConfig::ConfigKeyLen512() {
  cipher_bits_ = CFPGATypes::CIPHER_BITS / 2;
  cipher_byte_ = cipher_bits_ / CFPGATypes::BYTE_LEN;

  plain_bits_ = CFPGATypes::PLAIN_BITS / 2;
  plain_byte_ = plain_bits_ / CFPGATypes::BYTE_LEN;

  encr_random_bit_len_ = CFPGATypes::ENCR_RANDOM_BIT_LEN / 2;
  encr_random_byte_ = encr_random_bit_len_ / CFPGATypes::BYTE_LEN;
}

void CKeyLenConfig::ConfigKeyLen1024() {
  cipher_bits_ = CFPGATypes::CIPHER_BITS;
  cipher_byte_ = cipher_bits_ / CFPGATypes::BYTE_LEN;

  plain_bits_ = CFPGATypes::PLAIN_BITS;
  plain_byte_ = plain_bits_ / CFPGATypes::BYTE_LEN;

  encr_random_bit_len_ = CFPGATypes::ENCR_RANDOM_BIT_LEN;
  encr_random_byte_ = encr_random_bit_len_ / CFPGATypes::BYTE_LEN;
}

void CKeyLenConfig::ConfigKeyLen2048() {
  cipher_bits_ = CFPGATypes::CIPHER_BITS * 2;
  cipher_byte_ = cipher_bits_ / CFPGATypes::BYTE_LEN;

  plain_bits_ = CFPGATypes::PLAIN_BITS * 2;
  plain_byte_ = plain_bits_ / CFPGATypes::BYTE_LEN;

  encr_random_bit_len_ = CFPGATypes::ENCR_RANDOM_BIT_LEN * 2;
  encr_random_byte_ = encr_random_bit_len_ / CFPGATypes::BYTE_LEN;
}

}  // namespace heu::lib::algorithms::paillier_clustar_fpga::fpga_engine
