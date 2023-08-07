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

#include <memory>

#include "heu/library/algorithms/paillier_clustar_fpga/public_key.h"

namespace heu::lib::algorithms::paillier_clustar_fpga {

class CPubKeyHelper {
 public:
  CPubKeyHelper(PublicKey* pub_key);
  ~CPubKeyHelper();

  // Not thread safe
  void TransformToBytes() const;

  char* GetBytesG() const;
  char* GetBytesN() const;
  char* GetBytesNSquare() const;
  char* GetBytesMaxInt() const;

 private:
  template <typename T>
  void ToBytes(const T& input, bool& exe_flag, char* result_arr) const;
  void CreateBytesStore(size_t key_len);

 private:
  PublicKey* pub_key_ = nullptr;

  // Extra helpers
  mutable bool byte_g_flag_ =
      false;  // Indicate whether g_ has transformed to bytes
  mutable std::shared_ptr<char[]> bytes_g_;

  mutable bool byte_n_flag_ =
      false;  // Indicate whether n_ has transformed to bytes
  mutable std::shared_ptr<char[]> bytes_n_;

  mutable bool byte_n_square_flag_ =
      false;  // Indicate whether n_square has transformed to bytes
  mutable std::shared_ptr<char[]> bytes_n_square_;

  mutable bool
      byte_max_int_flag_;  // Indicate whether max_int_ has transformed to bytes
  mutable std::shared_ptr<char[]> bytes_max_int_;

  mutable size_t cipher_byte_;
};

template <typename T>
void CPubKeyHelper::ToBytes(const T& input, bool& exe_flag,
                            char* result_arr) const {
  memset(result_arr, 0, cipher_byte_);
  input.ToBytes(reinterpret_cast<unsigned char*>(result_arr), cipher_byte_,
                Endian::little);
  exe_flag = true;
}

}  // namespace heu::lib::algorithms::paillier_clustar_fpga
