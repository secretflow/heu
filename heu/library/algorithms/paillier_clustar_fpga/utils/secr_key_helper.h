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

#include "heu/library/algorithms/paillier_clustar_fpga/secret_key.h"

namespace heu::lib::algorithms::paillier_clustar_fpga {

class CSecrKeyHelper {
 public:
  CSecrKeyHelper(SecretKey *secr_key, size_t key_len);
  ~CSecrKeyHelper();

  //
  // Not thread safe
  void TransformToBytes() const;
  char *GetBytesP() const;
  char *GetBytesQ() const;
  char *GetBytesPSquare() const;
  char *GetBytesQSquare() const;
  char *GetBytesQInverse() const;
  char *GetBytesHP() const;
  char *GetBytesHQ() const;

 private:
  void ToBytes(const MPInt &input, bool &exe_flag, char *result_arr) const;
  void CreateBytesStore(size_t key_len);

 private:
  SecretKey *secr_key_;

  // Extra helpers
  mutable bool byte_p_flag_ = false;
  mutable std::shared_ptr<char[]> bytes_p_;

  mutable bool byte_q_flag_ = false;
  mutable std::shared_ptr<char[]> bytes_q_;

  mutable bool byte_p_square_flag_ = false;
  mutable std::shared_ptr<char[]> bytes_p_square_;

  mutable bool byte_q_square_flag_ = false;
  mutable std::shared_ptr<char[]> bytes_q_square_;

  mutable bool byte_q_inverse_flag_ = false;
  mutable std::shared_ptr<char[]> bytes_q_inverse_;

  mutable bool hp_flag_ = false;
  mutable std::shared_ptr<char[]> bytes_hp_;

  mutable bool hq_flag_ = false;
  mutable std::shared_ptr<char[]> bytes_hq_;

  mutable size_t cipher_byte_;
};

}  // namespace heu::lib::algorithms::paillier_clustar_fpga
