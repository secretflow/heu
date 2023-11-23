// Copyright 2023 Ant Group Co., Ltd.
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

#include "heu/library/algorithms/util/he_object.h"
#include "heu/library/algorithms/util/mp_int.h"

namespace heu::lib::algorithms::paillier_ic {

class PublicKey {
 public:
  MPInt n_;         // public modulus n = p * q
  MPInt n_square_;  // n_ * n_
  MPInt n_half_;    // n_ / 2
  MPInt h_s_;       // h^n mod n^2

  size_t key_size_;

  // Init pk based on n_ and h_s_
  void Init();
  [[nodiscard]] std::string ToString() const;

  bool operator==(const PublicKey &other) const;
  bool operator!=(const PublicKey &other) const;

  // Valid plaintext range: [n_half_, -n_half]
  [[nodiscard]] inline const MPInt &PlaintextBound() const & { return n_half_; }

  [[nodiscard]] yacl::Buffer Serialize() const;
  void Deserialize(yacl::ByteContainerView in);
};

}  // namespace heu::lib::algorithms::paillier_ic
