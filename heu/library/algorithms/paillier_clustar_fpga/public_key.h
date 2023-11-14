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

#include <cmath>

#include "msgpack.hpp"

#include "heu/library/algorithms/paillier_clustar_fpga/fpga_engine/paillier_operators/fpga_types.h"
#include "heu/library/algorithms/paillier_clustar_fpga/plaintext.h"
#include "heu/library/algorithms/util/he_object.h"
#include "heu/library/algorithms/util/mp_int.h"

namespace heu::lib::algorithms::paillier_clustar_fpga {

using fpga_engine::CFPGATypes;
class CPubKeyHelper;

class PublicKey : public HeObject<PublicKey> {
 public:
  PublicKey() = default;
  PublicKey(const PublicKey& pub_key);
  PublicKey(PublicKey&& pub_key);
  explicit PublicKey(const MPInt& n);
  explicit PublicKey(MPInt&& n);

  PublicKey& operator=(const PublicKey& pub_key);
  PublicKey& operator=(PublicKey&& pub_key);
  PublicKey& operator=(const MPInt& n);
  PublicKey& operator=(MPInt&& n);

  bool operator==(const PublicKey& other) const;
  bool operator!=(const PublicKey& other) const;

  std::string ToString() const override;

  // Valid plaintext range: [max_int_, -max_int_]
  const Plaintext& PlaintextBound() const&;

  // Serialize and Deserialize
  MSGPACK_DEFINE(n_, n_square_, g_, max_int_, pt_bound_);

  // Functions for unit test
  const MPInt& GetN() const;
  const MPInt& GetG() const;
  const MPInt& GetNSquare() const;
  const Plaintext GetMaxInt() const;

 private:
  void Init();
  void InitCopy(const PublicKey& pub_key);
  void InitMove(PublicKey&& pub_key);
  void CalcPlaintextBound();

  friend class CPubKeyHelper;

 private:
  MPInt g_;  // n + 1
  MPInt n_;
  MPInt n_square_;      // n^2
  Plaintext max_int_;   // n / 3 - 1
  Plaintext pt_bound_;  // std::numeric_limits<int64_t>::max() + 1
};

}  // namespace heu::lib::algorithms::paillier_clustar_fpga
