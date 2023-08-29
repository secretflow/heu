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

#include "fmt/format.h"
#include "yacl/crypto/base/ecc/ecc_spi.h"

#include "heu/library/algorithms/elgamal/plaintext.h"
#include "heu/library/algorithms/util/he_object.h"

namespace heu::lib::algorithms::elgamal {

class PublicKey {
 public:
  PublicKey() {}

  PublicKey(const std::shared_ptr<yacl::crypto::EcGroup> &curve,
            const yacl::crypto::EcPoint &h)
      : curve_(curve), h_(h) {}

  bool operator==(const PublicKey &other) const;
  bool operator!=(const PublicKey &other) const;

  std::string ToString() const;

  // Valid plaintext range: (max_int_, -max_int_)
  const Plaintext &PlaintextBound() const &;

  yacl::Buffer Serialize() const;
  void Deserialize(yacl::ByteContainerView in);

  const std::shared_ptr<yacl::crypto::EcGroup> &GetCurve() const {
    return curve_;
  }

  const yacl::crypto::EcPoint &GetH() const { return h_; }

 private:
  bool IsValid() const { return (bool)curve_; }

  std::shared_ptr<yacl::crypto::EcGroup> curve_;

  yacl::crypto::EcPoint h_;  // h = xG
};

}  // namespace heu::lib::algorithms::elgamal
