// Copyright 2023 Denglin Co., Ltd.
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
#include "heu/library/algorithms/paillier_dl/cgbn_wrapper/cgbn_wrapper_defs.h"
#include "heu/library/algorithms/paillier_dl/cgbn_wrapper/cgbn_wrapper.h"

namespace heu::lib::algorithms::paillier_dl {

class PublicKey : public HeObject<PublicKey> {
 public:
  PublicKey();
  ~PublicKey();
  PublicKey(const PublicKey& other);
  PublicKey& operator=(const PublicKey& other);
  PublicKey(PublicKey&& other) noexcept;
  PublicKey& operator=(PublicKey&& other) noexcept;

 public:
  MPInt g_;
  MPInt n_;
  MPInt nsquare_;
  MPInt max_int_;
  MPInt half_n_;
  dev_mem_t<BITS> *dev_g_;
  dev_mem_t<BITS> *dev_n_;
  dev_mem_t<BITS> *dev_nsquare_;
  dev_mem_t<BITS> *dev_max_int_;
  PublicKey *dev_pk_;

  // Init pk based on n_
  void Init(const MPInt &n, MPInt *g);
  [[nodiscard]] std::string ToString() const override;

  bool operator==(const PublicKey &other) const {
    return n_ == other.n_ && g_ == other.g_;
  }

  bool operator!=(const PublicKey &other) const {
    return !this->operator==(other);
  }
};

}  // namespace heu::lib::algorithms::paillier_dl

