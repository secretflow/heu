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

class SecretKey : public HeObject<SecretKey> {
 public:
  SecretKey();
  ~SecretKey();
  SecretKey(const SecretKey& other);
  SecretKey& operator=(const SecretKey& other);
  SecretKey(SecretKey&& other) noexcept;
  SecretKey& operator=(SecretKey&& other) noexcept;
  
 public:
  MPInt g_;
  MPInt p_;
  MPInt q_;
  MPInt psquare_;
  MPInt qsquare_;
  MPInt q_inverse_;
  MPInt hp_;
  MPInt hq_;

  dev_mem_t<BITS> *dev_g_;
  dev_mem_t<BITS> *dev_p_;
  dev_mem_t<BITS> *dev_q_;
  dev_mem_t<BITS> *dev_psquare_;
  dev_mem_t<BITS> *dev_qsquare_;
  dev_mem_t<BITS> *dev_q_inverse_;
  dev_mem_t<BITS> *dev_hp_;
  dev_mem_t<BITS> *dev_hq_;
  SecretKey *dev_sk_;

  void Init(MPInt g, MPInt raw_p, MPInt raw_q);

  bool operator==(const SecretKey &other) const {
    return p_ == other.p_ && q_ == other.q_ && q_ == other.q_ && g_ == other.g_;
  }

  bool operator!=(const SecretKey &other) const {
    return !this->operator==(other);
  }

  [[nodiscard]] std::string ToString() const override;
};

}  // namespace heu::lib::algorithms::paillier_dl
