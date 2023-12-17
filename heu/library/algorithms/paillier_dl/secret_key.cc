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

#include "heu/library/algorithms/paillier_dl/secret_key.h"
#include "heu/library/algorithms/util/mp_int.h"

namespace heu::lib::algorithms::paillier_dl {

void SecretKey::Init(MPInt g, MPInt raw_p, MPInt raw_q) {
  g_ = g;
  if(raw_q < raw_p) {
    p_ = std::move(raw_q);
    q_ = std::move(raw_p);
  } else {
    p_ = std::move(raw_p);
    q_ = std::move(raw_q);
  }

  CGBNWrapper::DevMalloc(this);
  CGBNWrapper::StoreToDev(this);

  CGBNWrapper::InitSK(this);
  CGBNWrapper::StoreToHost(this);
}

std::string SecretKey::ToString() const {
  NOT_SUPPORT;
  // return fmt::format("Z-paillier SK: p={}[{}bits], q={}[{}bits]",
  //                    p_.ToHexString(), p_.BitCount(), q_.ToHexString(),
  //                    q_.BitCount());
}

}  // namespace heu::lib::algorithms::paillier_dl
