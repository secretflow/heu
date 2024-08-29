// Copyright 2024 Ant Group Co., Ltd.
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

#include "heu/algorithms/incubator/mock_fhe/base.h"

#include <vector>

#include "yacl/utils/serializer.h"

#include "heu/spi/utils/formater.h"

namespace heu::algos::mock_fhe {

std::string Plaintext::ToString() const {
  return fmt::format("PT({}, scale={})",
                     spi::utils::ArrayToStringCompact<int64_t>(array_), scale_);
}

std::string Ciphertext::ToString() const {
  return fmt::format("CT({}, scale={})",
                     spi::utils::ArrayToStringCompact<int64_t>(array_), scale_);
}

Plaintext ItemTool::Clone(const Plaintext &pt) const { return pt; }

Ciphertext ItemTool::Clone(const Ciphertext &ct) const { return ct; }

}  // namespace heu::algos::mock_fhe
