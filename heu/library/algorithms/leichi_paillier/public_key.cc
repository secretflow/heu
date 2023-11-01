// Copyright 2023 Polar Bear Tech (Xi 'an) Co., LTD.
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

#include "heu/library/algorithms/leichi_paillier/public_key.h"
namespace heu::lib::algorithms::leichi_paillier {

    void SetCacheTableDensity(size_t density) {
      YACL_ENFORCE(density > 0, "density must > 0");
    }

    void PublicKey::Init() {

    }

    std::string PublicKey::ToString() const {
      return fmt::format(
          n_.ToHexString(), n_.BitCount(),
          PlaintextBound().ToHexString(), PlaintextBound().BitCount() - 1);
    }
}