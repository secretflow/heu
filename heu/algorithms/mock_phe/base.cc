
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

#include "heu/algorithms/mock_phe/base.h"

namespace heu::algos::mock_phe {

Plaintext ItemTool::Clone(const Plaintext &pt) const { return pt; }

Ciphertext ItemTool::Clone(const Ciphertext &ct) const {
  return Ciphertext(ct.bn_);
}

size_t ItemTool::Serialize(const Plaintext &pt, uint8_t *buf,
                           size_t buf_len) const {
  return pt.Serialize(buf, buf_len);
}

size_t ItemTool::Serialize(const Ciphertext &ct, uint8_t *buf,
                           size_t buf_len) const {
  return Serialize(ct.bn_, buf, buf_len);
}

Plaintext ItemTool::DeserializePT(yacl::ByteContainerView buffer) const {
  Plaintext res;
  res.Deserialize(buffer);
  return res;
}

Ciphertext ItemTool::DeserializeCT(yacl::ByteContainerView buffer) const {
  return Ciphertext(DeserializePT(buffer));
}

}  // namespace heu::algos::mock_phe
