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

#include "heu/library/algorithms/paillier_ic/public_key.h"

#include <cstdint>
#include <string>

#include "yacl/base/buffer.h"
#include "yacl/base/byte_container_view.h"

#include "heu/library/algorithms/paillier_ic/pb_utils.h"

namespace heu::lib::algorithms::paillier_ic {

void PublicKey::Init() {
  n_square_ = n_ * n_;
  n_half_ = n_ / MPInt::_2_;
  key_size_ = n_.BitCount();
}

std::string PublicKey::ToString() const {
  return fmt::format(
      "[interconnection] paillier03 PK: n={}[{}bits], h_s={}, "
      "max_plaintext={}[~{}bits]",
      n_.ToHexString(), n_.BitCount(), h_s_.ToHexString(),
      PlaintextBound().ToHexString(), PlaintextBound().BitCount());
}

bool PublicKey::operator==(const PublicKey &other) const {
  return n_ == other.n_ && h_s_ == other.h_s_;
}

bool PublicKey::operator!=(const PublicKey &other) const {
  return !this->operator==(other);
}

yacl::Buffer PublicKey::Serialize() const {
  pb_ns::PaillierPublicKey pk_pb;
  *pk_pb.mutable_n() = MPInt2Bigint(n_);
  *pk_pb.mutable_hs() = MPInt2Bigint(h_s_);

  yacl::Buffer buffer(pk_pb.ByteSizeLong());
  YACL_ENFORCE(pk_pb.SerializeToArray(buffer.data<uint8_t>(), buffer.size()),
               "Serialize public key fail");
  return buffer;
}

void PublicKey::Deserialize(yacl::ByteContainerView in) {
  pb_ns::PaillierPublicKey pk_pb;
  YACL_ENFORCE(pk_pb.ParseFromArray(in.data(), in.size()),
               "deserialize public key fail");

  n_ = Bigint2MPint(pk_pb.n());
  h_s_ = Bigint2MPint(pk_pb.hs());
  Init();
}

}  // namespace heu::lib::algorithms::paillier_ic
