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

#include "heu/library/algorithms/paillier_ic/ciphertext.h"

#include "heu/library/algorithms/paillier_ic/pb_utils.h"

#include "interconnection/runtime/phe.pb.h"

namespace heu::lib::algorithms::paillier_ic {

yacl::Buffer Ciphertext::Serialize() const {
  pb_ns::PaillierCiphertext pb_ct;
  *pb_ct.mutable_c() = BigInt2PbBigint(c_);

  yacl::Buffer buffer(pb_ct.ByteSizeLong());
  YACL_ENFORCE(pb_ct.SerializeToArray(buffer.data<uint8_t>(), buffer.size()),
               "serialize ciphertext fail");
  return buffer;
}

void Ciphertext::Deserialize(yacl::ByteContainerView in) {
  pb_ns::PaillierCiphertext pk_ct;
  YACL_ENFORCE(pk_ct.ParseFromArray(in.data(), in.size()),
               "deserialize ciphertext fail");

  PbBigint2BigInt(pk_ct.c(), c_);
}

}  // namespace heu::lib::algorithms::paillier_ic
