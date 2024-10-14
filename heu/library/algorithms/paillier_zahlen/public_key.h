// Copyright 2022 Ant Group Co., Ltd.
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
namespace heu::lib::algorithms::paillier_z {
// The density parameter of each participant can be different, so density is
// a local configuration and will not be automatically passed to other parties
// through the protocol
void SetCacheTableDensity(size_t density);
class PublicKey : public HeObject<PublicKey> {
 public:
  MPInt n_;         // public modulus n = p * q
  MPInt n_square_;  // n_ * n_
  MPInt n_half_;    // n_ / 2
  MPInt h_s_;       // h^n mod n^2
  size_t key_size_;
  std::shared_ptr<MontgomerySpace> m_space_;  // m-space for mod n^2
  std::shared_ptr<BaseTable> hs_table_;       // h_s_ table mod n^2
  // Init pk based on n_
  void Init();
  [[nodiscard]] std::string ToString() const override;
  bool operator==(const PublicKey &other) const {
    return n_ == other.n_ && h_s_ == other.h_s_;
  }
  bool operator!=(const PublicKey &other) const {
    return !this->operator==(other);
  }
  // Valid plaintext range: [n_half_, -n_half]
  [[nodiscard]] inline const MPInt &PlaintextBound() const & { return n_half_; }
};
}  // namespace heu::lib::algorithms::paillier_z
// clang-format off
namespace msgpack {
MSGPACK_API_VERSION_NAMESPACE(MSGPACK_DEFAULT_API_NS) {
namespace adaptor {
template<>
struct pack<heu::lib::algorithms::paillier_z::PublicKey> {
  template<typename Stream>
  packer<Stream> &operator()(msgpack::packer<Stream> &o,
      const heu::lib::algorithms::paillier_z::PublicKey &pk) const {
    // packing member variables as an array.
    o.pack_array(2);
    o.pack(pk.n_);
    o.pack(pk.h_s_);
    return o;
  }
};
template<>
struct convert<heu::lib::algorithms::paillier_z::PublicKey> {
  msgpack::object const &operator()(const msgpack::object &object,
      heu::lib::algorithms::paillier_z::PublicKey &pk) const {
    if (object.type != msgpack::type::ARRAY) { throw msgpack::type_error(); }
    if (object.via.array.size != 2) { throw msgpack::type_error(); }
    // The order here corresponds to the packer above
    pk.n_ = object.via.array.ptr[0].as<heu::lib::algorithms::MPInt>();
    pk.h_s_ = object.via.array.ptr[1].as<heu::lib::algorithms::MPInt>();
    pk.Init();
    return object;
  }
};
}  // namespace adaptor
}  // namespace msgpack
}  // namespace msgpack
// clang-format on
