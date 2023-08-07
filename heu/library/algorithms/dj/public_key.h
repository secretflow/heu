// Copyright 2023 zhangwfjh
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

namespace heu::lib::algorithms::dj {

class PublicKey : public HeObject<PublicKey> {
 public:
  void Init(MPInt const& n, uint32_t s, MPInt const& hs = MPInt{0});

  inline MPInt const& N() const { return n_; }
  inline uint32_t S() const { return s_; }
  // hs = h^(n^s) mod n^(s+1): h is a generator of Zn*
  inline MPInt const& Hs() const { return hs_; }
  inline MPInt const& PlainModule() const { return pmod_; }
  inline const MPInt& PlaintextBound() const& { return bound_; }
  inline MPInt const& CipherModule() const { return cmod_; }

  bool operator==(const PublicKey&) const;
  bool operator!=(const PublicKey&) const;
  std::string ToString() const override;

 public:
  // Random Zn* element of form r^(n^s) mod n^(s+1)
  MPInt RandomZnStar() const;
  // Deterministic encryption
  MPInt Encrypt(MPInt const&) const;
  // Encode into Montgomery form
  MPInt Encode(MPInt const&) const;
  // Decode from Montgomery form
  MPInt Decode(MPInt const&) const;

  void MulMod(MPInt const& a, MPInt const& b, MPInt* dst) const {
    lut_->m_space->MulMod(a, b, dst);
  }

 private:
  MPInt n_, hs_, pmod_, cmod_, bound_;
  uint32_t s_;

  struct LUT {
    std::unique_ptr<MontgomerySpace> m_space;  // m-space for mod n^(s+1)
    std::unique_ptr<BaseTable> hs_pow;         // powers of h^(n^s) mod n^(s+1)
    std::vector<MPInt> n_pow;                  // powers of n
    std::vector<MPInt> precomp;                // n^i/i! mod n^(s+1)
  };

  std::shared_ptr<LUT> lut_;
};

}  // namespace heu::lib::algorithms::dj

// clang-format off
namespace msgpack {
MSGPACK_API_VERSION_NAMESPACE(MSGPACK_DEFAULT_API_NS) {
namespace adaptor {

template<>
struct pack<heu::lib::algorithms::dj::PublicKey> {
  template<typename Stream>
  packer<Stream> &operator()(msgpack::packer<Stream> &o,
      const heu::lib::algorithms::dj::PublicKey &pk) const {
    // packing member variables as an array.
    o.pack_array(3);
    o.pack(pk.N());
    o.pack(pk.S());
    o.pack(pk.Hs());
    return o;
  }
};

template<>
struct convert<heu::lib::algorithms::dj::PublicKey> {
  msgpack::object const &operator()(const msgpack::object &object,
      heu::lib::algorithms::dj::PublicKey &pk) const {
    if (object.type != msgpack::type::ARRAY) { throw msgpack::type_error(); }
    if (object.via.array.size != 3) { throw msgpack::type_error(); }

    // The order here corresponds to the packer above
    auto n = object.via.array.ptr[0].as<heu::lib::algorithms::MPInt>();
    auto s = object.via.array.ptr[1].as<uint32_t>();
    auto hs = object.via.array.ptr[2].as<heu::lib::algorithms::MPInt>();
    pk.Init(n, s, hs);
    return object;
  }
};

}  // namespace adaptor
}  // namespace msgpack
}  // namespace msgpack
// clang-format on
