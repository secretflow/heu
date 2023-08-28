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

namespace heu::lib::algorithms::dgk {

class PublicKey : public HeObject<PublicKey> {
 public:
  void Init(const MPInt& n, const MPInt& g, const MPInt& h, const MPInt& u);

  const MPInt& N() const { return n_; }
  const MPInt& G() const { return g_; }
  const MPInt& H() const { return h_; }
  const MPInt& U() const { return u_; }
  MPInt PlainModule() const { return u_; }
  MPInt PlaintextBound() const { return u_ / MPInt::_2_; }
  MPInt CipherModule() const { return n_; }

  bool operator==(const PublicKey&) const;
  bool operator!=(const PublicKey&) const;
  std::string ToString() const override;

  // ---Helper functions--- //
  // Warning: DO NOT USE THE FOLLOWING FUNCTIONS DIRECTLY
 public:
  // Random element of form h^r mod n
  MPInt RandomHr() const;
  // Deterministic encryption
  MPInt Encrypt(const MPInt&) const;
  MPInt MapIntoMSpace(const MPInt&) const;
  MPInt MapBackToZSpace(const MPInt&) const;

  void MulMod(const MPInt& a, const MPInt& b, MPInt* dst) const {
    lut_->m_space.MulMod(a, b, dst);
  }

 private:
  MPInt n_, g_, h_, u_;

  struct LUT {
    LUT(const PublicKey* pub);

    MontgomerySpace m_space;  // m-space for mod n
    BaseTable g_pow;          // powers of g mod n
    BaseTable h_pow;          // powers of h mod n
  };

  std::shared_ptr<LUT> lut_;
};

}  // namespace heu::lib::algorithms::dgk

// clang-format off
namespace msgpack {
MSGPACK_API_VERSION_NAMESPACE(MSGPACK_DEFAULT_API_NS) {
namespace adaptor {

template<>
struct pack<heu::lib::algorithms::dgk::PublicKey> {
  template<typename Stream>
  packer<Stream> &operator()(msgpack::packer<Stream> &o,
      const heu::lib::algorithms::dgk::PublicKey &pk) const {
    // packing member variables as an array.
    o.pack_array(4);
    o.pack(pk.N());
    o.pack(pk.G());
    o.pack(pk.H());
    o.pack(pk.U());
    return o;
  }
};

template<>
struct convert<heu::lib::algorithms::dgk::PublicKey> {
  msgpack::object const &operator()(const msgpack::object &object,
      heu::lib::algorithms::dgk::PublicKey &pk) const {
    if (object.type != msgpack::type::ARRAY) { throw msgpack::type_error(); }
    if (object.via.array.size != 4) { throw msgpack::type_error(); }

    // The order here corresponds to the packer above
    auto n = object.via.array.ptr[0].as<heu::lib::algorithms::MPInt>();
    auto g = object.via.array.ptr[1].as<heu::lib::algorithms::MPInt>();
    auto h = object.via.array.ptr[2].as<heu::lib::algorithms::MPInt>();
    auto u = object.via.array.ptr[3].as<heu::lib::algorithms::MPInt>();
    pk.Init(n, g, h, u);
    return object;
  }
};

}  // namespace adaptor
}  // namespace msgpack
}  // namespace msgpack

// clang-format on
