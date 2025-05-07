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

#include "heu/library/algorithms/util/big_int.h"
#include "heu/library/algorithms/util/he_object.h"

namespace heu::lib::algorithms::dgk {

class PublicKey : public HeObject<PublicKey> {
 public:
  void Init(const BigInt &n, const BigInt &g, const BigInt &h, const BigInt &u);

  const BigInt &N() const { return n_; }

  const BigInt &G() const { return g_; }

  const BigInt &H() const { return h_; }

  const BigInt &U() const { return u_; }

  BigInt PlainModule() const { return u_; }

  BigInt PlaintextBound() const { return u_ / 2; }

  BigInt CipherModule() const { return n_; }

  bool operator==(const PublicKey &) const;
  bool operator!=(const PublicKey &) const;
  std::string ToString() const override;

  // ---Helper functions--- //
  // Warning: DO NOT USE THE FOLLOWING FUNCTIONS DIRECTLY
 public:
  // Random element of form h^r mod n
  BigInt RandomHr() const;
  // Deterministic encryption
  BigInt Encrypt(const BigInt &) const;
  BigInt MapIntoMSpace(const BigInt &) const;
  BigInt MapBackToZSpace(const BigInt &) const;

  void MulMod(const BigInt &a, const BigInt &b, BigInt *dst) const {
    *dst = lut_->m_space->MulMod(a, b);
  }

 private:
  BigInt n_, g_, h_, u_;

  struct LUT {
    LUT(const PublicKey *pub);

    std::shared_ptr<MontgomerySpace> m_space;  // m-space for mod n
    BaseTable g_pow;                           // powers of g mod n
    BaseTable h_pow;                           // powers of h mod n
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
    auto n = object.via.array.ptr[0].as<heu::lib::algorithms::BigInt>();
    auto g = object.via.array.ptr[1].as<heu::lib::algorithms::BigInt>();
    auto h = object.via.array.ptr[2].as<heu::lib::algorithms::BigInt>();
    auto u = object.via.array.ptr[3].as<heu::lib::algorithms::BigInt>();
    pk.Init(n, g, h, u);
    return object;
  }
};

}  // namespace adaptor
}  // namespace msgpack
}  // namespace msgpack

// clang-format on
