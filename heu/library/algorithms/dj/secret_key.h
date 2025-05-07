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

namespace heu::lib::algorithms::dj {

class SecretKey : public HeObject<SecretKey> {
  struct MPInt2 {
    BigInt P, Q;
  };

 public:
  void Init(const BigInt &p, const BigInt &q, uint32_t s);

  const auto &N() const { return n_; }

  uint32_t S() const { return s_; }

  bool operator==(const SecretKey &) const;
  bool operator!=(const SecretKey &) const;
  std::string ToString() const override;

  BigInt Decrypt(const BigInt &ct) const;

 private:
  MPInt2 n_;            // (p, q)
  BigInt lambda_, mu_;  // λ, μ
  BigInt pmod_;         // n^s
  uint32_t s_ = 0;      // Updated by Ant Group
  BigInt pp_;           // p^s * (p^(-s) mod q^s), used for CRT
  MPInt2 inv_pq_;       // ( q^(-1) mod p^s, p^(-1) mod q^s )

  struct LUT {
    std::vector<MPInt2> pq_pow;                // {p,q}^j
    std::vector<std::vector<MPInt2>> precomp;  // n^(i-1)/i! mod {p,q}^j
  };

  std::shared_ptr<LUT> lut_;
};

}  // namespace heu::lib::algorithms::dj

// clang-format off
namespace msgpack {
MSGPACK_API_VERSION_NAMESPACE(MSGPACK_DEFAULT_API_NS) {
namespace adaptor {

template<>
struct pack<heu::lib::algorithms::dj::SecretKey> {
  template<typename Stream>
  packer<Stream> &operator()(msgpack::packer<Stream> &o,
      const heu::lib::algorithms::dj::SecretKey &sk) const {
    // packing member variables as an array.
    o.pack_array(3);
    o.pack(sk.N().P);
    o.pack(sk.N().Q);
    o.pack(sk.S());
    return o;
  }
};

template<>
struct convert<heu::lib::algorithms::dj::SecretKey> {
  msgpack::object const &operator()(const msgpack::object &object,
      heu::lib::algorithms::dj::SecretKey &sk) const {
    if (object.type != msgpack::type::ARRAY) { throw msgpack::type_error(); }
    if (object.via.array.size != 3) { throw msgpack::type_error(); }

    // The order here corresponds to the packer above
    auto p = object.via.array.ptr[0].as<heu::lib::algorithms::BigInt>();
    auto q = object.via.array.ptr[1].as<heu::lib::algorithms::BigInt>();
    auto s = object.via.array.ptr[2].as<uint32_t>();
    sk.Init(p, q, s);
    return object;
  }
};

}  // namespace adaptor
}  // namespace msgpack
}  // namespace msgpack

// clang-format on
