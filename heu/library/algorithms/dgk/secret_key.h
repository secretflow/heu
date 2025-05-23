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

class SecretKey : public HeObject<SecretKey> {
 public:
  void Init(const BigInt &p, const BigInt &q, const BigInt &vp,
            const BigInt &vq, const BigInt &u, const BigInt &g);

  const BigInt &P() const { return p_; }

  const BigInt &Q() const { return q_; }

  const BigInt &Vp() const { return vp_; }

  const BigInt &Vq() const { return vq_; }

  const BigInt &U() const { return u_; }

  const BigInt &G() const { return g_; }

  bool operator==(const SecretKey &) const;
  bool operator!=(const SecretKey &) const;
  std::string ToString() const override;

  BigInt Decrypt(const BigInt &ct) const;

 private:
  BigInt p_, q_, vp_, vq_, u_, g_;

  std::shared_ptr<std::unordered_map<BigInt, BigInt>> log_table_;
};

}  // namespace heu::lib::algorithms::dgk

// clang-format off
namespace msgpack {
MSGPACK_API_VERSION_NAMESPACE(MSGPACK_DEFAULT_API_NS) {
namespace adaptor {

template<>
struct pack<heu::lib::algorithms::dgk::SecretKey> {
  template<typename Stream>
  packer<Stream> &operator()(msgpack::packer<Stream> &o,
      const heu::lib::algorithms::dgk::SecretKey &sk) const {
    // packing member variables as an array.
    o.pack_array(6);
    o.pack(sk.P());
    o.pack(sk.Q());
    o.pack(sk.Vp());
    o.pack(sk.Vq());
    o.pack(sk.U());
    o.pack(sk.G());
    return o;
  }
};

template<>
struct convert<heu::lib::algorithms::dgk::SecretKey> {
  msgpack::object const &operator()(const msgpack::object &object,
      heu::lib::algorithms::dgk::SecretKey &sk) const {
    if (object.type != msgpack::type::ARRAY) { throw msgpack::type_error(); }
    if (object.via.array.size != 6) { throw msgpack::type_error(); }

    // The order here corresponds to the packer above
    auto p = object.via.array.ptr[0].as<heu::lib::algorithms::BigInt>();
    auto q = object.via.array.ptr[1].as<heu::lib::algorithms::BigInt>();
    auto vp = object.via.array.ptr[2].as<heu::lib::algorithms::BigInt>();
    auto vq = object.via.array.ptr[3].as<heu::lib::algorithms::BigInt>();
    auto u = object.via.array.ptr[4].as<heu::lib::algorithms::BigInt>();
    auto g = object.via.array.ptr[5].as<heu::lib::algorithms::BigInt>();
    sk.Init(p, q, vp, vq, u, g);
    return object;
  }
};

}  // namespace adaptor
}  // namespace msgpack
}  // namespace msgpack

// clang-format on
