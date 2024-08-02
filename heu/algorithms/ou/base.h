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

#pragma once

#include "yacl/utils/serializer.h"

#include "heu/algorithms/common/type_alias.h"
#include "heu/spi/he/sketches/common/keys.h"
#include "heu/spi/he/sketches/scalar/item_tool.h"

namespace heu::algos::ou {

namespace internal_params {
inline constexpr size_t kRandomBits1024 = 80;
// Note: Why 110, not 112?
// 110 is divisible by kExpUnitBits, which can improve performance
inline constexpr size_t kRandomBits2048 = 110;
inline constexpr size_t kRandomBits3072 = 128;
}  // namespace internal_params

using Plaintext = MPInt;

class Ciphertext {
 public:
  Ciphertext() = default;

  explicit Ciphertext(MPInt c) : c_(std::move(c)) {}

  bool operator==(const Ciphertext &other) const { return c_ == other.c_; }

  bool operator!=(const Ciphertext &other) const {
    return !this->operator==(other);
  }

  MPInt c_;
};

class SecretKey : public spi::KeySketch<spi::HeKeyType::SecretKey> {
 public:
  MPInt p_, q_;   // primes such that log2(p), log2(q) ~ n_bits / 3
  MPInt t_;       // a big prime factor of p - 1, i.e., p = t * u + 1.
  MPInt gp_inv_;  // L(g^{p-1} mod p^2))^{-1} mod p

  MPInt p2_;      // p^2
  MPInt p_half_;  // p/2
  MPInt n_;       // n = p^2 * q

  bool operator==(const SecretKey &other) const {
    return p_ == other.p_ && q_ == other.q_ && t_ == other.t_ &&
           gp_inv_ == other.gp_inv_;
  }

  bool operator!=(const SecretKey &other) const {
    return !this->operator==(other);
  }

  [[nodiscard]] size_t Serialize(uint8_t *buf, size_t buf_len) const {
    return yacl::SerializeVarsTo(buf, buf_len, p_, q_, t_, gp_inv_, p2_,
                                 p_half_, n_);
  }

  static std::shared_ptr<SecretKey> LoadFrom(yacl::ByteContainerView in) {
    auto sk = std::make_shared<SecretKey>();
    yacl::DeserializeVarsTo(in, &sk->p_, &sk->q_, &sk->t_, &sk->gp_inv_,
                            &sk->p2_, &sk->p_half_, &sk->n_);
    return sk;
  }

  std::map<std::string, std::string> ListParams() const override {
    return {{"p", p_.ToString()}, {"q", q_.ToString()}};
  }
};

class PublicKey : public spi::KeySketch<spi::HeKeyType::PublicKey> {
 public:
  MPInt n_;          // n = p^2 * q
  MPInt capital_g_;  // G = g^u mod n for some random g \in [0, n)
  MPInt capital_h_;  // H = g'^{n*u} mod n for some random g' \in [0, n)

  MPInt capital_g_inv_;  // G^{-1} mod n
  MPInt max_plaintext_;  // always power of 2, e.g. max_plaintext_ == 2^681

  std::shared_ptr<MontgomerySpace> m_space_;
  // Cache table of bases (底数缓存表).
  // Used to speed up PowMod operations
  // The cache tables are relatively large (~10+MB), so place them in heap to
  // avoid copying the tables when public key is copied
  std::shared_ptr<BaseTable> cg_table_;   // Auxiliary array for capital_g_
  std::shared_ptr<BaseTable> cgi_table_;  // Auxiliary array for capital_g_inv_
  std::shared_ptr<BaseTable> ch_table_;   // Auxiliary array for capital_h_

  void Init();

  bool operator==(const PublicKey &other) const {
    return n_ == other.n_ && capital_g_ == other.capital_g_ &&
           capital_h_ == other.capital_h_;
  }

  bool operator!=(const PublicKey &other) const {
    return !this->operator==(other);
  }

  // Valid plaintext range: [max_plaintext_, -max_plaintext_]
  [[nodiscard]] const MPInt &PlaintextBound() const & { return max_plaintext_; }

  [[nodiscard]] size_t Serialize(uint8_t *buf, size_t buf_len) const {
    return yacl::SerializeVarsTo(buf, buf_len, n_, capital_g_, capital_h_,
                                 max_plaintext_.BitCount() - 1);
  }

  static std::shared_ptr<PublicKey> LoadFrom(yacl::ByteContainerView in) {
    auto pk = std::make_shared<PublicKey>();
    size_t max_bits;
    yacl::DeserializeVarsTo(in, &pk->n_, &pk->capital_g_, &pk->capital_h_,
                            &max_bits);
    pk->max_plaintext_ = MPInt(1) << max_bits;
    pk->Init();
    return pk;
  }

  std::map<std::string, std::string> ListParams() const override {
    return {{"n", n_.ToString()},
            {"G", capital_g_.ToString()},
            {"H", capital_h_.ToString()},
            {"max_plaintext", max_plaintext_.ToString()}};
  }
};

class ItemTool : public spi::ItemToolScalarSketch<Plaintext, Ciphertext,
                                                  SecretKey, PublicKey> {
 public:
  Plaintext Clone(const Plaintext &pt) const override;
  Ciphertext Clone(const Ciphertext &ct) const override;

  size_t Serialize(const Plaintext &pt, uint8_t *buf,
                   size_t buf_len) const override;
  size_t Serialize(const Ciphertext &ct, uint8_t *buf,
                   size_t buf_len) const override;

  Plaintext DeserializePT(yacl::ByteContainerView buffer) const override;
  Ciphertext DeserializeCT(yacl::ByteContainerView buffer) const override;
};

}  // namespace heu::algos::ou
