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

#include <map>
#include <string>
#include <utility>

#include "yacl/base/byte_container_view.h"
#include "yacl/math/mpint/mp_int.h"
#include "yacl/utils/serializer.h"

#include "heu/spi/he/sketches/common/keys.h"
#include "heu/spi/he/sketches/scalar/item_tool.h"

namespace heu::algos::ishe {

using yacl::math::MPInt;
using Plaintext = MPInt;

class Ciphertext {
 public:
  // default constructor
  Ciphertext() = default;

  explicit Ciphertext(MPInt n) : n_(std::move(n)) { d_ = MPInt(1); }

  explicit Ciphertext(MPInt n, MPInt d) : n_(std::move(n)) {
    this->d_ = std::move(d);
  }

  size_t Serialize(uint8_t *buf, size_t buf_len) const;
  [[nodiscard]] yacl::Buffer Serialize() const;
  static Ciphertext Deserialize(yacl::ByteContainerView buffer);
  [[nodiscard]] std::string ToString() const;

  bool operator==(const Ciphertext &other) const {
    return n_ == other.n_ && d_ == other.d_;
  }

  MPInt n_, d_;
};

class SecretKey : public spi::KeySketch<spi::HeKeyType::SecretKey> {
 private:
  MPInt s_, p_, L_;

 public:
  SecretKey(MPInt s, MPInt p, MPInt L);

  SecretKey() = default;

  [[nodiscard]] size_t Serialize(uint8_t *buf, size_t buf_len) const;
  static std::shared_ptr<SecretKey> LoadFrom(yacl::ByteContainerView in);

  [[nodiscard]] std::map<std::string, std::string> ListParams() const override {
    return {
        {"s_", s_.ToString()}, {"p_", p_.ToString()}, {"L_", L_.ToString()}};
  }

  [[nodiscard]] MPInt getS() const { return this->s_; }

  [[nodiscard]] MPInt getP() const { return this->p_; }

  [[nodiscard]] MPInt getL() const { return this->L_; }
};

class PublicParameters : public spi::KeySketch<heu::spi::HeKeyType::PublicKey> {
 private:
  MPInt N, M[2];

 public:
  int64_t k_M = 128;
  int64_t k_r = 160;
  int64_t k_0 = 4096;
  std::vector<MPInt> ADDONES;
  std::vector<MPInt> ONES;
  std::vector<MPInt> NEGS;
  PublicParameters() = default;

  PublicParameters(long k_0, long k_r, long k_M, MPInt &N);

  PublicParameters(long k_0, long k_r, long k_M, MPInt &N,
                   std::vector<MPInt> &ADDONES, std::vector<MPInt> &ONES,
                   std::vector<MPInt> &NEGS);
  [[nodiscard]] size_t Serialize(uint8_t *buf, size_t buf_len) const;
  static std::shared_ptr<PublicParameters> LoadFrom(yacl::ByteContainerView in);

  [[nodiscard]] size_t Maxsize() const { return k_M - 1; }

  [[nodiscard]] MPInt *MessageSpace() { return M; }

  [[nodiscard]] std::map<std::string, std::string> ListParams() const override {
    return {{"key_size", fmt::to_string(k_0)},
            {"random_number_size", fmt::to_string(k_r)},
            {"message_space_size", M[1].ToString()}};
  }

  void Init();

  [[nodiscard]] MPInt getN() const { return N; }
};

class ItemTool : public spi::ItemToolScalarSketch<Plaintext, Ciphertext,
                                                  SecretKey, PublicParameters> {
 public:
  [[nodiscard]] Plaintext Clone(const Plaintext &pt) const override;
  [[nodiscard]] Ciphertext Clone(const Ciphertext &ct) const override;

  size_t Serialize(const Plaintext &pt, uint8_t *buf,
                   size_t buf_len) const override;
  size_t Serialize(const Ciphertext &ct, uint8_t *buf,
                   size_t buf_len) const override;
  static yacl::Buffer Serialize(const Ciphertext &ct);
  [[nodiscard]] Plaintext DeserializePT(
      yacl::ByteContainerView buffer) const override;
  [[nodiscard]] Ciphertext DeserializeCT(
      yacl::ByteContainerView buffer) const override;
};

}  // namespace heu::algos::ishe
