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

#include "heu/spi/he/sketches/common/keys.h"
#include "heu/spi/he/sketches/scalar/item_tool.h"

namespace heu::algos::ishe {

using yacl::math::MPInt;
using Plaintext = MPInt;

class Ciphertext {
 public:
  // default constructor
  Ciphertext() = default;

  explicit Ciphertext(const MPInt n) : n_(n) { d_ = MPInt(1); }

  explicit Ciphertext(MPInt n, MPInt d) : n_(std::move(n)) {
    this->d_ = std::move(d);
  }

  [[nodiscard]] std::string ToString() const;

  bool operator==(const Ciphertext &other) const {
    return n_ == other.n_ && d_ == other.n_;
  }

  MSGPACK_DEFINE(n_, d_);
  MPInt n_, d_;
};

class SecretKey : public spi::KeySketch<heu::spi::HeKeyType::SecretKey> {
 private:
  MPInt s_, p_, L_;

 public:
  MSGPACK_DEFINE(s_, p_, L_);
  SecretKey(MPInt s, MPInt p, MPInt L);
  explicit SecretKey(std::tuple<MPInt, MPInt, MPInt> in);

  SecretKey() = default;

  [[nodiscard]] std::map<std::string, std::string> ListParams() const override {
    return {{"s_", fmt::to_string(s_)},
            {"p_", fmt::to_string(p_)},
            {"L_", fmt::to_string(L_)}};
  }

  MPInt getS() { return this->s_; }

  MPInt getP() { return this->p_; }

  MPInt getL() { return this->L_; }
};

class PublicKey : public spi::KeySketch<heu::spi::HeKeyType::PublicKey> {
 private:
  MPInt N, M[2];

 public:
  long k_M = 64;
  long k_r = 80;
  long k_0 = 1024;
  MSGPACK_DEFINE(k_0, k_r, k_M, N);
  PublicKey() = default;
  PublicKey(long k_0, long k_r, long k_M, MPInt N);
  explicit PublicKey(std::tuple<long, long, long, MPInt> in);

  [[nodiscard]] size_t Keysize() const { return 2 * k_0; }

  [[nodiscard]] MPInt *messageSpace() { return M; }

  [[nodiscard]] std::map<std::string, std::string> ListParams() const override {
    return {{"key_size", fmt::to_string(k_0)},
            {"random_number_size", fmt::to_string(k_r)},
            {"message_space_size", fmt::to_string(M[1])}};
  }

  [[nodiscard]] MPInt getN() const { return N; }
};

class ItemTool : public spi::ItemToolScalarSketch<Plaintext, Ciphertext,
                                                  SecretKey, PublicKey> {
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

  [[nodiscard]] std::string ToString(const spi::Item &item) const override {
    return item.ToString();
  }
};

}  // namespace heu::algos::ishe
