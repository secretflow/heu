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

  [[nodiscard]] std::string ToString() const { return n_.ToString(); }

  bool operator==(const Ciphertext &other) const { return n_ == other.n_; }

  MPInt n_, d_;
};

class SecretKey : public spi::EmptyKeySketch<spi::HeKeyType::SecretKey> {
 private:
  MPInt s_, p_, L_;

 public:
  SecretKey(MPInt s, MPInt p, MPInt L);
  SecretKey() = default;

  MPInt getS() { return this->s_; }

  MPInt getP() { return this->p_; }

  MPInt getL() { return this->L_; }
};

class PublicKey : public spi::EmptyKeySketch<spi::HeKeyType::PublicKey> {
 private:
  MPInt N, M[2];

 public:
  int k_r = 80;
  int k_0 = 1024;
  PublicKey() = default;
  explicit PublicKey(int k_0, int k_r, MPInt M[2], MPInt N);

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

  [[nodiscard]] Plaintext DeserializePT(
      yacl::ByteContainerView buffer) const override;
  [[nodiscard]] Ciphertext DeserializeCT(
      yacl::ByteContainerView buffer) const override;
};

}  // namespace heu::algos::ishe
