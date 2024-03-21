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

#include <string>
#include <vector>

#include "heu/spi/he/sketches/common/keys.h"
#include "heu/spi/he/sketches/scalar/item_tool.h"

namespace heu::algos::mock_fhe {

class MockObj {
 public:
  MockObj() = default;

  explicit MockObj(const std::vector<int64_t> &array, double scale = 1)
      : array_(array), scale_(scale) {}

  auto operator->() { return &array_; }

  auto operator->() const { return &array_; }

  bool operator==(const MockObj &rhs) const { return array_ == rhs.array_; }

  virtual std::string ToString() const = 0;

  std::vector<int64_t> array_;
  double scale_ = 1;  // only mock_ckks need scale
};

class Plaintext : public MockObj {
 public:
  using MockObj::MockObj;

  std::string ToString() const;
};

class Ciphertext : public MockObj {
 public:
  using MockObj::MockObj;

  std::string ToString() const;
};

class SecretKey : public spi::EmptyKeySketch<spi::HeKeyType::SecretKey> {};

class PublicKey : public spi::EmptyKeySketch<spi::HeKeyType::PublicKey> {};

class RelinKeys : public spi::EmptyKeySketch<spi::HeKeyType::RelinKeys> {};

class GaloisKeys : public spi::EmptyKeySketch<spi::HeKeyType::GaloisKeys> {};

class BootstrapKey : public spi::EmptyKeySketch<spi::HeKeyType::BootstrapKey> {
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

}  // namespace heu::algos::mock_fhe
