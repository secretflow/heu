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

#include "yacl/base/byte_container_view.h"
#include "yacl/math/mpint/mp_int.h"
#include "yacl/utils/serializer.h"

#include "heu/spi/he/sketches/common/keys.h"
#include "heu/spi/he/sketches/scalar/item_tool.h"

namespace heu::algos::mock_phe {

using yacl::math::MPInt;
using Plaintext = MPInt;

class Ciphertext {
 public:
  Ciphertext() = default;

  explicit Ciphertext(const MPInt &bn) : bn_(bn) {}

  std::string ToString() const { return bn_.ToString(); }

  bool operator==(const Ciphertext &rhs) const { return bn_ == rhs.bn_; }

  size_t Serialize(uint8_t *buf, size_t buf_len) const {
    return bn_.Serialize(buf, buf_len);
  }

  void Deserialize(yacl::ByteContainerView buffer) { bn_.Deserialize(buffer); }

  MPInt bn_;
};

class SecretKey : public spi::EmptyKeySketch<spi::HeKeyType::SecretKey> {};

class PublicKey : public spi::KeySketch<spi::HeKeyType::PublicKey> {
 public:
  explicit PublicKey(int64_t key_size) : key_size_(key_size) {
    YACL_ENFORCE(key_size > 0, "key size {} must > 0", key_size);
  }

  uint64_t KeySize() const { return key_size_; }

  std::map<std::string, std::string> ListParams() const override {
    return {{"key_size", fmt::to_string(key_size_)}};
  }

  size_t Serialize(uint8_t *buf, size_t buf_len) const {
    return yacl::SerializeVarsTo(buf, buf_len, key_size_);
  };

 private:
  const uint64_t key_size_;
};

class ItemTool : public spi::ItemToolScalarSketch<Plaintext, Ciphertext,
                                                  SecretKey, PublicKey> {
 public:
  Plaintext Clone(const Plaintext &pt) const override;
  Ciphertext Clone(const Ciphertext &ct) const override;
};

}  // namespace heu::algos::mock_phe
