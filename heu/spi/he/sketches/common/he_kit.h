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

#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <string>

#include "msgpack.hpp"
#include "yacl/base/buffer.h"
#include "yacl/base/byte_container_view.h"

#include "heu/spi/he/he_kit.h"
#include "heu/spi/he/item.h"
#include "heu/spi/he/sketches/common/placeholder.h"

// Suppress the superfluous warnings from clang
#if defined(__clang__)
#pragma clang diagnostic ignored "-Woverloaded-virtual"
#endif

namespace heu::spi {

// A sketch class pre-process all keys
// C++20: use concept to limit KeyT class
template <typename SecretKeyT, typename PublicKeyT = NoPk,
          typename RelinKeyT = NoRlk, typename GaloisKeyT = NoGlk,
          typename BootstrapKeyT = NoBsk>
class HeKitSketch : public HeKit {
 public:
  //===   Operators management   ===//

  std::shared_ptr<Encryptor> GetEncryptor() const override {
    YACL_ENFORCE(
        encryptor_,
        "Encryptor is not enabled according to your initialization params");
    return encryptor_;
  }

  std::shared_ptr<Decryptor> GetDecryptor() const override {
    YACL_ENFORCE(
        decryptor_,
        "Decryptor is not enabled according to your initialization params");
    return decryptor_;
  }

  std::shared_ptr<WordEvaluator> GetWordEvaluator() const override {
    YACL_ENFORCE(word_evaluator_,
                 "Word evaluator is not enabled according to your "
                 "initialization params");
    return word_evaluator_;
  }

  std::shared_ptr<GateEvaluator> GetGateEvaluator() const override {
    YACL_ENFORCE(gate_evaluator_,
                 "Gate evaluator is not enabled according to your "
                 "initialization params");
    return gate_evaluator_;
  }

  std::shared_ptr<BinaryEvaluator> GetBinaryEvaluator() const override {
    YACL_ENFORCE(binary_evaluator_,
                 "Binary evaluator is not enabled according to your "
                 "initialization params");
    return binary_evaluator_;
  }

  std::shared_ptr<ItemTool> GetItemTool() const override {
    YACL_ENFORCE(
        item_tool_,
        "Item-tool is not enabled according to your initialization params");
    return item_tool_;
  }

  //===   Key management   ===//

  // Convert to 'Serialize(HeKeyType, uint8_t *, size_t)'
  yacl::Buffer Serialize(HeKeyType key_type) const override {
    yacl::Buffer buf(Serialize(key_type, nullptr, 0));
    auto real = Serialize(key_type, buf.data<uint8_t>(), buf.size());
    YACL_ENFORCE(static_cast<int64_t>(real) == buf.size(),
                 "Serialize {} fail, size not match, exp={}, real={}", key_type,
                 buf.size(), real);
    return buf;
  }

  //===  I/O for HeKit itself  ===//

  using HeKit::Serialize;

  yacl::Buffer Serialize() const override {
    yacl::Buffer buf(Serialize(nullptr, 0));
    auto real = Serialize(buf.data<uint8_t>(), buf.size());
    YACL_ENFORCE(static_cast<int64_t>(real) == buf.size(),
                 "Serialize HeKit fail, size not match, exp={}, real={}",
                 buf.size(), real);
    return buf;
  }

 protected:
  //===   Key management   ===//

  bool HasSecretKey() const override { return HasKey(HeKeyType::SecretKey); }

  Item GetPublicKey() const override { return GetKey(HeKeyType::PublicKey); }

  Item GetSecretKey() const override { return GetKey(HeKeyType::SecretKey); }

  bool HasKey(heu::spi::HeKeyType key_type) const override {
    switch (key_type) {
      case HeKeyType::SecretKey:
        return static_cast<bool>(sk_);
      case HeKeyType::PublicKey:
        return static_cast<bool>(pk_);
      case HeKeyType::RelinKeys:
        return static_cast<bool>(rlk_);
      case HeKeyType::GaloisKeys:
        return static_cast<bool>(glk_);
      case HeKeyType::BootstrapKey:
        return static_cast<bool>(bsk_);
      default:
        YACL_THROW("Unsupported key type {}", key_type);
    }
  }

  Item GetKey(HeKeyType key_type) const override {
    YACL_ENFORCE(HasKey(key_type), "There is no {} in the current setting",
                 key_type);

    switch (key_type) {
      case HeKeyType::SecretKey:
        return {*sk_, ContentType::SecretKey};
      case HeKeyType::PublicKey:
        return {*pk_, ContentType::PublicKey};
      case HeKeyType::RelinKeys:
        return {*rlk_, ContentType::RelinKeys};
      case HeKeyType::GaloisKeys:
        return {*glk_, ContentType::GaloisKeys};
      case HeKeyType::BootstrapKey:
        return {*bsk_, ContentType::BootstrapKey};
      default:
        YACL_THROW("Unsupported key type {}", key_type);
    }
  }

  std::map<std::string, std::string> ListKeyParams(
      heu::spi::HeKeyType key_type) const override {
    YACL_ENFORCE(HasKey(key_type),
                 "{} not exist in the current settings, cannot list params",
                 key_type);

    switch (key_type) {
      case HeKeyType::SecretKey:
        return sk_->ListParams();
      case HeKeyType::PublicKey:
        return pk_->ListParams();
      case HeKeyType::RelinKeys:
        return rlk_->ListParams();
      case HeKeyType::GaloisKeys:
        return glk_->ListParams();
      case HeKeyType::BootstrapKey:
        return bsk_->ListParams();
      default:
        YACL_THROW("Unsupported key type {}", key_type);
    }
  }

  // The following fields should be initialized by subclasses
  std::shared_ptr<SecretKeyT> sk_;
  std::shared_ptr<PublicKeyT> pk_;
  std::shared_ptr<RelinKeyT> rlk_;
  std::shared_ptr<GaloisKeyT> glk_;
  std::shared_ptr<BootstrapKeyT> bsk_;

  std::shared_ptr<Encryptor> encryptor_;
  std::shared_ptr<Decryptor> decryptor_;
  std::shared_ptr<WordEvaluator> word_evaluator_;
  std::shared_ptr<GateEvaluator> gate_evaluator_;
  std::shared_ptr<BinaryEvaluator> binary_evaluator_;
  std::shared_ptr<ItemTool> item_tool_;
};

}  // namespace heu::spi
