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

namespace heu::lib::spi {

// A sketch class pre-process all keys
template <typename SecretKeyT, typename PublicKeyT = NoPk,
          typename RelinKeyT = NoRlk, typename GaloisKeyT = NoGlK,
          typename BootstrapKeyT = NoBsk>
class HeKitSketch : public HeKit {
 public:
  virtual SecretKeyT GetSecretKeyT() const = 0;

  virtual PublicKeyT GetPublicKeyT() const {
    YACL_ENFORCE((std::is_same_v<PublicKeyT, NoPk>),
                 "If you see this message, it means that the subclass misses "
                 "this interface. Please override the GetPublicKeyT() "
                 "method in the subclass.");
    YACL_THROW("There is no public key in the current setting");
  }

  virtual RelinKeyT GetRelinKeyT() const {
    YACL_ENFORCE((std::is_same_v<RelinKeyT, NoRlk>),
                 "If you see this message, it means that the subclass misses "
                 "this interface. Please override the GetRelinKeyT() "
                 "method in the subclass.");
    YACL_THROW("There is no relin key in the current setting");
  }

  virtual GaloisKeyT GetGaloisKeyT() const {
    YACL_ENFORCE((std::is_same_v<GaloisKeyT, NoGlK>),
                 "If you see this message, it means that the subclass misses "
                 "this interface. Please override the GetGaloisKeyT() "
                 "method in the subclass.");
    YACL_THROW("There is no galois key in the current setting");
  }

  virtual BootstrapKeyT GetBootstrapKeyT() const {
    YACL_ENFORCE((std::is_same_v<BootstrapKeyT, NoBsk>),
                 "If you see this message, it means that the subclass misses "
                 "this interface. Please override the GetBootstrapKeyT() "
                 "method in the subclass.");
    YACL_THROW("There is no bootstrapping key in the current setting");
  }

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

  std::shared_ptr<ItemManipulator> GetItemManipulator() const override {
    YACL_ENFORCE(item_manipulator_,
                 "Item manipulator is not enabled according to your "
                 "initialization params");
    return item_manipulator_;
  }

  //===   I/O for HE Objects   ===//

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
  // Generate all needed keys according to args.
  // Or recover keys from previous serialized buffer
  virtual void SetupContext(const SpiArgs& args) = 0;

  Item GetPublicKey() const override {
    return {GetPublicKeyT(), ContentType::PublicKey};
  }

  Item GetSecretKey() const override {
    return {GetSecretKeyT(), ContentType::SecretKey};
  }

  Item GetKey(HeKeyType key_type) const override {
    switch (key_type) {
      case HeKeyType::SecretKey:
        return {GetSecretKeyT(), ContentType::SecretKey};
      case HeKeyType::PublicKey:
        return {GetPublicKeyT(), ContentType::PublicKey};
      case HeKeyType::RelinKeys:
        return {GetRelinKeyT(), ContentType::RelinKeys};
      case HeKeyType::GaloisKeys:
        return {GetGaloisKeyT(), ContentType::GaloisKeys};
      case HeKeyType::BootstrapKey:
        return {GetBootstrapKeyT(), ContentType::BootstrapKey};
      default:
        YACL_THROW("Unsupported key type {}", key_type);
    }
  }

  std::shared_ptr<Encryptor> encryptor_;
  std::shared_ptr<Decryptor> decryptor_;
  std::shared_ptr<WordEvaluator> word_evaluator_;
  std::shared_ptr<GateEvaluator> gate_evaluator_;
  std::shared_ptr<BinaryEvaluator> binary_evaluator_;
  std::shared_ptr<ItemManipulator> item_manipulator_;
};

}  // namespace heu::lib::spi
