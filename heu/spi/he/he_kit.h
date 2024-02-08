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

#include "yacl/base/buffer.h"
#include "yacl/utils/spi/spi_factory.h"

#include "heu/spi/he/binary_evaluator.h"
#include "heu/spi/he/decryptor.h"
#include "heu/spi/he/encoder.h"
#include "heu/spi/he/encryptor.h"
#include "heu/spi/he/gate_evaluator.h"
#include "heu/spi/he/item.h"
#include "heu/spi/he/item_manipulator.h"
#include "heu/spi/he/word_evaluator.h"

namespace heu::lib::spi {

class HeKit {
 public:
  virtual ~HeKit() = default;

  //===   Meta query   ===//

  virtual std::string GetLibraryName() const = 0;
  virtual std::string GetSchemaName() const = 0;

  // equal to GetKey(HeKeyType::PublicKey);
  virtual Item GetPublicKey() const = 0;
  virtual Item GetSecretKey() const = 0;
  virtual Item GetKey(HeKeyType key_type) const = 0;

  //===   Get Operators   ===//

  // The state transition diagram:
  // 1. Cleartext --(encoder)--> Plaintext --(Encryptor)--> Ciphertext
  // 2. Plaintext/Ciphertext --(Evaluator)--> Plaintext/Ciphertext
  // 3. Ciphertext --(Decryptor)--> Plaintext --(Encoder)--> Cleartext
  // 4. ItemManipulator --> Apply operations to Items

  virtual std::shared_ptr<Encryptor> GetEncryptor() const = 0;
  virtual std::shared_ptr<Decryptor> GetDecryptor() const = 0;
  virtual std::shared_ptr<WordEvaluator> GetWordEvaluator() const = 0;
  virtual std::shared_ptr<GateEvaluator> GetGateEvaluator() const = 0;
  virtual std::shared_ptr<BinaryEvaluator> GetBinaryEvaluator() const = 0;
  virtual std::shared_ptr<ItemManipulator> GetItemManipulator() const = 0;

  template <typename... T>
  std::shared_ptr<Encoder> GetEncoder(T&&... encoder_args) const {
    return CreateEncoder({std::forward<T>(encoder_args)...});
  }

  //===  I/O for HeKit itself  ===//

  // Print context info, key info, and so on
  virtual std::string ToString() const = 0;

  // Serialize HeKit itself, without key
  // Save HeKit's param and context to Buffer
  // 保存 HeKit 的参数（即 Context）以便其它参与者可以恢复出相同的 HeKit
  virtual yacl::Buffer Serialize() const = 0;
  virtual size_t Serialize(uint8_t* buf, size_t buf_len) const = 0;

  // Special api for serializing keys (maybe in compressed format)
  // For some algorithms, the serialized string returned by `SaveKey` has a
  // higher compression rate than `Serialize(hekit->GetKey())`. This is because
  // the pseudorandom part of some keys can be instead stored as a seed.
  // For example, GaloisKeys can often be very large, but in reality
  // half of the data is pseudorandom and can be stored as a seed. Since
  // GaloisKeys are never used by the party that generates them, so it makes
  // sense to expand the seed at the point deserialization.
  // The `hekit->GetKey()` returns a valid, expanded key that cannot be
  // re-seeded and usually has a larger serialization size.
  //
  // The Key in HeKit is read-only and does not provide a mechanism to reset the
  // Key. Therefore, there is no interface such as `LoadKey()`. If you want to
  // deserialize the Key, please pass the serialized string to factory to get a
  // new HeKit with the same Key.
  // HeKit 中的 Key 是只读的，不提供重置 Key 的机制，因此没有 `LoadKey()`
  // 之类的接口， 想要反序列化 Key，请将 Key 的二进制串作为参数传给工厂，
  // 从而得到新的、有相同 Key 的 HeKit
  virtual yacl::Buffer Serialize(HeKeyType key_type) const = 0;
  virtual size_t Serialize(HeKeyType key_type, uint8_t* buf,
                           size_t buf_len) const = 0;

 protected:
  virtual std::shared_ptr<Encoder> CreateEncoder(const SpiArgs&) const = 0;
};

class HeFactory final : public yacl::SpiFactoryBase<HeKit> {
 public:
  static HeFactory& Instance();
};

/*
 * The sign of creator/checker:
 * > std::unique_ptr<HeKit> Create(const std::string &schema, const SpiArgs &);
 * > bool Check(const std::string &schema, const SpiArgs &args);
 */
#define REGISTER_HE_LIBRARY(lib_name, performance, checker, creator)     \
  REGISTER_SPI_LIBRARY_HELPER(HeFactory, lib_name, performance, checker, \
                              creator)

}  // namespace heu::lib::spi
