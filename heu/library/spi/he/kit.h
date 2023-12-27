// Copyright 2023 Ant Group Co., Ltd.
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

#include "yacl/base/buffer.h"
#include "yacl/base/byte_container_view.h"
#include "yacl/utils/spi/spi_factory.h"

#include "heu/library/spi/he/binary_evaluator.h"
#include "heu/library/spi/he/decryptor.h"
#include "heu/library/spi/he/encryptor.h"
#include "heu/library/spi/he/gate_evaluator.h"
#include "heu/library/spi/he/word_evaluator.h"

namespace heu::lib::spi {

enum class HeKeyType {
  PublicKey,
  SecretKey,
  RelinKeys,
  GaloisKeys,
  BootstrappingKey,
};

class HeKit {
 public:
  virtual ~HeKit() = default;

  //===   Meta query   ===//

  virtual std::string GetLibraryName() const = 0;
  virtual std::string GetSchemaName() const = 0;

  virtual Item GetPublicKey() = 0;  // equal to GetKey(HeKeyType::PublicKey);
  virtual Item GetSecretKey() = 0;
  virtual Item GetKey(HeKeyType key_type) = 0;

  //===   Get Operators   ===//

  virtual std::shared_ptr<Encryptor> GetEncryptor() const;
  virtual std::shared_ptr<Decryptor> GetDecryptor() const;
  virtual std::shared_ptr<WordEvaluator> GetWordEvaluator() const;
  virtual std::shared_ptr<GateEvaluator> GetGateEvaluator() const;
  virtual std::shared_ptr<BinaryEvaluator> GetBinaryEvaluator() const;

  //===   Get Encoders   ===//

  // TODO

  /*====================================//
   *          I/O for HE Objects
   *
   *  以下所有函数的入参出参均支持如下形式：
   *  1. Plaintext
   *  2. Plaintext array
   *  3. Ciphertext
   *  4. Ciphertext array
   *  5. All kinds of keys
   *====================================*/

  // Make a deep copy of obj.
  virtual Item Clone(const Item& obj) const = 0;

  // To human-readable string
  virtual std::string ToString(const Item& x) const = 0;

  // The format of object(s) is based on initial params
  virtual yacl::Buffer Serialize(const Item& x) const = 0;
  // serialize field element(s) to already allocated buffer.
  // if buf is nullptr, then calc serialize size only
  // @return: the actual size of serialized buffer
  virtual size_t Serialize(const Item& x, uint8_t* buf,
                           size_t buf_len) const = 0;

  virtual Item Deserialize(yacl::ByteContainerView buffer) const = 0;

 protected:
  // Generate all needed keys according to args.
  // Or recover keys from previous serialized buffer
  virtual void SetupContext(const SpiArgs& args) = 0;

  std::shared_ptr<Encryptor> encryptor_;
  std::shared_ptr<Decryptor> decryptor_;
  std::shared_ptr<WordEvaluator> word_evaluator_;
  std::shared_ptr<GateEvaluator> gate_evaluator_;
  std::shared_ptr<BinaryEvaluator> binary_evaluator_;
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
