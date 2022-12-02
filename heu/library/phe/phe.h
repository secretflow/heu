// Copyright 2022 Ant Group Co., Ltd.
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

#include <utility>

#include "heu/library/phe/decryptor.h"
#include "heu/library/phe/encryptor.h"
#include "heu/library/phe/evaluator.h"
#include "heu/library/phe/key_def.h"

namespace heu::lib::phe {

class HeKitPublicBase {
 public:
  [[nodiscard]] const std::shared_ptr<PublicKey>& GetPublicKey() const {
    return public_key_;
  }

  template <typename T, typename... ARGS>
  T GetEncoder(ARGS&&... args) {
    return T(schema_type_, std::forward<ARGS>(args)...);
  }

  SchemaType GetSchemaType() const { return schema_type_; }

 protected:
  HeKitPublicBase() = default;
  void Setup(std::shared_ptr<PublicKey> pk);

  SchemaType schema_type_;
  std::shared_ptr<PublicKey> public_key_;
};

class HeKitSecretBase : public HeKitPublicBase {
 public:
  [[nodiscard]] const std::shared_ptr<SecretKey>& GetSecretKey() const {
    return secret_key_;
  }

 protected:
  HeKitSecretBase() = default;
  void Setup(std::shared_ptr<PublicKey> pk, std::shared_ptr<SecretKey> sk);

  std::shared_ptr<SecretKey> secret_key_;
};

class HeKit : public HeKitSecretBase {
 public:
  HeKit(SchemaType schema_type, size_t key_size);

  [[nodiscard]] const std::shared_ptr<Encryptor>& GetEncryptor() const {
    return encryptor_;
  }

  [[nodiscard]] const std::shared_ptr<Evaluator>& GetEvaluator() const {
    return evaluator_;
  }

  [[nodiscard]] const std::shared_ptr<Decryptor>& GetDecryptor() const {
    return decryptor_;
  }

 private:
  std::shared_ptr<Encryptor> encryptor_;
  std::shared_ptr<Decryptor> decryptor_;
  std::shared_ptr<Evaluator> evaluator_;
};

// DestinationHeKit cannot generate pk/sk by itself, and must use the pk passed
// from the source Hekit to setup.
// After setup, only Encryptor and Evaluator are available
class DestinationHeKit : public HeKitPublicBase {
 public:
  explicit DestinationHeKit(std::shared_ptr<PublicKey> pk);
  explicit DestinationHeKit(yacl::ByteContainerView pk_buffer);

  [[nodiscard]] const std::shared_ptr<Encryptor>& GetEncryptor() const {
    return encryptor_;
  }

  [[nodiscard]] const std::shared_ptr<Evaluator>& GetEvaluator() const {
    return evaluator_;
  }

 private:
  std::shared_ptr<Encryptor> encryptor_;
  std::shared_ptr<Evaluator> evaluator_;
};

}  // namespace heu::lib::phe
