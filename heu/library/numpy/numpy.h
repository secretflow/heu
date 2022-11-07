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

#include "heu/library/numpy/decryptor.h"
#include "heu/library/numpy/encryptor.h"
#include "heu/library/numpy/evaluator.h"
#include "heu/library/phe/phe.h"

namespace heu::lib::numpy {

// numpy adapter of phe::HeKit
class HeKit : public phe::HeKitSecretBase {
 public:
  explicit HeKit(const phe::HeKit& phe_kit) {
    Setup(phe_kit.GetPublicKey(), phe_kit.GetSecretKey());

    encryptor_ = std::make_shared<Encryptor>(*phe_kit.GetEncryptor());
    decryptor_ = std::make_shared<Decryptor>(*phe_kit.GetDecryptor());
    evaluator_ = std::make_shared<Evaluator>(*phe_kit.GetEvaluator());
  }

  [[nodiscard]] const std::shared_ptr<Encryptor>& GetEncryptor() const {
    return encryptor_;
  }

  [[nodiscard]] const std::shared_ptr<Decryptor>& GetDecryptor() const {
    return decryptor_;
  }

  [[nodiscard]] const std::shared_ptr<Evaluator>& GetEvaluator() const {
    return evaluator_;
  }

 private:
  std::shared_ptr<Encryptor> encryptor_;
  std::shared_ptr<Decryptor> decryptor_;
  std::shared_ptr<Evaluator> evaluator_;
};

// numpy adapter of phe::DestinationHeKit
class DestinationHeKit : public phe::HeKitPublicBase {
 public:
  explicit DestinationHeKit(phe::DestinationHeKit phe_kit) {
    Setup(phe_kit.GetPublicKey());

    encryptor_ = std::make_shared<Encryptor>(*phe_kit.GetEncryptor());
    evaluator_ = std::make_shared<Evaluator>(*phe_kit.GetEvaluator());
  }

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

}  // namespace heu::lib::numpy
