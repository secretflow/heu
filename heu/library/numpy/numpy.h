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
class HeKit {
 public:
  explicit HeKit(phe::HeKit phe) : phe_kit_(std::move(phe)) {
    encryptor_ = std::make_shared<Encryptor>(*phe_kit_.GetEncryptor());
    decryptor_ = std::make_shared<Decryptor>(*phe_kit_.GetDecryptor());
    evaluator_ = std::make_shared<Evaluator>(*phe_kit_.GetEvaluator());
  }

  [[nodiscard]] const std::shared_ptr<phe::PublicKey>& GetPublicKey() const {
    return phe_kit_.GetPublicKey();
  }

  [[nodiscard]] const std::shared_ptr<phe::SecretKey>& GetSecretKey() const {
    return phe_kit_.GetSecretKey();
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
  phe::HeKit phe_kit_;
  std::shared_ptr<Encryptor> encryptor_;
  std::shared_ptr<Decryptor> decryptor_;
  std::shared_ptr<Evaluator> evaluator_;
};

// numpy adapter of phe::DestinationHeKit
class DestinationHeKit {
 public:
  explicit DestinationHeKit(phe::DestinationHeKit phe)
      : phe_kit_(std::move(phe)) {
    encryptor_ = std::make_shared<Encryptor>(*phe_kit_.GetEncryptor());
    evaluator_ = std::make_shared<Evaluator>(*phe_kit_.GetEvaluator());
  }

  [[nodiscard]] const std::shared_ptr<phe::PublicKey>& GetPublicKey() const {
    return phe_kit_.GetPublicKey();
  }

  [[nodiscard]] const std::shared_ptr<Encryptor>& GetEncryptor() const {
    return encryptor_;
  }

  [[nodiscard]] const std::shared_ptr<Evaluator>& GetEvaluator() const {
    return evaluator_;
  }

 private:
  phe::DestinationHeKit phe_kit_;
  std::shared_ptr<Encryptor> encryptor_;
  std::shared_ptr<Evaluator> evaluator_;
};

}  // namespace heu::lib::numpy
