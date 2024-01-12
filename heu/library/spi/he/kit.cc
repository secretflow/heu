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

#include "heu/library/spi/he/kit.h"

namespace heu::lib::spi {

std::shared_ptr<Encryptor> HeKit::GetEncryptor() const {
  YACL_ENFORCE(
      encryptor_,
      "Encryptor is not enabled according to your initialization params");
  return encryptor_;
}

std::shared_ptr<Decryptor> HeKit::GetDecryptor() const {
  YACL_ENFORCE(
      decryptor_,
      "Decryptor is not enabled according to your initialization params");
  return decryptor_;
}

std::shared_ptr<WordEvaluator> HeKit::GetWordEvaluator() const {
  YACL_ENFORCE(
      word_evaluator_,
      "Word evaluator is not enabled according to your initialization params");
  return word_evaluator_;
}

std::shared_ptr<GateEvaluator> HeKit::GetGateEvaluator() const {
  YACL_ENFORCE(
      gate_evaluator_,
      "Gate evaluator is not enabled according to your initialization params");
  return gate_evaluator_;
}

std::shared_ptr<BinaryEvaluator> HeKit::GetBinaryEvaluator() const {
  YACL_ENFORCE(binary_evaluator_,
               "Binary evaluator is not enabled according to your "
               "initialization params");
  return binary_evaluator_;
}

HeFactory& HeFactory::Instance() {
  static HeFactory factory;
  return factory;
}

}  // namespace heu::lib::spi
