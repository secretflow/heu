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

#include "heu/algorithms/incubator/mock_phe/he_kit.h"

#include <memory>
#include <string>

#include "yacl/utils/serializer.h"

#include "heu/algorithms/incubator/mock_phe/decryptor.h"
#include "heu/algorithms/incubator/mock_phe/encryptor.h"
#include "heu/algorithms/incubator/mock_phe/evaluator.h"
#include "heu/spi/he/he.h"

namespace heu::algos::mock_phe {

static const std::string kLibName = "mock_phe";  // do not change

std::string HeKit::GetLibraryName() const { return kLibName; }

spi::Schema HeKit::GetSchema() const { return spi::Schema::MockPhe; }

std::string HeKit::ToString() const {
  return fmt::format("{} schema from {} lib, key size={}", GetSchema(),
                     GetLibraryName(), pk_->KeySize());
}

size_t HeKit::Serialize(uint8_t *, size_t) const {
  // nothing to serialize
  return 0;
}

bool HeKit::Check(spi::Schema schema, const spi::SpiArgs &) {
  return schema == spi::Schema::MockPhe;
}

std::unique_ptr<spi::HeKit> HeKit::Create(spi::Schema schema,
                                          const spi::SpiArgs &args) {
  YACL_ENFORCE(schema == spi::Schema::MockPhe, "Schema {} not supported by {}",
               schema, kLibName);
  YACL_ENFORCE(
      args.Exist(spi::ArgGenNewPkSk) || args.Exist(spi::ArgPkFrom),
      "Neither ArgGenNewPkSk nor ArgPkFrom is set, you must set one of them");

  auto kit = std::make_unique<HeKit>();
  if (args.GetOptional(spi::ArgGenNewPkSk) == true) {
    // generate new pk, sk
    kit->sk_ = std::make_shared<SecretKey>();
    kit->pk_ =
        std::make_shared<PublicKey>(args.GetOrDefault(spi::ArgKeySize, 2048));
  } else {
    // recover pk/sk from buffer
    kit->pk_ = std::make_shared<PublicKey>(
        yacl::DeserializeVars<decltype(pk_->KeySize())>(
            args.GetRequired(spi::ArgPkFrom)));
    if (args.Exist(spi::ArgSkFrom)) {
      kit->sk_ = std::make_shared<SecretKey>();
    }
  }

  kit->InitOperators();
  return kit;
}

void HeKit::InitOperators() {
  item_tool_ = std::make_shared<ItemTool>();

  if (pk_) {
    encryptor_ = std::make_shared<Encryptor>(pk_);
    word_evaluator_ = std::make_shared<Evaluator>(pk_);
  }

  if (sk_) {
    decryptor_ = std::make_shared<Decryptor>();
  }
}

REGISTER_HE_LIBRARY(kLibName, 1, HeKit::Check, HeKit::Create);

}  // namespace heu::algos::mock_phe
