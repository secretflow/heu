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

#include "heu/library/phe/phe.h"

namespace heu::lib::phe {

#define INIT_FIELD_IN_NAMESPACE(ns)                                  \
  [&](ns::PublicKey& pk) {                                           \
    ns::SecretKey sk;                                                \
    ns::KeyGenerator::Generate(key_size, &sk, &pk);                  \
                                                                     \
    encryptor_ = std::make_shared<Encryptor>(ns::Encryptor(pk));     \
    decryptor_ = std::make_shared<Decryptor>(ns::Decryptor(pk, sk)); \
    evaluator_ = std::make_shared<Evaluator>(ns::Evaluator(pk));     \
    secret_key_ = std::make_shared<SecretKey>(std::move(sk));        \
  }

void HeKit::Setup(SchemaType schema_type, size_t key_size) {
  public_key_ = std::make_shared<PublicKey>(schema_type);
  public_key_->visit(HE_DISPATCH(INIT_FIELD_IN_NAMESPACE));
}

#define HE_SPECIAL_SETUP_BY_PK(ns)                                \
  [&](const ns::PublicKey& pk1) {                                 \
    evaluator_ = std::make_shared<Evaluator>(ns::Evaluator(pk1)); \
    encryptor_ = std::make_shared<Encryptor>(ns::Encryptor(pk1)); \
  }

void DestinationHeKit::Setup(std::shared_ptr<PublicKey> pk) {
  public_key_ = std::move(pk);
  public_key_->visit(HE_DISPATCH(HE_SPECIAL_SETUP_BY_PK));
}

void DestinationHeKit::Setup(yasl::ByteContainerView pk_buffer) {
  public_key_ = std::make_shared<PublicKey>();
  public_key_->Deserialize(pk_buffer);
  public_key_->visit(HE_DISPATCH(HE_SPECIAL_SETUP_BY_PK));
}

}  // namespace heu::lib::phe
