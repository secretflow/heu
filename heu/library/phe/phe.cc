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

#include <utility>

namespace heu::lib::phe {

void HeKitPublicBase::Setup(std::shared_ptr<PublicKey> pk) {
  public_key_ = std::move(pk);

  int hit = 0;
  for (const auto& schema : GetAllSchema()) {
    if (public_key_->IsCompatible(schema)) {
      schema_type_ = schema;
      ++hit;
    }
  }
  YACL_ENFORCE("Cannot detect schema type of public key {}, hit={}",
               public_key_->ToString(), hit);
}

void HeKitSecretBase::Setup(std::shared_ptr<PublicKey> pk,
                            std::shared_ptr<SecretKey> sk) {
  HeKitPublicBase::Setup(std::move(pk));
  secret_key_ = std::move(sk);
}

#define GEN_KEY_AND_INIT(ns)                                                  \
  [&](ns::PublicKey& pk) {                                                    \
    ns::SecretKey sk;                                                         \
    ns::KeyGenerator::Generate(key_size, &sk, &pk);                           \
                                                                              \
    encryptor_ = std::make_shared<Encryptor>(schema_type, ns::Encryptor(pk)); \
    decryptor_ =                                                              \
        std::make_shared<Decryptor>(schema_type, ns::Decryptor(pk, sk));      \
    evaluator_ = std::make_shared<Evaluator>(schema_type, ns::Evaluator(pk)); \
    return std::make_shared<SecretKey>(std::move(sk));                        \
  }

HeKit::HeKit(SchemaType schema_type, size_t key_size) {
  auto pk = std::make_shared<PublicKey>(schema_type);
  auto sk =
      pk->Visit(HE_DISPATCH_RET(std::shared_ptr<SecretKey>, GEN_KEY_AND_INIT));
  Setup(std::move(pk), std::move(sk));
}

#define HE_SPECIAL_SETUP_BY_PK(ns)                                     \
  [&](const ns::PublicKey& pk1) {                                      \
    evaluator_ =                                                       \
        std::make_shared<Evaluator>(schema_type_, ns::Evaluator(pk1)); \
    encryptor_ =                                                       \
        std::make_shared<Encryptor>(schema_type_, ns::Encryptor(pk1)); \
  }

DestinationHeKit::DestinationHeKit(std::shared_ptr<PublicKey> pk) {
  Setup(std::move(pk));
  public_key_->Visit(HE_DISPATCH(HE_SPECIAL_SETUP_BY_PK));
}

DestinationHeKit::DestinationHeKit(yacl::ByteContainerView pk_buffer) {
  auto pk = std::make_shared<PublicKey>();
  pk->Deserialize(pk_buffer);
  Setup(std::move(pk));
  public_key_->Visit(HE_DISPATCH(HE_SPECIAL_SETUP_BY_PK));
}

}  // namespace heu::lib::phe
