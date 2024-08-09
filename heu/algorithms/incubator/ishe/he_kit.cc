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

#include "heu/algorithms/incubator/ishe/he_kit.h"

#include <fmt/format.h>

#include <memory>
#include <string>

#include "yacl/utils/serializer.h"

#include "heu/algorithms/incubator/ishe/decryptor.h"
#include "heu/algorithms/incubator/ishe/encryptor.h"
#include "heu/algorithms/incubator/ishe/evaluator.h"
#include "heu/spi/he/he.h"

namespace heu::algos::ishe {

static const std::string kLibName = "iSHE";

std::string HeKit::GetLibraryName() const { return kLibName; }

spi::Schema HeKit::GetSchema() const { return spi::Schema::iSHE; }

std::string HeKit::ToString() const {
  return fmt::format("{} schema from {} lib", GetSchema(), GetLibraryName());
}

size_t HeKit::Serialize(uint8_t *buf, size_t buf_len) const {
  return yacl::SerializeVarsTo(buf, buf_len, sk_, pk_);
}

bool HeKit::Check(spi::Schema schema, const spi::SpiArgs &) {
  return schema == spi::Schema::iSHE;
}

size_t HeKit::Serialize(spi::HeKeyType key_type, uint8_t *buf,
                        const size_t buf_len) const {
  switch (key_type) {
    case spi::HeKeyType::SecretKey:
      return yacl::SerializeVarsTo(buf, buf_len, sk_->getS(), sk_->getP(),
                                   sk_->getL());
    case spi::HeKeyType::PublicKey:
      return yacl::SerializeVarsTo(buf, buf_len, pk_->k_0, pk_->k_r, pk_->k_M,
                                   pk_->getN());
    default:
      YACL_THROW("Unknown key type {}", key_type);
  }
}

bool HeKit::HasKey(heu::spi::HeKeyType key_type) const {
  switch (key_type) {
    case spi::HeKeyType::SecretKey:
      return static_cast<bool>(sk_);
    case spi::HeKeyType::PublicKey:
      return static_cast<bool>(pk_);
    default:
      YACL_THROW("Unsupported key type {}", key_type);
  }
}

std::unique_ptr<HeKit> HeKit::CreateParams(spi::Schema schema, const long k_0,
                                           const long k_r, const long k_M) {
  YACL_ENFORCE(schema == spi::Schema::iSHE, "Schema {} not supported by {}",
               schema, kLibName);
  YACL_ENFORCE(k_0 > k_r && k_r > k_M && k_M > 0,
               "do not obey the rule of params");
  auto kit = std::make_unique<HeKit>();
  MPInt p, q, s, L;
  // choose random prime p&q, k_0 bits
  MPInt::RandPrimeOver(k_0, &p);
  MPInt::RandPrimeOver(k_0, &q);
  // N = p * q
  const MPInt N = p * q;
  // choose s mod N < N
  MPInt::RandomLtN(N, &s);
  MPInt::RandomExactBits(k_r, &L);
  kit->sk_ = std::make_shared<SecretKey>(s, p, L);
  kit->pk_ = std::make_shared<PublicKey>(k_0, k_r, k_M, N);
  // init evaluator
  kit->InitOperators();
  return kit;
}

std::unique_ptr<HeKit> HeKit::Create(const spi::Schema schema,
                                     const spi::SpiArgs &args) {
  YACL_ENFORCE(schema == spi::Schema::iSHE, "Schema {} not supported by {}",
               schema, kLibName);
  YACL_ENFORCE(
      args.Exist(spi::ArgGenNewPkSk) || args.Exist(spi::ArgPkFrom),
      "Neither ArgGenNewPkSk nor ArgPkFrom is set, you must set one of them");

  auto kit = std::make_unique<HeKit>();
  if (args.GetOptional(spi::ArgGenNewPkSk) == true) {
    MPInt p, q, s, L, space[2];
    // choose random prime p&q, k_0 bits
    const auto k_0 = args.GetOrDefault(Argk0, 2048);
    const auto k_r = args.GetOrDefault(Argkr, 160);
    const auto k_M = args.GetOrDefault(ArgkM, 128);
    MPInt::RandPrimeOver(k_0, &p);
    MPInt::RandPrimeOver(k_0, &q);
    // N = p * q
    const MPInt N = p * q;
    // choose s mod N < N
    MPInt::RandomLtN(N, &s);
    // choose random L , k_r bits
    MPInt::RandomExactBits(k_r, &L);
    // init key pairs
    kit->sk_ = std::make_shared<SecretKey>(s, p, L);
    kit->pk_ = std::make_shared<PublicKey>(k_0, k_r, k_M, N);
  } else {
    kit->pk_ = std::make_shared<PublicKey>(
        yacl::DeserializeVars<decltype(pk_->k_0), decltype(pk_->k_r),
                              decltype(pk_->k_M), decltype(pk_->getN())>(
            args.GetRequired(spi::ArgPkFrom)));
    if (args.Exist(spi::ArgSkFrom)) {
      kit->sk_ = std::make_shared<SecretKey>(
          yacl::DeserializeVars<decltype(sk_->getS()), decltype(sk_->getP()),
                                decltype(sk_->getL())>(
              args.GetRequired(spi::ArgSkFrom)));
    }
  }
  kit->InitOperators();
  return kit;
}

void HeKit::InitOperators() {
  item_tool_ = std::make_shared<ItemTool>();

  if (pk_ && sk_) {
    encryptor_ = std::make_shared<Encryptor>(pk_, sk_);
    word_evaluator_ =
        std::make_shared<Evaluator>(pk_, std::make_shared<Encryptor>(pk_, sk_));
    decryptor_ = std::make_shared<Decryptor>(sk_, pk_);
  }
}

REGISTER_HE_LIBRARY(kLibName, 1, HeKit::Check, HeKit::Create);

}  // namespace heu::algos::ishe
