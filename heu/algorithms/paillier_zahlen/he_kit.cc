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

#include "heu/algorithms/paillier_zahlen/he_kit.h"

#include "heu/algorithms/paillier_zahlen/decryptor.h"
#include "heu/algorithms/paillier_zahlen/encryptor.h"
#include "heu/algorithms/paillier_zahlen/evaluator.h"
#include "heu/spi/he/he.h"

namespace heu::algos::paillier_z {

namespace {
const std::string kLibName = "paillier_zahlen";  // do not change
constexpr size_t kPQDifferenceBitLenSub = 2;     // >=1022-bit P-Q
}  // namespace

std::string HeKit::GetLibraryName() const { return kLibName; }

spi::Schema HeKit::GetSchema() const { return spi::Schema::Paillier; }

std::string HeKit::ToString() const {
  return fmt::format("{} schema from {} lib, key size={}", GetSchema(),
                     GetLibraryName(), pk_->key_size_);
}

size_t HeKit::Serialize(uint8_t *, size_t) const {
  // nothing to serialize
  return 0;  // TODO
}

bool HeKit::Check(spi::Schema schema, const spi::SpiArgs &) {
  return schema == spi::Schema::Paillier;
}

std::unique_ptr<spi::HeKit> HeKit::Create(spi::Schema schema,
                                          const spi::SpiArgs &args) {
  YACL_ENFORCE(schema == spi::Schema::Paillier, "Schema {} not supported by {}",
               schema, kLibName);
  YACL_ENFORCE(
      args.Exist(spi::ArgGenNewPkSk) || args.Exist(spi::ArgPkFrom),
      "Neither ArgGenNewPkSk nor ArgPkFrom is set, you must set one of them");

  auto kit = std::make_unique<HeKit>();
  if (args.GetOptional(spi::ArgGenNewPkSk) == true) {
    kit->GenPkSk(args.GetOrDefault(spi::ArgKeySize, 2048));
  } else {
    // recover pk/sk from buffer
    kit->pk_ = PublicKey::LoadFrom(args.GetRequired(spi::ArgPkFrom));
    if (args.Exist(spi::ArgSkFrom)) {
      kit->sk_ = SecretKey::LoadFrom(args.GetRequired(spi::ArgSkFrom));
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

    if (sk_) {
      decryptor_ = std::make_shared<Decryptor>(pk_, sk_);
    }
  }
}

void HeKit::GenPkSk(size_t key_size) {
  YACL_ENFORCE(key_size % 2 == 0, "Key size must be even");

  BigInt p, q, n, c;
  // To avoid square-root attacks, make sure the bit length of p-q is very
  // large.
  do {
    size_t half = key_size / 2;
    p = BigInt::RandPrimeOver(half, PrimeType::BBS);
    do {
      q = BigInt::RandPrimeOver(half, PrimeType::BBS);
      c = (p - 1).Gcd(q - 1);
    } while (c != 2 ||
             (p - q).BitCount() < key_size / 2 - kPQDifferenceBitLenSub);
    n = p * q;
  } while (n.BitCount() < key_size);

  BigInt x, h;
  do {
    x = BigInt::RandomLtN(n);
    c = x.Gcd(n);
  } while (c != 1);
  h = -x.MulMod(x, n);

  // fill secret key
  sk_ = std::make_shared<SecretKey>();
  sk_->p_ = p;
  sk_->q_ = q;
  sk_->lambda_ = (p - 1) * (q - 1) / 2;
  sk_->mu_ = sk_->lambda_.InvMod(n);
  sk_->Init();
  // fill public key
  pk_ = std::make_shared<PublicKey>();
  pk_->h_s_ = sk_->PowModNSquareCrt(h, n);
  pk_->n_ = std::move(n);
  pk_->Init();
}

REGISTER_HE_LIBRARY(kLibName, 100, HeKit::Check, HeKit::Create);

}  // namespace heu::algos::paillier_z
