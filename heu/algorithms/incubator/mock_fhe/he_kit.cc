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

#include "heu/algorithms/incubator/mock_fhe/he_kit.h"

#include <memory>
#include <string>

#include "yacl/utils/serializer.h"

#include "heu/algorithms/common/type_alias.h"
#include "heu/algorithms/incubator/mock_fhe/decryptor.h"
#include "heu/algorithms/incubator/mock_fhe/encoders.h"
#include "heu/algorithms/incubator/mock_fhe/encryptor.h"
#include "heu/algorithms/incubator/mock_fhe/evaluator.h"
#include "heu/spi/he/he.h"
#include "heu/spi/utils/math_tool.h"

namespace heu::algos::mock_fhe {

static const std::string kLibName = "mock_fhe";  // do not change

std::string HeKit::GetLibraryName() const { return kLibName; }

spi::Schema HeKit::GetSchema() const { return schema_; }

spi::FeatureSet HeKit::GetFeatureSet() const {
  return schema_ == spi::Schema::MockCkks ? spi::FeatureSet::ApproxFHE
                                          : spi::FeatureSet::WordFHE;
}

std::string HeKit::ToString() const {
  if (schema_ == spi::Schema::MockCkks) {
    return fmt::format("{} schema from {} lib, poly_degree={}, scale={}",
                       GetSchema(), GetLibraryName(), poly_degree_, scale_);
  } else {
    return fmt::format("{} schema from {} lib, poly_degree={}", GetSchema(),
                       GetLibraryName(), poly_degree_);
  }
}

size_t HeKit::Serialize(uint8_t *buf, size_t len) const {
  return yacl::SerializeVarsTo(buf, len, poly_degree_,
                               spi::Schema2String(schema_), scale_);
}

void HeKit::Deserialize(yacl::ByteContainerView in) {
  std::string schema_str;
  yacl::DeserializeVarsTo(in, &poly_degree_, &schema_str, &scale_);
  schema_ = spi::String2Schema(schema_str);
}

size_t HeKit::Serialize(spi::HeKeyType, uint8_t *, size_t) const { return 0; }

bool HeKit::Check(spi::Schema schema, const spi::SpiArgs &) {
  return schema == spi::Schema::MockBfv || schema == spi::Schema::MockCkks;
}

std::shared_ptr<spi::Encoder> HeKit::CreateEncoder(
    const yacl::SpiArgs &args) const {
  if (args.Exist(spi::ArgScale)) {
    YACL_ENFORCE(schema_ != spi::Schema::MockBfv,
                 "mock_bfv schema do not support scale arg.");
    YACL_ENFORCE(args.GetRequired(spi::ArgScale) == scale_,
                 "Mock_ckks: You shouldn't change scale, scale is already set "
                 "in factory");
  }

  auto em = args.GetOrDefault(spi::ArgEncodingMethod, "batch");
  if (em == "plain") {
    YACL_ENFORCE(schema_ == spi::Schema::MockBfv,
                 "Only mock_bfv schema supports plain encoder");
    return std::make_shared<PlainEncoder>(poly_degree_);
  } else if (em == "batch") {
    if (schema_ == spi::Schema::MockBfv) {
      return std::make_shared<BatchEncoder>(poly_degree_);
    } else {
      return std::make_shared<CkksEncoder>(poly_degree_, scale_);
    }
  } else {
    YACL_THROW("Unsupported encoding method {}", em);
  }
}

std::unique_ptr<spi::HeKit> HeKit::Create(spi::Schema schema,
                                          const spi::SpiArgs &args) {
  YACL_ENFORCE(
      schema == spi::Schema::MockBfv || schema == spi::Schema::MockCkks,
      "Schema {} not supported by {}", schema, kLibName);
  YACL_ENFORCE(args.Exist(spi::ArgGenNewPkSk) || args.Exist(spi::ArgPkFrom),
               "Neither ArgGenNewPkSk nor ArgPkFrom is set, you must set one "
               "of them, args={}",
               args);

  // process context
  auto kit = std::make_unique<HeKit>();
  // first deserialize previous context
  if (args.Exist(spi::ArgParamsFrom)) {
    kit->Deserialize(args.GetRequired(spi::ArgParamsFrom));
  }
  // next, if the user specifies arguments, override the previous context.
  kit->poly_degree_ =
      args.GetOrDefault(spi::ArgPolyModulusDegree, kit->poly_degree_);
  YACL_ENFORCE(spi::utils::IsPowerOf2(kit->poly_degree_),
               "Poly degree {} must be power of two", kit->poly_degree_);

  kit->schema_ = schema;
  if (kit->schema_ == spi::Schema::MockCkks) {
    kit->scale_ = args.GetOrDefault(spi::ArgScale, kit->scale_);
    YACL_ENFORCE(kit->scale_ != 0, "scale must not be zero");
  }

  // process keys
  if (args.GetOptional(spi::ArgGenNewPkSk) == true) {
    // generate new keys
    kit->sk_ = std::make_shared<SecretKey>();
    kit->pk_ = std::make_shared<PublicKey>();
    if (args.GetOrDefault(spi::ArgGenNewRlk, false)) {
      kit->rlk_ = std::make_shared<RelinKeys>();
    }
    if (args.GetOrDefault(spi::ArgGenNewGlk, false)) {
      kit->glk_ = std::make_shared<GaloisKeys>();
    }
    if (args.GetOrDefault(spi::ArgGenNewBsk, false)) {
      kit->bsk_ = std::make_shared<BootstrapKey>();
    }
  } else {
    // recover all keys from buffer
    if (args.Exist(spi::ArgSkFrom)) {
      kit->sk_ = std::make_shared<SecretKey>();
    }
    YACL_ENFORCE(args.Exist(spi::ArgPkFrom),
                 "no public key buffer found, cannot deserialize");
    kit->pk_ = std::make_shared<PublicKey>();
    if (args.Exist(spi::ArgRlkFrom)) {
      kit->rlk_ = std::make_shared<RelinKeys>();
    }
    if (args.Exist(spi::ArgGlkFrom)) {
      kit->glk_ = std::make_shared<GaloisKeys>();
    }
    if (args.Exist(spi::ArgBskFrom)) {
      kit->bsk_ = std::make_shared<BootstrapKey>();
    }
  }

  kit->InitOperators();
  return kit;
}

void HeKit::InitOperators() {
  item_tool_ = std::make_shared<ItemTool>();

  encryptor_ = std::make_shared<Encryptor>(poly_degree_, pk_);
  word_evaluator_ = std::make_shared<Evaluator>(poly_degree_, schema_, scale_,
                                                pk_, rlk_, glk_, bsk_);

  if (sk_) {
    decryptor_ = std::make_shared<Decryptor>(pk_, sk_);
  }
}

REGISTER_HE_LIBRARY(kLibName, 1, HeKit::Check, HeKit::Create);

}  // namespace heu::algos::mock_fhe
