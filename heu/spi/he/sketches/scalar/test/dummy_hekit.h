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

#pragma once

#include <cstdint>
#include <memory>
#include <string>

#include "gtest/gtest.h"
#include "yacl/base/byte_container_view.h"

#include "heu/spi/he/he_configs.h"
#include "heu/spi/he/sketches/common/he_kit.h"
#include "heu/spi/he/sketches/scalar/item_tool.h"
#include "heu/spi/he/sketches/scalar/test/dummy_encoder.h"
#include "heu/spi/he/sketches/scalar/test/dummy_ops.h"

namespace heu::spi::test {

template <HeKeyType key_type>
class DummyKey : public spi::KeySketch<key_type>, public DummyObj {
 public:
  using DummyObj::DummyObj;

  std::map<std::string, std::string> ListParams() const override {
    return {{"id", id_}};
  }

  friend std::ostream &operator<<(std::ostream &os, const DummyKey &obj) {
    return os << obj.ToString();
  }
};

class DummyPk : public DummyKey<HeKeyType::PublicKey> {
 public:
  using DummyKey<HeKeyType::PublicKey>::DummyKey;

  bool operator==(const DummyPk &rhs) const { return Id() == rhs.Id(); }
};

class DummySk : public DummyKey<HeKeyType::SecretKey> {
 public:
  using DummyKey<HeKeyType::SecretKey>::DummyKey;

  bool operator==(const DummySk &rhs) const { return Id() == rhs.Id(); }
};

class DummyRlk : public DummyKey<HeKeyType::RelinKeys> {
 public:
  using DummyKey<HeKeyType::RelinKeys>::DummyKey;

  bool operator==(const DummyRlk &rhs) const { return Id() == rhs.Id(); }
};

class DummyGlk : public DummyKey<HeKeyType::GaloisKeys> {
 public:
  using DummyKey<HeKeyType::GaloisKeys>::DummyKey;

  bool operator==(const DummyGlk &rhs) const { return Id() == rhs.Id(); }
};

class DummyBsk : public DummyKey<HeKeyType::BootstrapKey> {
 public:
  using DummyKey<HeKeyType::BootstrapKey>::DummyKey;

  bool operator==(const DummyBsk &rhs) const { return Id() == rhs.Id(); }
};

size_t Str2buf(const std::string &str, uint8_t *buf, size_t buf_len) {
  EXPECT_LE(str.length(), buf_len) << yacl::GetStacktraceString();
  std::copy(str.begin(), str.end(), buf);
  return str.length();
}

class DummyItemTool
    : public ItemToolScalarSketch<DummyPt, DummyCt, DummySk, DummyPk, DummyRlk,
                                  DummyGlk, DummyBsk> {
 public:
  DummyPt Clone(const DummyPt &pt) const override { return pt; }

  DummyCt Clone(const DummyCt &ct) const override { return ct; }

  std::string ToString(const DummyPt &x) const override {
    return "dummy " + x.Id();
  }

  std::string ToString(const DummyCt &x) const override {
    return "dummy " + x.Id();
  }

  size_t Serialize(const DummyPt &x, uint8_t *buf,
                   size_t buf_len) const override {
    return buf == nullptr ? x.Id().length() : Str2buf(x.Id(), buf, buf_len);
  }

  size_t Serialize(const DummyCt &x, uint8_t *buf,
                   size_t buf_len) const override {
    return buf == nullptr ? x.Id().length() : Str2buf(x.Id(), buf, buf_len);
  }

  DummyPt DeserializePT(yacl::ByteContainerView buffer) const override {
    return DummyPt((std::string)buffer);
  }

  DummyCt DeserializeCT(yacl::ByteContainerView buffer) const override {
    return DummyCt((std::string)buffer);
  }
};

DEFINE_ARG_uint64(Slot);

class DummyHeKit
    : public HeKitSketch<DummySk, DummyPk, DummyRlk, DummyGlk, DummyBsk> {
 public:
  DummyHeKit() {
    // This function is usually called by factory
    SetupContext({});
  }

  std::string GetLibraryName() const override { return "DummyLib"; }

  Schema GetSchema() const override { return Schema::Unknown; }

  FeatureSet GetFeatureSet() const override { return FeatureSet::WordFHE; }

  std::shared_ptr<Encoder> CreateEncoder(
      const yacl::SpiArgs &args) const override {
    std::string name = args.GetOrDefault(ArgEncodingMethod, "plain");
    if (name == "plain") {
      return std::make_shared<DummyPlainEncoder>();
    } else if (name == "batch") {
      return std::make_shared<DummyBatchEncoder>(args.GetRequired(ArgSlot));
    }
    YACL_THROW("unsupported encoder {}", name);
  }

  size_t Serialize(HeKeyType key_type, uint8_t *buf,
                   size_t buf_len) const override {
    switch (key_type) {
      case HeKeyType::SecretKey:
        return buf == nullptr ? sk_->Id().length()
                              : Str2buf(sk_->Id(), buf, buf_len);
      case HeKeyType::PublicKey:
        return buf == nullptr ? pk_->Id().length()
                              : Str2buf(pk_->Id(), buf, buf_len);
      case HeKeyType::RelinKeys:
        return buf == nullptr ? rlk_->Id().length()
                              : Str2buf(rlk_->Id(), buf, buf_len);
      case HeKeyType::GaloisKeys:
        return buf == nullptr ? glk_->Id().length()
                              : Str2buf(glk_->Id(), buf, buf_len);
      case HeKeyType::BootstrapKey:
        return buf == nullptr ? bsk_->Id().length()
                              : Str2buf(bsk_->Id(), buf, buf_len);
      default:
        YACL_THROW("never reach here");
    }
  }

  //===  I/O for HeKit itself  ===//

  std::string ToString() const override { return "dummy hekit"; }

  size_t Serialize(uint8_t *buf, size_t buf_len) const override {
    return buf == nullptr ? 5 : Str2buf("hekit", buf, buf_len);
  }

 private:
  void SetupContext(const yacl::SpiArgs &) {
    sk_ = std::make_shared<DummySk>("sk1");
    pk_ = std::make_shared<DummyPk>("pk1");
    rlk_ = std::make_shared<DummyRlk>("rlk1");
    glk_ = std::make_shared<DummyGlk>("glk1");
    bsk_ = std::make_shared<DummyBsk>("bsk1");

    encryptor_ = std::make_shared<DummyEncryptorImpl>();
    decryptor_ = std::make_shared<DummyDecryptorImpl>();
    word_evaluator_ = std::make_shared<DummyEvaluatorImpl>();
    item_tool_ = std::make_shared<DummyItemTool>();
  }
};

}  // namespace heu::spi::test
