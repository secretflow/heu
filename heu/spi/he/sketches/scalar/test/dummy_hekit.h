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

#include "heu/spi/he/sketches/common/he_kit.h"
#include "heu/spi/he/sketches/scalar/item_manipulator.h"
#include "heu/spi/he/sketches/scalar/test/dummy_encoder.h"
#include "heu/spi/he/sketches/scalar/test/dummy_ops.h"

namespace heu::lib::spi::test {

class DummyPk : public DummyObj {
 public:
  using DummyObj::DummyObj;

  bool operator==(const DummyPk &rhs) const { return Id() == rhs.Id(); }
};

class DummySk : public DummyObj {
 public:
  using DummyObj::DummyObj;

  bool operator==(const DummySk &rhs) const { return Id() == rhs.Id(); }
};

class DummyRlk : public DummyObj {
 public:
  using DummyObj::DummyObj;

  bool operator==(const DummyRlk &rhs) const { return Id() == rhs.Id(); }
};

class DummyGlk : public DummyObj {
 public:
  using DummyObj::DummyObj;

  bool operator==(const DummyGlk &rhs) const { return Id() == rhs.Id(); }
};

class DummyBsk : public DummyObj {
 public:
  using DummyObj::DummyObj;

  bool operator==(const DummyBsk &rhs) const { return Id() == rhs.Id(); }
};

size_t Str2buf(const std::string &str, uint8_t *buf, size_t buf_len) {
  EXPECT_LE(str.length(), buf_len) << yacl::GetStacktraceString();
  std::copy(str.begin(), str.end(), buf);
  return str.length();
}

class DummyItemManipulator
    : public ItemManipulatorScalarSketch<DummyPt, DummyCt, DummySk, DummyPk,
                                         DummyRlk, DummyGlk, DummyBsk> {
 public:
  DummySk Clone(const DummySk &key) const override { return key; }

  DummyPk Clone(const DummyPk &key) const override { return key; }

  DummyRlk Clone(const DummyRlk &key) const override { return key; }

  DummyGlk Clone(const DummyGlk &key) const override { return key; }

  DummyBsk Clone(const DummyBsk &key) const override { return key; }

  DummyPt Clone(const DummyPt &pt) const override { return pt; }

  DummyCt Clone(const DummyCt &ct) const override { return ct; }

  std::string ToString(const DummySk &key) const override {
    return "dummy " + key.Id();
  }

  std::string ToString(const DummyPk &key) const override {
    return "dummy " + key.Id();
  }

  std::string ToString(const DummyRlk &key) const override {
    return "dummy " + key.Id();
  }

  std::string ToString(const DummyGlk &key) const override {
    return "dummy " + key.Id();
  }

  std::string ToString(const DummyBsk &key) const override {
    return "dummy " + key.Id();
  }

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

DEFINE_ARG_string(Encoder);
DEFINE_ARG_uint64(Slot);

class DummyHeKit
    : public HeKitSketch<DummySk, DummyPk, DummyRlk, DummyGlk, DummyBsk> {
 public:
  DummyHeKit() {
    // This function is usually called by factory
    SetupContext({});
  }

  std::string GetLibraryName() const override { return "DummyLib"; }

  std::string GetSchemaName() const override { return "DummySchema"; }

  DummySk GetSecretKeyT() const override { return sk_; }

  DummyPk GetPublicKeyT() const override { return pk_; }

  DummyRlk GetRelinKeyT() const override { return rlk_; }

  DummyGlk GetGaloisKeyT() const override { return glk_; }

  DummyBsk GetBootstrapKeyT() const override { return bsk_; }

  std::shared_ptr<Encoder> CreateEncoder(
      const heu::lib::spi::SpiArgs &args) const override {
    std::string name = args.Get(ArgEncoder, "plain");
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
        return buf == nullptr ? sk_.Id().length()
                              : Str2buf(sk_.Id(), buf, buf_len);
      case HeKeyType::PublicKey:
        return buf == nullptr ? pk_.Id().length()
                              : Str2buf(pk_.Id(), buf, buf_len);
      case HeKeyType::RelinKeys:
        return buf == nullptr ? rlk_.Id().length()
                              : Str2buf(rlk_.Id(), buf, buf_len);
      case HeKeyType::GaloisKeys:
        return buf == nullptr ? glk_.Id().length()
                              : Str2buf(glk_.Id(), buf, buf_len);
      case HeKeyType::BootstrapKey:
        return buf == nullptr ? bsk_.Id().length()
                              : Str2buf(bsk_.Id(), buf, buf_len);
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
  void SetupContext(const heu::lib::spi::SpiArgs &) override {
    encryptor_ = std::make_shared<DummyEncryptorImpl>();
    decryptor_ = std::make_shared<DummyDecryptorImpl>();
    word_evaluator_ = std::make_shared<DummyEvaluatorImpl>();
    item_manipulator_ = std::make_shared<DummyItemManipulator>();
  }

  DummySk sk_{"sk1"};
  DummyPk pk_{"pk1"};
  DummyRlk rlk_{"rlk1"};
  DummyGlk glk_{"glk1"};
  DummyBsk bsk_{"bsk1"};
};

}  // namespace heu::lib::spi::test
