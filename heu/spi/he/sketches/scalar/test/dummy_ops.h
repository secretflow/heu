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

#include <ostream>
#include <string>
#include <utility>

#include "heu/spi/he/encoder.h"
#include "heu/spi/he/sketches/scalar/decryptor.h"
#include "heu/spi/he/sketches/scalar/encryptor.h"
#include "heu/spi/he/sketches/scalar/word_evaluator.h"

namespace heu::spi::test {

class DummyObj {
 public:
  DummyObj() = default;
  virtual ~DummyObj() = default;

  explicit DummyObj(std::string id) : id_(std::move(id)) {}

  const std::string &Id() const { return id_; }

  void SetId(const std::string &id) { id_ = id; }

  friend std::ostream &operator<<(std::ostream &os, const DummyObj &obj) {
    return os << obj.id_;
  }

 protected:
  std::string id_;
};

class DummyPt : public DummyObj {
 public:
  using DummyObj::DummyObj;

  std::string Sign() const { return "pt" + Id(); }

  bool operator==(const DummyPt &rhs) const { return Id() == rhs.Id(); }
};

class DummyCt : public DummyObj {
 public:
  using DummyObj::DummyObj;

  std::string Sign() const { return "ct" + Id(); }

  bool operator==(const DummyCt &rhs) const { return Id() == rhs.Id(); }
};

inline auto format_as(const DummyPt &a) { return a.Sign(); }

inline auto format_as(const DummyCt &a) { return a.Sign(); }

class DummyEncryptorImpl : public EncryptorScalarSketch<DummyPt, DummyCt> {
 public:
  DummyCt Encrypt(const DummyPt &plaintext) const override {
    return DummyCt(fmt::format("Enc({})", plaintext));
  }

  void Encrypt(const DummyPt &plaintext, DummyCt *out) const override {
    out->SetId(fmt::format("Enc({})", plaintext));
  }

  DummyCt EncryptZeroT() const override {
    return DummyCt(fmt::format("Enc({})", DummyPt("0")));
  }

  DummyCt SemiEncrypt(const DummyPt &plaintext) const override {
    return DummyCt(fmt::format("SemiEnc({})", plaintext));
  }

  void EncryptWithAudit(const DummyPt &plaintext, DummyCt *ct_out,
                        std::string *audit_out) const override {
    ct_out->SetId(fmt::format("Enc({})", plaintext));
    audit_out->assign(fmt::format("rand({})", plaintext));
  }
};

class DummyDecryptorImpl : public DecryptorScalarSketch<DummyPt, DummyCt> {
 public:
  void Decrypt(const DummyCt &ct, DummyPt *out) const override {
    out->SetId(fmt::format("Dec({})", ct));
  }

  DummyPt Decrypt(const DummyCt &ct) const override {
    return DummyPt(fmt::format("Dec({})", ct));
  }
};

class DummyEvaluatorImpl : public WordEvaluatorScalarSketch<DummyPt, DummyCt> {
 public:
  DummyPt Negate(const DummyPt &a) const override {
    return DummyPt(fmt::format("-{}", a));
  }

  void NegateInplace(DummyPt *a) const override {
    a->SetId(fmt::format(":= -{}", *a));
  }

  DummyCt Negate(const DummyCt &a) const override {
    return DummyCt(fmt::format("-{}", a));
  }

  void NegateInplace(DummyCt *a) const override {
    a->SetId(fmt::format(":= -{}", *a));
  }

  DummyPt Add(const DummyPt &a, const DummyPt &b) const override {
    return DummyPt(fmt::format("{}+{}", a, b));
  }

  DummyCt Add(const DummyPt &a, const DummyCt &b) const override {
    return DummyCt(fmt::format("{}+{}", a, b));
  }

  DummyCt Add(const DummyCt &a, const DummyPt &b) const override {
    return DummyCt(fmt::format("{}+{}", a, b));
  }

  DummyCt Add(const DummyCt &a, const DummyCt &b) const override {
    return DummyCt(fmt::format("{}+{}", a, b));
  }

  void AddInplace(DummyCt *a, const DummyPt &b) const override {
    a->SetId(fmt::format("{}+={}", *a, b));
  }

  void AddInplace(DummyCt *a, const DummyCt &b) const override {
    a->SetId(fmt::format("{}+={}", *a, b));
  }

  DummyPt Sub(const DummyPt &a, const DummyPt &b) const override {
    return DummyPt(fmt::format("{}-{}", a, b));
  }

  DummyCt Sub(const DummyPt &a, const DummyCt &b) const override {
    return DummyCt(fmt::format("{}-{}", a, b));
  }

  DummyCt Sub(const DummyCt &a, const DummyPt &b) const override {
    return DummyCt(fmt::format("{}-{}", a, b));
  }

  DummyCt Sub(const DummyCt &a, const DummyCt &b) const override {
    return DummyCt(fmt::format("{}-{}", a, b));
  }

  void SubInplace(DummyCt *a, const DummyPt &b) const override {
    a->SetId(fmt::format("{}-={}", *a, b));
  }

  void SubInplace(DummyCt *a, const DummyCt &b) const override {
    a->SetId(fmt::format("{}-={}", *a, b));
  }

  DummyPt Mul(const DummyPt &a, const DummyPt &b) const override {
    return DummyPt(fmt::format("{}*{}", a, b));
  }

  DummyCt Mul(const DummyPt &a, const DummyCt &b) const override {
    return DummyCt(fmt::format("{}*{}", a, b));
  }

  DummyCt Mul(const DummyCt &a, const DummyPt &b) const override {
    return DummyCt(fmt::format("{}*{}", a, b));
  }

  DummyCt Mul(const DummyCt &a, const DummyCt &b) const override {
    return DummyCt(fmt::format("{}*{}", a, b));
  }

  void MulInplace(DummyCt *a, const DummyPt &b) const override {
    a->SetId(fmt::format("{}*={}", *a, b));
  }

  void MulInplace(DummyCt *a, const DummyCt &b) const override {
    a->SetId(fmt::format("{}*={}", *a, b));
  }

  DummyPt Square(const DummyPt &a) const override {
    return DummyPt(fmt::format("({})^2", a));
  }

  DummyCt Square(const DummyCt &a) const override {
    return DummyCt(fmt::format("({})^2", a));
  }

  void SquareInplace(DummyPt *a) const override {
    a->SetId(fmt::format(":= ({})^2", *a));
  }

  void SquareInplace(DummyCt *a) const override {
    a->SetId(fmt::format(":= ({})^2", *a));
  }

  DummyPt Pow(const DummyPt &a, int64_t exponent) const override {
    return DummyPt(fmt::format("({})^{}", a, exponent));
  }

  DummyCt Pow(const DummyCt &a, int64_t exponent) const override {
    return DummyCt(fmt::format("({})^{}", a, exponent));
  }

  void PowInplace(DummyPt *a, int64_t exponent) const override {
    a->SetId(fmt::format(":= ({})^{}", *a, exponent));
  }

  void PowInplace(DummyCt *a, int64_t exponent) const override {
    a->SetId(fmt::format(":= ({})^{}", *a, exponent));
  }

  void Randomize(DummyCt *a) const override {
    a->SetId(fmt::format(":= rand({})", *a));
  }

  DummyCt Relinearize(const DummyCt &a) const override {
    return DummyCt(fmt::format("rl({})", a));
  }

  void RelinearizeInplace(DummyCt *a) const override {
    a->SetId(fmt::format(":= rl({})", *a));
  }

  DummyCt ModSwitch(const DummyCt &a) const override {
    return DummyCt(fmt::format("ms({})", a));
  }

  void ModSwitchInplace(DummyCt *a) const override {
    a->SetId(fmt::format(":= ms({})", *a));
  }

  DummyCt Rescale(const DummyCt &a) const override {
    return DummyCt(fmt::format("rs({})", a));
  }

  void RescaleInplace(DummyCt *a) const override {
    a->SetId(fmt::format(":= rs({})", *a));
  }

  DummyCt SwapRows(const DummyCt &a) const override {
    return DummyCt(fmt::format("sr({})", a));
  }

  void SwapRowsInplace(DummyCt *a) const override {
    a->SetId(fmt::format(":= sr({})", *a));
  }

  DummyCt Conjugate(const DummyCt &a) const override {
    return DummyCt(fmt::format("cj({})", a));
  }

  void ConjugateInplace(DummyCt *a) const override {
    a->SetId(fmt::format(":= cj({})", *a));
  }

  DummyCt Rotate(const DummyCt &a, int steps) const override {
    return DummyCt(fmt::format("{}<<{}", a, steps));
  }

  void RotateInplace(DummyCt *a, int steps) const override {
    a->SetId(fmt::format("{}<<={}", *a, steps));
  }

  void BootstrapInplace(heu::spi::test::DummyCt *ct) const override {
    ct->SetId(fmt::format(":= boot({})", *ct));
  }
};

template <typename T>
void ExpectItemEq(const Item &item, std::vector<std::string> ids) {
  if constexpr (std::is_same_v<T, DummyCt>) {
    EXPECT_TRUE(item.IsCiphertext());
  } else {
    EXPECT_TRUE(item.IsPlaintext());
  }

  auto sp = item.AsSpan<T>();
  ASSERT_EQ(sp.size(), ids.size());
  for (size_t i = 0; i < ids.size(); ++i) {
    EXPECT_EQ(sp[i].Id(), ids[i]);
  }
}

}  // namespace heu::spi::test
