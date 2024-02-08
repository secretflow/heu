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

#include <cstddef>
#include <cstdint>
#include <string>

#include "heu/spi/he/encryptor.h"
#include "heu/spi/he/sketches/scalar/helpful_macros.h"

namespace heu::lib::spi {

template <typename PlaintextT, typename CiphertextT>
class EncryptorScalarSketch : public Encryptor {
 public:
  virtual CiphertextT Encrypt(const PlaintextT &plaintext) const = 0;
  virtual void Encrypt(const PlaintextT &plaintext, CiphertextT *out) const = 0;

  virtual CiphertextT EncryptZeroT() const = 0;

  virtual CiphertextT SemiEncrypt(const PlaintextT &plaintext) const = 0;

  // Encrypt plaintext and record all pseudorandom data for audit.
  virtual void EncryptWithAudit(const PlaintextT &plaintext,
                                CiphertextT *ct_out,
                                std::string *audit_out) const = 0;

 private:
  DefineUnaryFuncPT(Encrypt);
  DefineUnaryFuncCStyle(Encrypt, PlaintextT, CiphertextT);

  DefineUnaryFuncPT(SemiEncrypt);

  Item EncryptZero() const override {
    return Item(EncryptZeroT(), ContentType::Ciphertext);
  }

  Item EncryptZero(size_t count) const override {
    std::vector<CiphertextT> res(count);
    yacl::parallel_for(0, count, [&](int64_t beg, int64_t end) {
      for (int64_t i = beg; i < end; ++i) {
        res[i] = EncryptZeroT();
      }
    });
    return Item::Take(std::move(res), ContentType::Ciphertext);
  }

  void EncryptWithAudit(const Item &x, Item *ct_out,
                        std::string *audit_out) const override {
    if (x.IsArray()) {
      auto xsp = x.AsSpan<PlaintextT>();
      auto ysp = ct_out->ResizeAndSpan<CiphertextT>(xsp.size());
      std::vector<std::string> audits(xsp.size());
      yacl::parallel_for(0, xsp.length(), [&](int64_t beg, int64_t end) {
        for (int64_t i = beg; i < end; ++i) {
          EncryptWithAudit(xsp[i], &ysp[i], &audits.at(i));
        }
      });
      audit_out->assign(absl::StrJoin(audits, "||"));
    } else {
      EncryptWithAudit(x.As<PlaintextT>(), ct_out->As<CiphertextT *>(),
                       audit_out);
    };

    ct_out->MarkAsCiphertext();
  }
};

}  // namespace heu::lib::spi
