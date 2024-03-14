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

#include "heu/library/algorithms/paillier_float/encryptor.h"

#include "fmt/compile.h"
#include "fmt/format.h"

namespace heu::lib::algorithms::paillier_f {

template <bool audit>
MPInt Encryptor::EncryptRaw(const MPInt &m, absl::optional<uint32_t> rand,
                            std::string *audit_str) const {
  MPInt r;
  if (rand.has_value()) {
    r = MPInt(*rand);
  } else {
    MPInt::RandomLtN(pk_.n_, &r);
  }

  MPInt obfuscator;
  MPInt::PowMod(r, pk_.n_, pk_.n_square_, &obfuscator);

  // we chose g = n + 1, exploit the fact that (1 + n)^m = (1 + n*m) mod n^2
  MPInt c;
  MPInt::MulMod(pk_.n_, m, pk_.n_square_, &c);
  MPInt::Mod(c.IncrOne(), pk_.n_square_, &c);
  MPInt::MulMod(c, obfuscator, pk_.n_square_, &c);
  if constexpr (audit) {
    YACL_ENFORCE(audit_str != nullptr);
    *audit_str = fmt::format(FMT_COMPILE("p:{},r:{},c:{}"), m.ToHexString(),
                             r.ToHexString(), c.ToHexString());
  }
  return c;
}

Ciphertext Encryptor::EncryptZero() const { return Encrypt(MPInt(0)); }

Ciphertext Encryptor::Encrypt(double value,
                              absl::optional<float> precision) const {
  internal::EncodedNumber encoding =
      internal::Codec(pk_).Encode(value, precision);

  return EncryptEncoded(encoding);
}

Ciphertext Encryptor::Encrypt(int64_t value) const {
  return Encrypt(MPInt(value));
}

Ciphertext Encryptor::Encrypt(const MPInt &value) const {
  internal::EncodedNumber encoding = internal::Codec(pk_).Encode(value);
  return EncryptEncoded(encoding);
}

Ciphertext Encryptor::EncryptEncoded(const internal::EncodedNumber &encoding,
                                     absl::optional<uint32_t> rand) const {
  // only encrypt EncodedNumber's encoding_
  MPInt encoding_cipher = EncryptRaw(encoding.encoding, rand);
  return Ciphertext(std::move(encoding_cipher), encoding.exponent);
}

std::pair<Ciphertext, std::string> Encryptor::EncryptWithAudit(
    const MPInt &m) const {
  internal::EncodedNumber encoding = internal::Codec(pk_).Encode(m);
  std::string audit_str;
  MPInt encoding_cipher =
      EncryptRaw<true>(encoding.encoding, absl::nullopt, &audit_str);
  auto c = Ciphertext(std::move(encoding_cipher), encoding.exponent);
  return {c, audit_str};
}

}  // namespace heu::lib::algorithms::paillier_f
