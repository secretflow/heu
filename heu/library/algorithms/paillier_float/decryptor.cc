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

#include "heu/library/algorithms/paillier_float/decryptor.h"

#include "heu/library/algorithms/paillier_float/internal/codec.h"

namespace heu::lib::algorithms::paillier_f {

void Decryptor::Decrypt(const Ciphertext &cipher, BigInt *plain) const {
  internal::EncodedNumber encoded;
  encoded.exponent = cipher.exponent_;
  DecryptRaw(cipher.c_, &encoded.encoding);

  internal::Codec(pk_).Decode(encoded, plain);
}

BigInt Decryptor::Decrypt(const Ciphertext &cipher) const {
  BigInt plain;
  Decrypt(cipher, &plain);
  return plain;
}

void Decryptor::Decrypt(const Ciphertext &cipher, double *plain) const {
  internal::EncodedNumber encoded;
  encoded.exponent = cipher.exponent_;
  DecryptRaw(cipher.c_, &encoded.encoding);

  internal::Codec(pk_).Decode(encoded, plain);
}

void Decryptor::DecryptRaw(const BigInt &c, BigInt *m) const {
  *m = c.PowMod(sk_.lambda_, pk_.n_square_);
  *m = (--(*m)) / pk_.n_;
  *m = m->MulMod(sk_.x_, pk_.n_);
}

}  // namespace heu::lib::algorithms::paillier_f
