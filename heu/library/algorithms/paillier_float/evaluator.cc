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

#include "heu/library/algorithms/paillier_float/evaluator.h"

#include "heu/library/algorithms/paillier_float/internal/codec.h"

namespace heu::lib::algorithms::paillier_f {

Ciphertext Evaluator::Add(const Ciphertext &a, const Ciphertext &b) const {
  Ciphertext c;
  if (a.exponent_ > b.exponent_) {
    Ciphertext new_a = a;
    DecreaseExponentTo(&new_a, b.exponent_);
    c.exponent_ = b.exponent_;
    c.c_ = AddRaw(new_a.c_, b.c_);
  } else if (a.exponent_ < b.exponent_) {
    Ciphertext new_b = b;
    DecreaseExponentTo(&new_b, a.exponent_);
    c.exponent_ = a.exponent_;
    c.c_ = AddRaw(a.c_, new_b.c_);
  } else {
    c.exponent_ = a.exponent_;
    c.c_ = AddRaw(a.c_, b.c_);
  }

  return c;
}

void Evaluator::Randomize(Ciphertext *ct) const {
  AddInplace(ct, encryptor_.EncryptZero());
}

Ciphertext Evaluator::Add(const Ciphertext &a, const BigInt &b) const {
  internal::EncodedNumber encoded_b = internal::Codec(pk_).Encode(b);

  Ciphertext cipher_b = encryptor_.EncryptEncoded(encoded_b, 1);
  return Add(a, cipher_b);
}

Ciphertext Evaluator::Add(const Ciphertext &a, double b) const {
  internal::EncodedNumber encoded_b = internal::Codec(pk_).Encode(b);

  Ciphertext cipher_b = encryptor_.EncryptEncoded(encoded_b, 1);
  return Add(a, cipher_b);
}

void Evaluator::AddInplace(Ciphertext *a, const Ciphertext &b) const {
  *a = Add(*a, b);
}

void Evaluator::AddInplace(Ciphertext *a, const BigInt &b) const {
  *a = Add(*a, b);
}

void Evaluator::AddInplace(Ciphertext *a, double b) const { *a = Add(*a, b); }

BigInt Evaluator::AddRaw(const BigInt &a, const BigInt &b) const {
  return a.MulMod(b, pk_.n_square_);
}

Ciphertext Evaluator::Sub(const Ciphertext &a, const Ciphertext &b) const {
  return Add(a, Negate(b));
}

Ciphertext Evaluator::Sub(const Ciphertext &a, const BigInt &b) const {
  return Add(a, -b);
}

void Evaluator::SubInplace(Ciphertext *a, const Ciphertext &b) const {
  *a = Sub(*a, b);
}

void Evaluator::SubInplace(Ciphertext *a, const BigInt &b) const {
  *a = Sub(*a, b);
}

Ciphertext Evaluator::Sub(const BigInt &p, const Ciphertext &a) const {
  return Add(Negate(a), p);
}

Ciphertext Evaluator::Mul(const Ciphertext &a, const BigInt &b) const {
  internal::EncodedNumber encoded_b = internal::Codec(pk_).Encode(b);

  Ciphertext c;
  c.exponent_ = a.exponent_ + encoded_b.exponent;
  c.c_ = MulRaw(a.c_, encoded_b.encoding);
  return c;
}

Ciphertext Evaluator::Mul(const Ciphertext &a, double b) const {
  internal::EncodedNumber encoded_b = internal::Codec(pk_).Encode(b);

  Ciphertext c;
  c.exponent_ = a.exponent_ + encoded_b.exponent;
  c.c_ = MulRaw(a.c_, encoded_b.encoding);
  return c;
}

void Evaluator::MulInplace(Ciphertext *a, const BigInt &b) const {
  *a = Mul(*a, b);
}

void Evaluator::MulInplace(Ciphertext *a, double b) const { *a = Mul(*a, b); }

Ciphertext Evaluator::Negate(const Ciphertext &a) const {
  return Mul(a, BigInt(-1));
}

void Evaluator::NegateInplace(Ciphertext *a) const { *a = Negate(*a); }

BigInt Evaluator::MulRaw(const BigInt &a, const BigInt &b) const {
  return a.PowMod(b, pk_.n_square_);
}

void Evaluator::DecreaseExponentTo(Ciphertext *cipher, int new_exp) const {
  YACL_ENFORCE(new_exp <= cipher->exponent_,
               "new_exp should <= cipher's exponent");

  BigInt factor = internal::Codec::kBaseCache.Pow(cipher->exponent_ - new_exp);

  internal::EncodedNumber encoded_factor = internal::Codec(pk_).Encode(factor);

  // TODO: mutiply c_ and factor
  cipher->c_ = MulRaw(cipher->c_, encoded_factor.encoding);
  cipher->exponent_ = new_exp;
}

}  // namespace heu::lib::algorithms::paillier_f
