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

#include "heu/algorithms/ishe/decryptor.h"

namespace heu::algos::ishe {

void Decryptor::Decrypt(const Ciphertext &ct, Plaintext *out) const {
  *out = Decrypt(ct);
}

Plaintext Decryptor::Decrypt(const Ciphertext &ct) const {
  /**
   * decrypt
   * m: plaintext
   * d: s's exponent
   */
  MPInt tmp;
  MPInt::PowMod(sk_->getS(), ct.d_, pk_->getN(), &tmp);  // m = s^d
  MPInt::InvertMod(tmp, pk_->getN(), &tmp);              // (s^d)^-1
  MPInt::MulMod(ct.n_, tmp, pk_->getN(), &tmp);          // (s^d)^-1 * m mod N
  MPInt::Mod(tmp, sk_->getP(), &tmp);
  MPInt::Mod(tmp, sk_->getL(), &tmp);  // (((s^d)^-1 * m mod N ) mod p) mod L
  if (tmp < sk_->getL() / MPInt(2)) {  // case 1 : m' < L/2
    return tmp;
  }
  return tmp - sk_->getL();  // case 2 : else
}

}  // namespace heu::algos::ishe
