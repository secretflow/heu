// Copyright 2023 Ant Group Co., Ltd.
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

#include "heu/library/algorithms/elgamal/key_generator.h"

#include "yacl/crypto/ecc/ecc_spi.h"

#include "heu/library/algorithms/elgamal/ciphertext.h"

namespace heu::lib::algorithms::elgamal {

void KeyGenerator::Generate(const yacl::crypto::CurveName &curve_name,
                            SecretKey *sk, PublicKey *pk) {
  std::shared_ptr<yacl::crypto::EcGroup> curve =
      ::yacl::crypto::EcGroupFactory::Instance().Create(curve_name);
  MPInt x;
  do {
    MPInt::RandomLtN(curve->GetOrder(), &x);
    // The following operations may not be necessary, but there is no harm even
    // if they are done. It is a kind of psychological comfort and makes people
    // feel safer.
    if (curve->GetCofactor().IsPositive()) {
      YACL_ENFORCE(curve->GetCofactor().BitCount() < 10,
                   "The cofactor of curve is very large, I don't know how to "
                   "do now, please open an issue on GitHub");
    }
    // For Ed25519, cofactor=8, so BitCount()==4, we set last 3 bits to zero
    for (int i = curve->GetCofactor().BitCount() - 1; i >= 0; --i) {
      x.SetBit(i, 0);
    }
    // We don't need to force the 254/255 bit of Ed25519 to 1/0, because there
    // is no side channel attack here
  } while (!x.IsPositive());

  *sk = SecretKey{x, curve};

  auto h = curve->MulBase(x);
  *pk = PublicKey(curve, h);

  Ciphertext::EnableEcGroup(pk->GetCurve());
}

void KeyGenerator::Generate(size_t key_size, SecretKey *sk, PublicKey *pk) {
  YACL_ENFORCE(key_size == 256,
               "Exponential EC Elgamal only supports 256 key_size now");
  // todo: change sm2 to fourq
  Generate("ed25519", sk, pk);
}

void KeyGenerator::Generate(SecretKey *sk, PublicKey *pk) {
  Generate(256, sk, pk);
}

}  // namespace heu::lib::algorithms::elgamal
