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

#include <string>

#include "absl/types/span.h"
#include "gtest/gtest.h"

#include "heu/library/algorithms/paillier_gpu/decryptor.h"
#include "heu/library/algorithms/paillier_gpu/encryptor.h"
#include "heu/library/algorithms/paillier_gpu/evaluator.h"
#include "heu/library/algorithms/paillier_gpu/key_generator.h"

namespace heu::lib::algorithms::paillier_g::test {

template <typename T>
using Span = absl::Span<T *const>;

template <typename T>
using ConstSpan = absl::Span<const T *const>;

class GPUTest : public ::testing::Test {
 protected:
  void SetUp() override {
    KeyGenerator::Generate(2048, &sk_, &pk_);
    evaluator_ = std::make_shared<Evaluator>(pk_);
    decryptor_ = std::make_shared<Decryptor>(pk_, sk_);
    encryptor_ = std::make_shared<Encryptor>(pk_);
  }

 protected:
  SecretKey sk_;
  PublicKey pk_;
  std::shared_ptr<Encryptor> encryptor_;
  std::shared_ptr<Evaluator> evaluator_;
  std::shared_ptr<Decryptor> decryptor_;
  // [-9223372036854775808, 9223372036854775807]
  static const int128_t iLow = std::numeric_limits<int64_t>::lowest();
  static const int128_t iMax = std::numeric_limits<int64_t>::max();
};

TEST_F(GPUTest, EncDecBigintTest) {
  auto enc_dec_func = [&](const BigInt &plain) {
    fmt::print("in = {}\n", plain);
    std::vector<const BigInt *> in = {&plain};
    auto cts = encryptor_->Encrypt(in);
    auto plain_dec = decryptor_->Decrypt({&cts[0]});
    fmt::print("out= {}\n", plain_dec[0]);
    EXPECT_EQ(plain, plain_dec[0]);
  };

  enc_dec_func(BigInt(0));
  enc_dec_func(BigInt(1));
  enc_dec_func(BigInt(100));
  enc_dec_func(BigInt(iLow));

  fmt::print("{}\n", pk_.ToString());

  auto plain = pk_.PlaintextBound();
  enc_dec_func(--plain);
  plain.NegateInplace();
  enc_dec_func(plain);
}

TEST_F(GPUTest, EncDecLongTest) {
  int num = 1e5;  // 10w. found num <= 208516 can PASS(test on
                  // 172.20.10.7(nvidia A100), 28/12/22)
  Plaintext p[num] = {Plaintext(33), Plaintext(33)};
  for (int i = 0; i < num; i++) {
    p[i] = Plaintext(33);
  }
  Plaintext *ppts[num];
  for (int i = 0; i < num; i++) {
    ppts[i] = &p[i];
  }
  // make the constspan for vector Encrypt
  ConstSpan<Plaintext> pts = absl::MakeConstSpan(ppts, num);
  std::vector<Ciphertext> res = encryptor_->Encrypt(pts);
  // make the constspan for vector Decrypt
  Ciphertext *ccts[num];
  for (int i = 0; i < num; i++) {
    ccts[i] = &res[i];
  }
  // create the constspan for GPU call
  ConstSpan<Ciphertext> cts;
  cts = absl::MakeConstSpan(ccts, num);
  // receive the GPU Decrypt results
  std::vector<Plaintext> apts;
  apts = decryptor_->Decrypt(cts);

  for (int i = 0; i < num; i++) {
    EXPECT_EQ(apts[i], Plaintext(33));
  }
}

}  // namespace heu::lib::algorithms::paillier_g::test
