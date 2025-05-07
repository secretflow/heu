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

#include "heu/library/algorithms/ou/encryptor.h"

#include <future>
#include <random>

#include "gtest/gtest.h"

#include "heu/library/algorithms/ou/decryptor.h"
#include "heu/library/algorithms/ou/key_generator.h"

namespace heu::lib::algorithms::ou::test {

class EncryptorTest : public testing::Test {
 protected:
  void SetUp() override { KeyGenerator::Generate(2048, &sk_, &pk_); }

 protected:
  SecretKey sk_;
  PublicKey pk_;
};

TEST_F(EncryptorTest, SingleThread) {
  Encryptor encryptor(pk_);
  Decryptor decryptor(pk_, sk_);
  encryptor.SetEnableCache(false);

  std::random_device rnd_device;
  std::mt19937 mt(rnd_device());
  std::uniform_int_distribution<int64_t> dist(
      std::numeric_limits<int64_t>::lowest(),
      std::numeric_limits<int64_t>::max());

  for (int i = 0; i < 1000; ++i) {
    BigInt mpint(dist(mt));
    {
      Ciphertext ct = encryptor.Encrypt(mpint);
      BigInt out;
      decryptor.Decrypt(ct, &out);
      ASSERT_EQ(mpint, out);
    }
    {
      auto cta = encryptor.EncryptWithAudit(mpint);
      BigInt out;
      decryptor.Decrypt(cta.first, &out);
      ASSERT_EQ(mpint, out);
    }
  }

  encryptor.SetEnableCache(true);
  for (int i = 0; i < 5000; ++i) {
    BigInt mpint(dist(mt));
    {
      Ciphertext ct = encryptor.Encrypt(mpint);
      BigInt out;
      decryptor.Decrypt(ct, &out);
      ASSERT_EQ(mpint, out);
    }
    {
      auto cta = encryptor.EncryptWithAudit(mpint);
      BigInt out;
      decryptor.Decrypt(cta.first, &out);
      ASSERT_EQ(mpint, out);
    }
  }
}

TEST_F(EncryptorTest, MultiThread) {
  Encryptor encryptor(pk_);
  Decryptor decryptor(pk_, sk_);
  encryptor.SetEnableCache(true);

  std::random_device rnd_device;
  std::mt19937 mt(rnd_device());
  std::uniform_int_distribution<int64_t> dist(
      std::numeric_limits<int64_t>::lowest(),
      std::numeric_limits<int64_t>::max());

  constexpr int th_size = 10;
  constexpr int case_size = 4000;
  std::future<void> threads[th_size];
  BigInt mpint[th_size * case_size];
  Ciphertext ct[th_size * case_size];

  for (int i = 0; i < th_size; ++i) {
    threads[i] = std::async([i, &dist, &mt, &mpint, &ct, &encryptor, this]() {
      for (int j = 0; j < case_size; ++j) {
        mpint[i * case_size + j] = BigInt(dist(mt));
        *(ct + i * case_size + j) = encryptor.Encrypt(mpint[i * case_size + j]);
      }
    });
  }

  for (int i = 0; i < th_size; ++i) {
    threads[i].wait();
    for (int j = 0; j < case_size; ++j) {
      BigInt out;
      decryptor.Decrypt(ct[i * case_size + j], &out);
      ASSERT_EQ(mpint[i * case_size + j], out);
    }
  }
}

}  // namespace heu::lib::algorithms::ou::test
