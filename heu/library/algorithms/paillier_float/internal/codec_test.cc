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

#include "heu/library/algorithms/paillier_float/internal/codec.h"

#include <gtest/gtest.h>

#include "heu/library/algorithms/paillier_float/paillier.h"

namespace heu::lib::algorithms::paillier_f::test {

class CodecTest : public testing::Test {
 protected:
  void SetUp() override {
    PublicKey public_key;
    SecretKey secret_key;
    KeyGenerator::Generate(1024, &secret_key, &public_key);

    codec_ = std::make_unique<internal::Codec>(public_key);
  }

 protected:
  std::unique_ptr<internal::Codec> codec_;
};

TEST_F(CodecTest, EncodeDoubleWorks) {
  double d1 = 123456.345;

  internal::EncodedNumber encoded_number = codec_->Encode(d1);

  double value = 0;
  codec_->Decode(encoded_number, &value);

  EXPECT_DOUBLE_EQ(value, d1);
}

TEST_F(CodecTest, EncodeNegativeDoubleWorks) {
  double d1 = -123456.345;

  internal::EncodedNumber encoded_number = codec_->Encode(d1);

  double value = 0;
  codec_->Decode(encoded_number, &value);

  EXPECT_DOUBLE_EQ(value, d1);
}

TEST_F(CodecTest, EncodePositiveIntegerWorks) {
  MPInt x(1233456);

  internal::EncodedNumber encoded_number = codec_->Encode(x);

  MPInt value;
  codec_->Decode(encoded_number, &value);

  EXPECT_EQ(value, x);
}

TEST_F(CodecTest, EncodeNegativeIntegerWorks) {
  MPInt x((int64_t)-12344356778);

  internal::EncodedNumber encoded_number = codec_->Encode(x);

  MPInt value;
  codec_->Decode(encoded_number, &value);

  EXPECT_EQ(value, x);
}

}  // namespace heu::lib::algorithms::paillier_f::test
