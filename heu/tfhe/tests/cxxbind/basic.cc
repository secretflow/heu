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

#include <iostream>
#include <vector>

#include "gtest/gtest.h"

#include "heu/tfhe/src/zq/ffi.rs.h"

namespace heu::tfhe::cxxbind {

class TfheCxxTest : public testing::Test {};

TEST_F(TfheCxxTest, AccumulatorWorks) {
  std::cout << "start keygen" << std::endl;
  SecurityParams sp{};
  sp.dimension = 2048;
  sp.log2_std_dev = -52;  // warning: this params are not secure, only for test
  auto keygen = new_cxx_key_generator(sp, 8u, 3u);
  auto sk = keygen->generate_only_sk();
  auto encryptor = new_cxx_encryptor(*sk);
  auto evaluator = cxx_new_leveled_evaluator();
  auto decryptor = new_cxx_decryptor(*sk);
  std::cout << "key generated." << std::endl;

  auto sum = encryptor->encrypt(0);
  const size_t count = 10000;
  for (size_t i = 0; i <= count; ++i) {
    auto ct = encryptor->encrypt(i);
    evaluator->add_inplace(*sum, *ct);
  }

  auto sum_expected = count * (count + 1) / 2;
  ASSERT_EQ(decryptor->decrypt(*sum), sum_expected);

  evaluator->mul_u32_inplace(*sum, 7);
  ASSERT_EQ(decryptor->decrypt(*sum), sum_expected * 7);
}

}  // namespace heu::tfhe::cxxbind
