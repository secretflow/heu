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

#include "heu/library/numpy/random.h"

#include "gtest/gtest.h"

namespace heu::lib::numpy::test {

auto CountValue(const PMatrix &m) {
  std::unordered_map<int, int> res;
  m.ForEach(
      [&](int64_t, int64_t, const phe::Plaintext &pt) { res[pt.As<int>()]++; },
      false);
  return res;
}

TEST(NumpyRandom, RandIntWorks) {
  auto DoTest = [](int min, int max) {
    auto m =
        Random::RandInt(phe::Plaintext(min), phe::Plaintext(max), {100, 100});
    auto res = CountValue(m);
    ASSERT_TRUE(res[min - 1] == 0);
    ASSERT_TRUE(res[min] > 0);
    ASSERT_TRUE(res[max - 1] > 0);
    ASSERT_TRUE(res[max] == 0);
  };

  DoTest(0, 100);
  DoTest(-100, 0);
  DoTest(50, 100);
  DoTest(-100, -50);
  DoTest(-50, 50);
}

TEST(NumpyRandom, RandBitsWorks) {
  auto m = Random::RandBits(10, {1});
  ASSERT_LE(m(0).BitCount(), 10) << m;

  auto DoTest = [](const Shape &s) {
    auto m = Random::RandBits(7, s);
    auto res = CountValue(m);
    ASSERT_TRUE(res[0] > 0);
    ASSERT_TRUE(res[127] > 0);
    ASSERT_TRUE(res[128] == 0);
  };

  DoTest({10000});
  DoTest({100, 100});
}

}  // namespace heu::lib::numpy::test
