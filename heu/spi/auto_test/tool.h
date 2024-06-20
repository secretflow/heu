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

#pragma once

#include <cctype>
#include <memory>
#include <string>
#include <unordered_set>
#include <vector>

#include "fmt/ostream.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"

#include "heu/spi/he/he_configs.h"
#include "heu/spi/he/he_kit.h"
#include "heu/spi/utils/formater.h"

namespace heu::spi::test {

auto SelectHeKitsForTest(std::unordered_set<FeatureSet> groups)
    -> decltype(::testing::ValuesIn(std::vector<std::shared_ptr<HeKit>>()));

std::string GenTestName(const std::shared_ptr<HeKit> &kit);

template <typename TestClass>
std::string GenTestName(
    const testing::TestParamInfo<typename TestClass::ParamType> &info) {
  return GenTestName(info.param);
}

MATCHER_P(BeginWith, exp_vec, utils::ArrayToStringCompact(exp_vec)) {
  *result_listener << "\r  Actual: " << utils::ArrayToStringCompact(arg)
                   << "\n  Reason: ";
  if (exp_vec.size() > arg.size()) {
    *result_listener << fmt::format(
        "Size doesn't match, actual size is {}, required {}", exp_vec.size(),
        arg.size());
    return false;
  }

  for (size_t i = 0; i < exp_vec.size(); ++i) {
    if (!testing::Matches(exp_vec[i])(arg[i])) {
      *result_listener << fmt::format("Element #{} not match, {} != {}", i,
                                      arg[i], exp_vec[i]);
      return false;
    }
  }
  return true;
}

}  // namespace heu::spi::test
