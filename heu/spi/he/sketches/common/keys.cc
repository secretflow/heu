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

#include "heu/spi/he/sketches/common/keys.h"

#include "fmt/ranges.h"

template <>
struct fmt::formatter<std::map<std::string, std::string>::value_type> {
  template <typename ParseContext>
  constexpr auto parse(ParseContext &ctx) {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto format(const std::map<std::string, std::string>::value_type &fp,
              FormatContext &ctx) const {
    return fmt::format_to(ctx.out(), "{}={}", fp.first, fp.second);
  }
};

namespace heu::spi::internal {

std::string FormatKey(HeKeyType key_type,
                      const std::map<std::string, std::string> &params) {
  // The default style of "fmt/ranges.h" do not meet our requirements
  // So we implemented a custom formatter
  return fmt::format("{}[{}]", key_type, fmt::join(params, ", "));
}

}  // namespace heu::spi::internal
