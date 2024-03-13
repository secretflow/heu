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

#include <string>
#include <vector>

#include "absl/types/span.h"
#include "fmt/format.h"

// for fmt lib
namespace std {
inline auto format_as(const complex<double> &n) {
  if (n.imag() == 0) {
    return fmt::to_string(n.real());
  }
  if (n.real() == 0) {
    return fmt::to_string(n.imag()) + "i";
  }
  if (n.imag() == 1) {
    return fmt::to_string(n.real()) + "i";
  }
  if (n.imag() == -1) {
    return fmt::to_string(n.real()) + "-i";
  }
  return fmt::format("{}{}{}i", n.real(), n.imag() < 0 ? "" : "+", n.imag());
}
}  // namespace std

namespace heu::spi::utils {

// Print array in compact format.
// For example, [1, 2, 5, 5, 5, 5, 5, 5, 5, 1]
// print: [1, 2, 5...repeated 7 times, 1]
template <typename T>
std::string ArrayToStringCompact(absl::Span<T> array) {
  if (array.empty()) {
    return "[(empty)]";
  }

  std::vector<std::string> tokens;
  int64_t count = 1;
  for (size_t i = 1; i <= array.size(); ++i) {
    if (i < array.size() && array[i] == array[i - 1]) {
      ++count;
      continue;
    }

    // gen string
    if (count <= 3) {
      for (int64_t j = 0; j < count; ++j) {
        tokens.emplace_back(fmt::format("{}", array[i - 1]));
      }
    } else {
      tokens.emplace_back(
          fmt::format("{}...repeated {} times", array[i - 1], count));
    }
    count = 1;
  }

  return fmt::format("[{}]", fmt::join(tokens, ", "));
}

template <typename T>
std::string ArrayToStringCompact(const std::vector<T> &array) {
  return ArrayToStringCompact(absl::MakeConstSpan(array));
}

}  // namespace heu::spi::utils
