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

#pragma once

#include <cstdint>
#include <vector>

namespace heu::lib::spi {

class Poly : public std::vector<uint64_t> {
 public:
  using std::vector<uint64_t>::vector;
};

// Polys can store a batch of independent Polys, or sub-polynomials decomposed
// by RNS.
class Polys {
 public:
  // add public functions here
 private:
  std::vector<Poly> polys_;
};

using Moduli = std::vector<uint64_t>;

using RnsPoly = Polys;

}  // namespace heu::lib::spi
