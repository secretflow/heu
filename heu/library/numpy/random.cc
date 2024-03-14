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

namespace heu::lib::numpy {

PMatrix Random::RandInt(const phe::Plaintext &min, const phe::Plaintext &max,
                        const Shape &size) {
  YACL_ENFORCE(min < max, "random range invalid, min={}, max={}", min, max);

  PMatrix res(size);
  auto up = max - min;
  res.ForEach([&](int64_t, int64_t, phe::Plaintext *item) {
    phe::Plaintext::RandomLtN(up, item);
    *item += min;
  });
  return res;
}

PMatrix Random::RandBits(phe::SchemaType schema, size_t bits,
                         const Shape &size) {
  PMatrix res(size);
  res.ForEach([&](int64_t, int64_t, phe::Plaintext *item) {
    phe::Plaintext::RandomExactBits(schema, bits, item);
  });
  return res;
}

}  // namespace heu::lib::numpy
