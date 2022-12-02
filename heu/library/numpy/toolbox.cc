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

#include "heu/library/numpy/toolbox.h"

namespace heu::lib::numpy {

yacl::Buffer Toolbox::PMatrixToBytes(const PMatrix& pm, size_t bytes_per_int,
                                     algorithms::Endian endian) {
  yacl::Buffer res(bytes_per_int * pm.size());
  auto* buf = res.data<unsigned char>();
  int64_t cols = pm.cols();
  pm.ForEach([&](int64_t row, int64_t col, const phe::Plaintext& pt) {
    // row major
    pt.ToBytes(buf + bytes_per_int * (row * cols + col), bytes_per_int, endian);
  });
  return res;
}

}  // namespace heu::lib::numpy
