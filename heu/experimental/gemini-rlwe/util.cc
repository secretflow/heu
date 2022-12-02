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

#include "heu/experimental/gemini-rlwe/util.h"

#include "yacl/base/exception.h"

namespace heu::expt::rlwe {

void RemoveCoefficientsInplace(RLWECt& ciphertext,
                               const std::set<size_t>& to_remove) {
  YACL_ENFORCE(!ciphertext.is_ntt_form());
  YACL_ENFORCE_EQ(2UL, ciphertext.size());

  size_t num_to_remove = to_remove.size();
  size_t num_coeff = ciphertext.poly_modulus_degree();
  size_t num_modulus = ciphertext.coeff_modulus_size();
  YACL_ENFORCE(std::all_of(to_remove.begin(), to_remove.end(),
                           [&](size_t idx) { return idx < num_coeff; }));
  YACL_ENFORCE(num_to_remove < num_coeff);
  if (num_to_remove == 0) return;

  for (size_t l = 0; l < num_modulus; ++l) {
    auto ct_ptr = ciphertext.data(0) + l * num_coeff;
    for (size_t idx : to_remove) {
      ct_ptr[idx] = 0;
    }
  }
}

void KeepCoefficientsInplace(RLWECt& ciphertext,
                             const std::set<size_t>& to_keep) {
  YACL_ENFORCE(!ciphertext.is_ntt_form());
  YACL_ENFORCE_EQ(2UL, ciphertext.size());

  size_t num_coeff = ciphertext.poly_modulus_degree();
  YACL_ENFORCE(std::all_of(to_keep.begin(), to_keep.end(),
                           [&](size_t idx) { return idx < num_coeff; }));
  if (to_keep.size() == num_coeff) return;

  std::set<size_t> to_remove;
  for (size_t idx = 0; idx < num_coeff; ++idx) {
    if (to_keep.find(idx) == to_keep.end()) {
      to_remove.insert(idx);
    }
  }
  RemoveCoefficientsInplace(ciphertext, to_remove);
}

}  // namespace heu::expt::rlwe
