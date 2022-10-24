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

#pragma once
#include <set>

#include "yasl/base/buffer.h"

#include "heu/experimental/gemini-rlwe/lwe_types.h"

namespace heu::expt::rlwe {

// requires ciphertext.is_ntt_form() is `false`
//          ciphertext.size() is `2`
void RemoveCoefficientsInplace(RLWECt& ciphertext,
                               const std::set<size_t>& to_remove);

void KeepCoefficientsInplace(RLWECt& ciphertext,
                             const std::set<size_t>& to_keep);

template <class SEALObj>
yasl::Buffer EncodeSEALObject(const SEALObj& obj) {
  size_t nbytes = obj.save_size();
  yasl::Buffer out;
  out.resize(nbytes);
  obj.save(out.data<seal::seal_byte>(), nbytes);
  return out;
}

template <class SEALObj>
std::vector<yasl::Buffer> EncodeSEALObjects(
    const std::vector<SEALObj>& obj_array,
    const std::vector<seal::SEALContext>& contexts) {
  const size_t obj_count = obj_array.size();
  const size_t context_count = contexts.size();
  YASL_ENFORCE(obj_count > 0, fmt::format("empty object"));
  YASL_ENFORCE(0 == obj_count % context_count,
               fmt::format("Number of objects and SEALContexts mismatch"));

  std::vector<yasl::Buffer> out(obj_count);
  for (size_t idx = 0; idx < obj_count; ++idx) {
    out[idx] = EncodeSEALObject(obj_array[idx]);
  }

  return out;
}

template <class SEALObj>
void DecodeSEALObject(const yasl::Buffer& buf_view,
                      const seal::SEALContext& context, SEALObj* out,
                      bool skip_sanity_check = false) {
  yasl::CheckNotNull(out);
  auto bytes = buf_view.data<seal::seal_byte>();
  if (skip_sanity_check) {
    out->unsafe_load(context, bytes, buf_view.size());
  } else {
    out->load(context, bytes, buf_view.size());
  }
}

template <class SEALObj>
void DecodeSEALObjects(const std::vector<yasl::Buffer>& buf_view,
                       const std::vector<seal::SEALContext>& contexts,
                       std::vector<SEALObj>* out,
                       bool skip_sanity_check = false) {
  yasl::CheckNotNull(out);
  const size_t obj_count = buf_view.size();
  if (obj_count > 0) {
    const size_t context_count = contexts.size();
    YASL_ENFORCE(
        0 == obj_count % context_count,
        fmt::format("doDecode: number of objects and SEALContexts mismatch"));

    out->resize(obj_count);
    const size_t stride = obj_count / context_count;
    for (size_t idx = 0, c = 0; idx < obj_count; idx += stride, ++c) {
      for (size_t offset = 0; offset < stride; ++offset) {
        DecodeSEALObject(buf_view[idx + offset], contexts[c],
                         out->at(idx + offset), skip_sanity_check);
      }
    }
  }
}

}  // namespace heu::expt::rlwe
