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

// Author (Wen-jie Lu)
#pragma once

#include "absl/types/span.h"

#include "heu/experimental/gemini-rlwe/lwe_types.h"
#include "heu/experimental/gemini-rlwe/modswitch_helper.h"

namespace heu::expt::rlwe {

class PolyEncoder {
 public:
  explicit PolyEncoder(const seal::SEALContext &context,
                       ModulusSwitchHelper ms_helper);

  void Forward(absl::Span<const uint32_t> vec, RLWEPt *out,
               bool scale_delta = true) const;
  void Forward(absl::Span<const uint64_t> vec, RLWEPt *out,
               bool scale_delta = true) const;
  void Forward(absl::Span<const uint128_t> vec, RLWEPt *out,
               bool scale_delta = true) const;

  void Backward(absl::Span<const uint32_t> vec, RLWEPt *out,
                bool scale_delta = false) const;
  void Backward(absl::Span<const uint64_t> vec, RLWEPt *out,
                bool scale_delta = false) const;
  void Backward(absl::Span<const uint128_t> vec, RLWEPt *out,
                bool scale_delta = false) const;

  void Vec2Poly(absl::Span<const uint32_t> vec, RLWEPt *out) const {
    Forward(vec, out, true);
  }

  void Vec2Poly(absl::Span<const uint64_t> vec, RLWEPt *out) const {
    Forward(vec, out, true);
  }

  void Vec2Poly(absl::Span<const uint128_t> vec, RLWEPt *out) const {
    Forward(vec, out, true);
  }

 protected:
  template <typename T>
  void DoForward(absl::Span<const T> vec, RLWEPt *out, bool scale_delta) const;

  template <typename T>
  void DoBackward(absl::Span<const T> vec, RLWEPt *out, bool scale_delta) const;

 private:
  size_t poly_deg_{0};
  ModulusSwitchHelper ms_helper_;
};

}  // namespace heu::expt::rlwe
