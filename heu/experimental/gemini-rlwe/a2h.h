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
#include "heu/experimental/gemini-rlwe/poly_encoder.h"

namespace heu::expt::rlwe {

class ShareConverter {
 public:
  using U8PRNG = std::function<void(uint8_t *, size_t)>;

  explicit ShareConverter(const seal::SEALContext &context,
                          std::shared_ptr<ModulusSwitchHelper> ms_helper);

  // RLWE(x0), x1 -> RLWE(x) s.t. x = x0 + x1 mod 2^k
  void A2H(RLWECt &rlwe, absl::Span<const uint32_t> shr) const;

  void A2H(RLWECt &rlwe, absl::Span<const uint64_t> shr) const;

  void A2H(RLWECt &rlwe, absl::Span<const uint128_t> shr) const;

  // LWE(x) -> LWE(x0), x1 s.t. x = x0 + x1 mod 2^k
  void H2A(LWECt &lwe, U8PRNG prng, uint32_t *out) const;

  void H2A(LWECt &lwe, U8PRNG prng, uint64_t *out) const;

  void H2A(LWECt &lwe, U8PRNG prng, uint128_t *out) const;

 protected:
  template <typename T>
  void DoH2A(LWECt &lwe, U8PRNG prng, T *out) const;

  template <typename T>
  void DoA2H(RLWECt &rlwe, absl::Span<const T> shr) const;

  void UniformOverPrime(absl::Span<uint64_t> out, const seal::Modulus &prime,
                        U8PRNG prng) const;

 private:
  const seal::SEALContext &context_;
  std::shared_ptr<ModulusSwitchHelper> ms_helper_;
  std::shared_ptr<PolyEncoder> encoder_;
};

}  // namespace heu::expt::rlwe
