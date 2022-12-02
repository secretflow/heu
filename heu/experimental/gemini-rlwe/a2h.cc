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

#include "heu/experimental/gemini-rlwe/a2h.h"

#include "seal/evaluator.h"
#include "seal/valcheck.h"
#include "yacl/base/exception.h"

#include "heu/experimental/gemini-rlwe/modswitch_helper.h"
#include "heu/experimental/gemini-rlwe/poly_encoder.h"

namespace heu::expt::rlwe {

ShareConverter::ShareConverter(const seal::SEALContext &context,
                               std::shared_ptr<ModulusSwitchHelper> ms_helper)
    : context_(context),
      ms_helper_(ms_helper),
      encoder_(new PolyEncoder(context_, *ms_helper)) {
  YACL_ENFORCE(context_.parameters_set());
  YACL_ENFORCE(context_.first_parms_id() == ms_helper_->parms_id());
}

template <typename T>
void ShareConverter::DoH2A(LWECt &lwe, U8PRNG prng, T *out) const {
  YACL_ENFORCE(lwe.IsValid() && lwe.parms_id() == context_.first_parms_id());
  YACL_ENFORCE(out != nullptr);

  uint32_t nbit = ms_helper_->base_mod_bitlen();
  T mask = static_cast<T>(-1);
  if (nbit < sizeof(T) * 8) {
    mask = (static_cast<T>(1) << nbit) - 1;
  }

  const auto &parms = context_.first_context_data()->parms();
  const auto &modulus = parms.coeff_modulus();
  std::vector<uint64_t> random(lwe.coeff_modulus_size(), 0);
  // uniform r from [0, Q)
  for (size_t l = 0; l < modulus.size(); ++l) {
    UniformOverPrime({&random[l], 1}, modulus[l], prng);
  }
  // LWE(Delta*m) + r
  lwe.AddPlainInplace(random, context_);

  // out = -round(r/Delta) mod 2^k
  T tmp;
  ms_helper_->ModulusDownRNS(random, {&tmp, 1});
  YACL_ENFORCE(tmp < mask);
  *out = (-tmp) & mask;
}

template <typename T>
void ShareConverter::DoA2H(RLWECt &rlwe, absl::Span<const T> shr) const {
  YACL_ENFORCE(seal::is_metadata_valid_for(rlwe, context_));
  YACL_ENFORCE(!rlwe.is_ntt_form() && rlwe.size() == 2, "invalid RLWE");
  YACL_ENFORCE(shr.size() > 0 && shr.size() <= rlwe.poly_modulus_degree(),
               fmt::format("A2H: share size out-of-bound {} > {}", shr.size(),
                           shr.size()));
  RLWEPt pt;
  encoder_->Forward(shr, &pt);
  seal::Evaluator evaluator(context_);
  evaluator.add_plain_inplace(rlwe, pt);
}

void ShareConverter::UniformOverPrime(absl::Span<uint64_t> out,
                                      const seal::Modulus &prime,
                                      U8PRNG prng) const {
  YACL_ENFORCE(out.size() > 0);
  using namespace seal::util;
  constexpr uint64_t max_random = static_cast<uint64_t>(0xFFFFFFFFFFFFFFFFULL);
  // sample from [0, n*p) such that n*p ~ 2^64
  auto max_multiple = max_random - barrett_reduce_64(max_random, prime) - 1;
  prng(reinterpret_cast<uint8_t *>(out.data()), out.size() * sizeof(uint64_t));
  std::transform(out.data(), out.data() + out.size(), out.data(),
                 [&](uint64_t r) {
                   while (r >= max_multiple) {
                     prng(reinterpret_cast<uint8_t *>(&r), sizeof(uint64_t));
                   }
                   return barrett_reduce_64(r, prime);
                 });
}

void ShareConverter::H2A(LWECt &lwe, U8PRNG prng, uint32_t *out) const {
  DoH2A<uint32_t>(lwe, prng, out);
}

void ShareConverter::H2A(LWECt &lwe, U8PRNG prng, uint64_t *out) const {
  DoH2A<uint64_t>(lwe, prng, out);
}

void ShareConverter::H2A(LWECt &lwe, U8PRNG prng, uint128_t *out) const {
  DoH2A<uint128_t>(lwe, prng, out);
}

void ShareConverter::A2H(RLWECt &rlwe, absl::Span<const uint32_t> shr) const {
  DoA2H<uint32_t>(rlwe, shr);
}

void ShareConverter::A2H(RLWECt &rlwe, absl::Span<const uint64_t> shr) const {
  DoA2H<uint64_t>(rlwe, shr);
}

void ShareConverter::A2H(RLWECt &rlwe, absl::Span<const uint128_t> shr) const {
  DoA2H<uint128_t>(rlwe, shr);
}

}  // namespace heu::expt::rlwe
