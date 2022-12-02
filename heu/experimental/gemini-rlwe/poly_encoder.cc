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

#include "heu/experimental/gemini-rlwe/poly_encoder.h"

#include "yacl/base/exception.h"

namespace heu::expt::rlwe {

PolyEncoder::PolyEncoder(const seal::SEALContext &context,
                         ModulusSwitchHelper ms_helper)
    : ms_helper_(ms_helper) {
  YACL_ENFORCE(context.parameters_set());
  auto pid0 = context.first_parms_id();
  auto pid1 = ms_helper.parms_id();
  YACL_ENFORCE_EQ(0, std::memcmp(&pid0, &pid1, sizeof(seal::parms_id_type)),
                  fmt::format("parameter set mismatch"));
  poly_deg_ = context.first_context_data()->parms().poly_modulus_degree();
}

template <typename T>
void PolyEncoder::DoForward(absl::Span<const T> vec, RLWEPt *out,
                            bool scale_delta) const {
  yacl::CheckNotNull(out);
  size_t num_coeffs = vec.size();
  size_t num_modulus = ms_helper_.coeff_modulus_size();
  YACL_ENFORCE_GT(num_coeffs, 0UL);
  YACL_ENFORCE(num_coeffs <= poly_deg_);

  out->parms_id() = seal::parms_id_zero;
  out->resize(seal::util::mul_safe(poly_deg_, num_modulus));

  uint64_t *dst = out->data();
  for (size_t mod_idx = 0; mod_idx < num_modulus; ++mod_idx, dst += poly_deg_) {
    std::fill_n(dst, poly_deg_, 0);
    absl::Span<uint64_t> wrap(dst, num_coeffs);
    if (scale_delta) {
      ms_helper_.ModulusUpAt(vec, mod_idx, wrap);
    } else {
      ms_helper_.CenteralizeAt(vec, mod_idx, wrap);
    }
  }
  out->parms_id() = ms_helper_.parms_id();
  out->scale() = 1.;
}

template <typename T>
void PolyEncoder::DoBackward(absl::Span<const T> vec, RLWEPt *out,
                             bool scale_delta) const {
  yacl::CheckNotNull(out);
  size_t num_coeffs = vec.size();
  size_t num_modulus = ms_helper_.coeff_modulus_size();
  YACL_ENFORCE_GT(num_coeffs, 0UL);
  YACL_ENFORCE(num_coeffs <= poly_deg_);

  size_t base_mod_bitlen = ms_helper_.base_mod_bitlen();
  T mask = static_cast<T>(-1);
  if (sizeof(T) * 8 < base_mod_bitlen) {
    mask = (static_cast<T>(1) << base_mod_bitlen) - 1;
  }
  auto mempool = seal::MemoryManager::GetPool();
  auto backward = seal::util::allocate<T>(poly_deg_, mempool);

  // a0, a1, a2, ..., an -> a0 - \sum_{i>0} ai*X^{N - i}
  std::fill_n(backward.get(), poly_deg_, static_cast<T>(0));
  backward.get()[0] = vec[0];
  for (size_t i = 1; i < num_coeffs; ++i) {
    backward.get()[poly_deg_ - i] = -vec[i] & mask;
  }
  absl::Span<const T> recv_vec(backward.get(), poly_deg_);

  out->parms_id() = seal::parms_id_zero;
  out->resize(seal::util::mul_safe(poly_deg_, num_modulus));

  uint64_t *dst = out->data();
  for (size_t mod_idx = 0; mod_idx < num_modulus; ++mod_idx, dst += poly_deg_) {
    std::fill_n(dst, poly_deg_, 0);
    absl::Span<uint64_t> wrap(dst, poly_deg_);
    if (scale_delta) {
      ms_helper_.ModulusUpAt(recv_vec, mod_idx, wrap);
    } else {
      ms_helper_.CenteralizeAt(recv_vec, mod_idx, wrap);
    }
  }

  seal::util::seal_memzero(backward.get(), sizeof(T) * poly_deg_);

  out->parms_id() = ms_helper_.parms_id();
  out->scale() = 1.;
}

void PolyEncoder::Forward(absl::Span<const uint32_t> vec, RLWEPt *out,
                          bool scale_delta) const {
  DoForward<uint32_t>(vec, out, scale_delta);
}

void PolyEncoder::Forward(absl::Span<const uint64_t> vec, RLWEPt *out,
                          bool scale_delta) const {
  DoForward<uint64_t>(vec, out, scale_delta);
}

void PolyEncoder::Forward(absl::Span<const uint128_t> vec, RLWEPt *out,
                          bool scale_delta) const {
  DoForward<uint128_t>(vec, out, scale_delta);
}

void PolyEncoder::Backward(absl::Span<const uint32_t> vec, RLWEPt *out,
                           bool scale_delta) const {
  DoBackward<uint32_t>(vec, out, scale_delta);
}

void PolyEncoder::Backward(absl::Span<const uint64_t> vec, RLWEPt *out,
                           bool scale_delta) const {
  DoBackward<uint64_t>(vec, out, scale_delta);
}

void PolyEncoder::Backward(absl::Span<const uint128_t> vec, RLWEPt *out,
                           bool scale_delta) const {
  DoBackward<uint128_t>(vec, out, scale_delta);
}

}  // namespace heu::expt::rlwe
