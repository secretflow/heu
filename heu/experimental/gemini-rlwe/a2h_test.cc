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

#include "gtest/gtest.h"
#include "seal/seal.h"
#include "seal/util/ntt.h"
#include "seal/util/polyarithsmallmod.h"

#include "heu/experimental/gemini-rlwe/lwe_decryptor.h"
#include "heu/experimental/gemini-rlwe/lwe_types.h"
#include "heu/experimental/gemini-rlwe/modswitch_helper.h"
#include "heu/experimental/gemini-rlwe/poly_encoder.h"
#include "heu/experimental/gemini-rlwe/util.h"

namespace heu::expt::rlwe::test {

template <typename T>
T MakeMask(size_t bw) {
  size_t n = sizeof(T) * 8;
  if (n == bw) {
    return static_cast<T>(-1);
  } else {
    return (static_cast<T>(1) << bw) - 1;
  }
}

bool transform_to_ntt_inplace(RLWEPt& pt, const seal::SEALContext& context) {
  using namespace seal::util;
  auto cntxt_data = context.get_context_data(pt.parms_id());
  YACL_ENFORCE(cntxt_data != nullptr);

  auto L = cntxt_data->parms().coeff_modulus().size();
  YACL_ENFORCE(pt.coeff_count() % L == 0);

  auto ntt_tables = cntxt_data->small_ntt_tables();
  size_t n = pt.coeff_count() / L;
  auto pt_ptr = pt.data();
  for (size_t l = 0; l < L; ++l) {
    ntt_negacyclic_harvey(pt_ptr, ntt_tables[l]);
    pt_ptr += n;
  }
  return true;
}

class A2HTest : public ::testing::TestWithParam<size_t> {
 public:
  static constexpr size_t poly_deg = 4096;
  void SetUp() override {
    rdv_.seed(std::time(0));
    auto scheme_type = seal::scheme_type::ckks;
    auto parms = seal::EncryptionParameters(scheme_type);
    size_t bitlen = GetParam();

    std::vector<int> modulus_bits;
    if (bitlen <= 32) {
      modulus_bits = {59, 30};
    } else if (bitlen <= 64) {
      modulus_bits = {59, 50, 30};
    } else if (bitlen <= 128) {
      // Todo: There may be a problem here: why we need so big modulus here
      modulus_bits = {59, 59, 59, 59, 59, 59, 59};
    }

    parms.set_poly_modulus_degree(poly_deg);
    auto modulus = seal::CoeffModulus::Create(poly_deg, modulus_bits);
    parms.set_coeff_modulus(modulus);

    context_ = std::make_shared<seal::SEALContext>(parms, true,
                                                   seal::sec_level_type::none);
    modulus.pop_back();
    parms.set_coeff_modulus(modulus);

    seal::SEALContext ms_context(parms, false, seal::sec_level_type::none);

    ms_helper_ = std::make_shared<ModulusSwitchHelper>(ms_context, bitlen);
    bitlen_ = bitlen;
    num_modulus_ = modulus_bits.size();
    rdv_.seed(std::time(0));

    seal::KeyGenerator keygen(*context_);
    rlwe_sk_ = std::make_shared<RLWESecretKey>(keygen.secret_key());
    lwe_sk_ = std::make_shared<LWESecretKey>(*rlwe_sk_, *context_);
  }

  template <typename T>
  void UniformRand(T* dst, size_t n, size_t bw = 0) {
    T mask = static_cast<T>(-1);
    if (bw > 0 && bw < sizeof(T) * 8) {
      mask = (static_cast<T>(1) << bw) - 1;
    }
    std::uniform_int_distribution<T> uniform(0, static_cast<T>(-1));
    std::generate_n(dst, n, [&]() { return uniform(rdv_) & mask; });
  }

  void UniformRand(uint128_t* dst, size_t n, size_t bw) {
    uint64_t mask = static_cast<uint64_t>(-1);
    if (bw > 0 && bw < 128) {
      mask = (1ULL << (bw - 64)) - 1;
    }

    uint64_t* cast = reinterpret_cast<uint64_t*>(dst);
    UniformRand(cast, 2 * n);
    for (size_t i = 1; i < 2 * n; i += 2) {
      cast[i] &= mask;
    }
  }

  std::mt19937_64 rdv_;
  size_t bitlen_;

  size_t num_modulus_;
  std::shared_ptr<ModulusSwitchHelper> ms_helper_;
  std::shared_ptr<seal::SEALContext> context_;

  std::shared_ptr<RLWESecretKey> rlwe_sk_;
  std::shared_ptr<LWESecretKey> lwe_sk_;
};

INSTANTIATE_TEST_SUITE_P(NormalCase, A2HTest,
                         testing::Values(30, 32, 60, 64, 120, 128));

TEST_P(A2HTest, Basic) {
  const uint32_t mask32 = MakeMask<uint32_t>(std::min(32UL, bitlen_));
  uint64_t mask64 = MakeMask<uint64_t>(std::min(64UL, bitlen_));
  uint128_t mask128 = MakeMask<uint128_t>(std::min(128UL, bitlen_));
  const size_t n = poly_deg;

  std::vector<uint32_t> vec_u32;
  std::vector<uint64_t> vec_u64;
  std::vector<uint128_t> vec_u128;

  PolyEncoder encoder(*context_, *ms_helper_);
  seal::Encryptor encryptor(*context_, *rlwe_sk_);
  seal::Evaluator evaluator(*context_);
  LWEDecryptor decryptor(*lwe_sk_, *context_, ms_helper_);
  ShareConverter shr_conv(*context_, ms_helper_);
  auto prng = [this](uint8_t* out, size_t n) { UniformRand(out, n); };

  if (bitlen_ <= 32) {
    using Scalar = uint32_t;
    auto mask = mask32;
    auto& vec = vec_u32;
    vec.resize(n);
    UniformRand(vec.data(), vec.size(), bitlen_);

    RLWEPt pt;
    encoder.Forward(vec, &pt);
    transform_to_ntt_inplace(pt, *context_);

    RLWECt ct;
    encryptor.encrypt_symmetric(pt, ct);
    evaluator.transform_from_ntt_inplace(ct);
    for (size_t i = 0; i < vec.size(); ++i) {
      LWECt lwe(ct, i, *context_);
      Scalar shr0;
      shr_conv.H2A(lwe, prng, &shr0);
      EXPECT_LT(shr0, mask);

      Scalar shr1;
      decryptor.Decrypt(lwe, &shr1);
      Scalar computed = (shr0 + shr1) & mask;
      EXPECT_EQ(computed, vec.at(i));
    }
  } else if (bitlen_ <= 64) {
    using Scalar = uint64_t;
    auto mask = mask64;
    auto& vec = vec_u64;
    vec.resize(n);
    UniformRand(vec.data(), vec.size(), bitlen_);

    RLWEPt pt;
    encoder.Forward(vec, &pt);
    transform_to_ntt_inplace(pt, *context_);

    RLWECt ct;
    encryptor.encrypt_symmetric(pt, ct);
    evaluator.transform_from_ntt_inplace(ct);
    for (size_t i = 0; i < vec.size(); ++i) {
      LWECt lwe(ct, i, *context_);
      Scalar shr0;
      shr_conv.H2A(lwe, prng, &shr0);
      EXPECT_LT(shr0, mask);

      Scalar shr1;
      decryptor.Decrypt(lwe, &shr1);
      Scalar computed = (shr0 + shr1) & mask;
      EXPECT_EQ(computed, vec.at(i));
    }
  } else if (bitlen_ <= 128) {
    using Scalar = uint128_t;
    auto mask = mask128;
    auto& vec = vec_u128;
    vec.resize(n);
    UniformRand(vec.data(), vec.size(), bitlen_);

    RLWEPt pt;
    encoder.Forward(vec, &pt);
    transform_to_ntt_inplace(pt, *context_);

    RLWECt ct;
    encryptor.encrypt_symmetric(pt, ct);
    evaluator.transform_from_ntt_inplace(ct);
    for (size_t i = 0; i < vec.size(); ++i) {
      LWECt lwe(ct, i, *context_);
      Scalar shr0;
      shr_conv.H2A(lwe, prng, &shr0);
      EXPECT_LT(shr0, mask);

      Scalar shr1;
      decryptor.Decrypt(lwe, &shr1);
      Scalar computed = (shr0 + shr1) & mask;
      EXPECT_EQ(computed, vec.at(i));
    }
  }
}

}  // namespace heu::expt::rlwe::test
