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

#include "heu/experimental/gemini-rlwe/matvec.h"

#include "gtest/gtest.h"
#include "seal/seal.h"
#include "seal/util/ntt.h"
#include "seal/util/polyarithsmallmod.h"

#include "heu/experimental/gemini-rlwe/a2h.h"
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

class MatVecTest : public ::testing::TestWithParam<
                       std::tuple<size_t, std::tuple<size_t, size_t>>> {
 protected:
  static constexpr size_t poly_deg = 4096;

  void SetUp() override {
    rdv_.seed(std::time(0));
    auto scheme_type = seal::scheme_type::ckks;
    auto parms = seal::EncryptionParameters(scheme_type);
    size_t bitlen = std::get<0>(GetParam());

    std::vector<int> modulus_bits;
    if (bitlen <= 32) {
      modulus_bits = {59, 50, 30};  // > 64
    } else if (bitlen <= 64) {
      modulus_bits = {59, 59, 50, 30};  // > 128
    } else if (bitlen <= 128) {         // > 256
      // Todo: There may be a problem here: why we need so big modulus here
      modulus_bits = {59, 59, 59, 59, 59, 59, 59, 59};
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
  void MatVecPlain(const T* mat, const T* vec, size_t nrows, size_t ncols,
                   T* out) const {
    for (size_t r = 0; r < nrows; ++r) {
      T accum{0};
      auto mat_row = mat + r * ncols;
      for (size_t c = 0; c < ncols; ++c) {
        accum += mat_row[c] * vec[c];
      }
      out[r] = accum;
    }
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

INSTANTIATE_TEST_SUITE_P(
    NormalCase, MatVecTest,
    testing::Combine(
        testing::Values(30, 32, 60, 64, 120, 128),         // ring bit length
        testing::Values(std::make_tuple<size_t>(8, 128),   // fit into one poly
                        std::make_tuple<size_t>(8, 1028),  // multi-rows
                        std::make_tuple<size_t>(7, 255),   // non-two power
                        std::make_tuple<size_t>(5, 4096),  // single row
                        std::make_tuple<size_t>(5, 5000)   // split columns
                        )));

TEST_P(MatVecTest, Basic) {
  const uint32_t mask32 = MakeMask<uint32_t>(std::min(32UL, bitlen_));
  const uint64_t mask64 = MakeMask<uint64_t>(std::min(64UL, bitlen_));
  const uint128_t mask128 = MakeMask<uint128_t>(std::min(128UL, bitlen_));

  std::vector<uint32_t> vec_u32;
  std::vector<uint32_t> mat_u32;

  std::vector<uint64_t> vec_u64;
  std::vector<uint64_t> mat_u64;

  std::vector<uint128_t> vec_u128;
  std::vector<uint128_t> mat_u128;

  MatVecProtocol matvec_prot(*context_, *ms_helper_);
  MatVecProtocol::Meta meta;
  meta.transposed = false;
  seal::Encryptor encryptor(*context_, *rlwe_sk_);

  meta.nrows = std::get<0>(std::get<1>(GetParam()));
  meta.ncols = std::get<1>(std::get<1>(GetParam()));

  if (bitlen_ <= 32) {
    using Scalar = uint32_t;
    auto& vec = vec_u32;
    auto& mat = mat_u32;
    vec.resize(meta.ncols);
    mat.resize(meta.nrows * meta.ncols);
    UniformRand(vec.data(), vec.size(), bitlen_);
    UniformRand(mat.data(), mat.size(), bitlen_);
    std::vector<Scalar> ground(meta.nrows);
    MatVecPlain<Scalar>(mat.data(), vec.data(), meta.nrows, meta.ncols,
                        ground.data());

    absl::Span<const Scalar> _vec(vec.data(), vec.size());
    std::vector<RLWEPt> ecd_vec;
    matvec_prot.EncodeVector(meta, _vec, &ecd_vec);
    std::vector<RLWECt> vec_cipher(ecd_vec.size());
    for (size_t i = 0; i < ecd_vec.size(); ++i) {
      ecd_vec[i].parms_id() = context_->first_parms_id();
      transform_to_ntt_inplace(ecd_vec[i], *context_);
      encryptor.encrypt_symmetric(ecd_vec[i], vec_cipher[i]);
    }

    absl::Span<const Scalar> _mat(mat.data(), mat.size());
    std::vector<LWECt> matvec_prod;
    matvec_prot.MatVec(meta, _mat, vec_cipher, &matvec_prod);

    LWEDecryptor decryptor(*lwe_sk_, *context_, ms_helper_);
    for (size_t r = 0; r < meta.nrows; ++r) {
      Scalar out;
      decryptor.Decrypt(matvec_prod[r], &out);
      EXPECT_EQ(out, ground[r] & mask32);
    }

  } else if (bitlen_ <= 64) {
    using Scalar = uint64_t;
    auto& vec = vec_u64;
    auto& mat = mat_u64;
    vec.resize(meta.ncols);
    mat.resize(meta.nrows * meta.ncols);

    UniformRand(vec.data(), vec.size(), bitlen_);
    UniformRand(mat.data(), mat.size(), bitlen_);
    std::vector<Scalar> ground(meta.nrows);
    MatVecPlain<Scalar>(mat.data(), vec.data(), meta.nrows, meta.ncols,
                        ground.data());

    absl::Span<const Scalar> _vec(vec.data(), vec.size());
    std::vector<RLWEPt> ecd_vec;
    matvec_prot.EncodeVector(meta, _vec, &ecd_vec);
    std::vector<RLWECt> vec_cipher(ecd_vec.size());
    for (size_t i = 0; i < ecd_vec.size(); ++i) {
      ecd_vec[i].parms_id() = context_->first_parms_id();
      transform_to_ntt_inplace(ecd_vec[i], *context_);
      encryptor.encrypt_symmetric(ecd_vec[i], vec_cipher[i]);
    }

    absl::Span<const Scalar> _mat(mat.data(), mat.size());
    std::vector<LWECt> matvec_prod;
    matvec_prot.MatVec(meta, _mat, vec_cipher, &matvec_prod);

    LWEDecryptor decryptor(*lwe_sk_, *context_, ms_helper_);
    for (size_t r = 0; r < meta.nrows; ++r) {
      Scalar out;
      decryptor.Decrypt(matvec_prod[r], &out);
      EXPECT_EQ(out, ground[r] & mask64);
    }
  } else if (bitlen_ <= 128) {
    using Scalar = uint128_t;
    auto& vec = vec_u128;
    auto& mat = mat_u128;
    vec.resize(meta.ncols);
    mat.resize(meta.nrows * meta.ncols);

    UniformRand(vec.data(), vec.size(), bitlen_);
    UniformRand(mat.data(), mat.size(), bitlen_);
    std::vector<Scalar> ground(meta.nrows);
    MatVecPlain<Scalar>(mat.data(), vec.data(), meta.nrows, meta.ncols,
                        ground.data());

    absl::Span<const Scalar> _vec(vec.data(), vec.size());
    std::vector<RLWEPt> ecd_vec;
    matvec_prot.EncodeVector(meta, _vec, &ecd_vec);
    std::vector<RLWECt> vec_cipher(ecd_vec.size());
    for (size_t i = 0; i < ecd_vec.size(); ++i) {
      ecd_vec[i].parms_id() = context_->first_parms_id();
      transform_to_ntt_inplace(ecd_vec[i], *context_);
      encryptor.encrypt_symmetric(ecd_vec[i], vec_cipher[i]);
    }

    absl::Span<const Scalar> _mat(mat.data(), mat.size());
    std::vector<LWECt> matvec_prod;
    matvec_prot.MatVec(meta, _mat, vec_cipher, &matvec_prod);

    LWEDecryptor decryptor(*lwe_sk_, *context_, ms_helper_);
    for (size_t r = 0; r < meta.nrows; ++r) {
      Scalar out;
      decryptor.Decrypt(matvec_prod[r], &out);
      EXPECT_EQ(out, ground[r] & mask128);
    }
  }
}

TEST_P(MatVecTest, RandomMat) {
  const uint32_t mask32 = MakeMask<uint32_t>(std::min(32UL, bitlen_));
  const uint64_t mask64 = MakeMask<uint64_t>(std::min(64UL, bitlen_));
  const uint128_t mask128 = MakeMask<uint128_t>(std::min(128UL, bitlen_));

  std::vector<uint32_t> vec_u32;
  std::vector<uint32_t> mat_u32;

  std::vector<uint64_t> vec_u64;
  std::vector<uint64_t> mat_u64;

  std::vector<uint128_t> vec_u128;
  std::vector<uint128_t> mat_u128;

  MatVecProtocol matvec_prot(*context_, *ms_helper_);
  MatVecProtocol::Meta meta;
  meta.transposed = false;
  seal::Encryptor encryptor(*context_, *rlwe_sk_);

  meta.nrows = std::get<0>(std::get<1>(GetParam()));
  meta.ncols = std::get<1>(std::get<1>(GetParam()));

  if (bitlen_ <= 32) {
    using Scalar = uint32_t;
    auto& vec = vec_u32;
    auto& mat = mat_u32;
    vec.resize(meta.ncols);
    mat.resize(meta.nrows * meta.ncols);
    UniformRand(vec.data(), vec.size(), bitlen_);

    absl::Span<const Scalar> _vec(vec.data(), vec.size());
    std::vector<RLWEPt> ecd_vec;
    matvec_prot.EncodeVector(meta, _vec, &ecd_vec);
    std::vector<RLWECt> vec_cipher(ecd_vec.size());
    for (size_t i = 0; i < ecd_vec.size(); ++i) {
      transform_to_ntt_inplace(ecd_vec[i], *context_);
      encryptor.encrypt_symmetric(ecd_vec[i], vec_cipher[i]);
    }

    std::vector<LWECt> matvec_prod;
    auto prng = [&](Scalar* out, size_t size) {
      UniformRand(out, size, bitlen_);
    };

    absl::Span<Scalar> _mat(mat.data(), mat.size());
    matvec_prot.MatVecRandomMat<Scalar>(meta, vec_cipher, prng, _mat,
                                        &matvec_prod);

    std::vector<Scalar> ground(meta.nrows);
    MatVecPlain<Scalar>(mat.data(), vec.data(), meta.nrows, meta.ncols,
                        ground.data());

    LWEDecryptor decryptor(*lwe_sk_, *context_, ms_helper_);
    for (size_t r = 0; r < meta.nrows; ++r) {
      Scalar out;
      decryptor.Decrypt(matvec_prod[r], &out);
      EXPECT_EQ(out, ground[r] & mask32);
    }
  } else if (bitlen_ <= 64) {
    using Scalar = uint64_t;
    auto& vec = vec_u64;
    auto& mat = mat_u64;
    vec.resize(meta.ncols);
    mat.resize(meta.nrows * meta.ncols);
    UniformRand(vec.data(), vec.size(), bitlen_);

    absl::Span<const Scalar> _vec(vec.data(), vec.size());
    std::vector<RLWEPt> ecd_vec;
    matvec_prot.EncodeVector(meta, _vec, &ecd_vec);
    std::vector<RLWECt> vec_cipher(ecd_vec.size());
    for (size_t i = 0; i < ecd_vec.size(); ++i) {
      ecd_vec[i].parms_id() = context_->first_parms_id();
      transform_to_ntt_inplace(ecd_vec[i], *context_);
      encryptor.encrypt_symmetric(ecd_vec[i], vec_cipher[i]);
    }

    std::vector<LWECt> matvec_prod;
    auto prng = [&](Scalar* out, size_t size) {
      UniformRand(out, size, bitlen_);
    };

    absl::Span<Scalar> _mat(mat.data(), mat.size());
    matvec_prot.MatVecRandomMat<Scalar>(meta, vec_cipher, prng, _mat,
                                        &matvec_prod);

    std::vector<Scalar> ground(meta.nrows);
    MatVecPlain<Scalar>(mat.data(), vec.data(), meta.nrows, meta.ncols,
                        ground.data());

    LWEDecryptor decryptor(*lwe_sk_, *context_, ms_helper_);
    for (size_t r = 0; r < meta.nrows; ++r) {
      Scalar out;
      decryptor.Decrypt(matvec_prod[r], &out);
      EXPECT_EQ(out, ground[r] & mask64);
    }
  } else if (bitlen_ <= 128) {
    using Scalar = uint128_t;
    auto& vec = vec_u128;
    auto& mat = mat_u128;
    vec.resize(meta.ncols);
    mat.resize(meta.nrows * meta.ncols);
    UniformRand(vec.data(), vec.size(), bitlen_);

    absl::Span<const Scalar> _vec(vec.data(), vec.size());
    std::vector<RLWEPt> ecd_vec;
    matvec_prot.EncodeVector(meta, _vec, &ecd_vec);
    std::vector<RLWECt> vec_cipher(ecd_vec.size());
    for (size_t i = 0; i < ecd_vec.size(); ++i) {
      ecd_vec[i].parms_id() = context_->first_parms_id();
      transform_to_ntt_inplace(ecd_vec[i], *context_);
      encryptor.encrypt_symmetric(ecd_vec[i], vec_cipher[i]);
    }

    std::vector<LWECt> matvec_prod;
    auto prng = [&](Scalar* out, size_t size) {
      UniformRand(out, size, bitlen_);
    };

    absl::Span<Scalar> _mat(mat.data(), mat.size());
    matvec_prot.MatVecRandomMat<Scalar>(meta, vec_cipher, prng, _mat,
                                        &matvec_prod);

    std::vector<Scalar> ground(meta.nrows);
    MatVecPlain<Scalar>(mat.data(), vec.data(), meta.nrows, meta.ncols,
                        ground.data());

    LWEDecryptor decryptor(*lwe_sk_, *context_, ms_helper_);
    for (size_t r = 0; r < meta.nrows; ++r) {
      Scalar out;
      decryptor.Decrypt(matvec_prod[r], &out);
      EXPECT_EQ(out, ground[r] & mask128);
    }
  }
}

// Random M0, v0, M1, v1
// Compute two MatVec: M0*v1, M1*v0
// Return (M0, v0, z0), (M1, v1, z1) such that z0 + z1 = (M0 + M1)*(v0 + v1)
TEST_P(MatVecTest, BiMatVecTriple) {
  const uint32_t mask32 = MakeMask<uint32_t>(std::min(32UL, bitlen_));
  const uint64_t mask64 = MakeMask<uint64_t>(std::min(64UL, bitlen_));
  const uint128_t mask128 = MakeMask<uint128_t>(std::min(128UL, bitlen_));

  // (M, v, z) s.t z = M*v
  // (M0 + M1) * (v0 + v1)
  // => M0*v0 + <M0*v1> + <M1*v0> + M1*v1

  std::vector<uint32_t> vec0_u32, vec1_u32;
  std::vector<uint32_t> mat0_u32, mat1_u32;

  std::vector<uint64_t> vec0_u64, vec1_u64;
  std::vector<uint64_t> mat0_u64, mat1_u64;

  std::vector<uint128_t> vec0_u128, vec1_u128;
  std::vector<uint128_t> mat0_u128, mat1_u128;

  MatVecProtocol matvec_prot(*context_, *ms_helper_);
  MatVecProtocol::Meta meta;
  meta.transposed = false;
  seal::Encryptor encryptor(*context_, *rlwe_sk_);
  seal::Evaluator evaluator(*context_);

  meta.nrows = std::get<0>(std::get<1>(GetParam()));
  meta.ncols = std::get<1>(std::get<1>(GetParam()));

  ShareConverter shr_conv(*context_, ms_helper_);
  LWEDecryptor decryptor(*lwe_sk_, *context_, ms_helper_);

  if (bitlen_ <= 32) {
    using Scalar = uint32_t;
    auto& vec0 = vec0_u32;
    auto& vec1 = vec1_u32;
    auto& mat0 = mat0_u32;
    auto& mat1 = mat1_u32;
    auto mask = mask32;

    vec0.resize(meta.ncols);
    vec1.resize(meta.ncols);
    UniformRand(vec0.data(), vec0.size(), bitlen_);
    UniformRand(vec1.data(), vec1.size(), bitlen_);

    std::vector<RLWEPt> ecd_vec0, ecd_vec1;
    matvec_prot.EncodeVector(meta, vec0, &ecd_vec0);
    matvec_prot.EncodeVector(meta, vec1, &ecd_vec1);

    std::vector<RLWECt> vec0_cipher(ecd_vec0.size());
    std::vector<RLWECt> vec1_cipher(ecd_vec1.size());

    for (size_t i = 0; i < ecd_vec0.size(); ++i) {
      transform_to_ntt_inplace(ecd_vec0[i], *context_);
      encryptor.encrypt_symmetric(ecd_vec0[i], vec0_cipher[i]);

      transform_to_ntt_inplace(ecd_vec1[i], *context_);
      encryptor.encrypt_symmetric(ecd_vec1[i], vec1_cipher[i]);
    }

    auto prng = [&](Scalar* out, size_t size) {
      UniformRand(out, size, bitlen_);
    };

    auto u8prng = [&](uint8_t* out, size_t size) { UniformRand(out, size); };

    // M0*[v1]
    mat0.resize(meta.nrows * meta.ncols);
    std::vector<LWECt> mat0_vec1_prod;
    absl::Span<Scalar> _mat(mat0.data(), mat0.size());
    matvec_prot.MatVecRandomMat<Scalar>(meta, vec1_cipher, prng, _mat,
                                        &mat0_vec1_prod);
    std::vector<Scalar> M0v1_shr0(meta.ncols);
    std::vector<Scalar> M0v1_shr1(meta.ncols);
    for (size_t l = 0; l < mat0_vec1_prod.size(); ++l) {
      shr_conv.H2A(mat0_vec1_prod[l], u8prng, &M0v1_shr1[l]);
      decryptor.Decrypt(mat0_vec1_prod[l], &M0v1_shr0[l]);
    }

    // M1*[v0]
    mat1.resize(meta.nrows * meta.ncols);
    std::vector<LWECt> mat1_vec0_prod;
    _mat = {mat1.data(), mat1.size()};
    matvec_prot.MatVecRandomMat<Scalar>(meta, vec0_cipher, prng, _mat,
                                        &mat1_vec0_prod);
    std::vector<Scalar> M1v0_shr0(meta.ncols);
    std::vector<Scalar> M1v0_shr1(meta.ncols);
    for (size_t l = 0; l < mat1_vec0_prod.size(); ++l) {
      shr_conv.H2A(mat1_vec0_prod[l], u8prng, &M1v0_shr1[l]);
      decryptor.Decrypt(mat1_vec0_prod[l], &M1v0_shr0[l]);
    }

    // z0 = M0*v0 + <M0*v1>_0 + <M1*v0>_0
    // z1 = M1*v1 + <M0*v1>_1 + <M1*v0>_1
    auto adder = [](Scalar x, Scalar y) { return x + y; };
    std::vector<Scalar> M0v0(meta.ncols);
    MatVecPlain<Scalar>(mat0.data(), vec0.data(), meta.nrows, meta.ncols,
                        M0v0.data());

    std::transform(M0v0.begin(), M0v0.end(), M0v1_shr0.data(), M0v0.data(),
                   adder);
    std::transform(M0v0.begin(), M0v0.end(), M1v0_shr0.data(), M0v0.data(),
                   adder);

    std::vector<Scalar> M1v1(meta.ncols);
    MatVecPlain<Scalar>(mat1.data(), vec1.data(), meta.nrows, meta.ncols,
                        M1v1.data());
    std::transform(M1v1.begin(), M1v1.end(), M0v1_shr1.data(), M1v1.data(),
                   adder);
    std::transform(M1v1.begin(), M1v1.end(), M1v0_shr1.data(), M1v1.data(),
                   adder);

    // Ground
    std::vector<Scalar> mat(meta.nrows * meta.ncols);
    std::vector<Scalar> vec(meta.ncols);
    std::vector<Scalar> ground(meta.ncols);
    std::transform(mat0.begin(), mat0.end(), mat1.begin(), mat.data(), adder);
    std::transform(vec0.begin(), vec0.end(), vec1.begin(), vec.data(), adder);

    MatVecPlain<Scalar>(mat.data(), vec.data(), meta.nrows, meta.ncols,
                        ground.data());

    for (size_t l = 0; l < ground.size(); ++l) {
      EXPECT_EQ(ground[l] & mask, (M0v0[l] + M1v1[l]) & mask);
    }
  } else if (bitlen_ <= 64) {
    using Scalar = uint64_t;
    auto& vec0 = vec0_u64;
    auto& vec1 = vec1_u64;
    auto& mat0 = mat0_u64;
    auto& mat1 = mat1_u64;
    auto mask = mask64;

    vec0.resize(meta.ncols);
    vec1.resize(meta.ncols);
    UniformRand(vec0.data(), vec0.size(), bitlen_);
    UniformRand(vec1.data(), vec1.size(), bitlen_);

    std::vector<RLWEPt> ecd_vec0, ecd_vec1;
    matvec_prot.EncodeVector(meta, vec0, &ecd_vec0);
    matvec_prot.EncodeVector(meta, vec1, &ecd_vec1);

    std::vector<RLWECt> vec0_cipher(ecd_vec0.size());
    std::vector<RLWECt> vec1_cipher(ecd_vec1.size());

    for (size_t i = 0; i < ecd_vec0.size(); ++i) {
      transform_to_ntt_inplace(ecd_vec0[i], *context_);
      encryptor.encrypt_symmetric(ecd_vec0[i], vec0_cipher[i]);

      transform_to_ntt_inplace(ecd_vec1[i], *context_);
      encryptor.encrypt_symmetric(ecd_vec1[i], vec1_cipher[i]);
    }

    auto prng = [&](Scalar* out, size_t size) {
      UniformRand(out, size, bitlen_);
    };

    auto u8prng = [&](uint8_t* out, size_t size) { UniformRand(out, size); };

    // M0*[v1]
    mat0.resize(meta.nrows * meta.ncols);
    std::vector<LWECt> mat0_vec1_prod;
    absl::Span<Scalar> _mat(mat0.data(), mat0.size());
    matvec_prot.MatVecRandomMat<Scalar>(meta, vec1_cipher, prng, _mat,
                                        &mat0_vec1_prod);
    std::vector<Scalar> M0v1_shr0(meta.ncols);
    std::vector<Scalar> M0v1_shr1(meta.ncols);
    for (size_t l = 0; l < mat0_vec1_prod.size(); ++l) {
      shr_conv.H2A(mat0_vec1_prod[l], u8prng, &M0v1_shr1[l]);
      decryptor.Decrypt(mat0_vec1_prod[l], &M0v1_shr0[l]);
    }

    // M1*[v0]
    mat1.resize(meta.nrows * meta.ncols);
    std::vector<LWECt> mat1_vec0_prod;
    _mat = {mat1.data(), mat1.size()};
    matvec_prot.MatVecRandomMat<Scalar>(meta, vec0_cipher, prng, _mat,
                                        &mat1_vec0_prod);
    std::vector<Scalar> M1v0_shr0(meta.ncols);
    std::vector<Scalar> M1v0_shr1(meta.ncols);
    for (size_t l = 0; l < mat1_vec0_prod.size(); ++l) {
      shr_conv.H2A(mat1_vec0_prod[l], u8prng, &M1v0_shr1[l]);
      decryptor.Decrypt(mat1_vec0_prod[l], &M1v0_shr0[l]);
    }

    // z0 = M0*v0 + <M0*v1>_0 + <M1*v0>_0
    // z1 = M1*v1 + <M0*v1>_1 + <M1*v0>_1
    auto adder = [](Scalar x, Scalar y) { return x + y; };
    std::vector<Scalar> M0v0(meta.ncols);
    MatVecPlain<Scalar>(mat0.data(), vec0.data(), meta.nrows, meta.ncols,
                        M0v0.data());

    std::transform(M0v0.begin(), M0v0.end(), M0v1_shr0.data(), M0v0.data(),
                   adder);
    std::transform(M0v0.begin(), M0v0.end(), M1v0_shr0.data(), M0v0.data(),
                   adder);

    std::vector<Scalar> M1v1(meta.ncols);
    MatVecPlain<Scalar>(mat1.data(), vec1.data(), meta.nrows, meta.ncols,
                        M1v1.data());
    std::transform(M1v1.begin(), M1v1.end(), M0v1_shr1.data(), M1v1.data(),
                   adder);
    std::transform(M1v1.begin(), M1v1.end(), M1v0_shr1.data(), M1v1.data(),
                   adder);

    // Ground
    std::vector<Scalar> mat(meta.nrows * meta.ncols);
    std::vector<Scalar> vec(meta.ncols);
    std::vector<Scalar> ground(meta.ncols);
    std::transform(mat0.begin(), mat0.end(), mat1.begin(), mat.data(), adder);
    std::transform(vec0.begin(), vec0.end(), vec1.begin(), vec.data(), adder);

    MatVecPlain<Scalar>(mat.data(), vec.data(), meta.nrows, meta.ncols,
                        ground.data());

    for (size_t l = 0; l < ground.size(); ++l) {
      EXPECT_EQ(ground[l] & mask, (M0v0[l] + M1v1[l]) & mask);
    }
  } else if (bitlen_ <= 128) {
    using Scalar = uint128_t;
    auto& vec0 = vec0_u128;
    auto& vec1 = vec1_u128;
    auto& mat0 = mat0_u128;
    auto& mat1 = mat1_u128;
    auto mask = mask128;

    vec0.resize(meta.ncols);
    vec1.resize(meta.ncols);
    UniformRand(vec0.data(), vec0.size(), bitlen_);
    UniformRand(vec1.data(), vec1.size(), bitlen_);

    std::vector<RLWEPt> ecd_vec0, ecd_vec1;
    matvec_prot.EncodeVector(meta, vec0, &ecd_vec0);
    matvec_prot.EncodeVector(meta, vec1, &ecd_vec1);

    std::vector<RLWECt> vec0_cipher(ecd_vec0.size());
    std::vector<RLWECt> vec1_cipher(ecd_vec1.size());

    for (size_t i = 0; i < ecd_vec0.size(); ++i) {
      transform_to_ntt_inplace(ecd_vec0[i], *context_);
      encryptor.encrypt_symmetric(ecd_vec0[i], vec0_cipher[i]);

      transform_to_ntt_inplace(ecd_vec1[i], *context_);
      encryptor.encrypt_symmetric(ecd_vec1[i], vec1_cipher[i]);
    }

    auto prng = [&](Scalar* out, size_t size) {
      UniformRand(out, size, bitlen_);
    };

    auto u8prng = [&](uint8_t* out, size_t size) { UniformRand(out, size); };

    // M0*[v1]
    mat0.resize(meta.nrows * meta.ncols);
    std::vector<LWECt> mat0_vec1_prod;
    absl::Span<Scalar> _mat(mat0.data(), mat0.size());
    matvec_prot.MatVecRandomMat<Scalar>(meta, vec1_cipher, prng, _mat,
                                        &mat0_vec1_prod);
    std::vector<Scalar> M0v1_shr0(meta.ncols);
    std::vector<Scalar> M0v1_shr1(meta.ncols);
    for (size_t l = 0; l < mat0_vec1_prod.size(); ++l) {
      shr_conv.H2A(mat0_vec1_prod[l], u8prng, &M0v1_shr1[l]);
      decryptor.Decrypt(mat0_vec1_prod[l], &M0v1_shr0[l]);
    }

    // M1*[v0]
    mat1.resize(meta.nrows * meta.ncols);
    std::vector<LWECt> mat1_vec0_prod;
    _mat = {mat1.data(), mat1.size()};
    matvec_prot.MatVecRandomMat<Scalar>(meta, vec0_cipher, prng, _mat,
                                        &mat1_vec0_prod);
    std::vector<Scalar> M1v0_shr0(meta.ncols);
    std::vector<Scalar> M1v0_shr1(meta.ncols);
    for (size_t l = 0; l < mat1_vec0_prod.size(); ++l) {
      shr_conv.H2A(mat1_vec0_prod[l], u8prng, &M1v0_shr1[l]);
      decryptor.Decrypt(mat1_vec0_prod[l], &M1v0_shr0[l]);
    }

    // z0 = M0*v0 + <M0*v1>_0 + <M1*v0>_0
    // z1 = M1*v1 + <M0*v1>_1 + <M1*v0>_1
    auto adder = [](Scalar x, Scalar y) { return x + y; };
    std::vector<Scalar> M0v0(meta.ncols);
    MatVecPlain<Scalar>(mat0.data(), vec0.data(), meta.nrows, meta.ncols,
                        M0v0.data());

    std::transform(M0v0.begin(), M0v0.end(), M0v1_shr0.data(), M0v0.data(),
                   adder);
    std::transform(M0v0.begin(), M0v0.end(), M1v0_shr0.data(), M0v0.data(),
                   adder);

    std::vector<Scalar> M1v1(meta.ncols);
    MatVecPlain<Scalar>(mat1.data(), vec1.data(), meta.nrows, meta.ncols,
                        M1v1.data());
    std::transform(M1v1.begin(), M1v1.end(), M0v1_shr1.data(), M1v1.data(),
                   adder);
    std::transform(M1v1.begin(), M1v1.end(), M1v0_shr1.data(), M1v1.data(),
                   adder);

    // Ground
    std::vector<Scalar> mat(meta.nrows * meta.ncols);
    std::vector<Scalar> vec(meta.ncols);
    std::vector<Scalar> ground(meta.ncols);
    std::transform(mat0.begin(), mat0.end(), mat1.begin(), mat.data(), adder);
    std::transform(vec0.begin(), vec0.end(), vec1.begin(), vec.data(), adder);

    MatVecPlain<Scalar>(mat.data(), vec.data(), meta.nrows, meta.ncols,
                        ground.data());

    for (size_t l = 0; l < ground.size(); ++l) {
      EXPECT_EQ(ground[l] & mask, (M0v0[l] + M1v1[l]) & mask);
    }
  }
}

}  // namespace heu::expt::rlwe::test
