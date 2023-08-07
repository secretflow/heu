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

#include "gtest/gtest.h"
#include "seal/seal.h"
#include "seal/util/ntt.h"
#include "seal/util/polyarithsmallmod.h"

#include "heu/experimental/gemini-rlwe/lwe_decryptor.h"
#include "heu/experimental/gemini-rlwe/lwe_types.h"
#include "heu/experimental/gemini-rlwe/matvec.h"
#include "heu/experimental/gemini-rlwe/modswitch_helper.h"
#include "heu/experimental/gemini-rlwe/poly_encoder.h"
#include "heu/experimental/gemini-rlwe/util.h"

namespace heu::expt::rlwe::test {

class RLWE2LWETest : public testing::Test {
 protected:
  static constexpr size_t poly_deg = 4096;

  void SetUp() override {
    rdv_.seed(std::time(0));
    auto scheme_type = seal::scheme_type::ckks;
    auto parms = seal::EncryptionParameters(scheme_type);
    // Todo: There may be a problem here: why we need so big modulus here
    std::vector<int> modulus_bits{59, 59, 59, 59, 59, 59, 59, 59};

    parms.set_poly_modulus_degree(poly_deg);
    auto modulus = seal::CoeffModulus::Create(poly_deg, modulus_bits);
    parms.set_coeff_modulus(modulus);

    context_ = std::make_shared<seal::SEALContext>(parms, true,
                                                   seal::sec_level_type::none);

    // Q ~ 145bit (55+55+35) should fine for sum 4096times
    modulus.pop_back();
    parms.set_coeff_modulus(modulus);
    ms_context_ = std::make_shared<seal::SEALContext>(
        parms, false, seal::sec_level_type::none);

    seal::KeyGenerator keygen(*context_);
    rlwe_sk_ = std::make_shared<RLWESecretKey>(keygen.secret_key());
    lwe_sk_ = std::make_shared<LWESecretKey>(*rlwe_sk_, *context_);

    u32_coeff_.resize(poly_deg);
    u64_coeff_.resize(poly_deg);
    u128_coeff_.resize(poly_deg);
    UniformRand(u32_coeff_.data(), poly_deg);
    UniformRand(u64_coeff_.data(), poly_deg);
    UniformRand(u128_coeff_.data(), poly_deg);
  }

  template <typename T>
  void MatVecPlain(const T *mat, const T *vec, size_t nrows, size_t ncols,
                   T *out) const {
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
  void UniformRand(T *dst, size_t n) {
    std::uniform_int_distribution<T> uniform(0, static_cast<T>(-1));
    std::generate_n(dst, n, [&]() { return uniform(rdv_); });
  }

  void UniformRand(uint128_t *dst, size_t n) {
    uint64_t *cast = reinterpret_cast<uint64_t *>(dst);
    UniformRand(cast, 2 * n);
    uint64_t mask = (1UL << 56) - 1;
    for (size_t i = 1; i < 2 * n; i += 2) {
      cast[i] &= mask;
    }
  }

 protected:
  std::mt19937_64 rdv_;
  std::vector<uint32_t> u32_coeff_;
  std::vector<uint64_t> u64_coeff_;
  std::vector<uint128_t> u128_coeff_;

  std::shared_ptr<seal::SEALContext> context_;

  std::shared_ptr<seal::SEALContext> ms_context_;

  std::shared_ptr<RLWESecretKey> rlwe_sk_;
  std::shared_ptr<LWESecretKey> lwe_sk_;
  std::shared_ptr<ModulusSwitchHelper> ms_helper_;
};

bool transform_to_ntt_inplace(RLWEPt &pt, const seal::SEALContext &context) {
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

bool transform_from_ntt_inplace(RLWEPt &pt, const seal::SEALContext &context) {
  using namespace seal::util;
  auto cntxt_data = context.get_context_data(pt.parms_id());
  YACL_ENFORCE(cntxt_data != nullptr);

  auto L = cntxt_data->parms().coeff_modulus().size();
  YACL_ENFORCE(pt.coeff_count() % L == 0);

  auto ntt_tables = cntxt_data->small_ntt_tables();
  size_t n = pt.coeff_count() / L;
  auto pt_ptr = pt.data();
  for (size_t l = 0; l < L; ++l) {
    inverse_ntt_negacyclic_harvey(pt_ptr, ntt_tables[l]);
    pt_ptr += n;
  }
  return true;
}

bool dyadic_product(RLWEPt &pt, const RLWEPt &oth,
                    const seal::SEALContext &context) {
  using namespace seal::util;
  auto cntxt_data = context.get_context_data(pt.parms_id());
  if (!cntxt_data) {
    return false;
  }

  auto L = cntxt_data->parms().coeff_modulus().size();
  if (pt.coeff_count() % L != 0) {
    return false;
  }

  auto ntt_tables = cntxt_data->small_ntt_tables();
  size_t n = pt.coeff_count() / L;
  auto pt_ptr = pt.data();
  auto oth_ptr = oth.data();
  for (size_t l = 0; l < L; ++l) {
    dyadic_product_coeffmod(pt_ptr, oth_ptr, n, ntt_tables[l].modulus(),
                            pt_ptr);
    pt_ptr += n;
    oth_ptr += n;
  }
  return true;
}

TEST_F(RLWE2LWETest, ExtractU32) {
  seal::Encryptor encryptor(*context_, *rlwe_sk_);
  seal::Evaluator evaluator(*context_);

  using Scalar = uint32_t;
  ms_helper_ =
      std::make_shared<ModulusSwitchHelper>(*ms_context_, sizeof(Scalar) * 8);
  LWEDecryptor decryptor(*lwe_sk_, *context_, ms_helper_);
  PolyEncoder encoder(*context_, *ms_helper_);

  RLWEPt pt;
  absl::Span<const Scalar> span(u32_coeff_.data(), u32_coeff_.size());
  encoder.Vec2Poly(span, &pt);
  pt.parms_id() = context_->first_parms_id();
  transform_to_ntt_inplace(pt, *context_);

  RLWECt ct;
  encryptor.encrypt_symmetric(pt, ct);
  evaluator.transform_from_ntt_inplace(ct);

  LWECt accum, sub;
  LWECt lazy_accum, lazy_sub;
  for (size_t i = 0; i < u32_coeff_.size(); ++i) {
    lazy_accum.AddLazyInplace(ct, i, *context_);
    lazy_sub.SubLazyInplace(ct, i, *context_);

    LWECt lwe(ct, i, *context_);
    accum.AddInplace(lwe, *context_);
    sub.SubInplace(lwe, *context_);

    Scalar dec{0};
    decryptor.Decrypt(lwe, &dec);
    EXPECT_EQ(dec, u32_coeff_[i]);

    lwe.NegateInplace(*context_);
    decryptor.Decrypt(lwe, &dec);
    EXPECT_EQ(dec, -u32_coeff_[i]);
  }

  Scalar ground = std::accumulate(u32_coeff_.begin(), u32_coeff_.end(), 0U);

  Scalar sum{0};
  decryptor.Decrypt(accum, &sum);
  EXPECT_EQ(sum, ground);

  lazy_accum.Reduce(*context_);
  decryptor.Decrypt(lazy_accum, &sum);
  EXPECT_EQ(sum, ground);

  // -2*ground
  lazy_sub.Reduce(*context_);
  sub.AddInplace(lazy_sub, *context_);
  decryptor.Decrypt(sub, &sum);
  EXPECT_EQ(sum, -(ground + ground));
}

TEST_F(RLWE2LWETest, ExtractU64) {
  seal::Encryptor encryptor(*context_, *rlwe_sk_);
  seal::Evaluator evaluator(*context_);

  using Scalar = uint64_t;
  ms_helper_ =
      std::make_shared<ModulusSwitchHelper>(*ms_context_, sizeof(Scalar) * 8);
  LWEDecryptor decryptor(*lwe_sk_, *context_, ms_helper_);
  PolyEncoder encoder(*context_, *ms_helper_);

  RLWEPt pt;
  absl::Span<const Scalar> span(u64_coeff_.data(), u64_coeff_.size());
  encoder.Vec2Poly(span, &pt);
  pt.parms_id() = context_->first_parms_id();
  transform_to_ntt_inplace(pt, *context_);

  RLWECt ct;
  encryptor.encrypt_symmetric(pt, ct);
  evaluator.transform_from_ntt_inplace(ct);

  LWECt accum;
  LWECt lazy_accum;
  for (size_t i = 0; i < u64_coeff_.size(); ++i) {
    lazy_accum.AddLazyInplace(ct, i, *context_);

    LWECt lwe(ct, i, *context_);
    accum.AddInplace(lwe, *context_);

    Scalar dec{0};
    decryptor.Decrypt(lwe, &dec);
    EXPECT_EQ(dec, u64_coeff_[i]);

    lwe.NegateInplace(*context_);
    decryptor.Decrypt(lwe, &dec);
    EXPECT_EQ(dec, -u64_coeff_[i]);
  }

  Scalar sum{0};
  decryptor.Decrypt(accum, &sum);
  Scalar ground = std::accumulate(u64_coeff_.begin(), u64_coeff_.end(), 0UL);
  EXPECT_EQ(sum, ground);

  lazy_accum.Reduce(*context_);
  decryptor.Decrypt(lazy_accum, &sum);
  EXPECT_EQ(sum, ground);
}

TEST_F(RLWE2LWETest, ExtractU120) {
  seal::Encryptor encryptor(*context_, *rlwe_sk_);
  seal::Evaluator evaluator(*context_);

  using Scalar = uint128_t;
  ms_helper_ = std::make_shared<ModulusSwitchHelper>(*ms_context_, 120);
  LWEDecryptor decryptor(*lwe_sk_, *context_, ms_helper_);
  PolyEncoder encoder(*context_, *ms_helper_);

  RLWEPt pt;
  absl::Span<const Scalar> span(u128_coeff_.data(), u128_coeff_.size());
  encoder.Vec2Poly(span, &pt);
  pt.parms_id() = context_->first_parms_id();
  transform_to_ntt_inplace(pt, *context_);

  RLWECt ct;
  encryptor.encrypt_symmetric(pt, ct);
  evaluator.transform_from_ntt_inplace(ct);

  Scalar mask = (static_cast<Scalar>(1) << 120) - 1;

  LWECt accum;
  LWECt lazy_accum;
  for (size_t i = 0; i < u128_coeff_.size(); ++i) {
    lazy_accum.AddLazyInplace(ct, i, *context_);

    LWECt lwe(ct, i, *context_);
    accum.AddInplace(lwe, *context_);

    Scalar dec{0};
    decryptor.Decrypt(lwe, &dec);
    EXPECT_EQ(dec, u128_coeff_[i]);

    lwe.NegateInplace(*context_);
    decryptor.Decrypt(lwe, &dec);
    EXPECT_EQ(dec, (-u128_coeff_[i]) & mask);
  }

  Scalar ground = std::accumulate(u128_coeff_.begin(), u128_coeff_.end(),
                                  static_cast<Scalar>(0U));
  ground &= mask;
  Scalar sum{0};
  decryptor.Decrypt(accum, &sum);
  EXPECT_EQ(sum, ground);

  lazy_accum.Reduce(*context_);
  decryptor.Decrypt(lazy_accum, &sum);
  EXPECT_EQ(sum, ground);
}

TEST_F(RLWE2LWETest, ExtractU128) {
  seal::Encryptor encryptor(*context_, *rlwe_sk_);
  seal::Evaluator evaluator(*context_);

  using Scalar = uint128_t;
  ms_helper_ = std::make_shared<ModulusSwitchHelper>(*ms_context_, 128);
  LWEDecryptor decryptor(*lwe_sk_, *context_, ms_helper_);
  PolyEncoder encoder(*context_, *ms_helper_);

  RLWEPt pt;
  absl::Span<const Scalar> span(u128_coeff_.data(), u128_coeff_.size());
  encoder.Vec2Poly(span, &pt);
  pt.parms_id() = context_->first_parms_id();
  transform_to_ntt_inplace(pt, *context_);

  RLWECt ct;
  encryptor.encrypt_symmetric(pt, ct);
  evaluator.transform_from_ntt_inplace(ct);

  LWECt accum, sub;
  LWECt lazy_accum, lazy_sub;

  for (size_t i = 0; i < u128_coeff_.size(); ++i) {
    lazy_accum.AddLazyInplace(ct, i, *context_);
    lazy_sub.SubLazyInplace(ct, i, *context_);

    LWECt lwe(ct, i, *context_);
    accum.AddInplace(lwe, *context_);
    sub.SubInplace(lwe, *context_);

    Scalar dec{0};
    decryptor.Decrypt(lwe, &dec);
    EXPECT_EQ(dec, u128_coeff_[i]);

    lwe.NegateInplace(*context_);
    decryptor.Decrypt(lwe, &dec);
    EXPECT_EQ(dec, -u128_coeff_[i]);
  }

  Scalar sum{0};
  decryptor.Decrypt(accum, &sum);
  Scalar ground = std::accumulate(u128_coeff_.begin(), u128_coeff_.end(),
                                  static_cast<Scalar>(0U));
  EXPECT_EQ(sum, ground);

  lazy_accum.Reduce(*context_);
  decryptor.Decrypt(lazy_accum, &sum);
  EXPECT_EQ(sum, ground);

  lazy_sub.Reduce(*context_);
  sub.AddInplace(lazy_sub, *context_);
  decryptor.Decrypt(sub, &sum);
  EXPECT_EQ(sum, -(ground + ground));
}

TEST_F(RLWE2LWETest, IO) {
  yacl::Buffer lwe_sk_str;
  lwe_sk_str = EncodeSEALObject(*lwe_sk_);

  seal::Encryptor encryptor(*context_, *rlwe_sk_);
  seal::Evaluator evaluator(*context_);

  using Scalar = uint128_t;
  ms_helper_ = std::make_shared<ModulusSwitchHelper>(*ms_context_, 128);
  LWEDecryptor decryptor(*lwe_sk_, *context_, ms_helper_);
  PolyEncoder encoder(*context_, *ms_helper_);

  RLWEPt pt;
  absl::Span<const Scalar> span(u128_coeff_.data(), u128_coeff_.size());
  encoder.Vec2Poly(span, &pt);
  pt.parms_id() = context_->first_parms_id();
  transform_to_ntt_inplace(pt, *context_);

  RLWECt ct;
  encryptor.encrypt_symmetric(pt, ct);
  evaluator.transform_from_ntt_inplace(ct);

  LWECt lwe(ct, 1, *context_);

  yacl::Buffer lwe_ct_str;
  lwe_ct_str = EncodeSEALObject(lwe);

  LWECt lwe2;
  LWESecretKey sk;
  EXPECT_THROW(DecodeSEALObject(lwe_sk_str, *context_, &lwe2), std::exception);
  EXPECT_THROW(DecodeSEALObject(lwe_ct_str, *context_, &sk), std::exception);

  DecodeSEALObject(lwe_sk_str, *context_, &sk);
  DecodeSEALObject(lwe_ct_str, *context_, &lwe2);

  uint128_t out;
  LWEDecryptor decryptor2(sk, *context_, ms_helper_);
  decryptor2.Decrypt(lwe2, &out);
  EXPECT_EQ(out, u128_coeff_[1]);
}

TEST_F(RLWE2LWETest, RemoveCoeff) {
  seal::Encryptor encryptor(*context_, *rlwe_sk_);
  seal::Evaluator evaluator(*context_);

  using Scalar = uint128_t;
  ms_helper_ = std::make_shared<ModulusSwitchHelper>(*ms_context_, 128);
  LWEDecryptor decryptor(*lwe_sk_, *context_, ms_helper_);
  PolyEncoder encoder(*context_, *ms_helper_);

  RLWEPt pt;
  absl::Span<const Scalar> span(u128_coeff_.data(), u128_coeff_.size());
  encoder.Vec2Poly(span, &pt);
  pt.parms_id() = context_->first_parms_id();
  transform_to_ntt_inplace(pt, *context_);

  RLWECt ct;
  encryptor.encrypt_symmetric(pt, ct);
  evaluator.transform_from_ntt_inplace(ct);
  RLWECt copy{ct};

  std::set<size_t> to_keep;
  to_keep.insert(0);
  to_keep.insert(3);
  to_keep.insert(5);
  to_keep.insert(7);
  to_keep.insert(511);
  to_keep.insert(4095);

  KeepCoefficientsInplace(ct, to_keep);
  RemoveCoefficientsInplace(copy, to_keep);

  for (size_t idx = 0; idx < ct.poly_modulus_degree(); ++idx) {
    LWECt lwe(ct, idx, *context_);
    LWECt lwe2(copy, idx, *context_);

    Scalar out, out2;
    decryptor.Decrypt(lwe, &out);
    decryptor.Decrypt(lwe2, &out2);

    if (to_keep.find(idx) != to_keep.end()) {
      EXPECT_EQ(out, u128_coeff_[idx]);
      EXPECT_NE(out2, u128_coeff_[idx]);
    } else {
      EXPECT_NE(out, u128_coeff_[idx]);
      EXPECT_EQ(out2, u128_coeff_[idx]);
    }
  }
}

TEST_F(RLWE2LWETest, ForwardBackwardU32) {
  using Scalar = uint32_t;
  auto &vec = u32_coeff_;
  const size_t n = std::min(127UL, poly_deg);

  ModulusSwitchHelper ms_helper(*ms_context_, 32);
  PolyEncoder encoder(*context_, ms_helper);

  absl::Span<const Scalar> span(vec.data(), n);

  RLWEPt pt0, pt1;
  encoder.Forward(span, &pt0);
  encoder.Backward(span, &pt1);

  transform_to_ntt_inplace(pt0, *context_);
  transform_to_ntt_inplace(pt1, *context_);
  dyadic_product(pt0, pt1, *context_);
  transform_from_ntt_inplace(pt0, *context_);

  size_t num_modulus = pt0.coeff_count() / poly_deg;
  std::vector<uint64_t> cnst(num_modulus);
  for (size_t l = 0; l < num_modulus; ++l) {
    cnst[l] = pt0.data()[l * poly_deg];
  }

  Scalar out;
  absl::Span<const uint64_t> _wrap(cnst.data(), num_modulus);
  absl::Span<Scalar> _out(&out, 1);
  ms_helper.ModulusDownRNS(_wrap, _out);

  Scalar ground{0};
  for (size_t i = 0; i < n; ++i) {
    ground += vec[i] * vec[i];
  }
  EXPECT_EQ(ground, out);
}

TEST_F(RLWE2LWETest, ForwardBackwardU64) {
  using Scalar = uint64_t;
  auto &vec = u64_coeff_;
  const size_t n = std::min(322UL, poly_deg);

  ModulusSwitchHelper ms_helper(*ms_context_, 64);
  PolyEncoder encoder(*context_, ms_helper);

  absl::Span<const Scalar> span(vec.data(), n);

  RLWEPt pt0, pt1;
  encoder.Forward(span, &pt0);
  encoder.Backward(span, &pt1);

  transform_to_ntt_inplace(pt0, *context_);
  transform_to_ntt_inplace(pt1, *context_);
  dyadic_product(pt0, pt1, *context_);
  transform_from_ntt_inplace(pt0, *context_);

  size_t num_modulus = pt0.coeff_count() / poly_deg;
  std::vector<uint64_t> cnst(num_modulus);
  for (size_t l = 0; l < num_modulus; ++l) {
    cnst[l] = pt0.data()[l * poly_deg];
  }

  Scalar out;
  absl::Span<const uint64_t> _wrap(cnst.data(), num_modulus);
  absl::Span<Scalar> _out(&out, 1);
  ms_helper.ModulusDownRNS(_wrap, _out);

  Scalar ground{0};
  for (size_t i = 0; i < n; ++i) {
    ground += vec[i] * vec[i];
  }
  EXPECT_EQ(ground, out);
}

TEST_F(RLWE2LWETest, ForwardBackwardU128) {
  using Scalar = uint128_t;
  auto &vec = u128_coeff_;
  const size_t n = poly_deg;

  ModulusSwitchHelper ms_helper(*ms_context_, 128);
  PolyEncoder encoder(*context_, ms_helper);

  absl::Span<const Scalar> span(vec.data(), n);

  RLWEPt pt0, pt1;
  encoder.Forward(span, &pt0);
  encoder.Backward(span, &pt1);

  transform_to_ntt_inplace(pt0, *context_);
  transform_to_ntt_inplace(pt1, *context_);
  dyadic_product(pt0, pt1, *context_);
  transform_from_ntt_inplace(pt0, *context_);

  size_t num_modulus = pt0.coeff_count() / poly_deg;
  std::vector<uint64_t> cnst(num_modulus);
  for (size_t l = 0; l < num_modulus; ++l) {
    cnst[l] = pt0.data()[l * poly_deg];
  }

  Scalar out;
  absl::Span<const uint64_t> _wrap(cnst.data(), num_modulus);
  absl::Span<Scalar> _out(&out, 1);
  ms_helper.ModulusDownRNS(_wrap, _out);

  Scalar ground{0};
  for (size_t i = 0; i < n; ++i) {
    ground += vec[i] * vec[i];
  }
  EXPECT_EQ(ground, out);
}

TEST_F(RLWE2LWETest, MatVec) {
  using Scalar = uint64_t;

  ms_helper_ =
      std::make_shared<ModulusSwitchHelper>(*ms_context_, sizeof(Scalar) * 8);
  MatVecProtocol matvec_prot(*context_, *ms_helper_);
  MatVecProtocol::Meta meta;
  seal::Encryptor encryptor(*context_, *rlwe_sk_);

  meta.nrows = 8;
  meta.ncols = 1024;
  meta.transposed = false;

  std::vector<Scalar> dummy_mat(meta.nrows * meta.ncols, 1);
  std::vector<Scalar> dummy_vec(meta.ncols, 1);
  UniformRand<Scalar>(dummy_mat.data(), dummy_mat.size());
  UniformRand<Scalar>(dummy_vec.data(), dummy_vec.size());
  std::vector<Scalar> ground(meta.nrows);
  MatVecPlain<Scalar>(dummy_mat.data(), dummy_vec.data(), meta.nrows,
                      meta.ncols, ground.data());

  absl::Span<const Scalar> vec(dummy_vec.data(), dummy_vec.size());
  std::vector<RLWEPt> ecd_vec;
  matvec_prot.EncodeVector(meta, vec, &ecd_vec);

  std::vector<RLWECt> vec_cipher(ecd_vec.size());
  for (size_t i = 0; i < ecd_vec.size(); ++i) {
    ecd_vec[i].parms_id() = context_->first_parms_id();
    transform_to_ntt_inplace(ecd_vec[i], *context_);
    encryptor.encrypt_symmetric(ecd_vec[i], vec_cipher[i]);
  }

  absl::Span<const Scalar> mat(dummy_mat.data(), dummy_mat.size());

  std::vector<LWECt> matvec_prod;
  matvec_prot.MatVec(meta, mat, vec_cipher, &matvec_prod);

  LWEDecryptor decryptor(*lwe_sk_, *context_, ms_helper_);
  for (size_t r = 0; r < meta.nrows; ++r) {
    Scalar out;
    decryptor.Decrypt(matvec_prod[r], &out);
    EXPECT_EQ(out, ground[r]);
  }
}

}  // namespace heu::expt::rlwe::test
