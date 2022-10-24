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

#include "heu/experimental/gemini-rlwe/modswitch_helper.h"

#include "gtest/gtest.h"
#include "seal/seal.h"
#include "seal/util/polyarithsmallmod.h"

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

// inline static uint64_t Lo64(uint128_t u) { return static_cast<uint64_t>(u); }
//
// inline static uint64_t Hi64(uint128_t u) {
//   return static_cast<uint64_t>(u >> 64);
// }

class ModSwitchTest : public ::testing::TestWithParam<size_t> {
 protected:
  void SetUp() override {
    constexpr size_t poly_deg = 128;  // toy N
    std::vector<int> modulus_bits;

    size_t bitlen = GetParam();
    if (bitlen <= 32) {
      modulus_bits = {59, 30};  // > 64
    } else if (bitlen <= 64) {
      modulus_bits = {59, 59, 30};  // > 128
    } else if (bitlen <= 128) {     // > 256
      // Todo: There may be a problem here: why we need so big modulus here
      modulus_bits = {59, 59, 59, 59, 59, 59, 30};
    }

    auto modulus = seal::CoeffModulus::Create(poly_deg, modulus_bits);
    auto parms = seal::EncryptionParameters(seal::scheme_type::ckks);
    parms.set_poly_modulus_degree(poly_deg);
    parms.set_coeff_modulus(modulus);
    context_ = std::make_shared<seal::SEALContext>(parms, false,
                                                   seal::sec_level_type::none);

    ms_helper_ = std::make_shared<ModulusSwitchHelper>(*context_, bitlen);
    bitlen_ = bitlen;
    num_modulus_ = modulus_bits.size();
    rdv_.seed(std::time(0));
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
};

INSTANTIATE_TEST_SUITE_P(NormalCase, ModSwitchTest,
                         testing::Values(28, 32, 60, 64, 120, 128));

TEST_P(ModSwitchTest, TestAdd) {
  const size_t ntrial = 1;

  std::vector<uint32_t> x32(ntrial);
  std::vector<uint32_t> y32(ntrial);
  std::vector<uint64_t> x64(ntrial);
  std::vector<uint64_t> y64(ntrial);
  std::vector<uint128_t> x128(ntrial);
  std::vector<uint128_t> y128(ntrial);
  uint32_t mask32 = MakeMask<uint32_t>(std::min(32UL, bitlen_));
  uint64_t mask64 = MakeMask<uint64_t>(std::min(64UL, bitlen_));
  uint128_t mask128 = MakeMask<uint128_t>(std::min(128UL, bitlen_));

  std::vector<uint64_t> lifted_x(num_modulus_ * ntrial);
  std::vector<uint64_t> lifted_y(num_modulus_ * ntrial);

  if (bitlen_ <= 32) {
    auto& x = x32;
    auto& y = y32;
    UniformRand(x.data(), x.size(), bitlen_);
    UniformRand(y.data(), y.size(), bitlen_);

    for (size_t l = 0; l < num_modulus_; ++l) {
      absl::Span<const uint32_t> x_span(x.data(), x.size());
      absl::Span<uint64_t> lifted_x_span(lifted_x.data() + l * x.size(),
                                         x.size());

      absl::Span<const uint32_t> y_span(y.data(), y.size());
      absl::Span<uint64_t> lifted_y_span(lifted_y.data() + l * y.size(),
                                         y.size());

      ms_helper_->ModulusUpAt(x_span, l, lifted_x_span);
      ms_helper_->ModulusUpAt(y_span, l, lifted_y_span);
    }
  } else if (bitlen_ <= 64) {
    auto& x = x64;
    auto& y = y64;

    UniformRand(x.data(), x.size(), bitlen_);
    UniformRand(y.data(), y.size(), bitlen_);

    for (size_t l = 0; l < num_modulus_; ++l) {
      absl::Span<const uint64_t> x_span(x.data(), x.size());
      absl::Span<uint64_t> lifted_x_span(lifted_x.data() + l * x.size(),
                                         x.size());

      absl::Span<const uint64_t> y_span(y.data(), y.size());
      absl::Span<uint64_t> lifted_y_span(lifted_y.data() + l * y.size(),
                                         y.size());

      ms_helper_->ModulusUpAt(x_span, l, lifted_x_span);
      ms_helper_->ModulusUpAt(y_span, l, lifted_y_span);
    }
  } else if (bitlen_ <= 128) {
    auto& x = x128;
    auto& y = y128;

    UniformRand(x.data(), x.size(), bitlen_);
    UniformRand(y.data(), y.size(), bitlen_);

    for (size_t l = 0; l < num_modulus_; ++l) {
      absl::Span<const uint128_t> x_span(x.data(), x.size());
      absl::Span<uint64_t> lifted_x_span(lifted_x.data() + l * x.size(),
                                         x.size());

      absl::Span<const uint128_t> y_span(y.data(), y.size());
      absl::Span<uint64_t> lifted_y_span(lifted_y.data() + l * y.size(),
                                         y.size());
      ms_helper_->ModulusUpAt(x_span, l, lifted_x_span);
      ms_helper_->ModulusUpAt(y_span, l, lifted_y_span);
    }
  }

  auto& modulus = context_->key_context_data()->parms().coeff_modulus();
  std::vector<uint64_t> computed(num_modulus_ * ntrial);
  for (size_t l = 0; l < num_modulus_; ++l) {
    auto op0 = lifted_x.data() + l * ntrial;
    auto op1 = lifted_y.data() + l * ntrial;
    auto ret = computed.data() + l * ntrial;
    seal::util::add_poly_coeffmod(op0, op1, ntrial, modulus[l], ret);
  }

  std::vector<uint32_t> ans32(ntrial);
  std::vector<uint64_t> ans64(ntrial);
  std::vector<uint128_t> ans128(ntrial);
  if (bitlen_ <= 32) {
    absl::Span<const uint64_t> inp(computed.data(), computed.size());
    absl::Span<uint32_t> oup(ans32.data(), ans32.size());
    ms_helper_->ModulusDownRNS(inp, oup);

    for (size_t i = 0; i < ntrial; ++i) {
      uint32_t g = (x32[i] + y32[i]) & mask32;
      EXPECT_EQ(g, ans32[i]);
    }
  } else if (bitlen_ <= 64) {
    absl::Span<const uint64_t> inp(computed.data(), computed.size());
    absl::Span<uint64_t> oup(ans64.data(), ans64.size());
    ms_helper_->ModulusDownRNS(inp, oup);

    for (size_t i = 0; i < ntrial; ++i) {
      uint64_t g = (x64[i] + y64[i]) & mask64;
      EXPECT_EQ(g, ans64[i]);
    }
  } else if (bitlen_ <= 128) {
    absl::Span<const uint64_t> inp(computed.data(), computed.size());
    absl::Span<uint128_t> oup(ans128.data(), ans128.size());
    ms_helper_->ModulusDownRNS(inp, oup);
    for (size_t i = 0; i < ntrial; ++i) {
      uint128_t g = (x128[i] + y128[i]) & mask128;
      EXPECT_EQ(g, ans128[i]);
    }
  }
}

TEST_P(ModSwitchTest, TestMul) {
  const size_t ntrial = 1024;
  std::mt19937_64 rdv(std::time(0));

  uint32_t x32;
  uint64_t x64;
  uint128_t x128;
  std::vector<uint32_t> y32(ntrial);
  std::vector<uint64_t> y64(ntrial);
  std::vector<uint128_t> y128(ntrial);

  uint32_t mask32 = MakeMask<uint32_t>(std::min(32UL, bitlen_));
  uint64_t mask64 = MakeMask<uint64_t>(std::min(64UL, bitlen_));
  uint128_t mask128 = MakeMask<uint128_t>(std::min(128UL, bitlen_));

  std::vector<uint64_t> lifted_x(num_modulus_);
  std::vector<uint64_t> lifted_y(num_modulus_ * ntrial);

  if (bitlen_ <= 32) {
    std::uniform_int_distribution<uint32_t> uniform(0,
                                                    static_cast<uint32_t>(-1));
    auto& y = y32;
    x32 = uniform(rdv);
    std::generate_n(y.data(), y.size(), [&]() { return uniform(rdv); });

    for (size_t l = 0; l < num_modulus_; ++l) {
      absl::Span<const uint32_t> x_span(&x32, 1);
      absl::Span<uint64_t> lifted_x_span(lifted_x.data() + l, 1);

      absl::Span<const uint32_t> y_span(y.data(), y.size());
      absl::Span<uint64_t> lifted_y_span(lifted_y.data() + l * y.size(),
                                         y.size());

      ms_helper_->CenteralizeAt(x_span, l, lifted_x_span);
      ms_helper_->ModulusUpAt(y_span, l, lifted_y_span);
    }
  } else if (bitlen_ <= 64) {
    std::uniform_int_distribution<uint64_t> uniform(0,
                                                    static_cast<uint64_t>(-1));
    auto& y = y64;
    x64 = uniform(rdv);
    std::generate_n(y.data(), y.size(), [&]() { return uniform(rdv); });

    for (size_t l = 0; l < num_modulus_; ++l) {
      absl::Span<const uint64_t> x_span(&x64, 1);
      absl::Span<uint64_t> lifted_x_span(lifted_x.data() + l, 1);

      absl::Span<const uint64_t> y_span(y.data(), y.size());
      absl::Span<uint64_t> lifted_y_span(lifted_y.data() + l * y.size(),
                                         y.size());

      ms_helper_->CenteralizeAt(x_span, l, lifted_x_span);
      ms_helper_->ModulusUpAt(y_span, l, lifted_y_span);
    }
  } else if (bitlen_ <= 128) {
    std::uniform_int_distribution<uint128_t> uniform(
        0, static_cast<uint128_t>(-1));
    auto& y = y128;
    x128 = uniform(rdv);
    std::generate_n(y.data(), y.size(), [&]() { return uniform(rdv); });

    for (size_t l = 0; l < num_modulus_; ++l) {
      absl::Span<const uint128_t> x_span(&x128, 1);
      absl::Span<uint64_t> lifted_x_span(lifted_x.data() + l, 1);

      absl::Span<const uint128_t> y_span(y.data(), y.size());
      absl::Span<uint64_t> lifted_y_span(lifted_y.data() + l * y.size(),
                                         y.size());

      ms_helper_->CenteralizeAt(x_span, l, lifted_x_span);
      ms_helper_->ModulusUpAt(y_span, l, lifted_y_span);
    }
  }

  auto& modulus = context_->key_context_data()->parms().coeff_modulus();

  std::vector<uint64_t> computed(num_modulus_ * ntrial);
  for (size_t l = 0; l < num_modulus_; ++l) {
    uint64_t op0 = lifted_x.at(l);
    auto op1 = lifted_y.data() + l * ntrial;
    auto ret = computed.data() + l * ntrial;
    seal::util::multiply_poly_scalar_coeffmod(op1, ntrial, op0, modulus[l],
                                              ret);
  }

  std::vector<uint32_t> ans32(ntrial);
  std::vector<uint64_t> ans64(ntrial);
  std::vector<uint128_t> ans128(ntrial);

  if (bitlen_ <= 32) {
    absl::Span<const uint64_t> inp(computed.data(), computed.size());
    absl::Span<uint32_t> oup(ans32.data(), ans32.size());
    ms_helper_->ModulusDownRNS(inp, oup);

    for (size_t i = 0; i < ntrial; ++i) {
      uint32_t g = (x32 * y32[i]) & mask32;
      ASSERT_EQ(g, ans32[i]);
    }
  } else if (bitlen_ <= 64) {
    absl::Span<const uint64_t> inp(computed.data(), computed.size());
    absl::Span<uint64_t> oup(ans64.data(), ans64.size());
    ms_helper_->ModulusDownRNS(inp, oup);

    for (size_t i = 0; i < ntrial; ++i) {
      uint64_t g = (x64 * y64[i]) & mask64;
      ASSERT_EQ(g, ans64[i]);
    }
  } else if (bitlen_ <= 128) {
    absl::Span<const uint64_t> inp(computed.data(), computed.size());
    absl::Span<uint128_t> oup(ans128.data(), ans128.size());
    ms_helper_->ModulusDownRNS(inp, oup);

    for (size_t i = 0; i < ntrial; ++i) {
      uint128_t g = (x128 * y128[i]) & mask128;
      ASSERT_EQ(g, ans128[i]);
    }
  }
}

}  // namespace heu::expt::rlwe::test
