#include <benchmark/benchmark.h>

#include <algorithm>
#include <cstdint>
#include <memory>
#include <random>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

// Our NTT implementation
#include "math/aux_base_extender.h"
#include "math/aux_base_plan.h"
#include "math/base_converter.h"
#include "math/basis_mapper.h"
#include "math/context.h"
#include "math/modulus.h"
#include "math/ntt.h"
#include "math/ntt_harvey.h"
#include "math/poly.h"
#include "math/primes.h"
#include "math/representation.h"
#include "math/residue_transfer_engine.h"
#include "math/rns_context.h"
#include "math/scaling_factor.h"

// SEAL NTT utilities
#include "seal/memorymanager.h"
#include "seal/modulus.h"
#include "seal/util/iterator.h"
#include "seal/util/ntt.h"
#include "seal/util/polyarithsmallmod.h"
#include "seal/util/rns.h"

using ::bfv::math::ntt::HarveyNTT;
using ::bfv::math::ntt::NttOperator;
using ::bfv::math::zq::Modulus;
using OurBaseConverter = ::bfv::math::rns::BaseConverter;
using OurMulBasisContext = ::bfv::math::AuxiliaryLiftBackend;
using OurMulBasisExtender = ::bfv::math::AuxBaseExtender;
using OurBigUint = ::bfv::math::rns::BigUint;
using OurContext = ::bfv::math::rq::Context;
using OurPoly = ::bfv::math::rq::Poly;
using OurBasisMapper = ::bfv::math::rq::BasisMapper;
using OurRnsContext = ::bfv::math::rns::RnsContext;
using OurResidueTransferEngine = ::bfv::math::rns::ResidueTransferEngine;
using OurScalingFactor = ::bfv::math::rns::ScalingFactor;

namespace {

// Common modulus used across our project and supported by SEAL for NTT
// Use a 49-bit NTT-friendly prime p where v2(p-1)=14 so 2N|p-1 for N up to 8192
constexpr std::uint64_t kMod = 562949954093057ULL;

// Degrees to compare
static const std::vector<std::size_t> kDegrees = {1024, 2048, 4096, 8192};

inline int Log2(std::size_t n) {
  int p = 0;
  while ((std::size_t(1) << p) < n) ++p;
  return p;
}

void ChangeToPowerBasisLazyBench(OurPoly &poly) {
  using ::bfv::math::rq::Representation;
  if (poly.representation() == Representation::PowerBasis) {
    return;
  }
  if (poly.representation() == Representation::NttShoup) {
    poly.change_representation(Representation::Ntt);
  }
  if (poly.representation() != Representation::Ntt) {
    throw std::runtime_error("Expected Ntt representation");
  }
  const auto &ops = poly.ctx()->ops();
  for (std::size_t i = 0; i < ops.size(); ++i) {
    ops[i].BackwardInPlaceLazy(poly.data(i));
  }
  poly.override_representation(Representation::PowerBasis);
}

void ChangeThreeToPowerBasisLazyBench(OurPoly &a, OurPoly &b, OurPoly &c) {
  using ::bfv::math::rq::Representation;
  auto normalize = [](OurPoly &p) {
    if (p.representation() == Representation::NttShoup) {
      p.change_representation(Representation::Ntt);
    }
  };
  normalize(a);
  normalize(b);
  normalize(c);
  if (a.representation() == Representation::PowerBasis &&
      b.representation() == Representation::PowerBasis &&
      c.representation() == Representation::PowerBasis) {
    return;
  }
  if (a.representation() != Representation::Ntt ||
      b.representation() != Representation::Ntt ||
      c.representation() != Representation::Ntt || a.ctx() != b.ctx() ||
      a.ctx() != c.ctx()) {
    ChangeToPowerBasisLazyBench(a);
    ChangeToPowerBasisLazyBench(b);
    ChangeToPowerBasisLazyBench(c);
    return;
  }
  const auto &ops = a.ctx()->ops();
  for (std::size_t i = 0; i < ops.size(); ++i) {
    const auto *tables = ops[i].GetNTTTables();
    if (!tables) {
      ChangeToPowerBasisLazyBench(a);
      ChangeToPowerBasisLazyBench(b);
      ChangeToPowerBasisLazyBench(c);
      return;
    }
    HarveyNTT::InverseHarveyNttLazy(a.data(i), *tables);
    HarveyNTT::InverseHarveyNttLazy(b.data(i), *tables);
    HarveyNTT::InverseHarveyNttLazy(c.data(i), *tables);
  }
  a.override_representation(Representation::PowerBasis);
  b.override_representation(Representation::PowerBasis);
  c.override_representation(Representation::PowerBasis);
}

std::vector<std::uint64_t> ToUint64(const std::vector<seal::Modulus> &moduli) {
  std::vector<std::uint64_t> result;
  result.reserve(moduli.size());
  for (const auto &mod : moduli) {
    result.push_back(mod.value());
  }
  return result;
}

std::uint64_t SelectNttPrime(std::size_t degree, int bit_count) {
  auto prime = ::bfv::math::zq::generate_prime(bit_count, 2 * degree,
                                               std::uint64_t{1} << bit_count);
  if (!prime.has_value()) {
    throw std::runtime_error("Failed to generate NTT-friendly prime");
  }
  return *prime;
}

// Build our operator and SEAL tables for a degree
struct NttEnv {
  std::size_t n;
  Modulus our_mod;
  NttOperator our_ntt;
  seal::Modulus seal_mod;
  seal::util::NTTTables seal_tables;
  std::vector<std::uint64_t> input;

  static NttEnv Make(std::size_t degree) {
    // Our modulus
    auto mod_opt = Modulus::New(kMod);
    if (!mod_opt) {
      throw std::runtime_error("Failed to create our Modulus");
    }
    Modulus mod = *mod_opt;

    // Our NTT operator
    auto op_opt = NttOperator::New(mod, degree);
    if (!op_opt) {
      throw std::runtime_error("NttOperator::New returned nullopt");
    }
    NttOperator op = *op_opt;

    // SEAL modulus and tables
    seal::Modulus smod(kMod);
    int pow = Log2(degree);
    seal::util::NTTTables tables(pow, smod, seal::MemoryPoolHandle::New());

    // Random input in [0, p)
    std::mt19937_64 rng(42);
    std::vector<std::uint64_t> a(degree);
    for (auto &x : a) x = rng() % kMod;

    return NttEnv{degree,      mod, std::move(op), smod, std::move(tables),
                  std::move(a)};
  }
};

struct InverseLazy3Env {
  std::size_t n;
  NttOperator our_ntt;
  const ::bfv::math::ntt::NTTTables *our_tables;
  seal::util::NTTTables seal_tables;
  std::vector<std::uint64_t> our_ntt0;
  std::vector<std::uint64_t> our_ntt1;
  std::vector<std::uint64_t> our_ntt2;
  std::vector<std::uint64_t> seal_ntt0;
  std::vector<std::uint64_t> seal_ntt1;
  std::vector<std::uint64_t> seal_ntt2;

  static InverseLazy3Env Make(std::size_t degree) {
    auto mod_opt = Modulus::New(kMod);
    if (!mod_opt) {
      throw std::runtime_error("Failed to create our Modulus");
    }
    auto op_opt = NttOperator::New(*mod_opt, degree);
    if (!op_opt) {
      throw std::runtime_error("Failed to create our NTT operator");
    }
    auto our_ntt = std::move(*op_opt);
    const auto *our_tables = our_ntt.GetNTTTables();
    if (!our_tables) {
      throw std::runtime_error("Missing our NTT tables");
    }

    seal::Modulus smod(kMod);
    seal::util::NTTTables seal_tables(Log2(degree), smod,
                                      seal::MemoryPoolHandle::New());

    std::mt19937_64 rng(123);
    auto make_input = [&](std::uint64_t salt) {
      std::vector<std::uint64_t> data(degree);
      for (auto &x : data) {
        x = (rng() ^ salt) % kMod;
      }
      return data;
    };

    auto our0 = our_ntt.ForwardHarveyLazy(make_input(0x11));
    auto our1 = our_ntt.ForwardHarveyLazy(make_input(0x22));
    auto our2 = our_ntt.ForwardHarveyLazy(make_input(0x33));

    auto seal0 = make_input(0x11);
    auto seal1 = make_input(0x22);
    auto seal2 = make_input(0x33);
    seal::util::ntt_negacyclic_harvey_lazy(seal::util::CoeffIter(seal0.data()),
                                           seal_tables);
    seal::util::ntt_negacyclic_harvey_lazy(seal::util::CoeffIter(seal1.data()),
                                           seal_tables);
    seal::util::ntt_negacyclic_harvey_lazy(seal::util::CoeffIter(seal2.data()),
                                           seal_tables);

    return InverseLazy3Env{degree,           std::move(our_ntt),
                           our_tables,       std::move(seal_tables),
                           std::move(our0),  std::move(our1),
                           std::move(our2),  std::move(seal0),
                           std::move(seal1), std::move(seal2)};
  }
};

struct InverseLazy1Env {
  std::size_t n;
  NttOperator our_ntt_op;
  const ::bfv::math::ntt::NTTTables *our_tables;
  seal::util::NTTTables seal_tables;
  std::vector<std::uint64_t> our_ntt_data;
  std::vector<std::uint64_t> seal_ntt;

  static InverseLazy1Env Make(std::size_t degree,
                              std::uint64_t modulus_value = kMod) {
    auto mod_opt = Modulus::New(modulus_value);
    if (!mod_opt) {
      throw std::runtime_error("Failed to create our Modulus");
    }
    auto op_opt = NttOperator::New(*mod_opt, degree);
    if (!op_opt) {
      throw std::runtime_error("Failed to create our NTT operator");
    }
    auto our_ntt_op = std::move(*op_opt);
    const auto *our_tables = our_ntt_op.GetNTTTables();
    if (!our_tables) {
      throw std::runtime_error("Missing our NTT tables");
    }

    seal::Modulus smod(modulus_value);
    seal::util::NTTTables seal_tables(Log2(degree), smod,
                                      seal::MemoryPoolHandle::New());

    std::mt19937_64 rng(789);
    std::vector<std::uint64_t> input(degree);
    for (auto &x : input) {
      x = rng() % modulus_value;
    }

    auto our_data = our_ntt_op.ForwardHarveyLazy(input);
    auto seal_data = input;
    seal::util::ntt_negacyclic_harvey_lazy(
        seal::util::CoeffIter(seal_data.data()), seal_tables);

    return InverseLazy1Env{degree,
                           std::move(our_ntt_op),
                           our_tables,
                           std::move(seal_tables),
                           std::move(our_data),
                           std::move(seal_data)};
  }
};

struct BaseConvEnv {
  std::size_t count;
  std::shared_ptr<OurRnsContext> our_ibase;
  std::shared_ptr<OurRnsContext> our_obase;
  std::unique_ptr<OurBaseConverter> our_conv;
  seal::MemoryPoolHandle seal_pool;
  seal::util::RNSBase seal_ibase;
  seal::util::RNSBase seal_obase;
  std::unique_ptr<seal::util::BaseConverter> seal_conv;
  std::vector<std::vector<std::uint64_t>> in_rows;
  std::vector<std::vector<std::uint64_t>> our_out_rows;
  std::vector<const std::uint64_t *> our_in_ptrs;
  std::vector<std::uint64_t *> our_out_ptrs;
  std::vector<std::uint64_t> seal_in_flat;
  std::vector<std::uint64_t> seal_out_flat;

  static BaseConvEnv Make(const std::vector<int> &in_bits,
                          const std::vector<int> &out_bits, std::size_t count) {
    auto in_mods_seal = seal::CoeffModulus::Create(8192, in_bits);
    auto out_mods_seal = seal::CoeffModulus::Create(8192, out_bits);
    auto in_mods = ToUint64(in_mods_seal);
    auto out_mods = ToUint64(out_mods_seal);

    auto our_ibase = OurRnsContext::create(in_mods);
    auto our_obase = OurRnsContext::create(out_mods);
    auto our_conv = std::make_unique<OurBaseConverter>(our_ibase, our_obase);

    auto seal_pool = seal::MemoryPoolHandle::New();
    seal::util::RNSBase seal_ibase(in_mods_seal, seal_pool);
    seal::util::RNSBase seal_obase(out_mods_seal, seal_pool);
    auto seal_conv = std::make_unique<seal::util::BaseConverter>(
        seal_ibase, seal_obase, seal_pool);

    std::mt19937_64 rng(456);
    std::vector<std::vector<std::uint64_t>> in_rows(in_mods.size());
    std::vector<std::vector<std::uint64_t>> our_out_rows(out_mods.size());
    std::vector<const std::uint64_t *> our_in_ptrs(in_mods.size());
    std::vector<std::uint64_t *> our_out_ptrs(out_mods.size());
    std::vector<std::uint64_t> seal_in_flat(in_mods.size() * count);
    std::vector<std::uint64_t> seal_out_flat(out_mods.size() * count);

    for (std::size_t i = 0; i < in_mods.size(); ++i) {
      in_rows[i].resize(count);
      const auto mod = in_mods[i];
      for (std::size_t j = 0; j < count; ++j) {
        auto value = rng() % mod;
        in_rows[i][j] = value;
        seal_in_flat[i * count + j] = value;
      }
      our_in_ptrs[i] = in_rows[i].data();
    }
    for (std::size_t i = 0; i < out_mods.size(); ++i) {
      our_out_rows[i].resize(count);
      our_out_ptrs[i] = our_out_rows[i].data();
    }

    return BaseConvEnv{count,
                       std::move(our_ibase),
                       std::move(our_obase),
                       std::move(our_conv),
                       std::move(seal_pool),
                       std::move(seal_ibase),
                       std::move(seal_obase),
                       std::move(seal_conv),
                       std::move(in_rows),
                       std::move(our_out_rows),
                       std::move(our_in_ptrs),
                       std::move(our_out_ptrs),
                       std::move(seal_in_flat),
                       std::move(seal_out_flat)};
  }
};

std::vector<std::uint64_t> GenerateDistinctNttPrimes(
    std::size_t degree, const std::vector<int> &bit_sizes) {
  std::unordered_map<int, std::uint64_t> next_upper_bound;
  std::vector<std::uint64_t> primes;
  primes.reserve(bit_sizes.size());
  for (int bit_size : bit_sizes) {
    auto &upper_bound = next_upper_bound[bit_size];
    if (!upper_bound) {
      upper_bound = std::uint64_t{1} << bit_size;
    }
    auto prime =
        ::bfv::math::zq::generate_prime(bit_size, 2 * degree, upper_bound);
    if (!prime.has_value()) {
      throw std::runtime_error("Failed to generate tensor benchmark prime");
    }
    upper_bound = *prime;
    primes.push_back(*prime);
  }
  return primes;
}

struct TensorEnv {
  std::size_t degree;
  std::vector<Modulus> our_moduli;
  std::vector<seal::Modulus> seal_moduli;
  std::vector<std::uint64_t> input00;
  std::vector<std::uint64_t> input01;
  std::vector<std::uint64_t> input10;
  std::vector<std::uint64_t> input11;

  static TensorEnv Make(std::size_t degree) {
    const std::vector<int> bit_sizes = {60, 50, 50, 58, 61, 61, 61};
    auto moduli_values = GenerateDistinctNttPrimes(degree, bit_sizes);

    std::vector<Modulus> our_moduli;
    std::vector<seal::Modulus> seal_moduli;
    our_moduli.reserve(moduli_values.size());
    seal_moduli.reserve(moduli_values.size());
    for (auto value : moduli_values) {
      auto mod_opt = Modulus::New(value);
      if (!mod_opt.has_value()) {
        throw std::runtime_error("Failed to create tensor benchmark modulus");
      }
      our_moduli.push_back(*mod_opt);
      seal_moduli.emplace_back(value);
    }

    const std::size_t total_coeff_count = moduli_values.size() * degree;
    std::vector<std::uint64_t> input00(total_coeff_count);
    std::vector<std::uint64_t> input01(total_coeff_count);
    std::vector<std::uint64_t> input10(total_coeff_count);
    std::vector<std::uint64_t> input11(total_coeff_count);
    std::mt19937_64 rng(2468);

    for (std::size_t mod_idx = 0; mod_idx < moduli_values.size(); ++mod_idx) {
      const auto modulus = moduli_values[mod_idx];
      const std::size_t offset = mod_idx * degree;
      for (std::size_t coeff_idx = 0; coeff_idx < degree; ++coeff_idx) {
        input00[offset + coeff_idx] = rng() % modulus;
        input01[offset + coeff_idx] = rng() % modulus;
        input10[offset + coeff_idx] = rng() % modulus;
        input11[offset + coeff_idx] = rng() % modulus;
      }
    }

    return TensorEnv{degree,
                     std::move(our_moduli),
                     std::move(seal_moduli),
                     std::move(input00),
                     std::move(input01),
                     std::move(input10),
                     std::move(input11)};
  }
};

struct DownscaleEnv {
  std::size_t degree;
  std::size_t base_q_size;
  std::size_t base_bsk_size;
  std::uint64_t plain_modulus;
  std::shared_ptr<OurRnsContext> our_from;
  std::shared_ptr<OurRnsContext> our_to;
  std::unique_ptr<OurResidueTransferEngine> our_scaler;
  std::vector<std::vector<std::uint64_t>> in_rows;
  std::vector<const std::uint64_t *> in_ptrs;
  seal::MemoryPoolHandle seal_pool;
  seal::util::RNSBase seal_base_q;
  std::unique_ptr<seal::util::RNSTool> seal_rns_tool;
  std::vector<std::uint64_t> seal_in_flat;

  static DownscaleEnv Make(std::size_t degree) {
    constexpr std::uint64_t kPlainModulus = 1032193;
    auto base_q_values = GenerateDistinctNttPrimes(degree, {60, 50, 50, 58});

    std::vector<seal::Modulus> seal_base_q_moduli;
    seal_base_q_moduli.reserve(base_q_values.size());
    for (auto value : base_q_values) {
      seal_base_q_moduli.emplace_back(value);
    }

    auto seal_pool = seal::MemoryPoolHandle::New();
    seal::util::RNSBase seal_base_q(seal_base_q_moduli, seal_pool);
    auto seal_rns_tool = std::make_unique<seal::util::RNSTool>(
        degree, seal_base_q, seal::Modulus(kPlainModulus), seal_pool);

    auto seal_base_bsk = seal_rns_tool->base_Bsk();
    std::vector<std::uint64_t> all_moduli = base_q_values;
    for (std::size_t i = 0; i < seal_base_bsk->size(); ++i) {
      all_moduli.push_back((*seal_base_bsk)[i].value());
    }

    auto our_from = OurRnsContext::create(all_moduli);
    auto our_to = OurRnsContext::create(base_q_values);
    OurScalingFactor factor(::bfv::math::rns::BigUint(kPlainModulus),
                            ::bfv::math::rns::BigUint(our_to->modulus()));
    auto our_scaler =
        std::make_unique<OurResidueTransferEngine>(our_from, our_to, factor);
    if (!our_scaler->uses_aux_base_multiply_path()) {
      throw std::runtime_error(
          "Expected auxiliary-base multiply downscale path");
    }

    std::mt19937_64 rng(13579);
    std::vector<std::vector<std::uint64_t>> in_rows(all_moduli.size());
    std::vector<const std::uint64_t *> in_ptrs(all_moduli.size());
    std::vector<std::uint64_t> seal_in_flat(all_moduli.size() * degree);
    for (std::size_t mod_idx = 0; mod_idx < all_moduli.size(); ++mod_idx) {
      in_rows[mod_idx].resize(degree);
      const auto modulus = all_moduli[mod_idx];
      for (std::size_t coeff_idx = 0; coeff_idx < degree; ++coeff_idx) {
        auto value = rng() % modulus;
        in_rows[mod_idx][coeff_idx] = value;
        seal_in_flat[mod_idx * degree + coeff_idx] = value;
      }
      in_ptrs[mod_idx] = in_rows[mod_idx].data();
    }

    return DownscaleEnv{degree,
                        base_q_values.size(),
                        seal_base_bsk->size(),
                        kPlainModulus,
                        std::move(our_from),
                        std::move(our_to),
                        std::move(our_scaler),
                        std::move(in_rows),
                        std::move(in_ptrs),
                        std::move(seal_pool),
                        std::move(seal_base_q),
                        std::move(seal_rns_tool),
                        std::move(seal_in_flat)};
  }
};

struct DecryptDotEnv {
  std::size_t degree;
  std::vector<std::uint64_t> moduli_values;
  std::shared_ptr<OurContext> our_ctx;
  std::vector<std::uint64_t> our_c0_flat;
  std::vector<std::uint64_t> our_c1_flat;
  std::vector<std::uint64_t> our_sk_ntt_flat;
  std::vector<seal::Modulus> seal_moduli;
  std::vector<seal::util::NTTTables> seal_tables;
  std::vector<std::uint64_t> seal_c0_flat;
  std::vector<std::uint64_t> seal_c1_flat;
  std::vector<std::uint64_t> seal_sk_ntt_flat;

  static DecryptDotEnv Make(std::size_t degree) {
    auto moduli_values = GenerateDistinctNttPrimes(degree, {60, 50, 50, 58});
    auto our_ctx = OurContext::create(moduli_values, degree);

    std::vector<seal::Modulus> seal_moduli;
    std::vector<seal::util::NTTTables> seal_tables;
    seal_moduli.reserve(moduli_values.size());
    seal_tables.reserve(moduli_values.size());
    auto seal_pool = seal::MemoryPoolHandle::New();
    for (auto value : moduli_values) {
      seal_moduli.emplace_back(value);
      seal_tables.emplace_back(Log2(degree), seal_moduli.back(), seal_pool);
    }

    const std::size_t total_coeff_count = moduli_values.size() * degree;
    std::vector<std::uint64_t> c0_flat(total_coeff_count);
    std::vector<std::uint64_t> c1_flat(total_coeff_count);
    std::vector<std::uint64_t> sk_power(total_coeff_count);
    std::mt19937_64 rng(424242);

    for (std::size_t mod_idx = 0; mod_idx < moduli_values.size(); ++mod_idx) {
      const auto modulus = moduli_values[mod_idx];
      const std::size_t offset = mod_idx * degree;
      std::vector<std::uint64_t> sk_coeffs(degree);
      for (std::size_t coeff_idx = 0; coeff_idx < degree; ++coeff_idx) {
        c0_flat[offset + coeff_idx] = rng() % modulus;
        c1_flat[offset + coeff_idx] = rng() % modulus;
        sk_coeffs[coeff_idx] = rng() % modulus;
      }

      auto our_ntt = sk_coeffs;
      HarveyNTT::HarveyNttLazy(our_ntt.data(),
                               *our_ctx->ops()[mod_idx].GetNTTTables());
      std::copy_n(our_ntt.data(), degree, sk_power.data() + offset);
    }

    auto seal_sk_ntt_flat = sk_power;
    for (std::size_t mod_idx = 0; mod_idx < moduli_values.size(); ++mod_idx) {
      auto *seal_ptr = seal_sk_ntt_flat.data() + mod_idx * degree;
      auto *our_ptr = sk_power.data() + mod_idx * degree;
      std::copy_n(our_ptr, degree, seal_ptr);
    }

    return DecryptDotEnv{degree,
                         std::move(moduli_values),
                         std::move(our_ctx),
                         c0_flat,
                         c1_flat,
                         sk_power,
                         std::move(seal_moduli),
                         std::move(seal_tables),
                         c0_flat,
                         c1_flat,
                         std::move(seal_sk_ntt_flat)};
  }
};

struct DecryptScaleEnv {
  std::size_t degree;
  std::uint64_t plain_modulus;
  std::shared_ptr<OurContext> our_from_ctx;
  std::shared_ptr<OurContext> our_to_ctx;
  std::unique_ptr<OurBasisMapper> our_scaler;
  OurPoly our_phase;
  seal::MemoryPoolHandle seal_pool;
  seal::util::RNSBase seal_base_q;
  std::unique_ptr<seal::util::RNSTool> seal_rns_tool;
  std::vector<std::uint64_t> seal_phase_flat;

  static DecryptScaleEnv Make(std::size_t degree) {
    constexpr std::uint64_t kPlainModulus = 1032193;
    auto base_q_values = GenerateDistinctNttPrimes(degree, {60, 50, 50, 58});
    auto our_from_ctx = OurContext::create(base_q_values, degree);
    auto our_to_ctx = OurContext::create({kPlainModulus}, degree);
    OurScalingFactor factor(
        ::bfv::math::rns::BigUint(kPlainModulus),
        ::bfv::math::rns::BigUint(our_from_ctx->rns()->modulus()));
    auto our_scaler = OurBasisMapper::create(our_from_ctx, our_to_ctx, factor);

    std::vector<std::vector<std::uint64_t>> phase_coeffs(base_q_values.size());
    std::vector<std::uint64_t> seal_phase_flat(base_q_values.size() * degree);
    std::mt19937_64 rng(171717);
    for (std::size_t mod_idx = 0; mod_idx < base_q_values.size(); ++mod_idx) {
      const auto modulus = base_q_values[mod_idx];
      phase_coeffs[mod_idx].resize(degree);
      for (std::size_t coeff_idx = 0; coeff_idx < degree; ++coeff_idx) {
        auto value = rng() % modulus;
        phase_coeffs[mod_idx][coeff_idx] = value;
        seal_phase_flat[mod_idx * degree + coeff_idx] = value;
      }
    }

    auto our_phase =
        OurPoly::from_coefficients(phase_coeffs, our_from_ctx, false,
                                   ::bfv::math::rq::Representation::PowerBasis);

    std::vector<seal::Modulus> seal_base_q_moduli;
    seal_base_q_moduli.reserve(base_q_values.size());
    for (auto value : base_q_values) {
      seal_base_q_moduli.emplace_back(value);
    }
    auto seal_pool = seal::MemoryPoolHandle::New();
    seal::util::RNSBase seal_base_q(seal_base_q_moduli, seal_pool);
    auto seal_rns_tool = std::make_unique<seal::util::RNSTool>(
        degree, seal_base_q, seal::Modulus(kPlainModulus), seal_pool);

    return DecryptScaleEnv{degree,
                           kPlainModulus,
                           std::move(our_from_ctx),
                           std::move(our_to_ctx),
                           std::move(our_scaler),
                           std::move(our_phase),
                           std::move(seal_pool),
                           std::move(seal_base_q),
                           std::move(seal_rns_tool),
                           std::move(seal_phase_flat)};
  }
};

OurMulBasisContext BuildMulBasisContext(
    const std::shared_ptr<const OurContext> &base_ctx,
    const std::shared_ptr<const OurContext> &mul_ctx) {
  return ::bfv::math::BuildAuxiliaryLiftBackend(base_ctx, mul_ctx);
}

struct LiftEnv {
  std::size_t degree;
  std::size_t base_q_size;
  std::size_t base_bsk_size;
  std::shared_ptr<const OurContext> base_ctx;
  std::shared_ptr<const OurContext> mul_ctx;
  OurMulBasisContext our_mul_basis_ctx;
  OurPoly our_input;
  seal::MemoryPoolHandle seal_pool;
  std::unique_ptr<seal::util::RNSTool> seal_rns_tool;
  seal::util::RNSBase seal_base_q;
  std::vector<seal::util::NTTTables> seal_base_q_ntt_tables;
  std::vector<seal::util::NTTTables> seal_base_bsk_ntt_tables;
  std::vector<std::uint64_t> seal_in_flat;

  static LiftEnv Make(std::size_t degree) {
    auto base_q_values = GenerateDistinctNttPrimes(degree, {60, 50, 50, 58});
    std::vector<seal::Modulus> seal_base_q_moduli;
    seal_base_q_moduli.reserve(base_q_values.size());
    for (auto value : base_q_values) {
      seal_base_q_moduli.emplace_back(value);
    }

    auto seal_pool = seal::MemoryPoolHandle::New();
    seal::util::RNSBase seal_base_q(seal_base_q_moduli, seal_pool);
    auto seal_rns_tool = std::make_unique<seal::util::RNSTool>(
        degree, seal_base_q, seal::Modulus(1032193), seal_pool);

    std::vector<std::uint64_t> mul_moduli = base_q_values;
    auto seal_base_bsk = seal_rns_tool->base_Bsk();
    for (std::size_t i = 0; i < seal_base_bsk->size(); ++i) {
      mul_moduli.push_back((*seal_base_bsk)[i].value());
    }

    auto base_ctx = OurContext::create(base_q_values, degree);
    auto mul_ctx = OurContext::create(mul_moduli, degree);
    auto our_mul_basis_ctx = BuildMulBasisContext(base_ctx, mul_ctx);

    std::mt19937_64 rng(424242);
    std::vector<std::vector<std::uint64_t>> coeffs(base_q_values.size());
    std::vector<std::uint64_t> seal_in_flat(base_q_values.size() * degree);
    for (std::size_t mod_idx = 0; mod_idx < base_q_values.size(); ++mod_idx) {
      coeffs[mod_idx].resize(degree);
      const auto modulus = base_q_values[mod_idx];
      for (std::size_t coeff_idx = 0; coeff_idx < degree; ++coeff_idx) {
        auto value = rng() % modulus;
        coeffs[mod_idx][coeff_idx] = value;
        seal_in_flat[mod_idx * degree + coeff_idx] = value;
      }
    }
    auto our_input = OurPoly::from_coefficients(
        coeffs, base_ctx, false, ::bfv::math::rq::Representation::PowerBasis);

    std::vector<seal::util::NTTTables> seal_base_q_ntt_tables;
    seal_base_q_ntt_tables.reserve(base_q_values.size());
    for (const auto &mod : seal_base_q_moduli) {
      seal_base_q_ntt_tables.emplace_back(Log2(degree), mod, seal_pool);
    }
    std::vector<seal::util::NTTTables> seal_base_bsk_ntt_tables;
    seal_base_bsk_ntt_tables.reserve(seal_base_bsk->size());
    for (std::size_t i = 0; i < seal_base_bsk->size(); ++i) {
      seal_base_bsk_ntt_tables.emplace_back(Log2(degree), (*seal_base_bsk)[i],
                                            seal_pool);
    }

    return LiftEnv{degree,
                   base_q_values.size(),
                   seal_base_bsk->size(),
                   std::move(base_ctx),
                   std::move(mul_ctx),
                   std::move(our_mul_basis_ctx),
                   std::move(our_input),
                   std::move(seal_pool),
                   std::move(seal_rns_tool),
                   std::move(seal_base_q),
                   std::move(seal_base_q_ntt_tables),
                   std::move(seal_base_bsk_ntt_tables),
                   std::move(seal_in_flat)};
  }
};

struct ToPowerEnv {
  std::size_t degree;
  std::size_t base_q_size;
  std::size_t base_bsk_size;
  std::shared_ptr<const OurContext> mul_ctx;
  std::vector<OurPoly> our_polys;
  std::vector<seal::util::NTTTables> seal_base_q_ntt_tables;
  std::vector<seal::util::NTTTables> seal_base_bsk_ntt_tables;
  std::vector<std::uint64_t> seal_q_flat;
  std::vector<std::uint64_t> seal_bsk_flat;

  static ToPowerEnv Make(std::size_t degree) {
    auto base_q_values = GenerateDistinctNttPrimes(degree, {60, 50, 50, 58});
    std::vector<seal::Modulus> seal_base_q_moduli;
    seal_base_q_moduli.reserve(base_q_values.size());
    for (auto value : base_q_values) {
      seal_base_q_moduli.emplace_back(value);
    }
    auto seal_pool = seal::MemoryPoolHandle::New();
    seal::util::RNSBase seal_base_q(seal_base_q_moduli, seal_pool);
    auto seal_rns_tool = std::make_unique<seal::util::RNSTool>(
        degree, seal_base_q, seal::Modulus(1032193), seal_pool);
    auto seal_base_bsk = seal_rns_tool->base_Bsk();

    std::vector<std::uint64_t> mul_moduli = base_q_values;
    for (std::size_t i = 0; i < seal_base_bsk->size(); ++i) {
      mul_moduli.push_back((*seal_base_bsk)[i].value());
    }
    auto mul_ctx = OurContext::create(mul_moduli, degree);

    std::mt19937_64 rng(86420);
    std::vector<OurPoly> our_polys;
    our_polys.reserve(3);
    for (int poly_idx = 0; poly_idx < 3; ++poly_idx) {
      std::vector<std::vector<std::uint64_t>> coeffs(mul_moduli.size());
      for (std::size_t mod_idx = 0; mod_idx < mul_moduli.size(); ++mod_idx) {
        coeffs[mod_idx].resize(degree);
        const auto modulus = mul_moduli[mod_idx];
        for (std::size_t coeff_idx = 0; coeff_idx < degree; ++coeff_idx) {
          coeffs[mod_idx][coeff_idx] = rng() % modulus;
        }
      }
      auto poly = OurPoly::from_coefficients(
          coeffs, mul_ctx, false, ::bfv::math::rq::Representation::Ntt);
      our_polys.emplace_back(std::move(poly));
    }

    std::vector<seal::util::NTTTables> seal_base_q_ntt_tables;
    seal_base_q_ntt_tables.reserve(base_q_values.size());
    for (const auto &mod : seal_base_q_moduli) {
      seal_base_q_ntt_tables.emplace_back(Log2(degree), mod, seal_pool);
    }
    std::vector<seal::util::NTTTables> seal_base_bsk_ntt_tables;
    seal_base_bsk_ntt_tables.reserve(seal_base_bsk->size());
    for (std::size_t i = 0; i < seal_base_bsk->size(); ++i) {
      seal_base_bsk_ntt_tables.emplace_back(Log2(degree), (*seal_base_bsk)[i],
                                            seal_pool);
    }

    std::vector<std::uint64_t> seal_q_flat(3 * base_q_values.size() * degree);
    std::vector<std::uint64_t> seal_bsk_flat(3 * seal_base_bsk->size() *
                                             degree);
    for (int poly_idx = 0; poly_idx < 3; ++poly_idx) {
      for (std::size_t mod_idx = 0; mod_idx < base_q_values.size(); ++mod_idx) {
        std::copy_n(our_polys[poly_idx].data(mod_idx), degree,
                    seal_q_flat.data() +
                        (poly_idx * base_q_values.size() + mod_idx) * degree);
      }
      for (std::size_t mod_idx = 0; mod_idx < seal_base_bsk->size();
           ++mod_idx) {
        std::copy_n(our_polys[poly_idx].data(base_q_values.size() + mod_idx),
                    degree,
                    seal_bsk_flat.data() +
                        (poly_idx * seal_base_bsk->size() + mod_idx) * degree);
      }
    }

    return ToPowerEnv{degree,
                      base_q_values.size(),
                      seal_base_bsk->size(),
                      std::move(mul_ctx),
                      std::move(our_polys),
                      std::move(seal_base_q_ntt_tables),
                      std::move(seal_base_bsk_ntt_tables),
                      std::move(seal_q_flat),
                      std::move(seal_bsk_flat)};
  }
};

struct MulCoreEnv {
  std::size_t degree;
  std::size_t base_q_size;
  std::size_t base_bsk_size;
  std::uint64_t plain_modulus;
  std::shared_ptr<const OurContext> base_ctx;
  std::shared_ptr<const OurContext> mul_ctx;
  OurMulBasisContext our_mul_basis_ctx;
  std::unique_ptr<OurBasisMapper> our_down_scaler;
  std::vector<OurPoly> our_inputs;
  seal::MemoryPoolHandle seal_pool;
  std::unique_ptr<seal::util::RNSTool> seal_rns_tool;
  seal::util::RNSBase seal_base_q;
  std::vector<seal::util::NTTTables> seal_base_q_ntt_tables;
  std::vector<seal::util::NTTTables> seal_base_bsk_ntt_tables;
  std::vector<seal::Modulus> seal_base_q_moduli;
  std::vector<std::uint64_t> seal_inputs_flat;

  static MulCoreEnv Make(std::size_t degree) {
    constexpr std::uint64_t kPlainModulus = 1032193;
    auto base_q_values = GenerateDistinctNttPrimes(degree, {60, 50, 50, 58});
    std::vector<seal::Modulus> seal_base_q_moduli;
    seal_base_q_moduli.reserve(base_q_values.size());
    for (auto value : base_q_values) {
      seal_base_q_moduli.emplace_back(value);
    }

    auto seal_pool = seal::MemoryPoolHandle::New();
    seal::util::RNSBase seal_base_q(seal_base_q_moduli, seal_pool);
    auto seal_rns_tool = std::make_unique<seal::util::RNSTool>(
        degree, seal_base_q, seal::Modulus(kPlainModulus), seal_pool);
    auto seal_base_bsk = seal_rns_tool->base_Bsk();

    std::vector<std::uint64_t> mul_moduli = base_q_values;
    for (std::size_t i = 0; i < seal_base_bsk->size(); ++i) {
      mul_moduli.push_back((*seal_base_bsk)[i].value());
    }

    auto base_ctx = OurContext::create(base_q_values, degree);
    auto mul_ctx = OurContext::create(mul_moduli, degree);
    auto our_mul_basis_ctx = BuildMulBasisContext(base_ctx, mul_ctx);
    OurScalingFactor factor(
        ::bfv::math::rns::BigUint(kPlainModulus),
        ::bfv::math::rns::BigUint(base_ctx->rns()->modulus()));
    auto our_down_scaler = OurBasisMapper::create(mul_ctx, base_ctx, factor);

    std::mt19937_64 rng(97531);
    std::vector<OurPoly> our_inputs;
    our_inputs.reserve(4);
    std::vector<std::uint64_t> seal_inputs_flat(4 * base_q_values.size() *
                                                degree);
    for (int poly_idx = 0; poly_idx < 4; ++poly_idx) {
      std::vector<std::vector<std::uint64_t>> coeffs(base_q_values.size());
      for (std::size_t mod_idx = 0; mod_idx < base_q_values.size(); ++mod_idx) {
        coeffs[mod_idx].resize(degree);
        const auto modulus = base_q_values[mod_idx];
        for (std::size_t coeff_idx = 0; coeff_idx < degree; ++coeff_idx) {
          auto value = rng() % modulus;
          coeffs[mod_idx][coeff_idx] = value;
          seal_inputs_flat[(poly_idx * base_q_values.size() + mod_idx) *
                               degree +
                           coeff_idx] = value;
        }
      }
      our_inputs.push_back(OurPoly::from_coefficients(
          coeffs, base_ctx, false,
          ::bfv::math::rq::Representation::PowerBasis));
    }

    std::vector<seal::util::NTTTables> seal_base_q_ntt_tables;
    seal_base_q_ntt_tables.reserve(base_q_values.size());
    for (const auto &mod : seal_base_q_moduli) {
      seal_base_q_ntt_tables.emplace_back(Log2(degree), mod, seal_pool);
    }
    std::vector<seal::util::NTTTables> seal_base_bsk_ntt_tables;
    seal_base_bsk_ntt_tables.reserve(seal_base_bsk->size());
    for (std::size_t i = 0; i < seal_base_bsk->size(); ++i) {
      seal_base_bsk_ntt_tables.emplace_back(Log2(degree), (*seal_base_bsk)[i],
                                            seal_pool);
    }

    return MulCoreEnv{degree,
                      base_q_values.size(),
                      seal_base_bsk->size(),
                      kPlainModulus,
                      std::move(base_ctx),
                      std::move(mul_ctx),
                      std::move(our_mul_basis_ctx),
                      std::move(our_down_scaler),
                      std::move(our_inputs),
                      std::move(seal_pool),
                      std::move(seal_rns_tool),
                      std::move(seal_base_q),
                      std::move(seal_base_q_ntt_tables),
                      std::move(seal_base_bsk_ntt_tables),
                      std::move(seal_base_q_moduli),
                      std::move(seal_inputs_flat)};
  }
};

// Register all benchmarks for one degree
void RegisterForDegree(std::size_t degree) {
  auto env = std::make_shared<NttEnv>(NttEnv::Make(degree));
  auto inv1_env =
      std::make_shared<InverseLazy1Env>(InverseLazy1Env::Make(degree));
  auto inv3_env =
      std::make_shared<InverseLazy3Env>(InverseLazy3Env::Make(degree));
  const std::string suffix = std::to_string(degree);

  // Our forward (Harvey optimized)
  benchmark::RegisterBenchmark(("cmp/ntt/forward/ours/" + suffix).c_str(),
                               [env](benchmark::State &st) {
                                 for (auto _ : st) {
                                   auto buf = env->input;
                                   auto out = env->our_ntt.ForwardHarvey(buf);
                                   benchmark::DoNotOptimize(out);
                                 }
                               })
      ->Iterations(50);

  // SEAL forward (Harvey)
  benchmark::RegisterBenchmark(("cmp/ntt/forward/seal/" + suffix).c_str(),
                               [env](benchmark::State &st) {
                                 for (auto _ : st) {
                                   auto buf = env->input;  // copy
                                   seal::util::ntt_negacyclic_harvey(
                                       seal::util::CoeffIter(buf.data()),
                                       env->seal_tables);
                                   benchmark::DoNotOptimize(buf);
                                 }
                               })
      ->Iterations(50);

  // Our backward (Harvey optimized)
  benchmark::RegisterBenchmark(("cmp/ntt/backward/ours/" + suffix).c_str(),
                               [env](benchmark::State &st) {
                                 for (auto _ : st) {
                                   // Start from NTT domain to measure pure
                                   // backward
                                   auto fwd =
                                       env->our_ntt.ForwardHarvey(env->input);
                                   auto inv = env->our_ntt.BackwardHarvey(fwd);
                                   benchmark::DoNotOptimize(inv);
                                 }
                               })
      ->Iterations(50);

  // SEAL backward (Harvey)
  benchmark::RegisterBenchmark(
      ("cmp/ntt/backward/seal/" + suffix).c_str(),
      [env](benchmark::State &st) {
        for (auto _ : st) {
          auto buf = env->input;
          // Forward then inverse to emulate same flow
          seal::util::ntt_negacyclic_harvey(seal::util::CoeffIter(buf.data()),
                                            env->seal_tables);
          seal::util::inverse_ntt_negacyclic_harvey(
              seal::util::CoeffIter(buf.data()), env->seal_tables);
          benchmark::DoNotOptimize(buf);
        }
      })
      ->Iterations(50);

  benchmark::RegisterBenchmark(("cmp/ntt/inv_lazy3/ours/" + suffix).c_str(),
                               [inv3_env](benchmark::State &st) {
                                 for (auto _ : st) {
                                   auto a = inv3_env->our_ntt0;
                                   auto b = inv3_env->our_ntt1;
                                   auto c = inv3_env->our_ntt2;
                                   HarveyNTT::InverseHarveyNttLazy3(
                                       a.data(), b.data(), c.data(),
                                       *inv3_env->our_tables);
                                   benchmark::DoNotOptimize(a);
                                   benchmark::DoNotOptimize(b);
                                   benchmark::DoNotOptimize(c);
                                 }
                               })
      ->Iterations(50);

  benchmark::RegisterBenchmark(("cmp/ntt/inv_lazy1/ours/" + suffix).c_str(),
                               [inv1_env](benchmark::State &st) {
                                 for (auto _ : st) {
                                   auto a = inv1_env->our_ntt_data;
                                   HarveyNTT::InverseHarveyNttLazy(
                                       a.data(), *inv1_env->our_tables);
                                   benchmark::DoNotOptimize(a);
                                 }
                               })
      ->Iterations(50);

  benchmark::RegisterBenchmark(
      ("cmp/ntt/inv_lazy1/seal/" + suffix).c_str(),
      [inv1_env](benchmark::State &st) {
        for (auto _ : st) {
          auto a = inv1_env->seal_ntt;
          seal::util::inverse_ntt_negacyclic_harvey_lazy(
              seal::util::CoeffIter(a.data()), inv1_env->seal_tables);
          benchmark::DoNotOptimize(a);
        }
      })
      ->Iterations(50);

  if (degree == 8192) {
    auto inv1_env_61 = std::make_shared<InverseLazy1Env>(
        InverseLazy1Env::Make(degree, SelectNttPrime(degree, 61)));

    benchmark::RegisterBenchmark("cmp/ntt/inv_lazy1/ours_61bit/8192",
                                 [inv1_env_61](benchmark::State &st) {
                                   for (auto _ : st) {
                                     auto a = inv1_env_61->our_ntt_data;
                                     HarveyNTT::InverseHarveyNttLazy(
                                         a.data(), *inv1_env_61->our_tables);
                                     benchmark::DoNotOptimize(a);
                                   }
                                 })
        ->Iterations(50);

    benchmark::RegisterBenchmark(
        "cmp/ntt/inv_lazy1/seal_61bit/8192",
        [inv1_env_61](benchmark::State &st) {
          for (auto _ : st) {
            auto a = inv1_env_61->seal_ntt;
            seal::util::inverse_ntt_negacyclic_harvey_lazy(
                seal::util::CoeffIter(a.data()), inv1_env_61->seal_tables);
            benchmark::DoNotOptimize(a);
          }
        })
        ->Iterations(50);
  }

  benchmark::RegisterBenchmark(
      ("cmp/ntt/inv_lazy3/seal/" + suffix).c_str(),
      [inv3_env](benchmark::State &st) {
        for (auto _ : st) {
          auto a = inv3_env->seal_ntt0;
          auto b = inv3_env->seal_ntt1;
          auto c = inv3_env->seal_ntt2;
          seal::util::inverse_ntt_negacyclic_harvey_lazy(
              seal::util::CoeffIter(a.data()), inv3_env->seal_tables);
          seal::util::inverse_ntt_negacyclic_harvey_lazy(
              seal::util::CoeffIter(b.data()), inv3_env->seal_tables);
          seal::util::inverse_ntt_negacyclic_harvey_lazy(
              seal::util::CoeffIter(c.data()), inv3_env->seal_tables);
          benchmark::DoNotOptimize(a);
          benchmark::DoNotOptimize(b);
          benchmark::DoNotOptimize(c);
        }
      })
      ->Iterations(50);
}

void RegisterBaseConverterBenchmarks() {
  auto env_4_to_3 = std::make_shared<BaseConvEnv>(
      BaseConvEnv::Make({50, 50, 50, 50}, {50, 50, 50}, 8192));
  auto env_4_to_1 = std::make_shared<BaseConvEnv>(
      BaseConvEnv::Make({50, 50, 50, 50}, {50}, 8192));
  auto env_4_to_5 = std::make_shared<BaseConvEnv>(
      BaseConvEnv::Make({50, 50, 50, 50}, {50, 50, 50, 50, 50}, 8192));
  auto env_2_to_5 = std::make_shared<BaseConvEnv>(
      BaseConvEnv::Make({50, 50}, {50, 50, 50, 50, 50}, 8192));

  benchmark::RegisterBenchmark(
      "cmp/baseconv/4to3/ours/8192",
      [env_4_to_3](benchmark::State &st) {
        for (auto _ : st) {
          env_4_to_3->our_conv->fast_convert_array(
              env_4_to_3->our_in_ptrs.data(), env_4_to_3->our_out_ptrs.data(),
              env_4_to_3->count);
          benchmark::DoNotOptimize(env_4_to_3->our_out_rows[0]);
        }
      })
      ->Iterations(100);

  benchmark::RegisterBenchmark(
      "cmp/baseconv/4to3/seal/8192",
      [env_4_to_3](benchmark::State &st) {
        for (auto _ : st) {
          env_4_to_3->seal_conv->fast_convert_array(
              seal::util::ConstRNSIter(env_4_to_3->seal_in_flat.data(),
                                       env_4_to_3->count),
              seal::util::RNSIter(env_4_to_3->seal_out_flat.data(),
                                  env_4_to_3->count),
              env_4_to_3->seal_pool);
          benchmark::DoNotOptimize(env_4_to_3->seal_out_flat.data());
        }
      })
      ->Iterations(100);

  benchmark::RegisterBenchmark(
      "cmp/baseconv/4to1/ours/8192",
      [env_4_to_1](benchmark::State &st) {
        for (auto _ : st) {
          env_4_to_1->our_conv->fast_convert_array(
              env_4_to_1->our_in_ptrs.data(), env_4_to_1->our_out_ptrs.data(),
              env_4_to_1->count);
          benchmark::DoNotOptimize(env_4_to_1->our_out_rows[0]);
        }
      })
      ->Iterations(100);

  benchmark::RegisterBenchmark(
      "cmp/baseconv/4to1/seal/8192",
      [env_4_to_1](benchmark::State &st) {
        for (auto _ : st) {
          env_4_to_1->seal_conv->fast_convert_array(
              seal::util::ConstRNSIter(env_4_to_1->seal_in_flat.data(),
                                       env_4_to_1->count),
              seal::util::RNSIter(env_4_to_1->seal_out_flat.data(),
                                  env_4_to_1->count),
              env_4_to_1->seal_pool);
          benchmark::DoNotOptimize(env_4_to_1->seal_out_flat.data());
        }
      })
      ->Iterations(100);

  benchmark::RegisterBenchmark(
      "cmp/baseconv/4to5/ours/8192",
      [env_4_to_5](benchmark::State &st) {
        for (auto _ : st) {
          env_4_to_5->our_conv->fast_convert_array(
              env_4_to_5->our_in_ptrs.data(), env_4_to_5->our_out_ptrs.data(),
              env_4_to_5->count);
          benchmark::DoNotOptimize(env_4_to_5->our_out_rows[0]);
        }
      })
      ->Iterations(100);

  benchmark::RegisterBenchmark(
      "cmp/baseconv/4to5/seal/8192",
      [env_4_to_5](benchmark::State &st) {
        for (auto _ : st) {
          env_4_to_5->seal_conv->fast_convert_array(
              seal::util::ConstRNSIter(env_4_to_5->seal_in_flat.data(),
                                       env_4_to_5->count),
              seal::util::RNSIter(env_4_to_5->seal_out_flat.data(),
                                  env_4_to_5->count),
              env_4_to_5->seal_pool);
          benchmark::DoNotOptimize(env_4_to_5->seal_out_flat.data());
        }
      })
      ->Iterations(100);

  benchmark::RegisterBenchmark(
      "cmp/baseconv/2to5/ours/8192",
      [env_2_to_5](benchmark::State &st) {
        for (auto _ : st) {
          env_2_to_5->our_conv->fast_convert_array(
              env_2_to_5->our_in_ptrs.data(), env_2_to_5->our_out_ptrs.data(),
              env_2_to_5->count);
          benchmark::DoNotOptimize(env_2_to_5->our_out_rows[0]);
        }
      })
      ->Iterations(100);

  benchmark::RegisterBenchmark(
      "cmp/baseconv/2to5/seal/8192",
      [env_2_to_5](benchmark::State &st) {
        for (auto _ : st) {
          env_2_to_5->seal_conv->fast_convert_array(
              seal::util::ConstRNSIter(env_2_to_5->seal_in_flat.data(),
                                       env_2_to_5->count),
              seal::util::RNSIter(env_2_to_5->seal_out_flat.data(),
                                  env_2_to_5->count),
              env_2_to_5->seal_pool);
          benchmark::DoNotOptimize(env_2_to_5->seal_out_flat.data());
        }
      })
      ->Iterations(100);
}

void RegisterTensorBenchmarks() {
  auto env = std::make_shared<TensorEnv>(TensorEnv::Make(8192));
  constexpr std::size_t kTileSize = 256;

  benchmark::RegisterBenchmark("cmp/tensor/ours/8192", [env](benchmark::State
                                                                 &st) {
    for (auto _ : st) {
      auto p00 = env->input00;
      auto p01 = env->input01;
      std::vector<std::uint64_t> p2(env->input00.size());
      for (std::size_t mod_idx = 0; mod_idx < env->our_moduli.size();
           ++mod_idx) {
        const std::size_t offset = mod_idx * env->degree;
        env->our_moduli[mod_idx].TensorProductVec(
            p00.data() + offset, p01.data() + offset,
            env->input10.data() + offset, env->input11.data() + offset,
            p2.data() + offset, env->degree);
      }
      benchmark::DoNotOptimize(p00);
      benchmark::DoNotOptimize(p01);
      benchmark::DoNotOptimize(p2);
    }
  })->Iterations(100);

  benchmark::RegisterBenchmark("cmp/tensor/seal/8192", [env](benchmark::State
                                                                 &st) {
    std::vector<std::uint64_t> temp(kTileSize);
    for (auto _ : st) {
      auto x0 = env->input00;
      auto x1 = env->input01;
      std::vector<std::uint64_t> x2(env->input00.size());
      for (std::size_t mod_idx = 0; mod_idx < env->seal_moduli.size();
           ++mod_idx) {
        const auto &modulus = env->seal_moduli[mod_idx];
        const std::size_t base_offset = mod_idx * env->degree;
        for (std::size_t offset = 0; offset < env->degree;
             offset += kTileSize) {
          const std::size_t tile_size =
              std::min<std::size_t>(256, env->degree - offset);
          auto *x0_ptr = x0.data() + base_offset + offset;
          auto *x1_ptr = x1.data() + base_offset + offset;
          auto *x2_ptr = x2.data() + base_offset + offset;
          auto *y0_ptr = env->input10.data() + base_offset + offset;
          auto *y1_ptr = env->input11.data() + base_offset + offset;

          seal::util::dyadic_product_coeffmod(
              seal::util::CoeffIter(x1_ptr), seal::util::CoeffIter(y1_ptr),
              tile_size, modulus, seal::util::CoeffIter(x2_ptr));
          seal::util::dyadic_product_coeffmod(
              seal::util::CoeffIter(x1_ptr), seal::util::CoeffIter(y0_ptr),
              tile_size, modulus, seal::util::CoeffIter(temp.data()));
          seal::util::dyadic_product_coeffmod(
              seal::util::CoeffIter(x0_ptr), seal::util::CoeffIter(y1_ptr),
              tile_size, modulus, seal::util::CoeffIter(x1_ptr));
          seal::util::add_poly_coeffmod(
              seal::util::CoeffIter(x1_ptr), seal::util::CoeffIter(temp.data()),
              tile_size, modulus, seal::util::CoeffIter(x1_ptr));
          seal::util::dyadic_product_coeffmod(
              seal::util::CoeffIter(x0_ptr), seal::util::CoeffIter(y0_ptr),
              tile_size, modulus, seal::util::CoeffIter(x0_ptr));
        }
      }
      benchmark::DoNotOptimize(x0);
      benchmark::DoNotOptimize(x1);
      benchmark::DoNotOptimize(x2);
    }
  })->Iterations(100);
}

void RegisterDownscaleBenchmarks() {
  auto env = std::make_shared<DownscaleEnv>(DownscaleEnv::Make(8192));

  benchmark::RegisterBenchmark("cmp/step6/ours/8192", [env](benchmark::State
                                                                &st) {
    std::vector<std::uint64_t> scaled_flat(
        (env->base_q_size + env->base_bsk_size) * env->degree);
    std::vector<std::uint64_t *> scaled_ptrs(env->base_q_size +
                                             env->base_bsk_size);
    for (std::size_t i = 0; i < env->base_q_size + env->base_bsk_size; ++i) {
      scaled_ptrs[i] = scaled_flat.data() + i * env->degree;
    }
    for (auto _ : st) {
      for (std::size_t i = 0; i < env->base_q_size + env->base_bsk_size; ++i) {
        env->our_from->moduli()[i].ScalarMulTo(scaled_ptrs[i], env->in_ptrs[i],
                                               env->degree, env->plain_modulus);
      }
      benchmark::DoNotOptimize(scaled_flat);
    }
  })->Iterations(100);

  benchmark::RegisterBenchmark("cmp/step6/seal/8192", [env](benchmark::State
                                                                &st) {
    for (auto _ : st) {
      std::vector<std::uint64_t> temp_q_bsk(
          (env->base_q_size + env->base_bsk_size) * env->degree);
      seal::util::multiply_poly_scalar_coeffmod(
          seal::util::ConstRNSIter(env->seal_in_flat.data(), env->degree),
          env->base_q_size, env->plain_modulus,
          seal::util::ConstModulusIter(env->seal_base_q.base()),
          seal::util::RNSIter(temp_q_bsk.data(), env->degree));
      seal::util::multiply_poly_scalar_coeffmod(
          seal::util::ConstRNSIter(
              env->seal_in_flat.data() + env->base_q_size * env->degree,
              env->degree),
          env->base_bsk_size, env->plain_modulus,
          seal::util::ConstModulusIter(env->seal_rns_tool->base_Bsk()->base()),
          seal::util::RNSIter(
              temp_q_bsk.data() + env->base_q_size * env->degree, env->degree));
      benchmark::DoNotOptimize(temp_q_bsk);
    }
  })->Iterations(100);

  benchmark::RegisterBenchmark("cmp/downscale/ours/8192", [env](benchmark::State
                                                                    &st) {
    std::vector<std::uint64_t> out_flat(env->base_q_size * env->degree);
    std::vector<std::uint64_t *> out_ptrs(env->base_q_size);
    for (std::size_t i = 0; i < env->base_q_size; ++i) {
      out_ptrs[i] = out_flat.data() + i * env->degree;
    }
    for (auto _ : st) {
      env->our_scaler->scale_batch(env->in_ptrs, out_ptrs, env->degree, 0);
      benchmark::DoNotOptimize(out_flat);
    }
  })->Iterations(50);

  benchmark::RegisterBenchmark("cmp/downscale/seal/8192", [env](benchmark::State
                                                                    &st) {
    for (auto _ : st) {
      std::vector<std::uint64_t> temp_q_bsk(
          (env->base_q_size + env->base_bsk_size) * env->degree);
      std::vector<std::uint64_t> temp_bsk(env->base_bsk_size * env->degree);
      std::vector<std::uint64_t> out_q(env->base_q_size * env->degree);

      seal::util::multiply_poly_scalar_coeffmod(
          seal::util::ConstRNSIter(env->seal_in_flat.data(), env->degree),
          env->base_q_size, env->plain_modulus,
          seal::util::ConstModulusIter(env->seal_base_q.base()),
          seal::util::RNSIter(temp_q_bsk.data(), env->degree));
      seal::util::multiply_poly_scalar_coeffmod(
          seal::util::ConstRNSIter(
              env->seal_in_flat.data() + env->base_q_size * env->degree,
              env->degree),
          env->base_bsk_size, env->plain_modulus,
          seal::util::ConstModulusIter(env->seal_rns_tool->base_Bsk()->base()),
          seal::util::RNSIter(
              temp_q_bsk.data() + env->base_q_size * env->degree, env->degree));
      env->seal_rns_tool->fast_floor(
          seal::util::ConstRNSIter(temp_q_bsk.data(), env->degree),
          seal::util::RNSIter(temp_bsk.data(), env->degree), env->seal_pool);
      env->seal_rns_tool->fastbconv_sk(
          seal::util::ConstRNSIter(temp_bsk.data(), env->degree),
          seal::util::RNSIter(out_q.data(), env->degree), env->seal_pool);
      benchmark::DoNotOptimize(out_q);
    }
  })->Iterations(50);

  benchmark::RegisterBenchmark("cmp/downscale3/ours/8192", [env](
                                                               benchmark::State
                                                                   &st) {
    constexpr std::size_t kPolyCount = 3;
    std::vector<std::uint64_t> out_flat(kPolyCount * env->base_q_size *
                                        env->degree);
    std::vector<std::uint64_t *> out_ptrs(env->base_q_size);
    for (auto _ : st) {
      for (std::size_t poly_idx = 0; poly_idx < kPolyCount; ++poly_idx) {
        for (std::size_t i = 0; i < env->base_q_size; ++i) {
          out_ptrs[i] =
              out_flat.data() + (poly_idx * env->base_q_size + i) * env->degree;
        }
        env->our_scaler->scale_batch(env->in_ptrs, out_ptrs, env->degree, 0);
      }
      benchmark::DoNotOptimize(out_flat);
    }
  })->Iterations(30);

  benchmark::RegisterBenchmark("cmp/downscale3/seal/8192", [env](
                                                               benchmark::State
                                                                   &st) {
    constexpr std::size_t kPolyCount = 3;
    for (auto _ : st) {
      std::vector<std::uint64_t> temp_q_bsk(
          kPolyCount * (env->base_q_size + env->base_bsk_size) * env->degree);
      std::vector<std::uint64_t> temp_bsk(kPolyCount * env->base_bsk_size *
                                          env->degree);
      std::vector<std::uint64_t> out_q(kPolyCount * env->base_q_size *
                                       env->degree);

      for (std::size_t poly_idx = 0; poly_idx < kPolyCount; ++poly_idx) {
        const std::size_t q_bsk_offset =
            poly_idx * (env->base_q_size + env->base_bsk_size) * env->degree;
        const std::size_t bsk_offset =
            poly_idx * env->base_bsk_size * env->degree;
        const std::size_t out_offset =
            poly_idx * env->base_q_size * env->degree;

        seal::util::multiply_poly_scalar_coeffmod(
            seal::util::ConstRNSIter(env->seal_in_flat.data(), env->degree),
            env->base_q_size, env->plain_modulus,
            seal::util::ConstModulusIter(env->seal_base_q.base()),
            seal::util::RNSIter(temp_q_bsk.data() + q_bsk_offset, env->degree));
        seal::util::multiply_poly_scalar_coeffmod(
            seal::util::ConstRNSIter(
                env->seal_in_flat.data() + env->base_q_size * env->degree,
                env->degree),
            env->base_bsk_size, env->plain_modulus,
            seal::util::ConstModulusIter(
                env->seal_rns_tool->base_Bsk()->base()),
            seal::util::RNSIter(temp_q_bsk.data() + q_bsk_offset +
                                    env->base_q_size * env->degree,
                                env->degree));
        env->seal_rns_tool->fast_floor(
            seal::util::ConstRNSIter(temp_q_bsk.data() + q_bsk_offset,
                                     env->degree),
            seal::util::RNSIter(temp_bsk.data() + bsk_offset, env->degree),
            env->seal_pool);
        env->seal_rns_tool->fastbconv_sk(
            seal::util::ConstRNSIter(temp_bsk.data() + bsk_offset, env->degree),
            seal::util::RNSIter(out_q.data() + out_offset, env->degree),
            env->seal_pool);
      }
      benchmark::DoNotOptimize(out_q);
    }
  })->Iterations(30);
}

void RegisterDecryptDotBenchmarks() {
  auto env = std::make_shared<DecryptDotEnv>(DecryptDotEnv::Make(8192));

  benchmark::RegisterBenchmark("cmp/decrypt_dot/ours/8192", [env](
                                                                benchmark::State
                                                                    &st) {
    std::vector<std::uint64_t> phase_flat(env->our_c0_flat.size());
    std::vector<std::uint64_t> scratch(env->degree);
    for (auto _ : st) {
      std::copy(env->our_c0_flat.begin(), env->our_c0_flat.end(),
                phase_flat.begin());
      for (std::size_t mod_idx = 0; mod_idx < env->moduli_values.size();
           ++mod_idx) {
        const std::size_t offset = mod_idx * env->degree;
        std::copy_n(env->our_c1_flat.data() + offset, env->degree,
                    scratch.data());
        const auto *tables = env->our_ctx->ops()[mod_idx].GetNTTTables();
        HarveyNTT::HarveyNttLazy(scratch.data(), *tables);
        env->our_ctx->q()[mod_idx].MulVec(
            scratch.data(), env->our_sk_ntt_flat.data() + offset, env->degree);
        HarveyNTT::InverseHarveyNtt(scratch.data(), *tables);
        env->our_ctx->q()[mod_idx].AddVec(phase_flat.data() + offset,
                                          scratch.data(), env->degree);
      }
      benchmark::DoNotOptimize(phase_flat);
    }
  })->Iterations(100);

  benchmark::RegisterBenchmark("cmp/decrypt_dot/seal/8192", [env](
                                                                benchmark::State
                                                                    &st) {
    std::vector<std::uint64_t> phase_flat(env->seal_c0_flat.size());
    for (auto _ : st) {
      for (std::size_t mod_idx = 0; mod_idx < env->seal_moduli.size();
           ++mod_idx) {
        const std::size_t offset = mod_idx * env->degree;
        auto *phase_ptr = phase_flat.data() + offset;
        std::copy_n(env->seal_c1_flat.data() + offset, env->degree, phase_ptr);
        seal::util::ntt_negacyclic_harvey_lazy(seal::util::CoeffIter(phase_ptr),
                                               env->seal_tables[mod_idx]);
        seal::util::dyadic_product_coeffmod(
            seal::util::CoeffIter(phase_ptr),
            seal::util::CoeffIter(env->seal_sk_ntt_flat.data() + offset),
            env->degree, env->seal_moduli[mod_idx],
            seal::util::CoeffIter(phase_ptr));
        seal::util::inverse_ntt_negacyclic_harvey(
            seal::util::CoeffIter(phase_ptr), env->seal_tables[mod_idx]);
        seal::util::add_poly_coeffmod(
            seal::util::CoeffIter(phase_ptr),
            seal::util::CoeffIter(env->seal_c0_flat.data() + offset),
            env->degree, env->seal_moduli[mod_idx],
            seal::util::CoeffIter(phase_ptr));
      }
      benchmark::DoNotOptimize(phase_flat);
    }
  })->Iterations(100);
}

void RegisterDecryptScaleBenchmarks() {
  auto env = std::make_shared<DecryptScaleEnv>(DecryptScaleEnv::Make(8192));

  benchmark::RegisterBenchmark("cmp/decrypt_scale/ours/8192",
                               [env](benchmark::State &st) {
                                 std::vector<std::uint64_t> out(env->degree);
                                 for (auto _ : st) {
                                   env->our_scaler->write_power_basis_u64(
                                       env->our_phase, out.data());
                                   benchmark::DoNotOptimize(out);
                                 }
                               })
      ->Iterations(100);

  benchmark::RegisterBenchmark(
      "cmp/decrypt_scale/seal/8192",
      [env](benchmark::State &st) {
        std::vector<std::uint64_t> out(env->degree);
        for (auto _ : st) {
          env->seal_rns_tool->decrypt_scale_and_round(
              seal::util::ConstRNSIter(env->seal_phase_flat.data(),
                                       env->degree),
              out.data(), env->seal_pool);
          benchmark::DoNotOptimize(out);
        }
      })
      ->Iterations(100);
}

void RegisterLiftBenchmarks() {
  auto env = std::make_shared<LiftEnv>(LiftEnv::Make(8192));
  auto our_input4_ptrs = std::make_shared<std::vector<const OurPoly *>>();
  our_input4_ptrs->reserve(4);
  for (int i = 0; i < 4; ++i) {
    our_input4_ptrs->push_back(&env->our_input);
  }

  benchmark::RegisterBenchmark("cmp/lift/ours/8192", [env](
                                                         benchmark::State &st) {
    for (auto _ : st) {
      std::vector<const OurPoly *> polys = {&env->our_input};
      std::vector<OurPoly> out;
      OurMulBasisExtender::ExtendToNtt(polys, env->base_ctx, env->mul_ctx,
                                       env->our_mul_basis_ctx, out);
      benchmark::DoNotOptimize(out);
    }
  })->Iterations(50);

  benchmark::RegisterBenchmark("cmp/lift/seal/8192", [env](
                                                         benchmark::State &st) {
    for (auto _ : st) {
      std::vector<std::uint64_t> q_out(env->base_q_size * env->degree);
      std::vector<std::uint64_t> bsk_out(env->base_bsk_size * env->degree);
      std::vector<std::uint64_t> temp_bsk_m_tilde((env->base_bsk_size + 1) *
                                                  env->degree);

      std::copy(env->seal_in_flat.begin(), env->seal_in_flat.end(),
                q_out.begin());
      seal::util::ntt_negacyclic_harvey_lazy(
          seal::util::RNSIter(q_out.data(), env->degree), env->base_q_size,
          env->seal_base_q_ntt_tables.data());
      env->seal_rns_tool->fastbconv_m_tilde(
          seal::util::ConstRNSIter(env->seal_in_flat.data(), env->degree),
          seal::util::RNSIter(temp_bsk_m_tilde.data(), env->degree),
          env->seal_pool);
      env->seal_rns_tool->sm_mrq(
          seal::util::ConstRNSIter(temp_bsk_m_tilde.data(), env->degree),
          seal::util::RNSIter(bsk_out.data(), env->degree), env->seal_pool);
      seal::util::ntt_negacyclic_harvey_lazy(
          seal::util::RNSIter(bsk_out.data(), env->degree), env->base_bsk_size,
          env->seal_base_bsk_ntt_tables.data());
      benchmark::DoNotOptimize(q_out);
      benchmark::DoNotOptimize(bsk_out);
    }
  })->Iterations(50);

  benchmark::RegisterBenchmark("cmp/lift2/ours/8192", [env](benchmark::State
                                                                &st) {
    for (auto _ : st) {
      std::vector<const OurPoly *> polys = {&env->our_input, &env->our_input};
      std::vector<OurPoly> out;
      OurMulBasisExtender::ExtendToNtt(polys, env->base_ctx, env->mul_ctx,
                                       env->our_mul_basis_ctx, out);
      benchmark::DoNotOptimize(out);
    }
  })->Iterations(50);

  benchmark::RegisterBenchmark("cmp/lift2/seal/8192", [env](benchmark::State
                                                                &st) {
    for (auto _ : st) {
      std::vector<std::uint64_t> q_out(2 * env->base_q_size * env->degree);
      std::vector<std::uint64_t> bsk_out(2 * env->base_bsk_size * env->degree);
      std::vector<std::uint64_t> temp_bsk_m_tilde(2 * (env->base_bsk_size + 1) *
                                                  env->degree);

      for (std::size_t poly_idx = 0; poly_idx < 2; ++poly_idx) {
        auto q_offset = poly_idx * env->base_q_size * env->degree;
        auto bsk_offset = poly_idx * env->base_bsk_size * env->degree;
        auto temp_offset = poly_idx * (env->base_bsk_size + 1) * env->degree;
        std::copy(env->seal_in_flat.begin(), env->seal_in_flat.end(),
                  q_out.begin() + q_offset);
        seal::util::ntt_negacyclic_harvey_lazy(
            seal::util::RNSIter(q_out.data() + q_offset, env->degree),
            env->base_q_size, env->seal_base_q_ntt_tables.data());
        env->seal_rns_tool->fastbconv_m_tilde(
            seal::util::ConstRNSIter(env->seal_in_flat.data(), env->degree),
            seal::util::RNSIter(temp_bsk_m_tilde.data() + temp_offset,
                                env->degree),
            env->seal_pool);
        env->seal_rns_tool->sm_mrq(
            seal::util::ConstRNSIter(temp_bsk_m_tilde.data() + temp_offset,
                                     env->degree),
            seal::util::RNSIter(bsk_out.data() + bsk_offset, env->degree),
            env->seal_pool);
        seal::util::ntt_negacyclic_harvey_lazy(
            seal::util::RNSIter(bsk_out.data() + bsk_offset, env->degree),
            env->base_bsk_size, env->seal_base_bsk_ntt_tables.data());
      }
      benchmark::DoNotOptimize(q_out);
      benchmark::DoNotOptimize(bsk_out);
    }
  })->Iterations(50);

  benchmark::RegisterBenchmark("cmp/lift4/ours/8192",
                               [env, our_input4_ptrs](benchmark::State &st) {
                                 for (auto _ : st) {
                                   std::vector<OurPoly> out;
                                   OurMulBasisExtender::ExtendToNtt(
                                       *our_input4_ptrs, env->base_ctx,
                                       env->mul_ctx, env->our_mul_basis_ctx,
                                       out);
                                   benchmark::DoNotOptimize(out);
                                 }
                               })
      ->Iterations(30);

  benchmark::RegisterBenchmark("cmp/lift4/seal/8192", [env](benchmark::State
                                                                &st) {
    constexpr std::size_t kPolyCount = 4;
    for (auto _ : st) {
      std::vector<std::uint64_t> q_out(kPolyCount * env->base_q_size *
                                       env->degree);
      std::vector<std::uint64_t> bsk_out(kPolyCount * env->base_bsk_size *
                                         env->degree);
      std::vector<std::uint64_t> temp_bsk_m_tilde(
          kPolyCount * (env->base_bsk_size + 1) * env->degree);

      for (std::size_t poly_idx = 0; poly_idx < kPolyCount; ++poly_idx) {
        const std::size_t q_offset = poly_idx * env->base_q_size * env->degree;
        const std::size_t bsk_offset =
            poly_idx * env->base_bsk_size * env->degree;
        const std::size_t temp_offset =
            poly_idx * (env->base_bsk_size + 1) * env->degree;

        std::copy(env->seal_in_flat.begin(), env->seal_in_flat.end(),
                  q_out.begin() + q_offset);
        seal::util::ntt_negacyclic_harvey_lazy(
            seal::util::RNSIter(q_out.data() + q_offset, env->degree),
            env->base_q_size, env->seal_base_q_ntt_tables.data());
        env->seal_rns_tool->fastbconv_m_tilde(
            seal::util::ConstRNSIter(env->seal_in_flat.data(), env->degree),
            seal::util::RNSIter(temp_bsk_m_tilde.data() + temp_offset,
                                env->degree),
            env->seal_pool);
        env->seal_rns_tool->sm_mrq(
            seal::util::ConstRNSIter(temp_bsk_m_tilde.data() + temp_offset,
                                     env->degree),
            seal::util::RNSIter(bsk_out.data() + bsk_offset, env->degree),
            env->seal_pool);
        seal::util::ntt_negacyclic_harvey_lazy(
            seal::util::RNSIter(bsk_out.data() + bsk_offset, env->degree),
            env->base_bsk_size, env->seal_base_bsk_ntt_tables.data());
      }
      benchmark::DoNotOptimize(q_out);
      benchmark::DoNotOptimize(bsk_out);
    }
  })->Iterations(30);
}

void RegisterMulCoreBenchmarks() {
  auto env = std::make_shared<MulCoreEnv>(MulCoreEnv::Make(8192));

  benchmark::RegisterBenchmark("cmp/mulcore/ours/8192", [env](benchmark::State
                                                                  &st) {
    std::vector<const OurPoly *> lhs = {&env->our_inputs[0],
                                        &env->our_inputs[1]};
    std::vector<const OurPoly *> rhs = {&env->our_inputs[2],
                                        &env->our_inputs[3]};
    for (auto _ : st) {
      std::vector<OurPoly> lhs_scaled;
      std::vector<OurPoly> rhs_scaled;
      OurMulBasisExtender::ExtendToNtt(lhs, env->base_ctx, env->mul_ctx,
                                       env->our_mul_basis_ctx, lhs_scaled);
      OurMulBasisExtender::ExtendToNtt(rhs, env->base_ctx, env->mul_ctx,
                                       env->our_mul_basis_ctx, rhs_scaled);
      auto c2 = OurPoly::uninitialized(lhs_scaled[0].ctx(),
                                       ::bfv::math::rq::Representation::Ntt);
      OurPoly::tensor_product_inplace(lhs_scaled[0], lhs_scaled[1], c2,
                                      rhs_scaled[0], rhs_scaled[1]);
      ChangeThreeToPowerBasisLazyBench(lhs_scaled[0], lhs_scaled[1], c2);
      std::vector<const OurPoly *> down_polys = {&lhs_scaled[0], &lhs_scaled[1],
                                                 &c2};
      auto out = env->our_down_scaler->map_many(down_polys);
      benchmark::DoNotOptimize(out);
    }
  })->Iterations(20);

  benchmark::RegisterBenchmark("cmp/mulcore/seal/8192", [env](benchmark::State
                                                                  &st) {
    constexpr std::size_t kInputPolyCount = 4;
    constexpr std::size_t kOutputPolyCount = 3;
    const auto *seal_base_bsk = env->seal_rns_tool->base_Bsk();
    for (auto _ : st) {
      std::vector<std::uint64_t> enc_q(kInputPolyCount * env->base_q_size *
                                       env->degree);
      std::vector<std::uint64_t> enc_bsk(kInputPolyCount * env->base_bsk_size *
                                         env->degree);
      std::vector<std::uint64_t> temp_bsk_m_tilde(
          kInputPolyCount * (env->base_bsk_size + 1) * env->degree);

      for (std::size_t poly_idx = 0; poly_idx < kInputPolyCount; ++poly_idx) {
        auto *q_ptr = enc_q.data() + poly_idx * env->base_q_size * env->degree;
        auto *bsk_ptr =
            enc_bsk.data() + poly_idx * env->base_bsk_size * env->degree;
        auto *tmp_ptr = temp_bsk_m_tilde.data() +
                        poly_idx * (env->base_bsk_size + 1) * env->degree;
        const auto *in_ptr = env->seal_inputs_flat.data() +
                             poly_idx * env->base_q_size * env->degree;
        std::copy_n(in_ptr, env->base_q_size * env->degree, q_ptr);
        seal::util::ntt_negacyclic_harvey_lazy(
            seal::util::RNSIter(q_ptr, env->degree), env->base_q_size,
            env->seal_base_q_ntt_tables.data());
        env->seal_rns_tool->fastbconv_m_tilde(
            seal::util::ConstRNSIter(in_ptr, env->degree),
            seal::util::RNSIter(tmp_ptr, env->degree), env->seal_pool);
        env->seal_rns_tool->sm_mrq(
            seal::util::ConstRNSIter(tmp_ptr, env->degree),
            seal::util::RNSIter(bsk_ptr, env->degree), env->seal_pool);
        seal::util::ntt_negacyclic_harvey_lazy(
            seal::util::RNSIter(bsk_ptr, env->degree), env->base_bsk_size,
            env->seal_base_bsk_ntt_tables.data());
      }

      std::vector<std::uint64_t> temp_dest_q(kOutputPolyCount *
                                             env->base_q_size * env->degree);
      std::vector<std::uint64_t> temp_dest_bsk(
          kOutputPolyCount * env->base_bsk_size * env->degree);
      std::vector<std::uint64_t> tmp(env->degree);

      for (std::size_t mod_idx = 0; mod_idx < env->base_q_size; ++mod_idx) {
        auto *x00 = enc_q.data() + mod_idx * env->degree;
        auto *x01 = enc_q.data() + (env->base_q_size + mod_idx) * env->degree;
        auto *x10 =
            enc_q.data() + (2 * env->base_q_size + mod_idx) * env->degree;
        auto *x11 =
            enc_q.data() + (3 * env->base_q_size + mod_idx) * env->degree;
        auto *o0 = temp_dest_q.data() + mod_idx * env->degree;
        auto *o1 =
            temp_dest_q.data() + (env->base_q_size + mod_idx) * env->degree;
        auto *o2 =
            temp_dest_q.data() + (2 * env->base_q_size + mod_idx) * env->degree;
        const auto &modulus = env->seal_base_q_moduli[mod_idx];
        seal::util::dyadic_product_coeffmod(
            seal::util::CoeffIter(x00), seal::util::CoeffIter(x10), env->degree,
            modulus, seal::util::CoeffIter(o0));
        seal::util::dyadic_product_coeffmod(
            seal::util::CoeffIter(x01), seal::util::CoeffIter(x10), env->degree,
            modulus, seal::util::CoeffIter(tmp.data()));
        seal::util::dyadic_product_coeffmod(
            seal::util::CoeffIter(x00), seal::util::CoeffIter(x11), env->degree,
            modulus, seal::util::CoeffIter(o1));
        seal::util::add_poly_coeffmod(
            seal::util::CoeffIter(o1), seal::util::CoeffIter(tmp.data()),
            env->degree, modulus, seal::util::CoeffIter(o1));
        seal::util::dyadic_product_coeffmod(
            seal::util::CoeffIter(x01), seal::util::CoeffIter(x11), env->degree,
            modulus, seal::util::CoeffIter(o2));
      }

      for (std::size_t mod_idx = 0; mod_idx < env->base_bsk_size; ++mod_idx) {
        auto *x00 = enc_bsk.data() + mod_idx * env->degree;
        auto *x01 =
            enc_bsk.data() + (env->base_bsk_size + mod_idx) * env->degree;
        auto *x10 =
            enc_bsk.data() + (2 * env->base_bsk_size + mod_idx) * env->degree;
        auto *x11 =
            enc_bsk.data() + (3 * env->base_bsk_size + mod_idx) * env->degree;
        auto *o0 = temp_dest_bsk.data() + mod_idx * env->degree;
        auto *o1 =
            temp_dest_bsk.data() + (env->base_bsk_size + mod_idx) * env->degree;
        auto *o2 = temp_dest_bsk.data() +
                   (2 * env->base_bsk_size + mod_idx) * env->degree;
        const auto &modulus = (*seal_base_bsk)[mod_idx];
        seal::util::dyadic_product_coeffmod(
            seal::util::CoeffIter(x00), seal::util::CoeffIter(x10), env->degree,
            modulus, seal::util::CoeffIter(o0));
        seal::util::dyadic_product_coeffmod(
            seal::util::CoeffIter(x01), seal::util::CoeffIter(x10), env->degree,
            modulus, seal::util::CoeffIter(tmp.data()));
        seal::util::dyadic_product_coeffmod(
            seal::util::CoeffIter(x00), seal::util::CoeffIter(x11), env->degree,
            modulus, seal::util::CoeffIter(o1));
        seal::util::add_poly_coeffmod(
            seal::util::CoeffIter(o1), seal::util::CoeffIter(tmp.data()),
            env->degree, modulus, seal::util::CoeffIter(o1));
        seal::util::dyadic_product_coeffmod(
            seal::util::CoeffIter(x01), seal::util::CoeffIter(x11), env->degree,
            modulus, seal::util::CoeffIter(o2));
      }

      seal::util::inverse_ntt_negacyclic_harvey_lazy(
          seal::util::PolyIter(temp_dest_q.data(), env->degree,
                               env->base_q_size),
          kOutputPolyCount, env->seal_base_q_ntt_tables.data());
      seal::util::inverse_ntt_negacyclic_harvey_lazy(
          seal::util::PolyIter(temp_dest_bsk.data(), env->degree,
                               env->base_bsk_size),
          kOutputPolyCount, env->seal_base_bsk_ntt_tables.data());

      std::vector<std::uint64_t> out_q(kOutputPolyCount * env->base_q_size *
                                       env->degree);
      std::vector<std::uint64_t> temp_q_bsk(
          (env->base_q_size + env->base_bsk_size) * env->degree);
      std::vector<std::uint64_t> temp_bsk(env->base_bsk_size * env->degree);
      for (std::size_t poly_idx = 0; poly_idx < kOutputPolyCount; ++poly_idx) {
        auto *q_ptr =
            temp_dest_q.data() + poly_idx * env->base_q_size * env->degree;
        auto *bsk_ptr =
            temp_dest_bsk.data() + poly_idx * env->base_bsk_size * env->degree;
        seal::util::multiply_poly_scalar_coeffmod(
            seal::util::ConstRNSIter(q_ptr, env->degree), env->base_q_size,
            env->plain_modulus,
            seal::util::ConstModulusIter(env->seal_base_q.base()),
            seal::util::RNSIter(temp_q_bsk.data(), env->degree));
        seal::util::multiply_poly_scalar_coeffmod(
            seal::util::ConstRNSIter(bsk_ptr, env->degree), env->base_bsk_size,
            env->plain_modulus,
            seal::util::ConstModulusIter(seal_base_bsk->base()),
            seal::util::RNSIter(
                temp_q_bsk.data() + env->base_q_size * env->degree,
                env->degree));
        env->seal_rns_tool->fast_floor(
            seal::util::ConstRNSIter(temp_q_bsk.data(), env->degree),
            seal::util::RNSIter(temp_bsk.data(), env->degree), env->seal_pool);
        env->seal_rns_tool->fastbconv_sk(
            seal::util::ConstRNSIter(temp_bsk.data(), env->degree),
            seal::util::RNSIter(
                out_q.data() + poly_idx * env->base_q_size * env->degree,
                env->degree),
            env->seal_pool);
      }

      benchmark::DoNotOptimize(out_q);
    }
  })->Iterations(20);
}

void RegisterToPowerBenchmarks() {
  auto env = std::make_shared<ToPowerEnv>(ToPowerEnv::Make(8192));

  benchmark::RegisterBenchmark("cmp/to_power/ours/8192", [env](benchmark::State
                                                                   &st) {
    const auto &ops = env->mul_ctx->ops();
    for (auto _ : st) {
      auto polys = env->our_polys;
      for (auto &poly : polys) {
        for (std::size_t mod_idx = 0; mod_idx < ops.size(); ++mod_idx) {
          ops[mod_idx].BackwardInPlaceLazy(poly.data(mod_idx));
        }
        poly.override_representation(
            ::bfv::math::rq::Representation::PowerBasis);
      }
      benchmark::DoNotOptimize(polys);
    }
  })->Iterations(100);

  benchmark::RegisterBenchmark("cmp/to_power/seal/8192", [env](benchmark::State
                                                                   &st) {
    for (auto _ : st) {
      auto q_flat = env->seal_q_flat;
      auto bsk_flat = env->seal_bsk_flat;
      seal::util::inverse_ntt_negacyclic_harvey_lazy(
          seal::util::PolyIter(q_flat.data(), env->degree, env->base_q_size), 3,
          env->seal_base_q_ntt_tables.data());
      seal::util::inverse_ntt_negacyclic_harvey_lazy(
          seal::util::PolyIter(bsk_flat.data(), env->degree,
                               env->base_bsk_size),
          3, env->seal_base_bsk_ntt_tables.data());
      benchmark::DoNotOptimize(q_flat);
      benchmark::DoNotOptimize(bsk_flat);
    }
  })->Iterations(100);
}

}  // namespace

// Entrypoint to register all degrees
static bool registered = []() {
  for (auto d : kDegrees) RegisterForDegree(d);
  RegisterBaseConverterBenchmarks();
  RegisterTensorBenchmarks();
  RegisterDownscaleBenchmarks();
  RegisterDecryptDotBenchmarks();
  RegisterDecryptScaleBenchmarks();
  RegisterLiftBenchmarks();
  RegisterMulCoreBenchmarks();
  RegisterToPowerBenchmarks();
  return true;
}();

BENCHMARK_MAIN();
