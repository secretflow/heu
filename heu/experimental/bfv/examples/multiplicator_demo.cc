#include <algorithm>
#include <cstdint>
#include <iostream>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>

#include "heu/experimental/bfv/crypto/bfv_parameters.h"
#include "heu/experimental/bfv/crypto/encoding.h"
#include "heu/experimental/bfv/crypto/multiplicator.h"
#include "heu/experimental/bfv/crypto/plaintext.h"
#include "heu/experimental/bfv/crypto/relinearization_key.h"
#include "heu/experimental/bfv/crypto/secret_key.h"
#include "heu/experimental/bfv/math/primes.h"

using namespace crypto::bfv;

namespace {

void Require(bool condition, const std::string &message) {
  if (!condition) {
    throw std::runtime_error(message);
  }
}

void PrintVectorPrefix(const std::string &label,
                       const std::vector<uint64_t> &values,
                       size_t prefix_len = 8) {
  const size_t count = std::min(prefix_len, values.size());
  std::cout << label << ": [";
  for (size_t i = 0; i < count; ++i) {
    if (i != 0) {
      std::cout << ", ";
    }
    std::cout << values[i];
  }
  if (values.size() > count) {
    std::cout << ", ...";
  }
  std::cout << "]" << std::endl;
}

std::vector<uint64_t> BuildExpectedProduct(const std::vector<uint64_t> &lhs,
                                           const std::vector<uint64_t> &rhs,
                                           uint64_t modulus) {
  std::vector<uint64_t> expected(lhs.size(), 0);
  for (size_t i = 0; i < lhs.size(); ++i) {
    expected[i] = (lhs[i] * rhs[i]) % modulus;
  }
  return expected;
}

std::vector<uint64_t> BuildExtendedBasis(
    const std::shared_ptr<BfvParameters> &params) {
  auto ctx = params->ctx_at_level(0);
  size_t modulus_size = 0;
  const auto moduli_sizes = params->moduli_sizes();
  for (size_t i = 0; i < ctx->moduli().size(); ++i) {
    modulus_size += moduli_sizes[i];
  }
  const size_t aux_moduli_count = (modulus_size + 60 + 62 - 1) / 62;

  std::vector<uint64_t> extended_basis = ctx->moduli();
  extended_basis.reserve(ctx->moduli().size() + aux_moduli_count);
  uint64_t upper_bound = 1ULL << 62;
  while (extended_basis.size() < ctx->moduli().size() + aux_moduli_count) {
    auto prime_opt =
        ::bfv::math::zq::generate_prime(62, 2 * params->degree(), upper_bound);
    Require(prime_opt.has_value(),
            "failed to generate an auxiliary prime for the custom basis");
    upper_bound = prime_opt.value();

    bool duplicate = false;
    for (uint64_t existing : extended_basis) {
      if (existing == upper_bound) {
        duplicate = true;
        break;
      }
    }
    if (!duplicate) {
      extended_basis.push_back(upper_bound);
    }
  }

  return extended_basis;
}

}  // namespace

int main() {
  std::cout << "=== BFV Multiplicator Demo ===\n" << std::endl;

  auto params = BfvParameters::default_arc(3, 16);
  std::mt19937_64 rng(42);
  auto secret_key = SecretKey::random(params, rng);
  auto relinearization_key =
      RelinearizationKey::from_secret_key(secret_key, rng);

  std::vector<uint64_t> lhs_values(params->degree(), 0);
  std::vector<uint64_t> rhs_values(params->degree(), 0);
  for (size_t i = 0; i < std::min<size_t>(8, lhs_values.size()); ++i) {
    lhs_values[i] = static_cast<uint64_t>(i + 1);
    rhs_values[i] = static_cast<uint64_t>(2 * (i + 1));
  }

  auto lhs_plaintext = Plaintext::encode(lhs_values, Encoding::simd(), params);
  auto rhs_plaintext = Plaintext::encode(rhs_values, Encoding::simd(), params);
  auto lhs_ciphertext = secret_key.encrypt(lhs_plaintext, rng);
  auto rhs_ciphertext = secret_key.encrypt(rhs_plaintext, rng);
  auto expected =
      BuildExpectedProduct(lhs_values, rhs_values, params->plaintext_modulus());

  auto multiplicator = Multiplicator::create_default(relinearization_key);
  auto product_ct = multiplicator->multiply(lhs_ciphertext, rhs_ciphertext);
  auto product_pt = secret_key.decrypt(product_ct, Encoding::simd());
  auto product_values = product_pt.decode_uint64(Encoding::simd());
  Require(product_values == expected,
          "default multiplicator result did not match the expected product");
  std::cout << "[Default] ciphertext size after relinearization: "
            << product_ct.size() << ", level: " << product_ct.level()
            << std::endl;
  PrintVectorPrefix("[Default] product", product_values);

  multiplicator->enable_mod_switching();
  auto switched_ct = multiplicator->multiply(lhs_ciphertext, rhs_ciphertext);
  auto switched_encoding = Encoding::simd_at_level(switched_ct.level());
  auto switched_pt = secret_key.decrypt(switched_ct, switched_encoding);
  auto switched_values = switched_pt.decode_uint64(switched_encoding);
  Require(switched_values == expected,
          "mod-switched multiplication did not match the expected product");
  std::cout << "[Default + mod switch] ciphertext size: " << switched_ct.size()
            << ", level: " << switched_ct.level() << std::endl;
  PrintVectorPrefix("[Default + mod switch] product", switched_values);

  const auto one_factor = ::bfv::math::rns::ScalingFactor::one();
  auto ctx = params->ctx_at_level(0);
  auto post_mul_factor = ::bfv::math::rns::ScalingFactor(
      ::bfv::math::rns::BigUint(params->plaintext_modulus()),
      ::bfv::math::rns::BigUint(ctx->modulus()));
  auto custom_basis = BuildExtendedBasis(params);

  auto custom_multiplicator = Multiplicator::create(
      one_factor, one_factor, custom_basis, post_mul_factor, params);
  auto custom_ct =
      custom_multiplicator->multiply(lhs_ciphertext, rhs_ciphertext);
  auto custom_pt = secret_key.decrypt(custom_ct, Encoding::simd());
  auto custom_values = custom_pt.decode_uint64(Encoding::simd());
  Require(custom_values == expected,
          "custom multiplicator result did not match the expected product");
  std::cout << "[Custom] ciphertext size without relinearization: "
            << custom_ct.size() << ", level: " << custom_ct.level()
            << std::endl;
  PrintVectorPrefix("[Custom] product", custom_values);

  return 0;
}
