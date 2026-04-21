#include "math/ntt_layout.h"

#include <cmath>

namespace bfv {
namespace math {
namespace ntt {
namespace internal {

std::optional<NttLayoutData> BuildNttLayout(const zq::Modulus &modulus,
                                            size_t coeff_count) {
  if (coeff_count < 2 || (coeff_count & (coeff_count - 1)) != 0) {
    return std::nullopt;
  }

  const uint64_t modulus_value = modulus.P();
  if (modulus_value <= 1 || (modulus_value - 1) % (2 * coeff_count) != 0) {
    return std::nullopt;
  }

  const uint64_t primitive_root = FindPrimitiveNthRoot(coeff_count, modulus);
  if (primitive_root == 0) {
    return std::nullopt;
  }

  auto primitive_root_inverse = modulus.Inv(primitive_root);
  if (!primitive_root_inverse.has_value()) {
    return std::nullopt;
  }

  auto inverse_degree = modulus.Inv(coeff_count);
  if (!inverse_degree.has_value()) {
    return std::nullopt;
  }

  NttLayoutData layout;
  layout.inverse_degree.set(inverse_degree.value(), modulus_value);

  std::vector<uint64_t> root_powers(coeff_count);
  root_powers[0] = 1;
  for (size_t i = 1; i < coeff_count; ++i) {
    root_powers[i] = modulus.Mul(root_powers[i - 1], primitive_root);
  }

  const size_t log_n = static_cast<size_t>(std::log2(coeff_count));
  layout.forward_root_layout.resize(coeff_count);
  for (size_t i = 0; i < coeff_count; ++i) {
    const size_t bit_reversed_index = ReverseBitOrder(i, log_n);
    layout.forward_root_layout[i].set(root_powers[bit_reversed_index],
                                      modulus_value);
  }

  layout.inverse_root_layout.resize(coeff_count);
  layout.inverse_root_layout[0].set(uint64_t{1}, modulus_value);
  uint64_t inverse_power = primitive_root_inverse.value();
  for (size_t i = 1; i < coeff_count; ++i) {
    const size_t inverse_index = ReverseBitOrder(i - 1, log_n) + 1;
    layout.inverse_root_layout[inverse_index].set(inverse_power, modulus_value);
    inverse_power = modulus.Mul(inverse_power, primitive_root_inverse.value());
  }

  return layout;
}

uint64_t FindPrimitiveNthRoot(size_t coeff_count, const zq::Modulus &modulus) {
  const uint64_t modulus_value = modulus.P();
  const uint64_t exponent = (modulus_value - 1) / (2 * coeff_count);
  const std::vector<uint64_t> seed_candidates = {2,  3,  5,  7,  11, 13,
                                                 17, 19, 23, 29, 31};

  for (uint64_t seed : seed_candidates) {
    if (seed >= modulus_value) {
      continue;
    }
    const uint64_t root = modulus.Pow(seed, exponent);
    if (root != 0 && MatchesPrimitiveRootOrder(root, coeff_count, modulus)) {
      return root;
    }
  }

  const uint64_t search_limit =
      (modulus_value < 1000ULL) ? modulus_value : 1000ULL;
  for (uint64_t seed = 37; seed < search_limit; ++seed) {
    const uint64_t root = modulus.Pow(seed, exponent);
    if (root != 0 && MatchesPrimitiveRootOrder(root, coeff_count, modulus)) {
      return root;
    }
  }

  return 0;
}

bool MatchesPrimitiveRootOrder(uint64_t root, size_t coeff_count,
                               const zq::Modulus &modulus) {
  const uint64_t modulus_value = modulus.P();
  if (modulus.Pow(root, 2 * coeff_count) != 1) {
    return false;
  }
  if (modulus.Pow(root, coeff_count) != modulus_value - 1) {
    return false;
  }
  if (coeff_count > 2) {
    const uint64_t half_order = modulus.Pow(root, coeff_count / 2);
    if (half_order == 1 || half_order == modulus_value - 1) {
      return false;
    }
  }
  return true;
}

size_t ReverseBitOrder(size_t value, size_t bit_count) {
  size_t reversed = 0;
  for (size_t i = 0; i < bit_count; ++i) {
    reversed = (reversed << 1) | (value & 1);
    value >>= 1;
  }
  return reversed;
}

}  // namespace internal
}  // namespace ntt
}  // namespace math
}  // namespace bfv
