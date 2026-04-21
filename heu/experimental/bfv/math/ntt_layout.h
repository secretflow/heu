#ifndef BFV_MATH_NTT_LAYOUT_H
#define BFV_MATH_NTT_LAYOUT_H

#include <cstdint>
#include <optional>
#include <vector>

#include "math/modulus.h"

namespace bfv {
namespace math {
namespace ntt {
namespace internal {

struct NttLayoutData {
  std::vector<zq::MultiplyUIntModOperand> forward_root_layout;
  std::vector<zq::MultiplyUIntModOperand> inverse_root_layout;
  zq::MultiplyUIntModOperand inverse_degree;
};

std::optional<NttLayoutData> BuildNttLayout(const zq::Modulus &modulus,
                                            size_t coeff_count);

uint64_t FindPrimitiveNthRoot(size_t coeff_count, const zq::Modulus &modulus);

bool MatchesPrimitiveRootOrder(uint64_t root, size_t coeff_count,
                               const zq::Modulus &modulus);

size_t ReverseBitOrder(size_t value, size_t bit_count);

}  // namespace internal
}  // namespace ntt
}  // namespace math
}  // namespace bfv

#endif  // BFV_MATH_NTT_LAYOUT_H
