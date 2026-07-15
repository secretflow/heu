#ifndef SCALING_FACTOR_H
#define SCALING_FACTOR_H

#include <cstdint>
#include <memory>

namespace bfv {
namespace math {
namespace rns {
class BigUint;  // forward declaration
}  // namespace rns
}  // namespace math
}  // namespace bfv

namespace bfv {
namespace math {
namespace rns {

class ScalingFactor {
 private:
  class Impl;
  std::unique_ptr<Impl> impl_;

 public:
  ScalingFactor(const BigUint &num, const BigUint &den);
  ScalingFactor(const ScalingFactor &other);
  ScalingFactor &operator=(const ScalingFactor &other);
  ~ScalingFactor();

  static ScalingFactor one();
  // Create scaling factor from a uint64 numerator and BigUint denominator
  static ScalingFactor from_uint64_over_biguint(uint64_t num,
                                                const BigUint &den);

  const BigUint &numerator() const;
  const BigUint &denominator() const;
  bool is_one() const;
};

}  // namespace rns
}  // namespace math
}  // namespace bfv

#endif
