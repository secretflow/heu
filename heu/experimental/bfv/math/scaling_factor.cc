#include "math/scaling_factor.h"

#include <stdexcept>

#include "math/biguint.h"

namespace bfv {
namespace math {
namespace rns {

class ScalingFactor::Impl {
 public:
  BigUint numerator;
  BigUint denominator;
  bool is_one;

  Impl(const BigUint &num, const BigUint &den)
      : numerator(num), denominator(den), is_one(num == den) {
    if (denominator == BigUint::zero()) {
      throw std::invalid_argument("Denominator cannot be zero");
    }
  }
};

ScalingFactor::ScalingFactor(const BigUint &num, const BigUint &den)
    : impl_(std::make_unique<Impl>(num, den)) {}

ScalingFactor::ScalingFactor(const ScalingFactor &other)
    : impl_(std::make_unique<Impl>(*other.impl_)) {}

ScalingFactor &ScalingFactor::operator=(const ScalingFactor &other) {
  if (this != &other) {
    impl_ = std::make_unique<Impl>(*other.impl_);
  }
  return *this;
}

ScalingFactor::~ScalingFactor() = default;

ScalingFactor ScalingFactor::one() {
  return ScalingFactor(BigUint::one(), BigUint::one());
}

ScalingFactor ScalingFactor::from_uint64_over_biguint(uint64_t num,
                                                      const BigUint &den) {
  return ScalingFactor(BigUint(num), den);
}

const BigUint &ScalingFactor::numerator() const { return impl_->numerator; }

const BigUint &ScalingFactor::denominator() const { return impl_->denominator; }

bool ScalingFactor::is_one() const { return impl_->is_one; }

}  // namespace rns
}  // namespace math
}  // namespace bfv
