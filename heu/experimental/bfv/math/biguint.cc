#include "math/biguint.h"

#include <libtommath/tommath.h>

#include <cstring>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>

namespace bfv {
namespace math {
namespace rns {

namespace {

[[noreturn]] void ThrowTomMathError(const char *operation, mp_err err) {
  throw std::runtime_error(std::string(operation) +
                           " failed: " + mp_error_to_string(err));
}

void CheckTomMath(mp_err err, const char *operation) {
  if (err != MP_OKAY) {
    ThrowTomMathError(operation, err);
  }
}

void InitMpInt(mp_int *value) { CheckTomMath(mp_init(value), "mp_init"); }

void InitMpIntWithU64(mp_int *value, uint64_t raw_value) {
  InitMpInt(value);
  mp_set_u64(value, raw_value);
}

void InitMpIntCopy(mp_int *value, const mp_int *other) {
  InitMpInt(value);
  const auto err = mp_copy(other, value);
  if (err != MP_OKAY) {
    mp_clear(value);
    ThrowTomMathError("mp_copy", err);
  }
}

class ScopedMpInt {
 public:
  ScopedMpInt() { InitMpInt(&value_); }

  ~ScopedMpInt() { mp_clear(&value_); }

  mp_int *get() { return &value_; }

  int64_t to_i64() const { return mp_get_i64(&value_); }

 private:
  mp_int value_;
};

}  // namespace

class BigUint::Impl {
 public:
  mp_int value;

  Impl() {
    InitMpInt(&value);
    mp_zero(&value);
  }

  Impl(uint64_t val) { InitMpIntWithU64(&value, val); }

  Impl(const Impl &other) { InitMpIntCopy(&value, &other.value); }

  ~Impl() { mp_clear(&value); }
};

BigUint::BigUint() : impl_(std::make_unique<Impl>()) {}

BigUint::BigUint(uint64_t val) : impl_(std::make_unique<Impl>(val)) {}

BigUint::BigUint(const BigUint &other)
    : impl_(std::make_unique<Impl>(*other.impl_)) {}

BigUint::BigUint(BigUint &&other) noexcept : impl_(std::move(other.impl_)) {}

BigUint::~BigUint() = default;

BigUint &BigUint::operator=(const BigUint &other) {
  if (this != &other) {
    impl_ = std::make_unique<Impl>(*other.impl_);
  }
  return *this;
}

BigUint &BigUint::operator=(BigUint &&other) noexcept {
  if (this != &other) {
    impl_ = std::move(other.impl_);
  }
  return *this;
}

BigUint BigUint::zero() { return BigUint(0); }

BigUint BigUint::one() { return BigUint(1); }

BigUint &BigUint::operator+=(const BigUint &other) {
  CheckTomMath(mp_add(&impl_->value, &other.impl_->value, &impl_->value),
               "mp_add");
  return *this;
}

BigUint &BigUint::operator-=(const BigUint &other) {
  if (mp_cmp(&impl_->value, &other.impl_->value) == MP_LT) {
    throw std::runtime_error(
        "BigUint subtraction would result in negative value");
  }
  CheckTomMath(mp_sub(&impl_->value, &other.impl_->value, &impl_->value),
               "mp_sub");
  return *this;
}

BigUint &BigUint::operator-=(uint64_t other) {
  if (mp_cmp_d(&impl_->value, other) == MP_LT) {
    throw std::runtime_error(
        "BigUint subtraction would result in negative value");
  }
  CheckTomMath(mp_sub_d(&impl_->value, other, &impl_->value), "mp_sub_d");
  return *this;
}

BigUint &BigUint::operator*=(const BigUint &other) {
  CheckTomMath(mp_mul(&impl_->value, &other.impl_->value, &impl_->value),
               "mp_mul");
  return *this;
}

BigUint &BigUint::operator*=(uint64_t other) {
  CheckTomMath(mp_mul_d(&impl_->value, other, &impl_->value), "mp_mul_d");
  return *this;
}

BigUint &BigUint::operator/=(const BigUint &other) {
  if (mp_iszero(&other.impl_->value))
    throw std::runtime_error("Division by zero");
  CheckTomMath(
      mp_div(&impl_->value, &other.impl_->value, &impl_->value, nullptr),
      "mp_div");
  return *this;
}

BigUint &BigUint::operator/=(uint64_t other) {
  if (other == 0) throw std::runtime_error("Division by zero");
  CheckTomMath(mp_div_d(&impl_->value, other, &impl_->value, nullptr),
               "mp_div_d");
  return *this;
}

BigUint &BigUint::operator%=(const BigUint &other) {
  if (mp_iszero(&other.impl_->value))
    throw std::runtime_error("Division by zero");
  CheckTomMath(mp_mod(&impl_->value, &other.impl_->value, &impl_->value),
               "mp_mod");
  return *this;
}

BigUint &BigUint::operator%=(uint64_t other) {
  if (other == 0) throw std::runtime_error("Division by zero");
  mp_digit remainder;
  CheckTomMath(mp_mod_d(&impl_->value, other, &remainder), "mp_mod_d");
  mp_set_u64(&impl_->value, remainder);
  return *this;
}

BigUint &BigUint::operator<<=(size_t shift) {
  CheckTomMath(mp_mul_2d(&impl_->value, shift, &impl_->value), "mp_mul_2d");
  return *this;
}

BigUint &BigUint::operator>>=(size_t shift) {
  CheckTomMath(mp_div_2d(&impl_->value, shift, &impl_->value, nullptr),
               "mp_div_2d");
  return *this;
}

BigUint BigUint::operator+(const BigUint &other) const {
  BigUint result = *this;
  result += other;
  return result;
}

BigUint BigUint::operator-(const BigUint &other) const {
  BigUint result = *this;
  result -= other;
  return result;
}

BigUint BigUint::operator-(uint64_t other) const {
  BigUint result = *this;
  result -= other;
  return result;
}

BigUint BigUint::operator*(const BigUint &other) const {
  BigUint result = *this;
  result *= other;
  return result;
}

BigUint BigUint::operator*(uint64_t other) const {
  BigUint result = *this;
  result *= other;
  return result;
}

BigUint BigUint::operator/(const BigUint &other) const {
  BigUint result = *this;
  result /= other;
  return result;
}

BigUint BigUint::operator/(uint64_t other) const {
  BigUint result = *this;
  result /= other;
  return result;
}

BigUint BigUint::operator%(const BigUint &other) const {
  BigUint result = *this;
  result %= other;
  return result;
}

BigUint BigUint::operator%(uint64_t other) const {
  BigUint result = *this;
  result %= other;
  return result;
}

BigUint BigUint::operator<<(size_t shift) const {
  BigUint result = *this;
  result <<= shift;
  return result;
}

BigUint BigUint::operator>>(size_t shift) const {
  BigUint result = *this;
  result >>= shift;
  return result;
}

bool BigUint::operator==(const BigUint &other) const {
  return mp_cmp(&impl_->value, &other.impl_->value) == MP_EQ;
}

bool BigUint::operator!=(const BigUint &other) const {
  return !(*this == other);
}

bool BigUint::operator<(const BigUint &other) const {
  return mp_cmp(&impl_->value, &other.impl_->value) == MP_LT;
}

bool BigUint::operator>(const BigUint &other) const {
  return mp_cmp(&impl_->value, &other.impl_->value) == MP_GT;
}

bool BigUint::operator<=(const BigUint &other) const {
  int cmp = mp_cmp(&impl_->value, &other.impl_->value);
  return cmp == MP_LT || cmp == MP_EQ;
}

bool BigUint::operator>=(const BigUint &other) const {
  int cmp = mp_cmp(&impl_->value, &other.impl_->value);
  return cmp == MP_GT || cmp == MP_EQ;
}

std::optional<BigUint> BigUint::mod_inverse(const BigUint &modulus) const {
  BigUint result;
  int res =
      mp_invmod(&impl_->value, &modulus.impl_->value, &result.impl_->value);
  if (res == MP_OKAY) {
    return result;
  } else {
    return std::nullopt;
  }
}

std::tuple<BigUint, int64_t, int64_t> BigUint::extended_gcd(const BigUint &a,
                                                            const BigUint &b) {
  BigUint gcd_result;
  ScopedMpInt u;
  ScopedMpInt v;

  CheckTomMath(mp_exteuclid(&a.impl_->value, &b.impl_->value, u.get(), v.get(),
                            &gcd_result.impl_->value),
               "mp_exteuclid");

  int64_t u_val = u.to_i64();
  int64_t v_val = v.to_i64();

  return std::make_tuple(gcd_result, u_val, v_val);
}

uint64_t BigUint::to_u64() const { return mp_get_u64(&impl_->value); }

std::string BigUint::to_string() const {
  // Estimate size needed for decimal representation
  size_t size = static_cast<size_t>(mp_count_bits(&impl_->value)) * 4 / 10 + 10;
  std::string result(size, '\0');
  CheckTomMath(mp_to_radix(&impl_->value, result.data(), size, nullptr, 10),
               "mp_to_radix");
  // Remove null terminator and trailing zeros
  result.resize(std::strlen(result.c_str()));
  return result;
}

size_t BigUint::bits() const { return mp_count_bits(&impl_->value); }

std::ostream &operator<<(std::ostream &os, const BigUint &value) {
  return os << value.to_string();
}

}  // namespace rns
}  // namespace math
}  // namespace bfv
