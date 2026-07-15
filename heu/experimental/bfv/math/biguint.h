#ifndef BIGUINT_H
#define BIGUINT_H

// #include "../../../external/libtommath/tommath.h"

#include <cstdint>
#include <memory>
#include <optional>
#include <ostream>
#include <string>
#include <tuple>
#include <type_traits>

namespace bfv {
namespace math {
namespace rns {

class BigUint {
 public:
  BigUint();
  explicit BigUint(uint64_t val);
  BigUint(const BigUint &other);
  BigUint(BigUint &&other) noexcept;
  ~BigUint();

  BigUint &operator=(const BigUint &other);
  BigUint &operator=(BigUint &&other) noexcept;

  static BigUint zero();
  static BigUint one();

  BigUint &operator+=(const BigUint &other);
  BigUint &operator-=(const BigUint &other);
  BigUint &operator-=(uint64_t other);
  BigUint &operator*=(const BigUint &other);
  BigUint &operator*=(uint64_t other);
  BigUint &operator/=(const BigUint &other);
  BigUint &operator/=(uint64_t other);
  BigUint &operator%=(const BigUint &other);
  BigUint &operator%=(uint64_t other);
  BigUint &operator<<=(size_t shift);
  BigUint &operator>>=(size_t shift);

  BigUint operator+(const BigUint &other) const;
  BigUint operator-(const BigUint &other) const;
  BigUint operator-(uint64_t other) const;
  BigUint operator*(const BigUint &other) const;
  BigUint operator*(uint64_t other) const;
  BigUint operator/(const BigUint &other) const;
  BigUint operator/(uint64_t other) const;
  BigUint operator%(const BigUint &other) const;
  BigUint operator%(uint64_t other) const;
  BigUint operator<<(size_t shift) const;
  BigUint operator>>(size_t shift) const;

  bool operator==(const BigUint &other) const;
  bool operator!=(const BigUint &other) const;
  bool operator<(const BigUint &other) const;
  bool operator>(const BigUint &other) const;
  bool operator<=(const BigUint &other) const;
  bool operator>=(const BigUint &other) const;

  std::optional<BigUint> mod_inverse(const BigUint &modulus) const;

  static std::tuple<BigUint, int64_t, int64_t> extended_gcd(const BigUint &a,
                                                            const BigUint &b);

  uint64_t to_u64() const;
  std::string to_string() const;
  size_t bits() const;

 private:
  class Impl;
  std::unique_ptr<Impl> impl_;
};

std::ostream &operator<<(std::ostream &os, const BigUint &value);

}  // namespace rns
}  // namespace math
}  // namespace bfv
#endif
