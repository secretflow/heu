#ifndef BFV_MATH_RNS_TRANSFER_ARITHMETIC_H
#define BFV_MATH_RNS_TRANSFER_ARITHMETIC_H

#include <cstddef>
#include <cstdint>

#include "math/modulus.h"

namespace bfv {
namespace math {
namespace rns {
namespace internal {

inline uint64_t transfer_mul64_high(uint64_t x, uint64_t y) {
  return static_cast<uint64_t>((static_cast<unsigned __int128>(x) * y) >> 64);
}

inline uint64_t transfer_cond_sub(uint64_t r, uint64_t p) {
  uint64_t mask = -(uint64_t)(r >= p);
  return r - (p & mask);
}

inline uint64_t transfer_reduce_u128(unsigned __int128 a,
                                     const zq::BarrettConstants &barrett) {
  const uint64_t p = barrett.value;
  const uint64_t ratio0 = barrett.barrett_lo;
  const uint64_t ratio1 = barrett.barrett_hi;

  const uint64_t a_lo = static_cast<uint64_t>(a);
  const uint64_t a_hi = static_cast<uint64_t>(a >> 64);

  const uint64_t p_lo_lo_hi = transfer_mul64_high(a_lo, ratio0);
  const unsigned __int128 p_hi_lo = (unsigned __int128)a_hi * ratio0;
  const unsigned __int128 p_lo_hi = (unsigned __int128)a_lo * ratio1;
  const unsigned __int128 q_hat = ((p_lo_hi + p_hi_lo + p_lo_lo_hi) >> 64) +
                                  (unsigned __int128)a_hi * ratio1;
  const uint64_t r = static_cast<uint64_t>(a - q_hat * p);
  return transfer_cond_sub(r, p);
}

inline uint64_t transfer_lazy_mul_shoup(uint64_t a, uint64_t b,
                                        uint64_t b_shoup, uint64_t p) {
  unsigned __int128 product = (unsigned __int128)a * b;
  uint64_t q = static_cast<uint64_t>(((unsigned __int128)a * b_shoup) >> 64);
  return static_cast<uint64_t>(product - (unsigned __int128)q * p);
}

struct alignas(32) U256 {
  uint64_t words[4];

  constexpr U256() noexcept : words{0, 0, 0, 0} {}

  explicit constexpr U256(uint64_t v) noexcept : words{v, 0, 0, 0} {}

  explicit constexpr U256(__uint128_t v) noexcept
      : words{static_cast<uint64_t>(v), static_cast<uint64_t>(v >> 64), 0, 0} {}

  inline U256 &wrapping_add(const U256 &other) noexcept {
    uint64_t carry = 0;
    __uint128_t sum0 = static_cast<__uint128_t>(words[0]) + other.words[0];
    words[0] = static_cast<uint64_t>(sum0);
    carry = static_cast<uint64_t>(sum0 >> 64);

    __uint128_t sum1 =
        static_cast<__uint128_t>(words[1]) + other.words[1] + carry;
    words[1] = static_cast<uint64_t>(sum1);
    carry = static_cast<uint64_t>(sum1 >> 64);

    __uint128_t sum2 =
        static_cast<__uint128_t>(words[2]) + other.words[2] + carry;
    words[2] = static_cast<uint64_t>(sum2);
    carry = static_cast<uint64_t>(sum2 >> 64);

    __uint128_t sum3 =
        static_cast<__uint128_t>(words[3]) + other.words[3] + carry;
    words[3] = static_cast<uint64_t>(sum3);
    return *this;
  }

  inline U256 &wrapping_sub(const U256 &other) noexcept {
    uint64_t borrow = 0;
    __uint128_t diff0 = static_cast<__uint128_t>(words[0]) - other.words[0];
    words[0] = static_cast<uint64_t>(diff0);
    borrow = (diff0 >> 127) & 1;

    __uint128_t diff1 =
        static_cast<__uint128_t>(words[1]) - other.words[1] - borrow;
    words[1] = static_cast<uint64_t>(diff1);
    borrow = (diff1 >> 127) & 1;

    __uint128_t diff2 =
        static_cast<__uint128_t>(words[2]) - other.words[2] - borrow;
    words[2] = static_cast<uint64_t>(diff2);
    borrow = (diff2 >> 127) & 1;

    __uint128_t diff3 =
        static_cast<__uint128_t>(words[3]) - other.words[3] - borrow;
    words[3] = static_cast<uint64_t>(diff3);
    return *this;
  }

  U256 operator*(const U256 &other) const noexcept {
    U256 result;
    __uint128_t prod, carry;

    prod = static_cast<__uint128_t>(words[0]) * other.words[0];
    result.words[0] = static_cast<uint64_t>(prod);
    carry = prod >> 64;

    prod = static_cast<__uint128_t>(words[0]) * other.words[1] + carry;
    result.words[1] = static_cast<uint64_t>(prod);
    carry = prod >> 64;

    prod = static_cast<__uint128_t>(words[0]) * other.words[2] + carry;
    result.words[2] = static_cast<uint64_t>(prod);
    carry = prod >> 64;

    prod = static_cast<__uint128_t>(words[0]) * other.words[3] + carry;
    result.words[3] = static_cast<uint64_t>(prod);

    prod =
        static_cast<__uint128_t>(words[1]) * other.words[0] + result.words[1];
    result.words[1] = static_cast<uint64_t>(prod);
    carry = prod >> 64;

    prod = static_cast<__uint128_t>(words[1]) * other.words[1] +
           result.words[2] + carry;
    result.words[2] = static_cast<uint64_t>(prod);
    carry = prod >> 64;

    prod = static_cast<__uint128_t>(words[1]) * other.words[2] +
           result.words[3] + carry;
    result.words[3] = static_cast<uint64_t>(prod);

    prod =
        static_cast<__uint128_t>(words[2]) * other.words[0] + result.words[2];
    result.words[2] = static_cast<uint64_t>(prod);
    carry = prod >> 64;

    prod = static_cast<__uint128_t>(words[2]) * other.words[1] +
           result.words[3] + carry;
    result.words[3] = static_cast<uint64_t>(prod);

    prod =
        static_cast<__uint128_t>(words[3]) * other.words[0] + result.words[3];
    result.words[3] = static_cast<uint64_t>(prod);
    return result;
  }

  inline U256 &operator>>=(size_t shift) noexcept {
    if (shift == 0) return *this;
    if (shift >= 256) {
      words[0] = words[1] = words[2] = words[3] = 0;
      return *this;
    }

    const size_t word_shift = shift / 64;
    const size_t bit_shift = shift % 64;

    if (word_shift > 0) {
      switch (word_shift) {
        case 1:
          words[0] = words[1];
          words[1] = words[2];
          words[2] = words[3];
          words[3] = 0;
          break;
        case 2:
          words[0] = words[2];
          words[1] = words[3];
          words[2] = words[3] = 0;
          break;
        case 3:
          words[0] = words[3];
          words[1] = words[2] = words[3] = 0;
          break;
        default:
          words[0] = words[1] = words[2] = words[3] = 0;
          break;
      }
    }

    if (bit_shift > 0) {
      const size_t left_shift = 64 - bit_shift;
      words[0] = (words[0] >> bit_shift) | (words[1] << left_shift);
      words[1] = (words[1] >> bit_shift) | (words[2] << left_shift);
      words[2] = (words[2] >> bit_shift) | (words[3] << left_shift);
      words[3] >>= bit_shift;
    }
    return *this;
  }

  inline U256 operator>>(size_t shift) const noexcept {
    U256 result = *this;
    result >>= shift;
    return result;
  }

  inline U256 operator~() const noexcept {
    U256 result;
    result.words[0] = ~words[0];
    result.words[1] = ~words[1];
    result.words[2] = ~words[2];
    result.words[3] = ~words[3];
    return result;
  }

  inline bool operator>(const U256 &other) const noexcept {
    if (words[3] != other.words[3]) return words[3] > other.words[3];
    if (words[2] != other.words[2]) return words[2] > other.words[2];
    if (words[1] != other.words[1]) return words[1] > other.words[1];
    return words[0] > other.words[0];
  }

  inline __uint128_t as_u128() const noexcept {
    return static_cast<__uint128_t>(words[0]) |
           (static_cast<__uint128_t>(words[1]) << 64);
  }
};

}  // namespace internal
}  // namespace rns
}  // namespace math
}  // namespace bfv

#endif  // BFV_MATH_RNS_TRANSFER_ARITHMETIC_H
