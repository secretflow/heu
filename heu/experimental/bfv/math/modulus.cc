// modulus.cpp
#include "math/modulus.h"

#if defined(__x86_64__) || defined(_M_X64)
#include <immintrin.h>
#endif

#include <algorithm>
#include <cassert>
#include <cstring>

#include "math/modulus_runtime.h"
#include "math/primes.h"

namespace bfv {
namespace math {
namespace zq {

struct Modulus::Impl {
  internal::RuntimeCapabilityProfile runtime;

  explicit Impl(uint64_t modulus)
      : runtime(internal::BuildRuntimeCapabilityProfile(modulus)) {}
};

Modulus::Modulus(std::unique_ptr<Impl> impl)
    : impl_(std::move(impl)),
      p_(0),
      barrett_lo_(0),
      barrett_hi_(0),
      leading_zeros_(0),
      supports_opt_(false) {}

Modulus::Modulus(Modulus &&other) noexcept
    : impl_(std::move(other.impl_)),
      p_(other.p_),
      barrett_lo_(other.barrett_lo_),
      barrett_hi_(other.barrett_hi_),
      leading_zeros_(other.leading_zeros_),
      supports_opt_(other.supports_opt_) {}

Modulus::Modulus(const Modulus &other)
    : impl_(std::make_unique<Impl>(*other.impl_)),
      p_(other.p_),
      barrett_lo_(other.barrett_lo_),
      barrett_hi_(other.barrett_hi_),
      leading_zeros_(other.leading_zeros_),
      supports_opt_(other.supports_opt_) {}

Modulus::~Modulus() = default;

std::optional<Modulus> Modulus::New(uint64_t p) {
  if (p < 2 || p >= (1ULL << 62)) {
    return std::nullopt;
  }

  auto impl = std::make_unique<Impl>(p);
  Modulus result(std::move(impl));
  result.p_ = p;
  result.leading_zeros_ = __builtin_clzll(p);
  result.supports_opt_ = zq::supports_opt(p);
  // Compute Barrett reduction constants: floor(2^128 / p)
  __uint128_t barrett = (__uint128_t(1) << 127) / p;
  barrett <<= 1;
  result.barrett_hi_ = static_cast<uint64_t>(barrett >> 64);
  result.barrett_lo_ = static_cast<uint64_t>(barrett);
  return result;
}

uint64_t Modulus::P() const { return p_; }

bool Modulus::SupportsOpt() const { return supports_opt_; }

BarrettConstants Modulus::GetBarrettConstants() const {
  return {p_, barrett_lo_, barrett_hi_, leading_zeros_};
}

// Shoup representation: (a << 64) / p
uint64_t Modulus::Shoup(uint64_t a) const {
  __uint128_t wide_a = __uint128_t(a) << 64;
  return static_cast<uint64_t>(wide_a / p_);
}

// Constant-time modular addition
uint64_t Modulus::Add(uint64_t a, uint64_t b) const {
  uint64_t sum = a + b;
  return sum >= p_ ? sum - p_ : sum;
}

// Variable-time modular addition
uint64_t Modulus::AddVt(uint64_t a, uint64_t b) const {
  uint64_t sum = a + b;
  return sum >= p_ ? sum - p_ : sum;
}

// Constant-time modular subtraction
uint64_t Modulus::Sub(uint64_t a, uint64_t b) const {
  uint64_t diff = a - b;
  return a < b ? diff + p_ : diff;
}

// Variable-time modular subtraction
uint64_t Modulus::SubVt(uint64_t a, uint64_t b) const {
  return a >= b ? a - b : a + p_ - b;
}

uint64_t Modulus::SubLazy(uint64_t a, uint64_t b) const { return a + p_ - b; }

// High 64 bits of 64x64->128 multiplication (used by standard Barrett 64)
static inline __attribute__((always_inline)) uint64_t mul64_high(uint64_t x,
                                                                 uint64_t y) {
#if defined(__BMI2__)
  uint64_t hi;
  _mulx_u64(x, y, (unsigned long long *)&hi);
  return hi;
#else
  __uint128_t p = static_cast<__uint128_t>(x) * static_cast<__uint128_t>(y);
  return static_cast<uint64_t>(p >> 64);
#endif
}

// 64-bit add with carry-out (returns carry, stores sum in out)
static inline __attribute__((always_inline)) uint64_t
add64_carry(uint64_t x, uint64_t y, uint64_t &out) {
#if defined(__ADX__)
  unsigned char cf = 0;
  cf = _addcarry_u64(cf, x, y, (unsigned long long *)&out);
  return cf;
#else
  __uint128_t s = static_cast<__uint128_t>(x) + static_cast<__uint128_t>(y);
  out = static_cast<uint64_t>(s);
  return static_cast<uint64_t>(s >> 64);
#endif
}

// 64x64 -> 128 split to lo/hi
static inline __attribute__((always_inline)) void mul64_128(uint64_t x,
                                                            uint64_t y,
                                                            uint64_t &lo,
                                                            uint64_t &hi) {
#if defined(__BMI2__)
  lo = _mulx_u64(x, y, (unsigned long long *)&hi);
#else
  __uint128_t p = static_cast<__uint128_t>(x) * static_cast<__uint128_t>(y);
  lo = static_cast<uint64_t>(p);
  hi = static_cast<uint64_t>(p >> 64);
#endif
}

// Branchless conditional subtraction: returns r in [0, p)
static inline __attribute__((always_inline)) uint64_t cond_sub(uint64_t r,
                                                               uint64_t p) {
  return r >= p ? r - p : r;
}

// ---------- Optimized ReduceU128 (Barrett-style, CPU-paths: BMI2+ADX fast
// path) ----------

// Overload for signed __int128
uint64_t Modulus::ReduceU128(__int128 a) const {
  // Handle signed input by mapping to unsigned and applying negation when
  // needed
  if (a >= 0) {
    return ReduceU128(static_cast<__uint128_t>(a));
  } else {
    // Reduce |-a| then negate in modulus
    uint64_t r = ReduceU128(static_cast<__uint128_t>(-a));
    return Neg(r);
  }
}

uint64_t Modulus::ReduceU128Vt(__int128 a) const {
  // Variable-time path shares the same core arithmetic
  return ReduceU128(a);
}

// Overload for unsigned __uint128_t
uint64_t Modulus::ReduceU128(__uint128_t a) const {
  const uint64_t p = p_;
  const uint64_t ratio0 = barrett_lo_;
  const uint64_t ratio1 = barrett_hi_;

  const uint64_t a_lo = static_cast<uint64_t>(a);
  const uint64_t a_hi = static_cast<uint64_t>(a >> 64);

  // Use mul64_high for better performance on some architectures
  const uint64_t p_lo_lo_hi = mul64_high(a_lo, ratio0);
  const __uint128_t p_hi_lo = static_cast<__uint128_t>(a_hi) * ratio0;
  const __uint128_t p_lo_hi = static_cast<__uint128_t>(a_lo) * ratio1;

  const __uint128_t q = ((p_lo_hi + p_hi_lo + p_lo_lo_hi) >> 64) +
                        static_cast<__uint128_t>(a_hi) * ratio1;
  const uint64_t r = static_cast<uint64_t>(a - q * p);

  return r >= p ? r - p : r;
}

uint64_t Modulus::ReduceOptU128(__int128 a) const {
  if (a >= 0) {
    return ReduceOptU128(static_cast<__uint128_t>(a));
  } else {
    uint64_t r = ReduceOptU128(static_cast<__uint128_t>(-a));
    return Neg(r);
  }
}

uint64_t Modulus::ReduceOptU128Vt(__int128 a) const {
  if (a >= 0) {
    return ReduceOptU128Vt(static_cast<__uint128_t>(a));
  } else {
    uint64_t r = ReduceOptU128Vt(static_cast<__uint128_t>(-a));
    return NegVt(r);
  }
}

// Optimized reduction for unsigned __uint128_t
uint64_t Modulus::ReduceOptU128(__uint128_t a) const {
  // Optimized algorithm for special primes
  const uint64_t p = p_;
  const uint64_t ratio0 = barrett_lo_;
  const uint32_t lz = leading_zeros_;

  const uint64_t q = static_cast<uint64_t>(
      ((static_cast<__uint128_t>(ratio0) * (a >> 64)) + (a << lz)) >> 64);
  const uint64_t r = static_cast<uint64_t>(a - static_cast<__uint128_t>(q) * p);

  return r >= p ? r - p : r;
}

uint64_t Modulus::ReduceOptU128Vt(__uint128_t a) const {
  // Variable-time version
  const uint64_t p = p_;
  const uint64_t ratio0 = barrett_lo_;
  const uint32_t lz = leading_zeros_;

  const uint64_t q = static_cast<uint64_t>(
      ((static_cast<__uint128_t>(ratio0) * (a >> 64)) + (a << lz)) >> 64);
  const uint64_t r = static_cast<uint64_t>(a - static_cast<__uint128_t>(q) * p);

  return r >= p ? r - p : r;
}

// Modular multiplication
uint64_t Modulus::Mul(uint64_t a, uint64_t b) const {
  __uint128_t product = __uint128_t(a) * b;
  return ReduceU128(product);
}

uint64_t Modulus::MulVt(uint64_t a, uint64_t b) const {
  __uint128_t product = __uint128_t(a) * b;
  return ReduceU128(product);
}

uint64_t Modulus::MulOpt(uint64_t a, uint64_t b) const {
  __uint128_t product = __uint128_t(a) * b;
  return ReduceOptU128(product);
}

uint64_t Modulus::MulOptVt(uint64_t a, uint64_t b) const {
  __uint128_t product = __uint128_t(a) * b;
  return ReduceOptU128Vt(product);
}

// Shoup multiplication
uint64_t Modulus::MulShoup(uint64_t a, uint64_t b, uint64_t b_shoup) const {
  __uint128_t product = __uint128_t(a) * b;
  uint64_t q = static_cast<uint64_t>(((__uint128_t(a) * b_shoup) >> 64));
  uint64_t result = static_cast<uint64_t>(product) - q * p_;
  return result >= p_ ? result - p_ : result;
}

uint64_t Modulus::MulShoupVt(uint64_t a, uint64_t b, uint64_t b_shoup) const {
  return MulShoup(a, b, b_shoup);
}

uint64_t Modulus::LazyMulShoup(uint64_t a, uint64_t b, uint64_t q) const {
  // q is b_shoup = floor((b << 64) / p). Use high64(a * b_shoup).
  uint64_t quotient = static_cast<uint64_t>(((__uint128_t)a * q) >> 64);
  __uint128_t product = (__uint128_t)a * b;
  return static_cast<uint64_t>(product - (__uint128_t)quotient * p_);
}

// Optimized multiplication with precomputed operand
MultiplyUIntModOperand Modulus::PrepareMultiplyOperand(uint64_t operand) const {
  return MultiplyUIntModOperand(operand, p_);
}

uint64_t Modulus::MulOptimized(uint64_t x,
                               const MultiplyUIntModOperand &y) const {
  __uint128_t product = __uint128_t(x) * y.operand;
  uint64_t q = static_cast<uint64_t>(((__uint128_t(x) * y.quotient) >> 64));
  uint64_t result = static_cast<uint64_t>(product) - q * p_;
  return result >= p_ ? result - p_ : result;
}

uint64_t Modulus::MulOptimizedLazy(uint64_t x,
                                   const MultiplyUIntModOperand &y) const {
  return static_cast<uint64_t>(__uint128_t(x) * y.operand) -
         static_cast<uint64_t>(((__uint128_t(x) * y.quotient) >> 64)) * p_;
}

uint64_t Modulus::MulAddOptimized(uint64_t x, const MultiplyUIntModOperand &y,
                                  uint64_t acc) const {
  uint64_t prod =
      static_cast<uint64_t>((__uint128_t)x * y.operand) -
      static_cast<uint64_t>(((__uint128_t)x * y.quotient) >> 64) * p_;
  prod = cond_sub(prod, p_);
  return cond_sub(acc + prod, p_);
}

// Modular negation
uint64_t Modulus::Neg(uint64_t a) const { return a != 0 ? p_ - a : 0; }

uint64_t Modulus::NegVt(uint64_t a) const { return a == 0 ? 0 : p_ - a; }

// Modular reduction
uint64_t Modulus::Reduce(uint64_t a) const {
  const uint64_t p = p_;
  const uint64_t ratio_hi = barrett_hi_;
  uint64_t q_hat = mul64_high(a, ratio_hi);
  uint64_t r = a - q_hat * p;
  return cond_sub(r, p);
}

uint64_t Modulus::ReduceVt(uint64_t a) const {
  const uint64_t p = p_;
  const uint64_t ratio_hi = barrett_hi_;
  uint64_t q_hat = mul64_high(a, ratio_hi);
  uint64_t r = a - q_hat * p;
  return cond_sub(r, p);
}

uint64_t Modulus::ReduceOpt(uint64_t a) const {
  if (!supports_opt_) {
    return Reduce(a);
  }
  return cond_sub(a, p_);
}

uint64_t Modulus::ReduceOptVt(uint64_t a) const { return ReduceVt(a); }

uint64_t Modulus::ReduceI64(int64_t a) const {
  if (a >= 0) {
    return Reduce(static_cast<uint64_t>(a));
  } else {
    return Neg(Reduce(static_cast<uint64_t>(-a)));
  }
}

uint64_t Modulus::ReduceI64Vt(int64_t a) const {
  if (a >= 0) {
    return ReduceVt(static_cast<uint64_t>(a));
  } else {
    return NegVt(ReduceVt(static_cast<uint64_t>(-a)));
  }
}

uint64_t Modulus::Reduce1(uint64_t x, uint64_t mod) const {
  return x >= mod ? x - mod : x;
}

uint64_t Modulus::Reduce1Vt(uint64_t x, uint64_t mod) const {
  return x >= mod ? x - mod : x;
}

// Lazy reduction
uint64_t Modulus::LazyReduce(uint64_t a) const {
  // Fast path when a < 2p: single conditional subtraction
  uint64_t two_p = p_ << 1;
  if (a < two_p) {
    return cond_sub(a, p_);
  }
  // Fallback to Barrett lazy reduction to fold larger values down to [0, 2p)
  __uint128_t p_lo_lo = (static_cast<__uint128_t>(a) * barrett_lo_) >> 64;
  __uint128_t p_lo_hi = static_cast<__uint128_t>(a) * barrett_hi_;
  __uint128_t q = (p_lo_hi + p_lo_lo) >> 64;
  __uint128_t r = static_cast<__uint128_t>(a) - q * p_;
  return static_cast<uint64_t>(r);
}

uint64_t Modulus::LazyReduceU128(__uint128_t a) const {
  // Lazy variant: same quotient estimate, but keep result in [0, 2p)
  const uint64_t p = p_;
  const uint64_t ratio0 = barrett_lo_;
  const uint64_t ratio1 = barrett_hi_;
  const uint64_t in0 = static_cast<uint64_t>(a);
  const uint64_t in1 = static_cast<uint64_t>(a >> 64);

  if (in1 == 0) {
    // Fold to [0, 2p)
    return cond_sub(in0, p);
  }

  uint64_t carry = mul64_high(in0, ratio0);
  uint64_t tmp2_lo, tmp2_hi;
  mul64_128(in0, ratio1, tmp2_lo, tmp2_hi);
  uint64_t tmp1 = 0;
  uint64_t c1 = add64_carry(tmp2_lo, carry, tmp1);
  uint64_t tmp3 = tmp2_hi + c1;

  mul64_128(in1, ratio0, tmp2_lo, tmp2_hi);
  uint64_t c2 = add64_carry(tmp1, tmp2_lo, tmp1);
  carry = tmp2_hi + c2;

  uint64_t q_hat = in1 * ratio1 + tmp3 + carry;
  __uint128_t r128 = a - static_cast<__uint128_t>(q_hat) * p;
  return static_cast<uint64_t>(r128);
}

uint64_t Modulus::LazyReduceOpt(uint64_t a) const { return LazyReduce(a); }

uint64_t Modulus::LazyReduceOptU128(__int128 a) const {
  return LazyReduceU128(static_cast<__uint128_t>(a));
}

// Vector operations
// Vector operations
void Modulus::AddVec(std::vector<uint64_t> &a,
                     const std::vector<uint64_t> &b) const {
  AddVec(a.data(), b.data(), a.size());
}

void Modulus::AddVecVt(std::vector<uint64_t> &a,
                       const std::vector<uint64_t> &b) const {
  AddVecVt(a.data(), b.data(), a.size());
}

void Modulus::SubVec(std::vector<uint64_t> &a,
                     const std::vector<uint64_t> &b) const {
  SubVec(a.data(), b.data(), a.size());
}

void Modulus::SubVecVt(std::vector<uint64_t> &a,
                       const std::vector<uint64_t> &b) const {
  SubVecVt(a.data(), b.data(), a.size());
}

// Helper functions for AVX2
#ifdef __AVX2__
static inline __m256i add_mod_avx2(__m256i a, __m256i b, __m256i p) {
  __m256i sum = _mm256_add_epi64(a, b);
  __m256i diff = _mm256_sub_epi64(sum, p);
  __m256i p_minus_1 = _mm256_sub_epi64(p, _mm256_set1_epi64x(1));
  __m256i mask = _mm256_cmpgt_epi64(sum, p_minus_1);
  return _mm256_blendv_epi8(sum, diff, mask);
}

static inline __m256i sub_mod_avx2(__m256i a, __m256i b, __m256i p) {
  __m256i diff = _mm256_sub_epi64(a, b);
  __m256i mask = _mm256_cmpgt_epi64(b, a);
  __m256i add_p = _mm256_and_si256(mask, p);
  return _mm256_add_epi64(diff, add_p);
}
#endif

void Modulus::AddVec(uint64_t *a, const uint64_t *b, size_t n) const {
#ifdef __AVX2__
  if (impl_->runtime.has_avx2) {
    size_t i = 0;
    __m256i p_vec = _mm256_set1_epi64x(p_);
    for (; i + 3 < n; i += 4) {
      __m256i av = _mm256_loadu_si256(reinterpret_cast<const __m256i *>(a + i));
      __m256i bv = _mm256_loadu_si256(reinterpret_cast<const __m256i *>(b + i));
      __m256i res = add_mod_avx2(av, bv, p_vec);
      _mm256_storeu_si256(reinterpret_cast<__m256i *>(a + i), res);
    }
    for (; i < n; ++i) a[i] = Add(a[i], b[i]);
    return;
  }
#endif
  for (size_t i = 0; i < n; ++i) {
    a[i] = Add(a[i], b[i]);
  }
}

void Modulus::AddVecVt(uint64_t *a, const uint64_t *b, size_t n) const {
#ifdef __AVX2__
  if (impl_->runtime.has_avx2) {
    AddVec(a, b, n);
    return;
  }
#endif
  for (size_t i = 0; i < n; ++i) {
    a[i] = AddVt(a[i], b[i]);
  }
}

void Modulus::SubVec(uint64_t *a, const uint64_t *b, size_t n) const {
#ifdef __AVX2__
  if (impl_->runtime.has_avx2) {
    size_t i = 0;
    __m256i p_vec = _mm256_set1_epi64x(p_);
    for (; i + 3 < n; i += 4) {
      __m256i av = _mm256_loadu_si256(reinterpret_cast<const __m256i *>(a + i));
      __m256i bv = _mm256_loadu_si256(reinterpret_cast<const __m256i *>(b + i));
      __m256i res = sub_mod_avx2(av, bv, p_vec);
      _mm256_storeu_si256(reinterpret_cast<__m256i *>(a + i), res);
    }
    for (; i < n; ++i) a[i] = Sub(a[i], b[i]);
    return;
  }
#endif
  for (size_t i = 0; i < n; ++i) {
    a[i] = Sub(a[i], b[i]);
  }
}

void Modulus::SubVecVt(uint64_t *a, const uint64_t *b, size_t n) const {
#ifdef __AVX2__
  if (impl_->runtime.has_avx2) {
    SubVec(a, b, n);
    return;
  }
#endif
  for (size_t i = 0; i < n; ++i) {
    a[i] = SubVt(a[i], b[i]);
  }
}

void Modulus::MulVec(std::vector<uint64_t> &a,
                     const std::vector<uint64_t> &b) const {
  MulVec(a.data(), b.data(), a.size());
}

void Modulus::MulVecVt(std::vector<uint64_t> &a,
                       const std::vector<uint64_t> &b) const {
  MulVecVt(a.data(), b.data(), a.size());
}

void Modulus::MulVec(uint64_t *a, const uint64_t *b, size_t n) const {
  if (supports_opt_) {
    // Use optimized multiplication for special primes
    size_t i = 0;
    for (; i + 7 < n; i += 8) {
      a[i] = MulOpt(a[i], b[i]);
      a[i + 1] = MulOpt(a[i + 1], b[i + 1]);
      a[i + 2] = MulOpt(a[i + 2], b[i + 2]);
      a[i + 3] = MulOpt(a[i + 3], b[i + 3]);
      a[i + 4] = MulOpt(a[i + 4], b[i + 4]);
      a[i + 5] = MulOpt(a[i + 5], b[i + 5]);
      a[i + 6] = MulOpt(a[i + 6], b[i + 6]);
      a[i + 7] = MulOpt(a[i + 7], b[i + 7]);
    }
    for (; i < n; ++i) {
      a[i] = MulOpt(a[i], b[i]);
    }
  } else {
    // Standard Barrett reduction
    size_t i = 0;
    for (; i + 7 < n; i += 8) {
      a[i] = Mul(a[i], b[i]);
      a[i + 1] = Mul(a[i + 1], b[i + 1]);
      a[i + 2] = Mul(a[i + 2], b[i + 2]);
      a[i + 3] = Mul(a[i + 3], b[i + 3]);
      a[i + 4] = Mul(a[i + 4], b[i + 4]);
      a[i + 5] = Mul(a[i + 5], b[i + 5]);
      a[i + 6] = Mul(a[i + 6], b[i + 6]);
      a[i + 7] = Mul(a[i + 7], b[i + 7]);
    }
    for (; i < n; ++i) {
      a[i] = Mul(a[i], b[i]);
    }
  }
}

void Modulus::MulVecVt(uint64_t *a, const uint64_t *b, size_t n) const {
  if (supports_opt_) {
    // Use optimized multiplication for special primes
    size_t i = 0;
    for (; i + 7 < n; i += 8) {
      a[i] = MulOptVt(a[i], b[i]);
      a[i + 1] = MulOptVt(a[i + 1], b[i + 1]);
      a[i + 2] = MulOptVt(a[i + 2], b[i + 2]);
      a[i + 3] = MulOptVt(a[i + 3], b[i + 3]);
      a[i + 4] = MulOptVt(a[i + 4], b[i + 4]);
      a[i + 5] = MulOptVt(a[i + 5], b[i + 5]);
      a[i + 6] = MulOptVt(a[i + 6], b[i + 6]);
      a[i + 7] = MulOptVt(a[i + 7], b[i + 7]);
    }
    for (; i < n; ++i) {
      a[i] = MulOptVt(a[i], b[i]);
    }
  } else {
    // Standard Barrett reduction
    size_t i = 0;
    for (; i + 7 < n; i += 8) {
      a[i] = MulVt(a[i], b[i]);
      a[i + 1] = MulVt(a[i + 1], b[i + 1]);
      a[i + 2] = MulVt(a[i + 2], b[i + 2]);
      a[i + 3] = MulVt(a[i + 3], b[i + 3]);
      a[i + 4] = MulVt(a[i + 4], b[i + 4]);
      a[i + 5] = MulVt(a[i + 5], b[i + 5]);
      a[i + 6] = MulVt(a[i + 6], b[i + 6]);
      a[i + 7] = MulVt(a[i + 7], b[i + 7]);
    }
    for (; i < n; ++i) {
      a[i] = MulVt(a[i], b[i]);
    }
  }
}

void Modulus::MulTo(uint64_t *dst, const uint64_t *a, const uint64_t *b,
                    size_t n) const {
  if (supports_opt_) {
    size_t i = 0;
    for (; i + 7 < n; i += 8) {
      dst[i] = MulOpt(a[i], b[i]);
      dst[i + 1] = MulOpt(a[i + 1], b[i + 1]);
      dst[i + 2] = MulOpt(a[i + 2], b[i + 2]);
      dst[i + 3] = MulOpt(a[i + 3], b[i + 3]);
      dst[i + 4] = MulOpt(a[i + 4], b[i + 4]);
      dst[i + 5] = MulOpt(a[i + 5], b[i + 5]);
      dst[i + 6] = MulOpt(a[i + 6], b[i + 6]);
      dst[i + 7] = MulOpt(a[i + 7], b[i + 7]);
    }
    for (; i < n; ++i) {
      dst[i] = MulOpt(a[i], b[i]);
    }
  } else {
    size_t i = 0;
    for (; i + 7 < n; i += 8) {
      dst[i] = Mul(a[i], b[i]);
      dst[i + 1] = Mul(a[i + 1], b[i + 1]);
      dst[i + 2] = Mul(a[i + 2], b[i + 2]);
      dst[i + 3] = Mul(a[i + 3], b[i + 3]);
      dst[i + 4] = Mul(a[i + 4], b[i + 4]);
      dst[i + 5] = Mul(a[i + 5], b[i + 5]);
      dst[i + 6] = Mul(a[i + 6], b[i + 6]);
      dst[i + 7] = Mul(a[i + 7], b[i + 7]);
    }
    for (; i < n; ++i) {
      dst[i] = Mul(a[i], b[i]);
    }
  }
}

void Modulus::MulToVt(uint64_t *dst, const uint64_t *a, const uint64_t *b,
                      size_t n) const {
  if (supports_opt_) {
    size_t i = 0;
    for (; i + 7 < n; i += 8) {
      dst[i] = MulOptVt(a[i], b[i]);
      dst[i + 1] = MulOptVt(a[i + 1], b[i + 1]);
      dst[i + 2] = MulOptVt(a[i + 2], b[i + 2]);
      dst[i + 3] = MulOptVt(a[i + 3], b[i + 3]);
      dst[i + 4] = MulOptVt(a[i + 4], b[i + 4]);
      dst[i + 5] = MulOptVt(a[i + 5], b[i + 5]);
      dst[i + 6] = MulOptVt(a[i + 6], b[i + 6]);
      dst[i + 7] = MulOptVt(a[i + 7], b[i + 7]);
    }
    for (; i < n; ++i) {
      dst[i] = MulOptVt(a[i], b[i]);
    }
  } else {
    size_t i = 0;
    for (; i + 7 < n; i += 8) {
      dst[i] = MulVt(a[i], b[i]);
      dst[i + 1] = MulVt(a[i + 1], b[i + 1]);
      dst[i + 2] = MulVt(a[i + 2], b[i + 2]);
      dst[i + 3] = MulVt(a[i + 3], b[i + 3]);
      dst[i + 4] = MulVt(a[i + 4], b[i + 4]);
      dst[i + 5] = MulVt(a[i + 5], b[i + 5]);
      dst[i + 6] = MulVt(a[i + 6], b[i + 6]);
      dst[i + 7] = MulVt(a[i + 7], b[i + 7]);
    }
    for (; i < n; ++i) {
      dst[i] = MulVt(a[i], b[i]);
    }
  }
}

void Modulus::MulOptimizedVec(
    std::vector<uint64_t> &a,
    const std::vector<MultiplyUIntModOperand> &b_precomp) const {
  // Assume a.size() == b_precomp.size(); caller ensures sizing
  const size_t n = a.size();
  size_t i = 0;
  for (; i + 7 < n; i += 8) {
    a[i] = MulOptimized(a[i], b_precomp[i]);
    a[i + 1] = MulOptimized(a[i + 1], b_precomp[i + 1]);
    a[i + 2] = MulOptimized(a[i + 2], b_precomp[i + 2]);
    a[i + 3] = MulOptimized(a[i + 3], b_precomp[i + 3]);
    a[i + 4] = MulOptimized(a[i + 4], b_precomp[i + 4]);
    a[i + 5] = MulOptimized(a[i + 5], b_precomp[i + 5]);
    a[i + 6] = MulOptimized(a[i + 6], b_precomp[i + 6]);
    a[i + 7] = MulOptimized(a[i + 7], b_precomp[i + 7]);
  }
  for (; i < n; ++i) {
    a[i] = MulOptimized(a[i], b_precomp[i]);
  }
}

void Modulus::MulOptimizedVecLazy(
    std::vector<uint64_t> &a,
    const std::vector<MultiplyUIntModOperand> &b_precomp) const {
  // Result kept in [0, 2p); useful for subsequent lazy operations
  const uint64_t p = p_;
  const size_t n = a.size();
  size_t i = 0;
  for (; i + 7 < n; i += 8) {
    uint64_t x = a[i];
    const auto &y = b_precomp[i];
    uint64_t r = static_cast<uint64_t>((__uint128_t)x * y.operand) -
                 static_cast<uint64_t>(((__uint128_t)x * y.quotient) >> 64) * p;
    a[i] = r;  // leave as-is; caller may reduce later

    x = a[i + 1];
    const auto &y1 = b_precomp[i + 1];
    r = static_cast<uint64_t>((__uint128_t)x * y1.operand) -
        static_cast<uint64_t>(((__uint128_t)x * y1.quotient) >> 64) * p;
    a[i + 1] = r;

    x = a[i + 2];
    const auto &y2 = b_precomp[i + 2];
    r = static_cast<uint64_t>((__uint128_t)x * y2.operand) -
        static_cast<uint64_t>(((__uint128_t)x * y2.quotient) >> 64) * p;
    a[i + 2] = r;

    x = a[i + 3];
    const auto &y3 = b_precomp[i + 3];
    r = static_cast<uint64_t>((__uint128_t)x * y3.operand) -
        static_cast<uint64_t>(((__uint128_t)x * y3.quotient) >> 64) * p;
    a[i + 3] = r;

    x = a[i + 4];
    const auto &y4 = b_precomp[i + 4];
    r = static_cast<uint64_t>((__uint128_t)x * y4.operand) -
        static_cast<uint64_t>(((__uint128_t)x * y4.quotient) >> 64) * p;
    a[i + 4] = r;

    x = a[i + 5];
    const auto &y5 = b_precomp[i + 5];
    r = static_cast<uint64_t>((__uint128_t)x * y5.operand) -
        static_cast<uint64_t>(((__uint128_t)x * y5.quotient) >> 64) * p;
    a[i + 5] = r;

    x = a[i + 6];
    const auto &y6 = b_precomp[i + 6];
    r = static_cast<uint64_t>((__uint128_t)x * y6.operand) -
        static_cast<uint64_t>(((__uint128_t)x * y6.quotient) >> 64) * p;
    a[i + 6] = r;

    x = a[i + 7];
    const auto &y7 = b_precomp[i + 7];
    r = static_cast<uint64_t>((__uint128_t)x * y7.operand) -
        static_cast<uint64_t>(((__uint128_t)x * y7.quotient) >> 64) * p;
    a[i + 7] = r;
  }
  for (; i < n; ++i) {
    uint64_t x = a[i];
    const auto &y = b_precomp[i];
    uint64_t r = static_cast<uint64_t>((__uint128_t)x * y.operand) -
                 static_cast<uint64_t>(((__uint128_t)x * y.quotient) >> 64) * p;
    a[i] = r;
  }
}

void Modulus::ScalarMulVec(std::vector<uint64_t> &a, uint64_t b) const {
  ScalarMulVec(a.data(), a.size(), b);
}

void Modulus::ScalarMulVecVt(std::vector<uint64_t> &a, uint64_t b) const {
  ScalarMulVecVt(a.data(), a.size(), b);
}

void Modulus::ScalarMulVec(uint64_t *a, size_t n, uint64_t b) const {
  MultiplyUIntModOperand y = PrepareMultiplyOperand(b);
  // Cache modulus locally to avoid repeated PIMPL pointer-chase on every coeff.
  const uint64_t p = p_;
  size_t i = 0;
  for (; i + 7 < n; i += 8) {
    auto do_mul = [&](uint64_t x) -> uint64_t {
      __uint128_t product = __uint128_t(x) * y.operand;
      uint64_t q = static_cast<uint64_t>(((__uint128_t(x) * y.quotient) >> 64));
      uint64_t result = static_cast<uint64_t>(product) - q * p;
      return cond_sub(result, p);
    };
    a[i] = do_mul(a[i]);
    a[i + 1] = do_mul(a[i + 1]);
    a[i + 2] = do_mul(a[i + 2]);
    a[i + 3] = do_mul(a[i + 3]);
    a[i + 4] = do_mul(a[i + 4]);
    a[i + 5] = do_mul(a[i + 5]);
    a[i + 6] = do_mul(a[i + 6]);
    a[i + 7] = do_mul(a[i + 7]);
  }
  for (; i < n; ++i) {
    __uint128_t product = __uint128_t(a[i]) * y.operand;
    uint64_t q =
        static_cast<uint64_t>(((__uint128_t(a[i]) * y.quotient) >> 64));
    uint64_t result = static_cast<uint64_t>(product) - q * p;
    a[i] = cond_sub(result, p);
  }
}

void Modulus::ScalarMulVecVt(uint64_t *a, size_t n, uint64_t b) const {
  MultiplyUIntModOperand y = PrepareMultiplyOperand(b);
  const uint64_t p = p_;
  size_t i = 0;
  auto do_mul = [&](uint64_t x) -> uint64_t {
    __uint128_t product = __uint128_t(x) * y.operand;
    uint64_t q = static_cast<uint64_t>(((__uint128_t)x * y.quotient) >> 64);
    uint64_t result = static_cast<uint64_t>(product) - q * p;
    return cond_sub(result, p);
  };
  for (; i + 7 < n; i += 8) {
    a[i] = do_mul(a[i]);
    a[i + 1] = do_mul(a[i + 1]);
    a[i + 2] = do_mul(a[i + 2]);
    a[i + 3] = do_mul(a[i + 3]);
    a[i + 4] = do_mul(a[i + 4]);
    a[i + 5] = do_mul(a[i + 5]);
    a[i + 6] = do_mul(a[i + 6]);
    a[i + 7] = do_mul(a[i + 7]);
  }
  for (; i < n; ++i) {
    a[i] = do_mul(a[i]);
  }
}

void Modulus::ScalarMulTo(uint64_t *dst, const uint64_t *src, size_t n,
                          uint64_t b) const {
  MultiplyUIntModOperand y = PrepareMultiplyOperand(b);
  const uint64_t p = p_;
  size_t i = 0;
  auto do_mul = [&](uint64_t x) -> uint64_t {
    __uint128_t product = __uint128_t(x) * y.operand;
    uint64_t q = static_cast<uint64_t>(((__uint128_t)x * y.quotient) >> 64);
    uint64_t result = static_cast<uint64_t>(product) - q * p;
    return cond_sub(result, p);
  };
  for (; i + 7 < n; i += 8) {
    dst[i] = do_mul(src[i]);
    dst[i + 1] = do_mul(src[i + 1]);
    dst[i + 2] = do_mul(src[i + 2]);
    dst[i + 3] = do_mul(src[i + 3]);
    dst[i + 4] = do_mul(src[i + 4]);
    dst[i + 5] = do_mul(src[i + 5]);
    dst[i + 6] = do_mul(src[i + 6]);
    dst[i + 7] = do_mul(src[i + 7]);
  }
  for (; i < n; ++i) {
    dst[i] = do_mul(src[i]);
  }
}

void Modulus::ScalarMulToVt(uint64_t *dst, const uint64_t *src, size_t n,
                            uint64_t b) const {
  MultiplyUIntModOperand y = PrepareMultiplyOperand(b);
  const uint64_t p = p_;
  size_t i = 0;
  auto do_mul = [&](uint64_t x) -> uint64_t {
    __uint128_t product = __uint128_t(x) * y.operand;
    uint64_t q = static_cast<uint64_t>(((__uint128_t)x * y.quotient) >> 64);
    uint64_t result = static_cast<uint64_t>(product) - q * p;
    return cond_sub(result, p);
  };
  for (; i + 7 < n; i += 8) {
    dst[i] = do_mul(src[i]);
    dst[i + 1] = do_mul(src[i + 1]);
    dst[i + 2] = do_mul(src[i + 2]);
    dst[i + 3] = do_mul(src[i + 3]);
    dst[i + 4] = do_mul(src[i + 4]);
    dst[i + 5] = do_mul(src[i + 5]);
    dst[i + 6] = do_mul(src[i + 6]);
    dst[i + 7] = do_mul(src[i + 7]);
  }
  for (; i < n; ++i) {
    dst[i] = do_mul(src[i]);
  }
}

std::vector<uint64_t> Modulus::ShoupVec(const std::vector<uint64_t> &a) const {
  std::vector<uint64_t> result(a.size());
  for (size_t i = 0; i < a.size(); ++i) {
    result[i] = Shoup(a[i]);
  }
  return result;
}

void Modulus::MulShoupVec(std::vector<uint64_t> &a,
                          const std::vector<uint64_t> &b,
                          const std::vector<uint64_t> &b_shoup) const {
  MulShoupVec(a.data(), b.data(), b_shoup.data(), a.size());
}

void Modulus::MulShoupVecVt(std::vector<uint64_t> &a,
                            const std::vector<uint64_t> &b,
                            const std::vector<uint64_t> &b_shoup) const {
  MulShoupVecVt(a.data(), b.data(), b_shoup.data(), a.size());
}

void Modulus::MulShoupVec(uint64_t *a, const uint64_t *b,
                          const uint64_t *b_shoup, size_t n) const {
  const uint64_t p = p_;
  size_t i = 0;

  // Optimized 8x loop unrolling with better instruction scheduling
  for (; i + 7 < n; i += 8) {
    uint64_t x0 = a[i];
    uint64_t y0 = b[i];
    uint64_t q0 = static_cast<uint64_t>(((__uint128_t)x0 * b_shoup[i]) >> 64);
    __uint128_t prod0 = (__uint128_t)x0 * y0;
    uint64_t r0 = static_cast<uint64_t>(prod0) - q0 * p;
    a[i] = cond_sub(r0, p);

    uint64_t x1 = a[i + 1];
    uint64_t y1 = b[i + 1];
    uint64_t q1 =
        static_cast<uint64_t>(((__uint128_t)x1 * b_shoup[i + 1]) >> 64);
    __uint128_t prod1 = (__uint128_t)x1 * y1;
    uint64_t r1 = static_cast<uint64_t>(prod1) - q1 * p;
    a[i + 1] = cond_sub(r1, p);

    uint64_t x2 = a[i + 2];
    uint64_t y2 = b[i + 2];
    uint64_t q2 =
        static_cast<uint64_t>(((__uint128_t)x2 * b_shoup[i + 2]) >> 64);
    __uint128_t prod2 = (__uint128_t)x2 * y2;
    uint64_t r2 = static_cast<uint64_t>(prod2) - q2 * p;
    a[i + 2] = cond_sub(r2, p);

    uint64_t x3 = a[i + 3];
    uint64_t y3 = b[i + 3];
    uint64_t q3 =
        static_cast<uint64_t>(((__uint128_t)x3 * b_shoup[i + 3]) >> 64);
    __uint128_t prod3 = (__uint128_t)x3 * y3;
    uint64_t r3 = static_cast<uint64_t>(prod3) - q3 * p;
    a[i + 3] = cond_sub(r3, p);

    uint64_t x4 = a[i + 4];
    uint64_t y4 = b[i + 4];
    uint64_t q4 =
        static_cast<uint64_t>(((__uint128_t)x4 * b_shoup[i + 4]) >> 64);
    __uint128_t prod4 = (__uint128_t)x4 * y4;
    uint64_t r4 = static_cast<uint64_t>(prod4) - q4 * p;
    a[i + 4] = cond_sub(r4, p);

    uint64_t x5 = a[i + 5];
    uint64_t y5 = b[i + 5];
    uint64_t q5 =
        static_cast<uint64_t>(((__uint128_t)x5 * b_shoup[i + 5]) >> 64);
    __uint128_t prod5 = (__uint128_t)x5 * y5;
    uint64_t r5 = static_cast<uint64_t>(prod5) - q5 * p;
    a[i + 5] = cond_sub(r5, p);

    uint64_t x6 = a[i + 6];
    uint64_t y6 = b[i + 6];
    uint64_t q6 =
        static_cast<uint64_t>(((__uint128_t)x6 * b_shoup[i + 6]) >> 64);
    __uint128_t prod6 = (__uint128_t)x6 * y6;
    uint64_t r6 = static_cast<uint64_t>(prod6) - q6 * p;
    a[i + 6] = cond_sub(r6, p);

    uint64_t x7 = a[i + 7];
    uint64_t y7 = b[i + 7];
    uint64_t q7 =
        static_cast<uint64_t>(((__uint128_t)x7 * b_shoup[i + 7]) >> 64);
    __uint128_t prod7 = (__uint128_t)x7 * y7;
    uint64_t r7 = static_cast<uint64_t>(prod7) - q7 * p;
    a[i + 7] = cond_sub(r7, p);
  }
  for (; i < n; ++i) {
    uint64_t x = a[i];
    uint64_t y = b[i];
    uint64_t q = static_cast<uint64_t>(((__uint128_t)x * b_shoup[i]) >> 64);
    __uint128_t prod = (__uint128_t)x * y;
    uint64_t r = static_cast<uint64_t>(prod) - q * p;
    a[i] = cond_sub(r, p);
  }
}

void Modulus::MulShoupVecVt(uint64_t *a, const uint64_t *b,
                            const uint64_t *b_shoup, size_t n) const {
  const uint64_t p = p_;
  // 8x loop unrolling
  size_t i = 0;
  for (; i + 7 < n; i += 8) {
    uint64_t x0 = a[i];
    uint64_t y0 = b[i];
    uint64_t q0 = static_cast<uint64_t>(((__uint128_t)x0 * b_shoup[i]) >> 64);
    __uint128_t prod0 = (__uint128_t)x0 * y0;
    uint64_t r0 = static_cast<uint64_t>(prod0) - q0 * p;
    a[i] = cond_sub(r0, p);

    uint64_t x1 = a[i + 1];
    uint64_t y1 = b[i + 1];
    uint64_t q1 =
        static_cast<uint64_t>(((__uint128_t)x1 * b_shoup[i + 1]) >> 64);
    __uint128_t prod1 = (__uint128_t)x1 * y1;
    uint64_t r1 = static_cast<uint64_t>(prod1) - q1 * p;
    a[i + 1] = cond_sub(r1, p);

    uint64_t x2 = a[i + 2];
    uint64_t y2 = b[i + 2];
    uint64_t q2 =
        static_cast<uint64_t>(((__uint128_t)x2 * b_shoup[i + 2]) >> 64);
    __uint128_t prod2 = (__uint128_t)x2 * y2;
    uint64_t r2 = static_cast<uint64_t>(prod2) - q2 * p;
    a[i + 2] = cond_sub(r2, p);

    uint64_t x3 = a[i + 3];
    uint64_t y3 = b[i + 3];
    uint64_t q3 =
        static_cast<uint64_t>(((__uint128_t)x3 * b_shoup[i + 3]) >> 64);
    __uint128_t prod3 = (__uint128_t)x3 * y3;
    uint64_t r3 = static_cast<uint64_t>(prod3) - q3 * p;
    a[i + 3] = cond_sub(r3, p);

    uint64_t x4 = a[i + 4];
    uint64_t y4 = b[i + 4];
    uint64_t q4 =
        static_cast<uint64_t>(((__uint128_t)x4 * b_shoup[i + 4]) >> 64);
    __uint128_t prod4 = (__uint128_t)x4 * y4;
    uint64_t r4 = static_cast<uint64_t>(prod4) - q4 * p;
    a[i + 4] = cond_sub(r4, p);

    uint64_t x5 = a[i + 5];
    uint64_t y5 = b[i + 5];
    uint64_t q5 =
        static_cast<uint64_t>(((__uint128_t)x5 * b_shoup[i + 5]) >> 64);
    __uint128_t prod5 = (__uint128_t)x5 * y5;
    uint64_t r5 = static_cast<uint64_t>(prod5) - q5 * p;
    a[i + 5] = cond_sub(r5, p);

    uint64_t x6 = a[i + 6];
    uint64_t y6 = b[i + 6];
    uint64_t q6 =
        static_cast<uint64_t>(((__uint128_t)x6 * b_shoup[i + 6]) >> 64);
    __uint128_t prod6 = (__uint128_t)x6 * y6;
    uint64_t r6 = static_cast<uint64_t>(prod6) - q6 * p;
    a[i + 6] = cond_sub(r6, p);

    uint64_t x7 = a[i + 7];
    uint64_t y7 = b[i + 7];
    uint64_t q7 =
        static_cast<uint64_t>(((__uint128_t)x7 * b_shoup[i + 7]) >> 64);
    __uint128_t prod7 = (__uint128_t)x7 * y7;
    uint64_t r7 = static_cast<uint64_t>(prod7) - q7 * p;
    a[i + 7] = cond_sub(r7, p);
  }
  for (; i < n; ++i) {
    uint64_t x = a[i];
    uint64_t y = b[i];
    uint64_t q = static_cast<uint64_t>(((__uint128_t)x * b_shoup[i]) >> 64);
    __uint128_t prod = (__uint128_t)x * y;
    uint64_t r = static_cast<uint64_t>(prod) - q * p;
    a[i] = cond_sub(r, p);
  }
}

void Modulus::MulAddVec(uint64_t *acc, const uint64_t *a, const uint64_t *b,
                        size_t n) const {
  const uint64_t p = p_;
  size_t i = 0;
  if (supports_opt_) {
    for (; i + 7 < n; i += 8) {
      uint64_t p0 = MulOpt(a[i], b[i]);
      uint64_t p1 = MulOpt(a[i + 1], b[i + 1]);
      uint64_t p2 = MulOpt(a[i + 2], b[i + 2]);
      uint64_t p3 = MulOpt(a[i + 3], b[i + 3]);
      uint64_t p4 = MulOpt(a[i + 4], b[i + 4]);
      uint64_t p5 = MulOpt(a[i + 5], b[i + 5]);
      uint64_t p6 = MulOpt(a[i + 6], b[i + 6]);
      uint64_t p7 = MulOpt(a[i + 7], b[i + 7]);
      acc[i] = cond_sub(acc[i] + p0, p);
      acc[i + 1] = cond_sub(acc[i + 1] + p1, p);
      acc[i + 2] = cond_sub(acc[i + 2] + p2, p);
      acc[i + 3] = cond_sub(acc[i + 3] + p3, p);
      acc[i + 4] = cond_sub(acc[i + 4] + p4, p);
      acc[i + 5] = cond_sub(acc[i + 5] + p5, p);
      acc[i + 6] = cond_sub(acc[i + 6] + p6, p);
      acc[i + 7] = cond_sub(acc[i + 7] + p7, p);
    }
    for (; i < n; ++i) {
      acc[i] = cond_sub(acc[i] + MulOpt(a[i], b[i]), p);
    }
  } else {
    for (; i + 7 < n; i += 8) {
      uint64_t p0 = Mul(a[i], b[i]);
      uint64_t p1 = Mul(a[i + 1], b[i + 1]);
      uint64_t p2 = Mul(a[i + 2], b[i + 2]);
      uint64_t p3 = Mul(a[i + 3], b[i + 3]);
      uint64_t p4 = Mul(a[i + 4], b[i + 4]);
      uint64_t p5 = Mul(a[i + 5], b[i + 5]);
      uint64_t p6 = Mul(a[i + 6], b[i + 6]);
      uint64_t p7 = Mul(a[i + 7], b[i + 7]);
      acc[i] = cond_sub(acc[i] + p0, p);
      acc[i + 1] = cond_sub(acc[i + 1] + p1, p);
      acc[i + 2] = cond_sub(acc[i + 2] + p2, p);
      acc[i + 3] = cond_sub(acc[i + 3] + p3, p);
      acc[i + 4] = cond_sub(acc[i + 4] + p4, p);
      acc[i + 5] = cond_sub(acc[i + 5] + p5, p);
      acc[i + 6] = cond_sub(acc[i + 6] + p6, p);
      acc[i + 7] = cond_sub(acc[i + 7] + p7, p);
    }
    for (; i < n; ++i) {
      acc[i] = cond_sub(acc[i] + Mul(a[i], b[i]), p);
    }
  }
}

void Modulus::MulAddVecVt(uint64_t *acc, const uint64_t *a, const uint64_t *b,
                          size_t n) const {
  const uint64_t p = p_;
  size_t i = 0;
  if (supports_opt_) {
    for (; i + 7 < n; i += 8) {
      uint64_t p0 = MulOptVt(a[i], b[i]);
      uint64_t p1 = MulOptVt(a[i + 1], b[i + 1]);
      uint64_t p2 = MulOptVt(a[i + 2], b[i + 2]);
      uint64_t p3 = MulOptVt(a[i + 3], b[i + 3]);
      uint64_t p4 = MulOptVt(a[i + 4], b[i + 4]);
      uint64_t p5 = MulOptVt(a[i + 5], b[i + 5]);
      uint64_t p6 = MulOptVt(a[i + 6], b[i + 6]);
      uint64_t p7 = MulOptVt(a[i + 7], b[i + 7]);
      uint64_t s0 = acc[i] + p0;
      uint64_t s1 = acc[i + 1] + p1;
      uint64_t s2 = acc[i + 2] + p2;
      uint64_t s3 = acc[i + 3] + p3;
      uint64_t s4 = acc[i + 4] + p4;
      uint64_t s5 = acc[i + 5] + p5;
      uint64_t s6 = acc[i + 6] + p6;
      uint64_t s7 = acc[i + 7] + p7;
      acc[i] = (s0 >= p) ? (s0 - p) : s0;
      acc[i + 1] = (s1 >= p) ? (s1 - p) : s1;
      acc[i + 2] = (s2 >= p) ? (s2 - p) : s2;
      acc[i + 3] = (s3 >= p) ? (s3 - p) : s3;
      acc[i + 4] = (s4 >= p) ? (s4 - p) : s4;
      acc[i + 5] = (s5 >= p) ? (s5 - p) : s5;
      acc[i + 6] = (s6 >= p) ? (s6 - p) : s6;
      acc[i + 7] = (s7 >= p) ? (s7 - p) : s7;
    }
    for (; i < n; ++i) {
      uint64_t sum = acc[i] + MulOptVt(a[i], b[i]);
      acc[i] = (sum >= p) ? (sum - p) : sum;
    }
  } else {
    for (; i + 7 < n; i += 8) {
      uint64_t p0 = MulVt(a[i], b[i]);
      uint64_t p1 = MulVt(a[i + 1], b[i + 1]);
      uint64_t p2 = MulVt(a[i + 2], b[i + 2]);
      uint64_t p3 = MulVt(a[i + 3], b[i + 3]);
      uint64_t p4 = MulVt(a[i + 4], b[i + 4]);
      uint64_t p5 = MulVt(a[i + 5], b[i + 5]);
      uint64_t p6 = MulVt(a[i + 6], b[i + 6]);
      uint64_t p7 = MulVt(a[i + 7], b[i + 7]);
      uint64_t s0 = acc[i] + p0;
      uint64_t s1 = acc[i + 1] + p1;
      uint64_t s2 = acc[i + 2] + p2;
      uint64_t s3 = acc[i + 3] + p3;
      uint64_t s4 = acc[i + 4] + p4;
      uint64_t s5 = acc[i + 5] + p5;
      uint64_t s6 = acc[i + 6] + p6;
      uint64_t s7 = acc[i + 7] + p7;
      acc[i] = (s0 >= p) ? (s0 - p) : s0;
      acc[i + 1] = (s1 >= p) ? (s1 - p) : s1;
      acc[i + 2] = (s2 >= p) ? (s2 - p) : s2;
      acc[i + 3] = (s3 >= p) ? (s3 - p) : s3;
      acc[i + 4] = (s4 >= p) ? (s4 - p) : s4;
      acc[i + 5] = (s5 >= p) ? (s5 - p) : s5;
      acc[i + 6] = (s6 >= p) ? (s6 - p) : s6;
      acc[i + 7] = (s7 >= p) ? (s7 - p) : s7;
    }
    for (; i < n; ++i) {
      uint64_t sum = acc[i] + MulVt(a[i], b[i]);
      acc[i] = (sum >= p) ? (sum - p) : sum;
    }
  }
}

void Modulus::MulAddShoupVec(uint64_t *acc, const uint64_t *a,
                             const uint64_t *b, const uint64_t *b_shoup,
                             size_t n) const {
  const uint64_t p = p_;
  size_t i = 0;
  for (; i + 7 < n; i += 8) {
    uint64_t x0 = a[i];
    uint64_t q0 = static_cast<uint64_t>(((__uint128_t)x0 * b_shoup[i]) >> 64);
    uint64_t r0 = static_cast<uint64_t>((__uint128_t)x0 * b[i]) - q0 * p;
    acc[i] = cond_sub(acc[i] + cond_sub(r0, p), p);

    uint64_t x1 = a[i + 1];
    uint64_t q1 =
        static_cast<uint64_t>(((__uint128_t)x1 * b_shoup[i + 1]) >> 64);
    uint64_t r1 = static_cast<uint64_t>((__uint128_t)x1 * b[i + 1]) - q1 * p;
    acc[i + 1] = cond_sub(acc[i + 1] + cond_sub(r1, p), p);

    uint64_t x2 = a[i + 2];
    uint64_t q2 =
        static_cast<uint64_t>(((__uint128_t)x2 * b_shoup[i + 2]) >> 64);
    uint64_t r2 = static_cast<uint64_t>((__uint128_t)x2 * b[i + 2]) - q2 * p;
    acc[i + 2] = cond_sub(acc[i + 2] + cond_sub(r2, p), p);

    uint64_t x3 = a[i + 3];
    uint64_t q3 =
        static_cast<uint64_t>(((__uint128_t)x3 * b_shoup[i + 3]) >> 64);
    uint64_t r3 = static_cast<uint64_t>((__uint128_t)x3 * b[i + 3]) - q3 * p;
    acc[i + 3] = cond_sub(acc[i + 3] + cond_sub(r3, p), p);

    uint64_t x4 = a[i + 4];
    uint64_t q4 =
        static_cast<uint64_t>(((__uint128_t)x4 * b_shoup[i + 4]) >> 64);
    uint64_t r4 = static_cast<uint64_t>((__uint128_t)x4 * b[i + 4]) - q4 * p;
    acc[i + 4] = cond_sub(acc[i + 4] + cond_sub(r4, p), p);

    uint64_t x5 = a[i + 5];
    uint64_t q5 =
        static_cast<uint64_t>(((__uint128_t)x5 * b_shoup[i + 5]) >> 64);
    uint64_t r5 = static_cast<uint64_t>((__uint128_t)x5 * b[i + 5]) - q5 * p;
    acc[i + 5] = cond_sub(acc[i + 5] + cond_sub(r5, p), p);

    uint64_t x6 = a[i + 6];
    uint64_t q6 =
        static_cast<uint64_t>(((__uint128_t)x6 * b_shoup[i + 6]) >> 64);
    uint64_t r6 = static_cast<uint64_t>((__uint128_t)x6 * b[i + 6]) - q6 * p;
    acc[i + 6] = cond_sub(acc[i + 6] + cond_sub(r6, p), p);

    uint64_t x7 = a[i + 7];
    uint64_t q7 =
        static_cast<uint64_t>(((__uint128_t)x7 * b_shoup[i + 7]) >> 64);
    uint64_t r7 = static_cast<uint64_t>((__uint128_t)x7 * b[i + 7]) - q7 * p;
    acc[i + 7] = cond_sub(acc[i + 7] + cond_sub(r7, p), p);
  }
  for (; i < n; ++i) {
    uint64_t q = static_cast<uint64_t>(((__uint128_t)a[i] * b_shoup[i]) >> 64);
    uint64_t r = static_cast<uint64_t>((__uint128_t)a[i] * b[i]) - q * p;
    acc[i] = cond_sub(acc[i] + cond_sub(r, p), p);
  }
}

void Modulus::MulAddShoupVecVt(uint64_t *acc, const uint64_t *a,
                               const uint64_t *b, const uint64_t *b_shoup,
                               size_t n) const {
  const uint64_t p = p_;
  size_t i = 0;
  for (; i + 7 < n; i += 8) {
    uint64_t x0 = a[i];
    uint64_t q0 = static_cast<uint64_t>(((__uint128_t)x0 * b_shoup[i]) >> 64);
    uint64_t r0 = static_cast<uint64_t>((__uint128_t)x0 * b[i]) - q0 * p;
    r0 = (r0 >= p) ? (r0 - p) : r0;
    uint64_t s0 = acc[i] + r0;
    acc[i] = (s0 >= p) ? (s0 - p) : s0;

    uint64_t x1 = a[i + 1];
    uint64_t q1 =
        static_cast<uint64_t>(((__uint128_t)x1 * b_shoup[i + 1]) >> 64);
    uint64_t r1 = static_cast<uint64_t>((__uint128_t)x1 * b[i + 1]) - q1 * p;
    r1 = (r1 >= p) ? (r1 - p) : r1;
    uint64_t s1 = acc[i + 1] + r1;
    acc[i + 1] = (s1 >= p) ? (s1 - p) : s1;

    uint64_t x2 = a[i + 2];
    uint64_t q2 =
        static_cast<uint64_t>(((__uint128_t)x2 * b_shoup[i + 2]) >> 64);
    uint64_t r2 = static_cast<uint64_t>((__uint128_t)x2 * b[i + 2]) - q2 * p;
    r2 = (r2 >= p) ? (r2 - p) : r2;
    uint64_t s2 = acc[i + 2] + r2;
    acc[i + 2] = (s2 >= p) ? (s2 - p) : s2;

    uint64_t x3 = a[i + 3];
    uint64_t q3 =
        static_cast<uint64_t>(((__uint128_t)x3 * b_shoup[i + 3]) >> 64);
    uint64_t r3 = static_cast<uint64_t>((__uint128_t)x3 * b[i + 3]) - q3 * p;
    r3 = (r3 >= p) ? (r3 - p) : r3;
    uint64_t s3 = acc[i + 3] + r3;
    acc[i + 3] = (s3 >= p) ? (s3 - p) : s3;

    uint64_t x4 = a[i + 4];
    uint64_t q4 =
        static_cast<uint64_t>(((__uint128_t)x4 * b_shoup[i + 4]) >> 64);
    uint64_t r4 = static_cast<uint64_t>((__uint128_t)x4 * b[i + 4]) - q4 * p;
    r4 = (r4 >= p) ? (r4 - p) : r4;
    uint64_t s4 = acc[i + 4] + r4;
    acc[i + 4] = (s4 >= p) ? (s4 - p) : s4;

    uint64_t x5 = a[i + 5];
    uint64_t q5 =
        static_cast<uint64_t>(((__uint128_t)x5 * b_shoup[i + 5]) >> 64);
    uint64_t r5 = static_cast<uint64_t>((__uint128_t)x5 * b[i + 5]) - q5 * p;
    r5 = (r5 >= p) ? (r5 - p) : r5;
    uint64_t s5 = acc[i + 5] + r5;
    acc[i + 5] = (s5 >= p) ? (s5 - p) : s5;

    uint64_t x6 = a[i + 6];
    uint64_t q6 =
        static_cast<uint64_t>(((__uint128_t)x6 * b_shoup[i + 6]) >> 64);
    uint64_t r6 = static_cast<uint64_t>((__uint128_t)x6 * b[i + 6]) - q6 * p;
    r6 = (r6 >= p) ? (r6 - p) : r6;
    uint64_t s6 = acc[i + 6] + r6;
    acc[i + 6] = (s6 >= p) ? (s6 - p) : s6;

    uint64_t x7 = a[i + 7];
    uint64_t q7 =
        static_cast<uint64_t>(((__uint128_t)x7 * b_shoup[i + 7]) >> 64);
    uint64_t r7 = static_cast<uint64_t>((__uint128_t)x7 * b[i + 7]) - q7 * p;
    r7 = (r7 >= p) ? (r7 - p) : r7;
    uint64_t s7 = acc[i + 7] + r7;
    acc[i + 7] = (s7 >= p) ? (s7 - p) : s7;
  }
  for (; i < n; ++i) {
    uint64_t q = static_cast<uint64_t>(((__uint128_t)a[i] * b_shoup[i]) >> 64);
    uint64_t r = static_cast<uint64_t>((__uint128_t)a[i] * b[i]) - q * p;
    r = (r >= p) ? (r - p) : r;
    uint64_t sum = acc[i] + r;
    acc[i] = (sum >= p) ? (sum - p) : sum;
  }
}

void Modulus::ReduceVec(std::vector<uint64_t> &a) const {
  ReduceVec(a.data(), a.size());
}

void Modulus::ReduceVecVt(std::vector<uint64_t> &a) const {
  // Keeping vector loop for Vt as we didn't add pointer overload for
  // ReduceVecVt to header to minimize changes.
  const uint64_t p = p_;
  const uint64_t ratio_hi = barrett_hi_;
  const size_t n = a.size();
  size_t i = 0;
  for (; i + 7 < n; i += 8) {
    uint64_t q_hat = mul64_high(a[i], ratio_hi);
    uint64_t r = a[i] - q_hat * p;
    a[i] = cond_sub(r, p);

    q_hat = mul64_high(a[i + 1], ratio_hi);
    r = a[i + 1] - q_hat * p;
    a[i + 1] = cond_sub(r, p);

    q_hat = mul64_high(a[i + 2], ratio_hi);
    r = a[i + 2] - q_hat * p;
    a[i + 2] = cond_sub(r, p);

    q_hat = mul64_high(a[i + 3], ratio_hi);
    r = a[i + 3] - q_hat * p;
    a[i + 3] = cond_sub(r, p);

    q_hat = mul64_high(a[i + 4], ratio_hi);
    r = a[i + 4] - q_hat * p;
    a[i + 4] = cond_sub(r, p);

    q_hat = mul64_high(a[i + 5], ratio_hi);
    r = a[i + 5] - q_hat * p;
    a[i + 5] = cond_sub(r, p);

    q_hat = mul64_high(a[i + 6], ratio_hi);
    r = a[i + 6] - q_hat * p;
    a[i + 6] = cond_sub(r, p);

    q_hat = mul64_high(a[i + 7], ratio_hi);
    r = a[i + 7] - q_hat * p;
    a[i + 7] = cond_sub(r, p);
  }
  for (; i < n; ++i) {
    uint64_t q_hat = mul64_high(a[i], ratio_hi);
    uint64_t r = a[i] - q_hat * p;
    a[i] = cond_sub(r, p);
  }
}

void Modulus::ReduceVec(uint64_t *a, size_t n) const {
  const uint64_t p = p_;
  const uint64_t ratio_hi = barrett_hi_;
  size_t i = 0;
  for (; i + 7 < n; i += 8) {
    uint64_t q_hat = mul64_high(a[i], ratio_hi);
    uint64_t r = a[i] - q_hat * p;
    a[i] = cond_sub(r, p);

    q_hat = mul64_high(a[i + 1], ratio_hi);
    r = a[i + 1] - q_hat * p;
    a[i + 1] = cond_sub(r, p);

    q_hat = mul64_high(a[i + 2], ratio_hi);
    r = a[i + 2] - q_hat * p;
    a[i + 2] = cond_sub(r, p);

    q_hat = mul64_high(a[i + 3], ratio_hi);
    r = a[i + 3] - q_hat * p;
    a[i + 3] = cond_sub(r, p);

    q_hat = mul64_high(a[i + 4], ratio_hi);
    r = a[i + 4] - q_hat * p;
    a[i + 4] = cond_sub(r, p);

    q_hat = mul64_high(a[i + 5], ratio_hi);
    r = a[i + 5] - q_hat * p;
    a[i + 5] = cond_sub(r, p);

    q_hat = mul64_high(a[i + 6], ratio_hi);
    r = a[i + 6] - q_hat * p;
    a[i + 6] = cond_sub(r, p);

    q_hat = mul64_high(a[i + 7], ratio_hi);
    r = a[i + 7] - q_hat * p;
    a[i + 7] = cond_sub(r, p);
  }
  for (; i < n; ++i) {
    uint64_t q_hat = mul64_high(a[i], ratio_hi);
    uint64_t r = a[i] - q_hat * p;
    a[i] = cond_sub(r, p);
  }
}

std::vector<int64_t> Modulus::CenterVecVt(
    const std::vector<uint64_t> &a) const {
  std::vector<int64_t> result(a.size());
  uint64_t half_p = p_ >> 1;
  for (size_t i = 0; i < a.size(); ++i) {
    result[i] = a[i] > half_p ? static_cast<int64_t>(a[i] - p_)
                              : static_cast<int64_t>(a[i]);
  }
  return result;
}

std::vector<uint64_t> Modulus::ReduceVecNew(
    const std::vector<uint64_t> &a) const {
  std::vector<uint64_t> result(a.size());
  for (size_t i = 0; i < a.size(); ++i) {
    result[i] = Reduce(a[i]);
  }
  return result;
}

std::vector<uint64_t> Modulus::ReduceVecNewVt(
    const std::vector<uint64_t> &a) const {
  std::vector<uint64_t> result(a.size());
  for (size_t i = 0; i < a.size(); ++i) {
    result[i] = ReduceVt(a[i]);
  }
  return result;
}

std::vector<uint64_t> Modulus::ReduceVecI64(
    const std::vector<int64_t> &a) const {
  std::vector<uint64_t> result(a.size());
  for (size_t i = 0; i < a.size(); ++i) {
    result[i] = ReduceI64(a[i]);
  }
  return result;
}

std::vector<uint64_t> Modulus::ReduceVecI64Vt(
    const std::vector<int64_t> &a) const {
  std::vector<uint64_t> result(a.size());
  for (size_t i = 0; i < a.size(); ++i) {
    result[i] = ReduceI64Vt(a[i]);
  }
  return result;
}

void Modulus::NegVec(std::vector<uint64_t> &a) const {
  NegVec(a.data(), a.size());
}

void Modulus::NegVecVt(std::vector<uint64_t> &a) const {
  NegVecVt(a.data(), a.size());
}

void Modulus::LazyReduceVec(std::vector<uint64_t> &a) const {
  LazyReduceVec(a.data(), a.size());
}

void Modulus::NegVec(uint64_t *a, size_t n) const {
  for (size_t i = 0; i < n; ++i) {
    a[i] = Neg(a[i]);
  }
}

void Modulus::NegVecVt(uint64_t *a, size_t n) const {
  for (size_t i = 0; i < n; ++i) {
    a[i] = NegVt(a[i]);
  }
}

void Modulus::LazyReduceVec(uint64_t *a, size_t n) const {
  for (size_t i = 0; i < n; ++i) {
    a[i] = LazyReduce(a[i]);
  }
}

// Modular exponentiation
uint64_t Modulus::Pow(uint64_t a, uint64_t n) const {
  if (n == 0) return 1;
  if (n == 1) return a;

  uint64_t result = 1;
  uint64_t base = a;

  while (n > 0) {
    if (n & 1) {
      result = Mul(result, base);
    }
    base = Mul(base, base);
    n >>= 1;
  }

  return result;
}

// Modular inverse using extended Euclidean algorithm
std::optional<uint64_t> Modulus::Inv(uint64_t a) const {
  if (a == 0) return std::nullopt;

  int64_t old_r = p_, r = a;
  int64_t old_s = 0, s = 1;

  while (r != 0) {
    int64_t quotient = old_r / r;
    int64_t temp = r;
    r = old_r - quotient * r;
    old_r = temp;

    temp = s;
    s = old_s - quotient * s;
    old_s = temp;
  }

  if (old_r > 1) return std::nullopt;  // Not invertible

  if (old_s < 0) old_s += p_;
  return static_cast<uint64_t>(old_s);
}

// Random vector generation
std::vector<uint64_t> Modulus::RandomVec(size_t size,
                                         std::mt19937_64 &rng) const {
  std::vector<uint64_t> result(size);
  for (size_t i = 0; i < size; ++i) {
    result[i] = impl_->runtime.distribution(rng);
  }
  return result;
}

// Serialization
size_t Modulus::SerializationLength(size_t size) const {
  // Each element needs at most 8 bytes
  return size * 8;
}

std::vector<uint8_t> Modulus::SerializeVec(
    const std::vector<uint64_t> &a) const {
  std::vector<uint8_t> result(a.size() * 8);
  for (size_t i = 0; i < a.size(); ++i) {
    uint64_t val = a[i];
    for (int j = 0; j < 8; ++j) {
      result[i * 8 + j] = static_cast<uint8_t>(val >> (j * 8));
    }
  }
  return result;
}

std::vector<uint64_t> Modulus::DeserializeVec(
    const std::vector<uint8_t> &b) const {
  std::vector<uint64_t> result(b.size() / 8);
  for (size_t i = 0; i < result.size(); ++i) {
    uint64_t val = 0;
    for (int j = 0; j < 8; ++j) {
      val |= static_cast<uint64_t>(b[i * 8 + j]) << (j * 8);
    }
    result[i] = val;
  }
  return result;
}

void Modulus::TensorProductVec(uint64_t *p00, uint64_t *p01,
                               const uint64_t *p10, const uint64_t *p11,
                               uint64_t *p2, size_t n) const {
  if (supports_opt_) {
    // Use MulOpt
    size_t i = 0;
    for (; i + 3 < n; i += 4) {
      // Unroll 0
      uint64_t v00 = p00[i];
      uint64_t v01 = p01[i];
      uint64_t v10 = p10[i];
      uint64_t v11 = p11[i];

      p00[i] = MulOpt(v00, v10);  // c0
      p2[i] = MulOpt(v01, v11);   // c2

      uint64_t t1 = MulOpt(v00, v11);
      uint64_t t2 = MulOpt(v01, v10);
      p01[i] = Add(t1, t2);  // c1

      // Unroll 1
      v00 = p00[i + 1];
      v01 = p01[i + 1];
      v10 = p10[i + 1];
      v11 = p11[i + 1];
      p00[i + 1] = MulOpt(v00, v10);
      p2[i + 1] = MulOpt(v01, v11);
      t1 = MulOpt(v00, v11);
      t2 = MulOpt(v01, v10);
      p01[i + 1] = Add(t1, t2);

      // Unroll 2
      v00 = p00[i + 2];
      v01 = p01[i + 2];
      v10 = p10[i + 2];
      v11 = p11[i + 2];
      p00[i + 2] = MulOpt(v00, v10);
      p2[i + 2] = MulOpt(v01, v11);
      t1 = MulOpt(v00, v11);
      t2 = MulOpt(v01, v10);
      p01[i + 2] = Add(t1, t2);

      // Unroll 3
      v00 = p00[i + 3];
      v01 = p01[i + 3];
      v10 = p10[i + 3];
      v11 = p11[i + 3];
      p00[i + 3] = MulOpt(v00, v10);
      p2[i + 3] = MulOpt(v01, v11);
      t1 = MulOpt(v00, v11);
      t2 = MulOpt(v01, v10);
      p01[i + 3] = Add(t1, t2);
    }
    for (; i < n; ++i) {
      uint64_t v00 = p00[i];
      uint64_t v01 = p01[i];
      uint64_t v10 = p10[i];
      uint64_t v11 = p11[i];
      p00[i] = MulOpt(v00, v10);
      p2[i] = MulOpt(v01, v11);
      p01[i] = Add(MulOpt(v00, v11), MulOpt(v01, v10));
    }
  } else {
    // Use standard Mul/Add
    size_t i = 0;
    for (; i + 3 < n; i += 4) {
      uint64_t v00 = p00[i];
      uint64_t v01 = p01[i];
      uint64_t v10 = p10[i];
      uint64_t v11 = p11[i];
      p00[i] = Mul(v00, v10);
      p2[i] = Mul(v01, v11);
      p01[i] = Add(Mul(v00, v11), Mul(v01, v10));

      v00 = p00[i + 1];
      v01 = p01[i + 1];
      v10 = p10[i + 1];
      v11 = p11[i + 1];
      p00[i + 1] = Mul(v00, v10);
      p2[i + 1] = Mul(v01, v11);
      p01[i + 1] = Add(Mul(v00, v11), Mul(v01, v10));

      v00 = p00[i + 2];
      v01 = p01[i + 2];
      v10 = p10[i + 2];
      v11 = p11[i + 2];
      p00[i + 2] = Mul(v00, v10);
      p2[i + 2] = Mul(v01, v11);
      p01[i + 2] = Add(Mul(v00, v11), Mul(v01, v10));

      v00 = p00[i + 3];
      v01 = p01[i + 3];
      v10 = p10[i + 3];
      v11 = p11[i + 3];
      p00[i + 3] = Mul(v00, v10);
      p2[i + 3] = Mul(v01, v11);
      p01[i + 3] = Add(Mul(v00, v11), Mul(v01, v10));
    }
    for (; i < n; ++i) {
      uint64_t v00 = p00[i];
      uint64_t v01 = p01[i];
      uint64_t v10 = p10[i];
      uint64_t v11 = p11[i];
      p00[i] = Mul(v00, v10);
      p2[i] = Mul(v01, v11);
      p01[i] = Add(Mul(v00, v11), Mul(v01, v10));
    }
  }
}

void Modulus::TensorProductVecVt(uint64_t *p00, uint64_t *p01,
                                 const uint64_t *p10, const uint64_t *p11,
                                 uint64_t *p2, size_t n) const {
  if (supports_opt_) {
    size_t i = 0;
    for (; i + 3 < n; i += 4) {
      uint64_t v00 = p00[i];
      uint64_t v01 = p01[i];
      uint64_t v10 = p10[i];
      uint64_t v11 = p11[i];
      p00[i] = MulOptVt(v00, v10);
      p2[i] = MulOptVt(v01, v11);
      p01[i] = AddVt(MulOptVt(v00, v11), MulOptVt(v01, v10));

      v00 = p00[i + 1];
      v01 = p01[i + 1];
      v10 = p10[i + 1];
      v11 = p11[i + 1];
      p00[i + 1] = MulOptVt(v00, v10);
      p2[i + 1] = MulOptVt(v01, v11);
      p01[i + 1] = AddVt(MulOptVt(v00, v11), MulOptVt(v01, v10));

      v00 = p00[i + 2];
      v01 = p01[i + 2];
      v10 = p10[i + 2];
      v11 = p11[i + 2];
      p00[i + 2] = MulOptVt(v00, v10);
      p2[i + 2] = MulOptVt(v01, v11);
      p01[i + 2] = AddVt(MulOptVt(v00, v11), MulOptVt(v01, v10));

      v00 = p00[i + 3];
      v01 = p01[i + 3];
      v10 = p10[i + 3];
      v11 = p11[i + 3];
      p00[i + 3] = MulOptVt(v00, v10);
      p2[i + 3] = MulOptVt(v01, v11);
      p01[i + 3] = AddVt(MulOptVt(v00, v11), MulOptVt(v01, v10));
    }
    for (; i < n; ++i) {
      uint64_t v00 = p00[i];
      uint64_t v01 = p01[i];
      uint64_t v10 = p10[i];
      uint64_t v11 = p11[i];
      p00[i] = MulOptVt(v00, v10);
      p2[i] = MulOptVt(v01, v11);
      p01[i] = AddVt(MulOptVt(v00, v11), MulOptVt(v01, v10));
    }
  } else {
    size_t i = 0;
    for (; i + 3 < n; i += 4) {
      uint64_t v00 = p00[i];
      uint64_t v01 = p01[i];
      uint64_t v10 = p10[i];
      uint64_t v11 = p11[i];
      p00[i] = MulVt(v00, v10);
      p2[i] = MulVt(v01, v11);
      p01[i] = AddVt(MulVt(v00, v11), MulVt(v01, v10));

      v00 = p00[i + 1];
      v01 = p01[i + 1];
      v10 = p10[i + 1];
      v11 = p11[i + 1];
      p00[i + 1] = MulVt(v00, v10);
      p2[i + 1] = MulVt(v01, v11);
      p01[i + 1] = AddVt(MulVt(v00, v11), MulVt(v01, v10));

      v00 = p00[i + 2];
      v01 = p01[i + 2];
      v10 = p10[i + 2];
      v11 = p11[i + 2];
      p00[i + 2] = MulVt(v00, v10);
      p2[i + 2] = MulVt(v01, v11);
      p01[i + 2] = AddVt(MulVt(v00, v11), MulVt(v01, v10));

      v00 = p00[i + 3];
      v01 = p01[i + 3];
      v10 = p10[i + 3];
      v11 = p11[i + 3];
      p00[i + 3] = MulVt(v00, v10);
      p2[i + 3] = MulVt(v01, v11);
      p01[i + 3] = AddVt(MulVt(v00, v11), MulVt(v01, v10));
    }
    for (; i < n; ++i) {
      uint64_t v00 = p00[i];
      uint64_t v01 = p01[i];
      uint64_t v10 = p10[i];
      uint64_t v11 = p11[i];
      p00[i] = MulVt(v00, v10);
      p2[i] = MulVt(v01, v11);
      p01[i] = AddVt(MulVt(v00, v11), MulVt(v01, v10));
    }
  }
}

}  // namespace zq
}  // namespace math
}  // namespace bfv
