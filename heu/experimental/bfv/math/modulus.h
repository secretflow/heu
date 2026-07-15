#ifndef MODULUS_H
#define MODULUS_H

#include <cstdint>
#include <memory>
#include <optional>
#include <random>
#include <vector>

namespace bfv {
namespace math {
namespace zq {

// Structure for optimized multiplication with precomputed quotient
struct MultiplyUIntModOperand {
  std::uint64_t operand;
  std::uint64_t quotient;  // (operand << 64) / modulus

  MultiplyUIntModOperand() : operand(0), quotient(0) {}

  MultiplyUIntModOperand(std::uint64_t op, std::uint64_t mod) : operand(op) {
    set_quotient(mod);
  }

  void set_quotient(std::uint64_t modulus) {
    // Compute (operand << 64) / modulus for Shoup multiplication
    __uint128_t wide_operand = __uint128_t(operand) << 64;
    quotient = static_cast<std::uint64_t>(wide_operand / modulus);
  }

  void set(std::uint64_t new_operand, std::uint64_t modulus) {
    operand = new_operand;
    set_quotient(modulus);
  }
};

// Structure to expose internal Barrett constants for inlining
struct BarrettConstants {
  uint64_t value;          // Modulus value P
  uint64_t barrett_lo;     // Low 64 bits of (1<<128)/P
  uint64_t barrett_hi;     // High 64 bits
  uint32_t leading_zeros;  // LZCNT(P)
};

class Modulus {
 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;

  // Hot fields moved out of PIMPL for inlining in tight loops.
  // These are the constants used by every arithmetic operation.
  uint64_t p_;              // Modulus value
  uint64_t barrett_lo_;     // Low 64 bits of floor(2^128 / p)
  uint64_t barrett_hi_;     // High 64 bits of floor(2^128 / p)
  uint32_t leading_zeros_;  // __builtin_clzll(p)
  bool supports_opt_;       // Optimized reduction supported

  Modulus(std::unique_ptr<Impl> impl);

 public:
  Modulus(Modulus &&other) noexcept;
  Modulus(const Modulus &other);
  ~Modulus();
  // Constructor
  static std::optional<Modulus> New(uint64_t p);

  // Accessor for modulus value
  uint64_t P() const;

  // Check if optimized operations are supported
  bool SupportsOpt() const;

  BarrettConstants GetBarrettConstants() const;

  // Shoup representation
  uint64_t Shoup(uint64_t a) const;

  // Modular addition
  uint64_t Add(uint64_t a, uint64_t b) const;
  uint64_t AddVt(uint64_t a, uint64_t b) const;  // Variable time

  // Modular subtraction
  uint64_t Sub(uint64_t a, uint64_t b) const;
  uint64_t SubVt(uint64_t a, uint64_t b) const;  // Variable time
  uint64_t SubLazy(uint64_t a, uint64_t b) const;

  // Modular multiplication
  uint64_t Mul(uint64_t a, uint64_t b) const;
  uint64_t MulVt(uint64_t a, uint64_t b) const;  // Variable time
  uint64_t MulOpt(uint64_t a, uint64_t b) const;
  uint64_t MulOptVt(uint64_t a, uint64_t b) const;  // Variable time
  uint64_t MulShoup(uint64_t a, uint64_t b, uint64_t b_shoup) const;
  uint64_t MulShoupVt(uint64_t a, uint64_t b,
                      uint64_t b_shoup) const;  // Variable time
  uint64_t LazyMulShoup(uint64_t a, uint64_t b, uint64_t q) const;

  // Optimized multiplication with MultiplyUIntModOperand
  MultiplyUIntModOperand PrepareMultiplyOperand(uint64_t operand) const;
  uint64_t MulOptimized(uint64_t x, const MultiplyUIntModOperand &y) const;
  uint64_t MulOptimizedLazy(uint64_t x, const MultiplyUIntModOperand &y) const;
  uint64_t MulAddOptimized(uint64_t x, const MultiplyUIntModOperand &y,
                           uint64_t acc) const;
  void MulOptimizedVec(
      std::vector<uint64_t> &a,
      const std::vector<MultiplyUIntModOperand> &b_precomp) const;
  void MulOptimizedVecLazy(
      std::vector<uint64_t> &a,
      const std::vector<MultiplyUIntModOperand> &b_precomp) const;

  // Modular negation
  uint64_t Neg(uint64_t a) const;
  uint64_t NegVt(uint64_t a) const;  // Variable time

  // Modular reduction
  uint64_t Reduce(uint64_t a) const;
  uint64_t ReduceVt(uint64_t a) const;  // Variable time
  uint64_t ReduceOpt(uint64_t a) const;
  uint64_t ReduceOptVt(uint64_t a) const;  // Variable time
  uint64_t ReduceU128(__int128 a) const;
  uint64_t ReduceU128Vt(__int128 a) const;  // Variable time
  uint64_t ReduceU128(__uint128_t a) const;
  uint64_t ReduceOptU128(__int128 a) const;
  uint64_t ReduceOptU128(__uint128_t a) const;
  uint64_t ReduceOptU128Vt(__uint128_t a) const;
  uint64_t ReduceOptU128Vt(__int128 a) const;  // Variable time
  uint64_t ReduceI64(int64_t a) const;
  uint64_t ReduceI64Vt(int64_t a) const;  // Variable time

  // General reduction functions
  uint64_t Reduce1(uint64_t x, uint64_t mod) const;
  uint64_t Reduce1Vt(uint64_t x, uint64_t mod) const;

  // Lazy reductions
  uint64_t LazyReduce(uint64_t a) const;
  uint64_t LazyReduceU128(__uint128_t a) const;
  uint64_t LazyReduceOpt(uint64_t a) const;
  uint64_t LazyReduceOptU128(__int128 a) const;

  // Vector operations
  void AddVec(std::vector<uint64_t> &a, const std::vector<uint64_t> &b) const;
  void AddVecVt(std::vector<uint64_t> &a,
                const std::vector<uint64_t> &b) const;  // Variable time
  void SubVec(std::vector<uint64_t> &a, const std::vector<uint64_t> &b) const;
  void SubVecVt(std::vector<uint64_t> &a,
                const std::vector<uint64_t> &b) const;  // Variable time
  void MulVec(std::vector<uint64_t> &a, const std::vector<uint64_t> &b) const;
  void MulVecVt(std::vector<uint64_t> &a,
                const std::vector<uint64_t> &b) const;  // Variable time
  void ScalarMulVec(std::vector<uint64_t> &a, uint64_t b) const;
  void ScalarMulVecVt(std::vector<uint64_t> &a,
                      uint64_t b) const;  // Variable time

  // Pointer-based Vector operations (Core implementation)
  void AddVec(uint64_t *a, const uint64_t *b, size_t n) const;
  void AddVecVt(uint64_t *a, const uint64_t *b, size_t n) const;
  void SubVec(uint64_t *a, const uint64_t *b, size_t n) const;
  void SubVecVt(uint64_t *a, const uint64_t *b, size_t n) const;
  void MulVec(uint64_t *a, const uint64_t *b, size_t n) const;
  void MulVecVt(uint64_t *a, const uint64_t *b, size_t n) const;
  void MulTo(uint64_t *dst, const uint64_t *a, const uint64_t *b,
             size_t n) const;
  void MulToVt(uint64_t *dst, const uint64_t *a, const uint64_t *b,
               size_t n) const;
  void ScalarMulVec(uint64_t *a, size_t n, uint64_t b) const;
  void ScalarMulVecVt(uint64_t *a, size_t n, uint64_t b) const;
  void ScalarMulTo(uint64_t *dst, const uint64_t *src, size_t n,
                   uint64_t b) const;
  void ScalarMulToVt(uint64_t *dst, const uint64_t *src, size_t n,
                     uint64_t b) const;

  void MulShoupVec(uint64_t *a, const uint64_t *b, const uint64_t *b_shoup,
                   size_t n) const;
  void MulShoupVecVt(uint64_t *a, const uint64_t *b, const uint64_t *b_shoup,
                     size_t n) const;
  void MulAddVec(uint64_t *acc, const uint64_t *a, const uint64_t *b,
                 size_t n) const;
  void MulAddVecVt(uint64_t *acc, const uint64_t *a, const uint64_t *b,
                   size_t n) const;
  void MulAddShoupVec(uint64_t *acc, const uint64_t *a, const uint64_t *b,
                      const uint64_t *b_shoup, size_t n) const;
  void MulAddShoupVecVt(uint64_t *acc, const uint64_t *a, const uint64_t *b,
                        const uint64_t *b_shoup, size_t n) const;

  // Optimized fused tensor product for multiplication
  // p00 -> c0 = p00 * p10
  // p01 -> c1 = p00 * p11 + p01 * p10
  // p2  -> c2 = p01 * p11
  void TensorProductVec(uint64_t *p00, uint64_t *p01, const uint64_t *p10,
                        const uint64_t *p11, uint64_t *p2, size_t n) const;
  void TensorProductVecVt(uint64_t *p00, uint64_t *p01, const uint64_t *p10,
                          const uint64_t *p11, uint64_t *p2, size_t n) const;

  std::vector<uint64_t> ShoupVec(const std::vector<uint64_t> &a) const;
  void MulShoupVec(std::vector<uint64_t> &a, const std::vector<uint64_t> &b,
                   const std::vector<uint64_t> &b_shoup) const;
  void MulShoupVecVt(
      std::vector<uint64_t> &a, const std::vector<uint64_t> &b,
      const std::vector<uint64_t> &b_shoup) const;  // Variable time
  void ReduceVec(std::vector<uint64_t> &a) const;
  void ReduceVecVt(std::vector<uint64_t> &a) const;  // Variable time

  // Pointer-based Reduce
  void ReduceVec(uint64_t *a, size_t n) const;
  void NegVec(uint64_t *a, size_t n) const;
  void NegVecVt(uint64_t *a, size_t n) const;
  void LazyReduceVec(uint64_t *a, size_t n) const;

  std::vector<int64_t> CenterVecVt(
      const std::vector<uint64_t> &a) const;  // Variable time
  std::vector<uint64_t> ReduceVecNew(const std::vector<uint64_t> &a) const;
  std::vector<uint64_t> ReduceVecNewVt(
      const std::vector<uint64_t> &a) const;  // Variable time
  std::vector<uint64_t> ReduceVecI64(const std::vector<int64_t> &a) const;
  std::vector<uint64_t> ReduceVecI64Vt(
      const std::vector<int64_t> &a) const;  // Variable time
  void NegVec(std::vector<uint64_t> &a) const;
  void NegVecVt(std::vector<uint64_t> &a) const;  // Variable time
  void LazyReduceVec(std::vector<uint64_t> &a) const;

  // Power and inverse
  uint64_t Pow(uint64_t a, uint64_t n) const;
  std::optional<uint64_t> Inv(uint64_t a) const;

  // Random vector
  std::vector<uint64_t> RandomVec(size_t size, std::mt19937_64 &rng) const;

  // Serialization
  size_t SerializationLength(size_t size) const;
  std::vector<uint8_t> SerializeVec(const std::vector<uint64_t> &a) const;
  std::vector<uint64_t> DeserializeVec(const std::vector<uint8_t> &b) const;
};
}  // namespace zq
}  // namespace math
}  // namespace bfv
#endif  // MODULUS_H
