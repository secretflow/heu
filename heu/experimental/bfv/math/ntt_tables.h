#ifndef NTT_TABLES_H
#define NTT_TABLES_H

#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

#include "math/modulus.h"
#include "math/ntt_layout.h"

namespace bfv {
namespace math {
namespace ntt {

/**
 * NTT Tables class for precomputing and managing root powers.
 * Precomputes all necessary root powers and stores them in optimized format
 * for Harvey butterfly operations with lazy reduction.
 */
class NTTTables {
 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;

  NTTTables(std::unique_ptr<Impl> impl);

 public:
  NTTTables(const NTTTables &other);
  NTTTables(NTTTables &&other) noexcept;
  ~NTTTables();

  /**
   * Create NTT tables for a modulus and transform size.
   * @param modulus The modulus for NTT operations
   * @param coeff_count Number of coefficients (must be power of 2)
   * @return Optional NTTTables if the modulus supports the requested root
   *         layout
   */
  static std::optional<NTTTables> Create(const zq::Modulus &modulus,
                                         size_t coeff_count);

  // Accessors
  const zq::Modulus &GetModulus() const;
  size_t GetCoeffCount() const;

  // Root power accessors for Harvey butterfly operations
  const std::vector<zq::MultiplyUIntModOperand> &GetRootPowers() const;
  const std::vector<zq::MultiplyUIntModOperand> &GetInvRootPowers() const;
  const zq::MultiplyUIntModOperand &GetInvDegreeModulo() const;

  // Utility functions kept as thin wrappers around internal layout helpers.
  static uint64_t FindPrimitiveRoot(size_t coeff_count,
                                    const zq::Modulus &modulus);
  static bool IsPrimitiveRoot(uint64_t root, size_t coeff_count,
                              const zq::Modulus &modulus);
  static size_t ReverseBits(size_t value, size_t bit_count);

 private:
};

}  // namespace ntt
}  // namespace math
}  // namespace bfv

#endif  // NTT_TABLES_H
