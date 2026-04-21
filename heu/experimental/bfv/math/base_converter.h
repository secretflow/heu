#ifndef BASE_CONVERTER_H
#define BASE_CONVERTER_H

#include <memory>
#include <vector>

#include "math/rns_context.h"
#include "util/arena_allocator.h"

namespace bfv {
namespace math {
namespace rns {

using util::ArenaHandle;

/**
 * BaseConverter implements the fast base conversion for RNS integers.
 *
 * Algorithm (CRT-based):
 * 1. Precompute inv_punctured_prod[i] = (Q/q_i)^{-1} mod q_i
 * 2. Precompute base_change_matrix[j][i] = (Q/q_i) mod p_j
 * 3. At runtime:
 *    - temp[i] = x[i] * inv_punctured_prod[i] mod q_i
 *    - out[j] = sum(temp[i] * matrix[j][i]) mod p_j
 *
 * All operations stay in native 64-bit modular arithmetic.
 */
class BaseConverter {
 public:
  /**
   * Construct a base converter from input base to output base.
   * @param ibase Input RNS base (source moduli)
   * @param obase Output RNS base (target moduli)
   */
  BaseConverter(const std::shared_ptr<RnsContext> &ibase,
                const std::shared_ptr<RnsContext> &obase);

  ~BaseConverter();

  // Accessors
  size_t ibase_size() const { return ibase_size_; }

  size_t obase_size() const { return obase_size_; }

  const std::shared_ptr<RnsContext> &ibase() const { return ibase_; }

  const std::shared_ptr<RnsContext> &obase() const { return obase_; }

  /**
   * Convert a single RNS coefficient from input base to output base.
   * @param in  Input array of size ibase_size (one residue per input modulus)
   * @param out Output array of size obase_size (one residue per output modulus)
   */
  void fast_convert(const uint64_t *in, uint64_t *out) const;

  /**
   * Convert an array of RNS coefficients (batch operation).
   * This is the optimized main API for polynomial conversion.
   *
   * @param in_ptrs  Vector of pointers to input arrays [ibase_size][count]
   * @param out_ptrs Vector of pointers to output arrays [obase_size][count]
   * @param count    Number of coefficients to convert
   * @param pool     Memory pool for temporary allocations
   */
  void fast_convert_array(const std::vector<const uint64_t *> &in_ptrs,
                          const std::vector<uint64_t *> &out_ptrs, size_t count,
                          ArenaHandle pool = ArenaHandle::Shared()) const;

  /**
   * Pointer-array overload to avoid constructing temporary std::vector in hot
   * paths. in_ptrs must have at least ibase_size() entries; out_ptrs at least
   * obase_size().
   */
  void fast_convert_array(const uint64_t *const *in_ptrs,
                          uint64_t *const *out_ptrs, size_t count) const;

  /**
   * Convert an array of RNS coefficients to a subset of the output base.
   * Useful for partial base extension or when outputting to a slice of moduli.
   *
   * @param in_ptrs        Vector of pointers to input arrays
   * [ibase_size][count]
   * @param out_ptrs       Vector of pointers to output arrays
   * [out_count][count]
   * @param count          Number of coefficients to convert
   * @param starting_index Index in obase to start outputting to
   * @param pool           Memory pool for temporary allocations
   */
  void fast_convert_array_partial(
      const std::vector<const uint64_t *> &in_ptrs,
      const std::vector<uint64_t *> &out_ptrs, size_t count,
      size_t starting_index, ArenaHandle pool = ArenaHandle::Shared()) const;

 private:
  class Impl;
  std::unique_ptr<Impl> pimpl_;

  std::shared_ptr<RnsContext> ibase_;
  std::shared_ptr<RnsContext> obase_;
  size_t ibase_size_;
  size_t obase_size_;
};

}  // namespace rns
}  // namespace math
}  // namespace bfv

#endif  // BASE_CONVERTER_H
