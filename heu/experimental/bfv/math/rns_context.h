#ifndef RNS_CONTEXT_H
#define RNS_CONTEXT_H

#include <memory>
#include <vector>

#include "math/biguint.h"
#include "math/modulus.h"

namespace bfv {
namespace math {
namespace rns {

class RnsContext {
 private:
  class Impl;
  std::unique_ptr<Impl> impl_;

 public:
  RnsContext(const std::vector<uint64_t> &moduli_u64);
  ~RnsContext();

  /**
   * @brief Build an RNS basis context from residue-basis values.
   */
  static std::shared_ptr<RnsContext> create(
      const std::vector<uint64_t> &moduli_u64);

  /**
   * @brief Return the product of the active residue basis.
   */
  const BigUint &modulus() const;

  /**
   * @brief Project an integer into all residue channels of this basis.
   */
  std::vector<uint64_t> project(const BigUint &a) const;

  /**
   * @brief Reconstruct an integer from its residue-channel values.
   */
  BigUint lift(const std::vector<uint64_t> &rests) const;

  /**
   * @brief Return the cached reconstruction term for one residue channel.
   */
  BigUint get_garner(size_t i) const;

  /**
   * @brief Return the raw residue-basis values.
   */
  const std::vector<uint64_t> &moduli_u64() const;

  /**
   * @brief Return cached modulus operators for each residue channel.
   */
  const std::vector<zq::Modulus> &moduli() const;

  /**
   * @brief Return the cached reconstruction terms used by lift().
   */
  const std::vector<BigUint> &garner() const;
};

}  // namespace rns
}  // namespace math
}  // namespace bfv

#endif
