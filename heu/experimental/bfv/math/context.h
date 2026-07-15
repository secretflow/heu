#ifndef CONTEXT_H
#define CONTEXT_H

#include <cstdint>
#include <memory>
#include <vector>

#include "math/biguint.h"
#include "math/modulus.h"
#include "math/ntt.h"
#include "math/rns_context.h"

namespace bfv::math::rq {

class SubstitutionExponent;  // Forward declaration

/**
 * @brief Ring context shared by polynomials stored over a fixed residue basis.
 */
class Context : public std::enable_shared_from_this<Context> {
 public:
  /**
   * @brief Build a ring context from a residue basis and polynomial degree.
   *
   * @param moduli Prime basis values supporting NTT at the requested degree
   * @param degree Polynomial degree (must be a power of 2 and >= 8)
   * @return std::shared_ptr<Context> The constructed ring context
   * @throws DefaultException if the basis or degree is not supported
   */
  static std::shared_ptr<Context> create(const std::vector<uint64_t> &moduli,
                                         size_t degree);

  /**
   * @brief Shared-pointer wrapper around create().
   */
  static std::shared_ptr<Context> create_arc(
      const std::vector<uint64_t> &moduli, size_t degree);

  ~Context();

  // Disable copy constructor and assignment
  Context(const Context &) = delete;
  Context &operator=(const Context &) = delete;

  // Enable move constructor and assignment
  Context(Context &&) noexcept;
  Context &operator=(Context &&) noexcept;

  /**
   * @brief Return the product of the active residue basis as a BigUint.
   */
  const ::bfv::math::rns::BigUint &modulus() const;

  /**
   * @brief Return the raw residue basis values for this context.
   */
  const std::vector<uint64_t> &moduli() const;

  /**
   * @brief Return the active residue basis values.
   */
  const std::vector<uint64_t> &residue_basis() const { return moduli(); }

  /**
   * @brief Return the modulus operators associated with the residue basis.
   */
  const std::vector<::bfv::math::zq::Modulus> &moduli_operators() const;

  /**
   * @brief Return arithmetic operators attached to the active residue basis.
   */
  const std::vector<::bfv::math::zq::Modulus> &residue_operators() const {
    return moduli_operators();
  }

  /**
   * @brief Get the polynomial degree.
   */
  size_t degree() const;

  /**
   * @brief Count how many lower-level drops separate this context from target.
   *
   * @param context The target context
   * @return size_t Number of tail-modulus drops needed
   * @throws InvalidContextException if the target is outside this chain
   */
  size_t niterations_to(std::shared_ptr<const Context> context) const;

  /**
   * @brief Count how many lower-level drops separate this context from target.
   */
  size_t level_drop_distance(std::shared_ptr<const Context> context) const {
    return niterations_to(std::move(context));
  }

  /**
   * @brief Return the context reached after dropping `level` tail moduli.
   *
   * @param level Number of chain steps to descend
   * @return std::shared_ptr<Context> The requested lower-level context
   * @throws DefaultException if the requested level is out of range
   */
  std::shared_ptr<Context> context_at_level(size_t level) const;

  /**
   * @brief Return the next lower ring-level context, if one exists.
   */
  std::shared_ptr<const Context> next_context() const;

  /**
   * @brief Return the next lower-level context, if one exists.
   */
  std::shared_ptr<const Context> lower_level() const { return next_context(); }

  // Internal accessors for ring-storage, transfer, and transform helpers.
  const std::vector<::bfv::math::zq::Modulus> &q() const;
  std::shared_ptr<const ::bfv::math::rns::RnsContext> rns() const;
  const std::vector<::bfv::math::ntt::NttOperator> &ops() const;
  // Slot permutation used by substitution and NTT-domain reindexing helpers.
  const std::vector<size_t> &bitrev() const;
  // Tail-modulus inverse cached for dropping one ring level at a time.
  const std::vector<uint64_t> &inv_last_qi_mod_qj() const;
  const std::vector<uint64_t> &inv_last_qi_mod_qj_shoup() const;

  /**
   * @brief Return a cached substitution exponent, creating it on demand.
   * Thread-safe.
   */
  std::shared_ptr<SubstitutionExponent> get_substitution_exponent(
      size_t exponent) const;

  // Equality comparison
  bool operator==(const Context &other) const;
  bool operator!=(const Context &other) const;

 private:
  class Impl;
  std::unique_ptr<Impl> pimpl_;

  // Private constructor for PIMPL
  explicit Context(std::unique_ptr<Impl> impl);
};

}  // namespace bfv::math::rq

#endif  // CONTEXT_H
