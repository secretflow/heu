#ifndef TRAITS_H
#define TRAITS_H

#include <memory>
#include <optional>

#include "math/representation.h"

namespace bfv::math::rq {

// Forward declarations
class Context;
class Poly;

/**
 * @brief Trait for converting various types to polynomials.
 */
template <typename T>
struct TryConvertFrom {
  /**
   * @brief Attempt to convert the value into a polynomial.
   *
   * @param value The value to convert
   * @param ctx The context for the polynomial
   * @param variable_time Whether to allow variable time computations
   * @param representation The desired representation (optional)
   * @return Poly The converted polynomial
   * @throws RqException if conversion fails
   */
  static Poly try_convert_from(const T &value,
                               std::shared_ptr<const Context> ctx,
                               bool variable_time,
                               std::optional<Representation> representation);
};

// Template specializations will be provided in poly_convert.h/cc
// for the following types:
// - std::vector<uint64_t>
// - std::vector<int64_t>
// - std::vector<::bfv::math::rns::BigUint>
// - ndarray::Array2<uint64_t> (if we implement ndarray equivalent)

}  // namespace bfv::math::rq
#endif  // TRAITS_H
