#ifndef REPRESENTATION_H
#define REPRESENTATION_H

#include <string>

namespace bfv::math::rq {

/**
 * @brief Possible representations of the underlying polynomial.
 */
enum class Representation {
  /**
   * @brief This is the list of coefficients ci, such that the polynomial is
   * c0 + c1 * x + ... + c_(degree - 1) * x^(degree - 1)
   */
  PowerBasis = 0,

  /**
   * @brief This is the NTT representation of the PowerBasis representation.
   */
  Ntt = 1,

  /**
   * @brief This is a "Shoup" representation of the Ntt representation used for
   * faster multiplication.
   */
  NttShoup = 2
};

/**
 * @brief Convert representation enum to string for debugging and serialization.
 *
 * @param repr The representation to convert
 * @return const char* String representation
 */
const char *representation_to_string(Representation repr);

/**
 * @brief Convert string to representation enum.
 *
 * @param str String representation
 * @return Representation The corresponding enum value
 * @throws std::invalid_argument if string is not recognized
 */
Representation representation_from_string(const std::string &str);

}  // namespace bfv::math::rq
#endif  // REPRESENTATION_H
