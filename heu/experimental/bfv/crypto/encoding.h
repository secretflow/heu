#pragma once

#include <memory>
#include <string>

namespace crypto {
namespace bfv {

/**
 * Enumeration for different encoding types
 */
enum class EncodingType {
  Poly,  // Polynomial encoding - coefficients as polynomial coefficients
  Simd   // SIMD encoding - component-wise operations on vectors
};

/**
 * An encoding for the plaintext.
 *
 * This class specifies how data should be encoded into polynomials for
 * homomorphic encryption. It supports both polynomial encoding (where
 * operations are polynomial operations) and SIMD encoding (where operations
 * are component-wise on vectors).
 */
class Encoding {
 public:
  /**
   * @brief Default constructor
   */
  Encoding();

  /**
   * @brief Destructor
   */
  ~Encoding();

  // Copy and move semantics
  Encoding(const Encoding &other);
  Encoding &operator=(const Encoding &other);
  Encoding(Encoding &&other) noexcept;
  Encoding &operator=(Encoding &&other) noexcept;

  // Factory methods
  /**
   * @brief Create a polynomial encoding at level 0
   *
   * A Poly encoding encodes a vector as coefficients of a polynomial;
   * homomorphic operations are therefore polynomial operations.
   *
   * @return Encoding with polynomial type at level 0
   */
  static Encoding poly();

  /**
   * @brief Create a SIMD encoding at level 0
   *
   * A Simd encoding encodes a vector so that homomorphic operations are
   * component-wise operations on the coefficients of the underlying vectors.
   * The Simd encoding requires that the plaintext modulus is congruent to 1
   * modulo the degree of the underlying polynomial.
   *
   * @return Encoding with SIMD type at level 0
   */
  static Encoding simd();

  /**
   * @brief Create a polynomial encoding at a specific level
   *
   * @param level The level for the encoding
   * @return Encoding with polynomial type at the specified level
   */
  static Encoding poly_at_level(size_t level);

  /**
   * @brief Create a SIMD encoding at a specific level
   *
   * @param level The level for the encoding
   * @return Encoding with SIMD type at the specified level
   */
  static Encoding simd_at_level(size_t level);

  // Accessors
  /**
   * @brief Get the encoding type
   * @return The encoding type (Poly or Simd)
   */
  EncodingType encoding_type() const;

  /**
   * @brief Get the level
   * @return The level of this encoding
   */
  size_t level() const;

  // Comparison operators
  /**
   * @brief Equality comparison
   * @param other The other encoding to compare with
   * @return true if encodings are equal, false otherwise
   */
  bool operator==(const Encoding &other) const;

  /**
   * @brief Inequality comparison
   * @param other The other encoding to compare with
   * @return true if encodings are not equal, false otherwise
   */
  bool operator!=(const Encoding &other) const;

  /**
   * @brief Convert encoding to string representation
   * @return String representation of the encoding
   */
  std::string to_string() const;

 private:
  // PIMPL idiom
  class Impl;
  std::unique_ptr<Impl> pImpl;

  // Private constructor for factory methods
  Encoding(EncodingType type, size_t level);
};

}  // namespace bfv
}  // namespace crypto
