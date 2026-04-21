#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

#include "crypto/encoding.h"
#include "crypto/exceptions.h"
#include "yacl/base/byte_container_view.h"

// Forward declarations for math library components
namespace bfv::math::rq {
class Poly;
class Context;
}  // namespace bfv::math::rq

namespace crypto {
namespace bfv {

// Forward declarations
class BfvParameters;

/**
 * A plaintext object that encodes a vector according to a specific encoding.
 *
 * This class represents encoded plaintext data ready for encryption in the BFV
 * scheme. It supports both polynomial and SIMD encodings, and provides secure
 * memory handling with automatic zeroization of sensitive data.
 */
class Plaintext {
 public:
  // Constructor and destructor
  /**
   * @brief Default constructor - creates an empty plaintext
   */
  Plaintext();

  /**
   * @brief Destructor - automatically zeroizes sensitive data
   */
  ~Plaintext();

  // Copy and move semantics
  Plaintext(const Plaintext &other);
  Plaintext &operator=(const Plaintext &other);
  Plaintext(Plaintext &&other) noexcept;
  Plaintext &operator=(Plaintext &&other) noexcept;

  // Equality comparison
  /**
   * @brief Equality comparison
   * Two plaintexts are equal if they have the same parameters, values, and
   * encoding (if both have encoding information)
   */
  bool operator==(const Plaintext &other) const;
  bool operator!=(const Plaintext &other) const;

  // Static factory methods for encoding
  /**
   * @brief Encode a vector of uint64_t values
   * @param values Vector of values to encode
   * @param encoding Encoding type and level
   * @param params BFV parameters
   * @return Encoded plaintext
   * @throws EncodingException if encoding fails
   * @throws ParameterException if values are too many for the degree
   */
  static Plaintext encode(const std::vector<uint64_t> &values,
                          const Encoding &encoding,
                          std::shared_ptr<BfvParameters> params);

  /**
   * @brief Encode a vector of int64_t values
   * @param values Vector of values to encode
   * @param encoding Encoding type and level
   * @param params BFV parameters
   * @return Encoded plaintext
   * @throws EncodingException if encoding fails
   * @throws ParameterException if values are too many for the degree
   */
  static Plaintext encode(const std::vector<int64_t> &values,
                          const Encoding &encoding,
                          std::shared_ptr<BfvParameters> params);

  /**
   * @brief Encode an array of uint64_t values
   * @param values Array of values to encode
   * @param size Size of the array
   * @param encoding Encoding type and level
   * @param params BFV parameters
   * @return Encoded plaintext
   * @throws EncodingException if encoding fails
   * @throws ParameterException if values are too many for the degree
   */
  static Plaintext encode(const uint64_t *values, size_t size,
                          const Encoding &encoding,
                          std::shared_ptr<BfvParameters> params);

  /**
   * @brief Encode an array of int64_t values
   * @param values Array of values to encode
   * @param size Size of the array
   * @param encoding Encoding type and level
   * @param params BFV parameters
   * @return Encoded plaintext
   * @throws EncodingException if encoding fails
   * @throws ParameterException if values are too many for the degree
   */
  static Plaintext encode(const int64_t *values, size_t size,
                          const Encoding &encoding,
                          std::shared_ptr<BfvParameters> params);

  // Decoding methods
  /**
   * @brief Decode plaintext to vector of uint64_t values
   * @param encoding Optional encoding specification (uses stored encoding if
   * not provided)
   * @return Decoded values
   * @throws EncodingException if no encoding is specified or encoding mismatch
   */
  std::vector<uint64_t> decode_uint64(
      const std::optional<Encoding> &encoding = std::nullopt) const;

  /**
   * @brief Decode plaintext to vector of int64_t values
   * @param encoding Optional encoding specification (uses stored encoding if
   * not provided)
   * @return Decoded values
   * @throws EncodingException if no encoding is specified or encoding mismatch
   */
  std::vector<int64_t> decode_int64(
      const std::optional<Encoding> &encoding = std::nullopt) const;

  // Utility methods
  /**
   * @brief Generate a zero plaintext
   * @param encoding Encoding type and level
   * @param params BFV parameters
   * @return Zero plaintext
   * @throws ParameterException if parameters are invalid
   */
  static Plaintext zero(const Encoding &encoding,
                        std::shared_ptr<BfvParameters> params);

  /**
   * @brief Create plaintext from decrypted coefficients (internal use)
   * @param coeffs Decrypted coefficient values
   * @param poly_ntt Polynomial in NTT representation
   * @param level Ciphertext level
   * @param params BFV parameters
   * @param encoding Optional encoding to preserve from original plaintext
   * @return Plaintext object
   */
  static Plaintext from_decrypted_coeffs(
      const std::vector<uint64_t> &coeffs,
      const ::bfv::math::rq::Poly &poly_ntt, size_t level,
      std::shared_ptr<BfvParameters> params,
      const std::optional<Encoding> &encoding = std::nullopt);

  // 轻量重载：仅以系数构造，poly_ntt 将按需惰性生成
  static Plaintext from_decrypted_coeffs(
      const std::vector<uint64_t> &coeffs, size_t level,
      std::shared_ptr<BfvParameters> params,
      const std::optional<Encoding> &encoding = std::nullopt);

  // 移动重载：直接接管系数内存，避免一次拷贝
  static Plaintext from_decrypted_coeffs(
      std::vector<uint64_t> &&coeffs, size_t level,
      std::shared_ptr<BfvParameters> params,
      const std::optional<Encoding> &encoding = std::nullopt);

  // 就地设置解密后的系数，避免临时对象构造
  void set_decrypted_coeffs(
      std::vector<uint64_t> &&coeffs, size_t level,
      std::shared_ptr<BfvParameters> params,
      const std::optional<Encoding> &encoding = std::nullopt);

  /// @brief Resize the internal coefficients buffer without discarding capacity
  void resize_raw(size_t size);

  /// @brief Get mutable pointer to internal coefficients
  uint64_t *data();

  /// @brief Update metadata after in-place decryption
  void set_metadata(size_t level, std::shared_ptr<BfvParameters> params,
                    const std::optional<Encoding> &encoding);

  /**
   * @brief Returns the level of this plaintext
   * @return The level
   */
  size_t level() const;

  /**
   * @brief Get the encoding of this plaintext (if known)
   * @return Optional encoding
   */
  std::optional<Encoding> encoding() const;

  /**
   * @brief Get the BFV parameters
   * @return Shared pointer to parameters
   */
  std::shared_ptr<BfvParameters> parameters() const;

  /**
   * @brief Securely clear all sensitive data (zeroize)
   * This method overwrites all sensitive data with zeros
   */
  void zeroize();

  /**
   * @brief Check if this plaintext is empty/uninitialized
   * @return true if empty, false otherwise
   */
  bool empty() const;

  /**
   * @brief Get the internal NTT polynomial (for advanced operations)
   * @return Reference to the internal NTT polynomial
   */
  const ::bfv::math::rq::Poly &polynomial_ntt() const;

  /**
   * @brief Get the polynomial for homomorphic operations
   * This method returns the properly scaled polynomial for use in homomorphic
   * operations
   * @return Polynomial ready for homomorphic operations
   */
  ::bfv::math::rq::Poly polynomial_for_ops() const;

  // Serialization methods
  /**
   * @brief Serialize plaintext to bytes using msgpack
   * @return Serialized plaintext data as yacl::Buffer
   * @throws SerializationException if serialization fails
   */
  [[nodiscard]] yacl::Buffer Serialize() const;

  /**
   * @brief Deserialize plaintext from bytes
   * @param in Serialized plaintext data
   * @param params BFV parameters for reconstruction
   * @throws SerializationException if deserialization fails
   */
  void Deserialize(yacl::ByteContainerView in,
                   std::shared_ptr<BfvParameters> params);

  /**
   * @brief Create plaintext from serialized bytes
   * @param bytes Serialized plaintext data
   * @param params BFV parameters for reconstruction
   * @return Deserialized plaintext
   * @throws SerializationException if deserialization fails
   */
  static Plaintext from_bytes(yacl::ByteContainerView bytes,
                              std::shared_ptr<BfvParameters> params);

 private:
  // PIMPL idiom
  class Impl;
  std::unique_ptr<Impl> pImpl;

  // Private constructor for internal use
  explicit Plaintext(std::unique_ptr<Impl> impl);

  // Internal method to convert to polynomial (used by encryption)
  ::bfv::math::rq::Poly to_poly() const;

  // Friend classes that need access to internal methods
  friend class SecretKey;
  friend class PublicKey;
  friend class Ciphertext;
};

}  // namespace bfv
}  // namespace crypto
