#pragma once

#include <cstdint>
#include <memory>
#include <random>
#include <vector>

#include "crypto/exceptions.h"
#include "yacl/base/byte_container_view.h"

// Forward declarations for BFV components
namespace crypto {
namespace bfv {
class BfvParameters;
class Ciphertext;
class Plaintext;
class SecretKey;
class KeySwitchingKey;
}  // namespace bfv
}  // namespace crypto

namespace crypto {
namespace bfv {

/**
 * A RGSW ciphertext encrypting a plaintext.
 *
 * RGSW (Ring-GSW) is a variant of the GSW encryption scheme that works
 * over polynomial rings. It enables external products between RGSW
 * ciphertexts and regular BFV ciphertexts.
 */
class RGSWCiphertext {
 public:
  // Destructor
  ~RGSWCiphertext();

  // Copy constructor and assignment
  RGSWCiphertext(const RGSWCiphertext &other);
  RGSWCiphertext &operator=(const RGSWCiphertext &other);

  // Move constructor and assignment
  RGSWCiphertext(RGSWCiphertext &&other) noexcept;
  RGSWCiphertext &operator=(RGSWCiphertext &&other) noexcept;

  // Accessors
  /**
   * @brief Get the BFV parameters
   * @return Shared pointer to parameters
   */
  std::shared_ptr<BfvParameters> parameters() const;

  /**
   * @brief Get the level of this RGSW ciphertext
   * @return The level
   */
  size_t level() const;

  /**
   * @brief Check if this RGSW ciphertext is empty/uninitialized
   * @return true if empty, false otherwise
   */
  bool empty() const;

  /**
   * @brief Get the first key switching key (for serialization)
   * @return Reference to ksk0
   */
  const KeySwitchingKey &ksk0() const;

  /**
   * @brief Get the second key switching key (for serialization)
   * @return Reference to ksk1
   */
  const KeySwitchingKey &ksk1() const;

  // Equality operators
  bool operator==(const RGSWCiphertext &other) const;
  bool operator!=(const RGSWCiphertext &other) const;

  // Arithmetic operators
  /**
   * @brief Add two RGSW ciphertexts
   * @param other The other RGSW ciphertext to add
   * @return The sum of the two RGSW ciphertexts
   * @throws ParameterException if parameters don't match
   */
  RGSWCiphertext operator+(const RGSWCiphertext &other) const;

  // Serialization methods
  /**
   * @brief Serialize RGSW ciphertext to bytes using msgpack
   * @return Serialized RGSW ciphertext data as yacl::Buffer
   * @throws SerializationException if serialization fails
   */
  [[nodiscard]] yacl::Buffer Serialize() const;

  /**
   * @brief Deserialize RGSW ciphertext from bytes
   * @param in Serialized RGSW ciphertext data
   * @param params BFV parameters for reconstruction
   * @throws SerializationException if deserialization fails
   */
  void Deserialize(yacl::ByteContainerView in,
                   std::shared_ptr<BfvParameters> params);

  /**
   * @brief Create RGSW ciphertext from serialized bytes
   * @param bytes Serialized RGSW ciphertext data
   * @param params BFV parameters for reconstruction
   * @return Deserialized RGSW ciphertext
   * @throws SerializationException if deserialization fails
   */
  static RGSWCiphertext from_bytes(yacl::ByteContainerView bytes,
                                   std::shared_ptr<BfvParameters> params);

  /**
   * @brief Create RGSW ciphertext from key switching keys
   * @param ksk0 Key switching key for m
   * @param ksk1 Key switching key for m*s
   * @return RGSW ciphertext
   */
  static RGSWCiphertext create_from_keys(KeySwitchingKey ksk0,
                                         KeySwitchingKey ksk1);

 private:
  // PIMPL idiom
  class Impl;
  std::unique_ptr<Impl> pImpl;

  // Private constructor for internal use
  explicit RGSWCiphertext(std::unique_ptr<Impl> impl);

  // Friend classes that need access to internal methods
  friend class SecretKey;

  // Friend functions for external product operations
  friend Ciphertext operator*(const Ciphertext &ct, const RGSWCiphertext &rgsw);
  friend Ciphertext operator*(const RGSWCiphertext &rgsw, const Ciphertext &ct);
};

// External product operations
/**
 * @brief External product between a BFV ciphertext and RGSW ciphertext
 * @param ct The BFV ciphertext (must have exactly 2 polynomials)
 * @param rgsw The RGSW ciphertext
 * @return The result of the external product
 * @throws ParameterException if parameters don't match or ct has wrong size
 * @throws MathException if operation fails
 */
Ciphertext operator*(const Ciphertext &ct, const RGSWCiphertext &rgsw);

/**
 * @brief External product between RGSW ciphertext and a BFV ciphertext
 * (commutative)
 * @param rgsw The RGSW ciphertext
 * @param ct The BFV ciphertext (must have exactly 2 polynomials)
 * @return The result of the external product
 * @throws ParameterException if parameters don't match or ct has wrong size
 * @throws MathException if operation fails
 */
Ciphertext operator*(const RGSWCiphertext &rgsw, const Ciphertext &ct);

}  // namespace bfv
}  // namespace crypto
