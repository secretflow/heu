#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <random>
#include <vector>

#include "crypto/encoding.h"
#include "crypto/exceptions.h"
#include "yacl/base/byte_container_view.h"

// Forward declarations for BFV components
namespace crypto {
namespace bfv {
class BfvParameters;
class Plaintext;
class Ciphertext;
class RGSWCiphertext;
}  // namespace bfv
}  // namespace crypto

// Forward declarations for math library components
namespace bfv::math::rq {
class Context;
class Poly;
class SubstitutionExponent;
}  // namespace bfv::math::rq

namespace crypto {
namespace bfv {

/**
 * Secret key for the BFV encryption scheme.
 *
 * This class represents a secret key used for encryption and decryption in the
 * BFV scheme. Secret keys should not be copied for security reasons, only
 * moved. The key automatically zeroizes its memory when destroyed.
 */
class SecretKey {
 public:
  // Destructor - automatically zeroizes sensitive data
  ~SecretKey();

  // Delete copy constructor and assignment (move-only semantics)
  SecretKey(const SecretKey &) = delete;
  SecretKey &operator=(const SecretKey &) = delete;

  // Move constructor and assignment
  SecretKey(SecretKey &&other) noexcept;
  SecretKey &operator=(SecretKey &&other) noexcept;

  // Static factory methods for key generation
  /**
   * @brief Generate a random secret key using CBD sampling
   * @tparam RNG Random number generator type (must satisfy CryptoRng
   * requirements)
   * @param params BFV parameters
   * @param rng Random number generator
   * @return Generated secret key
   * @throws ParameterException if parameters are invalid
   */
  template <typename RNG>
  static SecretKey random(std::shared_ptr<BfvParameters> params, RNG &rng);

  /**
   * @brief Generate a random secret key using std::mt19937_64
   * @param params BFV parameters
   * @param rng Random number generator
   * @return Generated secret key
   * @throws ParameterException if parameters are invalid
   */
  static SecretKey random(std::shared_ptr<BfvParameters> params,
                          std::mt19937_64 &rng);

  /**
   * @brief Create a secret key with all coefficients set to 1 (for debugging)
   * @param params BFV parameters
   * @return Secret key with all coefficients = 1
   * @throws ParameterException if parameters are invalid
   */
  static SecretKey ones(std::shared_ptr<BfvParameters> params);

  // Encryption methods
  /**
   * @brief Encrypt a plaintext
   * @tparam RNG Random number generator type
   * @param plaintext Plaintext to encrypt
   * @param rng Random number generator
   * @return Encrypted ciphertext
   * @throws ParameterException if parameters don't match
   * @throws MathException if encryption fails
   */
  template <typename RNG>
  Ciphertext encrypt(const Plaintext &plaintext, RNG &rng) const;

  /**
   * @brief Encrypt a plaintext using std::mt19937_64
   * @param plaintext Plaintext to encrypt
   * @param rng Random number generator
   * @return Encrypted ciphertext
   * @throws ParameterException if parameters don't match
   * @throws MathException if encryption fails
   */
  Ciphertext encrypt(const Plaintext &plaintext, std::mt19937_64 &rng) const;

  /**
   * @brief Encrypt a plaintext with zero noise (for debugging)
   * @param plaintext Plaintext to encrypt
   * @return Encrypted ciphertext with zero noise
   * @throws ParameterException if parameters don't match
   * @throws MathException if encryption fails
   */
  Ciphertext encrypt_zero_noise(const Plaintext &plaintext) const;

  // RGSW encryption methods
  /**
   * @brief Encrypt a plaintext as RGSW ciphertext
   * @tparam RNG Random number generator type
   * @param plaintext Plaintext to encrypt
   * @param rng Random number generator
   * @return Encrypted RGSW ciphertext
   * @throws ParameterException if parameters don't match
   * @throws MathException if encryption fails
   */
  template <typename RNG>
  RGSWCiphertext encrypt_rgsw(const Plaintext &plaintext, RNG &rng) const;

  /**
   * @brief Encrypt a plaintext as RGSW ciphertext using std::mt19937_64
   * @param plaintext Plaintext to encrypt
   * @param rng Random number generator
   * @return Encrypted RGSW ciphertext
   * @throws ParameterException if parameters don't match
   * @throws MathException if encryption fails
   */
  RGSWCiphertext encrypt_rgsw(const Plaintext &plaintext,
                              std::mt19937_64 &rng) const;

  // Decryption methods
  /**
   * @brief Decrypt a ciphertext
   * @param ciphertext The ciphertext to decrypt
   * @param encoding Optional encoding to preserve from original plaintext
   * @return Decrypted plaintext
   * @throws ParameterException if parameters are incompatible
   * @throws MathException if decryption fails
   */
  Plaintext decrypt(
      const Ciphertext &ciphertext,
      const std::optional<Encoding> &encoding = std::nullopt) const;

  // 新增：更高效的解密接口，通过输出参数返回以减少拷贝
  void decrypt(const Ciphertext &ciphertext, Plaintext &out,
               const std::optional<Encoding> &encoding = std::nullopt) const;

  // Noise measurement (unsafe - variable time)
  /**
   * @brief Measure the noise in a ciphertext
   *
   * # Safety
   *
   * This operation may run in variable time depending on the value of the
   * noise. It should only be used for debugging and testing purposes.
   *
   * @param ciphertext Ciphertext to measure noise in
   * @return Noise level in bits
   * @throws ParameterException if parameters don't match
   * @throws MathException if measurement fails
   */
  size_t measure_noise(const Ciphertext &ciphertext) const;

  // Accessors
  /**
   * @brief Get the BFV parameters
   * @return Shared pointer to parameters
   */
  std::shared_ptr<BfvParameters> parameters() const;

  /**
   * @brief Check if this secret key is empty/uninitialized
   * @return true if empty, false otherwise
   */
  bool empty() const;

  /**
   * @brief Get the secret key coefficients (for internal use)
   * @return Reference to the coefficient vector
   * @throws ParameterException if key is not initialized
   */
  const std::vector<int64_t> &coefficients() const;

  /**
   * @brief Securely clear all sensitive data (zeroize)
   * This method overwrites all sensitive data with zeros
   */
  void zeroize();

  // Serialization methods
  /**
   * @brief Serialize secret key to bytes using msgpack
   * @return Serialized secret key data as yacl::Buffer
   * @throws SerializationException if serialization fails
   */
  [[nodiscard]] yacl::Buffer Serialize() const;

  /**
   * @brief Deserialize secret key from bytes
   * @param in Serialized secret key data
   * @param params BFV parameters for reconstruction
   * @throws SerializationException if deserialization fails
   */
  void Deserialize(yacl::ByteContainerView in,
                   std::shared_ptr<BfvParameters> params);

  /**
   * @brief Create secret key from serialized bytes
   * @param bytes Serialized secret key data
   * @param params BFV parameters for reconstruction
   * @return Deserialized secret key
   * @throws SerializationException if deserialization fails
   */
  static SecretKey from_bytes(yacl::ByteContainerView bytes,
                              std::shared_ptr<BfvParameters> params);

  /**
   * @brief Create secret key from coefficients (for deserialization)
   * @param coeffs Secret key coefficients
   * @param params BFV parameters
   * @return SecretKey constructed from coefficients
   */
  static SecretKey from_coefficients(const std::vector<int64_t> &coeffs,
                                     std::shared_ptr<BfvParameters> params);

 private:
  // PIMPL idiom
  class Impl;
  std::unique_ptr<Impl> pImpl;

  // Private constructor for internal use
  explicit SecretKey(std::unique_ptr<Impl> impl);

  // Private constructor from coefficients (for internal use)
  SecretKey(const std::vector<int64_t> &coeffs,
            std::shared_ptr<BfvParameters> params);

  // Internal method to encrypt a polynomial directly
  template <typename RNG>
  Ciphertext encrypt_poly(const ::bfv::math::rq::Poly &poly, RNG &rng) const;

  // Internal implementation for std::mt19937_64
  Ciphertext encrypt_poly_impl(const ::bfv::math::rq::Poly &poly,
                               std::mt19937_64 &rng) const;

  const ::bfv::math::rq::Poly &cached_ntt_key_at(
      std::shared_ptr<const ::bfv::math::rq::Context> ctx) const;
  const ::bfv::math::rq::Poly &cached_square_ntt_key_at(
      std::shared_ptr<const ::bfv::math::rq::Context> ctx) const;
  const ::bfv::math::rq::Poly &cached_substituted_ntt_key_at(
      std::shared_ptr<const ::bfv::math::rq::Context> ctx,
      const ::bfv::math::rq::SubstitutionExponent &exponent) const;

  // Friend classes that need access to internal methods
  friend class PublicKey;
  friend class RelinearizationKey;
  friend class EvaluationKey;
  friend class GaloisKey;
};

}  // namespace bfv
}  // namespace crypto

// Include template implementations
#include "crypto/secret_key_impl.h"
