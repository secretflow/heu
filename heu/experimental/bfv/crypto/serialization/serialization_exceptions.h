#pragma once

#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>

namespace crypto {
namespace bfv {
namespace serialization {

/**
 * @brief Base exception class for all serialization-related errors
 */
class SerializationException : public std::exception {
 private:
  std::string message_;

 public:
  /**
   * @brief Construct a serialization exception with a message
   * @param message Descriptive error message
   */
  explicit SerializationException(const std::string &message)
      : message_("Serialization error: " + message) {}

  /**
   * @brief Get the exception message
   * @return C-style string containing the error message
   */
  const char *what() const noexcept override { return message_.c_str(); }

  /**
   * @brief Get the stored error message, including the class-specific prefix
   * @return The formatted error message
   */
  const std::string &get_message() const noexcept { return message_; }
};

/**
 * @brief Exception thrown when serialized schema validation fails
 */
class SchemaValidationException : public SerializationException {
 public:
  /**
   * @brief Construct a schema validation exception
   * @param message Descriptive error message about schema validation failure
   */
  explicit SchemaValidationException(const std::string &message)
      : SerializationException("Schema validation failed: " + message) {}
};

/**
 * @brief Exception thrown when deserialized data fails integrity checks
 */
class DataCorruptionException : public SerializationException {
 public:
  /**
   * @brief Construct a data corruption exception
   * @param message Descriptive error message about data corruption
   */
  explicit DataCorruptionException(const std::string &message)
      : SerializationException("Data corruption detected: " + message) {}
};

/**
 * @brief Exception thrown when schema versions are incompatible
 */
class VersionMismatchException : public SerializationException {
 private:
  uint32_t expected_version_;
  uint32_t actual_version_;

 public:
  /**
   * @brief Construct a version mismatch exception
   * @param expected_version The expected schema version
   * @param actual_version The actual schema version found in data
   */
  VersionMismatchException(uint32_t expected_version, uint32_t actual_version)
      : SerializationException("Schema version mismatch: expected " +
                               std::to_string(expected_version) + ", got " +
                               std::to_string(actual_version)),
        expected_version_(expected_version),
        actual_version_(actual_version) {}

  /**
   * @brief Get the expected schema version
   * @return Expected version number
   */
  uint32_t get_expected_version() const noexcept { return expected_version_; }

  /**
   * @brief Get the actual schema version found in data
   * @return Actual version number
   */
  uint32_t get_actual_version() const noexcept { return actual_version_; }
};

/**
 * @brief Exception thrown when parameters don't match during deserialization
 */
class ParameterMismatchException : public SerializationException {
 public:
  /**
   * @brief Construct a parameter mismatch exception
   * @param message Descriptive error message about parameter mismatch
   */
  explicit ParameterMismatchException(const std::string &message)
      : SerializationException("Parameter mismatch: " + message) {}
};

/**
 * @brief Exception thrown when memory allocation fails during serialization
 */
class MemoryAllocationException : public SerializationException {
 public:
  /**
   * @brief Construct a memory allocation exception
   * @param message Descriptive error message about memory allocation failure
   */
  explicit MemoryAllocationException(const std::string &message)
      : SerializationException("Memory allocation failed: " + message) {}
};

/**
 * @brief Exception thrown when polynomial data validation fails
 */
class PolynomialValidationException : public SerializationException {
 private:
  size_t polynomial_index_;
  size_t coefficient_index_;

 public:
  /**
   * @brief Construct a polynomial validation exception
   * @param message Descriptive error message
   * @param polynomial_index Index of the polynomial that failed validation
   * @param coefficient_index Index of the coefficient that failed validation
   */
  PolynomialValidationException(const std::string &message,
                                size_t polynomial_index,
                                size_t coefficient_index)
      : SerializationException(
            "Polynomial validation failed at polynomial " +
            std::to_string(polynomial_index) + ", coefficient " +
            std::to_string(coefficient_index) + ": " + message),
        polynomial_index_(polynomial_index),
        coefficient_index_(coefficient_index) {}

  /**
   * @brief Get the index of the polynomial that failed validation
   * @return Polynomial index
   */
  size_t get_polynomial_index() const noexcept { return polynomial_index_; }

  /**
   * @brief Get the index of the coefficient that failed validation
   * @return Coefficient index
   */
  size_t get_coefficient_index() const noexcept { return coefficient_index_; }
};

/**
 * @brief Exception thrown when buffer operations fail
 */
class BufferException : public SerializationException {
 public:
  /**
   * @brief Construct a buffer exception
   * @param message Descriptive error message about buffer operation failure
   */
  explicit BufferException(const std::string &message)
      : SerializationException("Buffer operation failed: " + message) {}
};

}  // namespace serialization
}  // namespace bfv
}  // namespace crypto
