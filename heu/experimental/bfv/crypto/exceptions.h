#pragma once

#include <exception>
#include <string>

namespace crypto {
namespace bfv {

/**
 * Base exception class for BFV homomorphic encryption operations
 */
class BfvException : public std::exception {
 public:
  explicit BfvException(const std::string &message) : message_(message) {}

  const char *what() const noexcept override { return message_.c_str(); }

 private:
  std::string message_;
};

/**
 * Exception thrown when invalid parameters are provided
 */
class ParameterException : public BfvException {
 public:
  explicit ParameterException(const std::string &message)
      : BfvException("Parameter error: " + message) {}
};

/**
 * Exception thrown when encoding/decoding operations fail
 */
class EncodingException : public BfvException {
 public:
  explicit EncodingException(const std::string &message)
      : BfvException("Encoding error: " + message) {}
};

/**
 * Exception thrown when mathematical operations fail
 */
class MathException : public BfvException {
 public:
  explicit MathException(const std::string &message)
      : BfvException("Math error: " + message) {}
};

/**
 * Exception thrown when serialization operations fail
 */
class SerializationException : public BfvException {
 public:
  explicit SerializationException(const std::string &message)
      : BfvException("Serialization error: " + message) {}
};

}  // namespace bfv
}  // namespace crypto
