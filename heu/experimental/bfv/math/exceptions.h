#ifndef RQ_EXCEPTIONS_H
#define RQ_EXCEPTIONS_H

#include <stdexcept>
#include <string>

#include "math/representation.h"

namespace bfv::math::rq {

/**
 * @brief Base exception class for RQ module errors.
 */
class RqException : public std::exception {
 public:
  explicit RqException(const std::string &message) : message_(message) {}

  const char *what() const noexcept override { return message_.c_str(); }

 private:
  std::string message_;
};

/**
 * @brief Exception thrown when context is invalid or incompatible.
 */
class InvalidContextException : public RqException {
 public:
  InvalidContextException()
      : RqException("Contexts are not compatible for this operation") {}
};

/**
 * @brief Exception thrown when polynomial representation is incorrect for
 * operation.
 */
class IncorrectRepresentationException : public RqException {
 public:
  IncorrectRepresentationException(Representation current,
                                   Representation expected)
      : RqException("Operation requires representation " +
                    std::string(representation_to_string(expected)) +
                    " but found " +
                    std::string(representation_to_string(current))) {}
};

/**
 * @brief Exception thrown when no more context is available for modulus
 * switching.
 */
class NoMoreContextException : public RqException {
 public:
  NoMoreContextException()
      : RqException("Polynomial is already at the last context level") {}
};

/**
 * @brief Exception thrown for general default errors.
 */
class DefaultException : public RqException {
 public:
  explicit DefaultException(const std::string &message)
      : RqException(message) {}
};

}  // namespace bfv::math::rq

#endif  // RQ_EXCEPTIONS_H
