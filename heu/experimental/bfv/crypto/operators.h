#pragma once

#include "crypto/ciphertext.h"
#include "crypto/plaintext.h"

namespace crypto {
namespace bfv {

/**
 * @brief BFV homomorphic operators implementation
 *
 * This file implements all homomorphic operations for BFV ciphertexts
 */

// Addition operators for Ciphertext + Ciphertext
Ciphertext operator+(const Ciphertext &lhs, const Ciphertext &rhs);

// Addition operators for Ciphertext + Plaintext (both directions)
Ciphertext operator+(const Ciphertext &lhs, const Plaintext &rhs);
Ciphertext operator+(const Plaintext &lhs, const Ciphertext &rhs);

// Subtraction operators for Ciphertext - Ciphertext
Ciphertext operator-(const Ciphertext &lhs, const Ciphertext &rhs);

// Subtraction operators for Ciphertext - Plaintext and Plaintext - Ciphertext
Ciphertext operator-(const Ciphertext &lhs, const Plaintext &rhs);
Ciphertext operator-(const Plaintext &lhs, const Ciphertext &rhs);

// Multiplication operators for Ciphertext * Ciphertext
Ciphertext operator*(const Ciphertext &lhs, const Ciphertext &rhs);

// Multiplication operators for Ciphertext * Plaintext (both directions)
Ciphertext operator*(const Ciphertext &lhs, const Plaintext &rhs);
Ciphertext operator*(const Plaintext &lhs, const Ciphertext &rhs);

// Negation operator
Ciphertext operator-(const Ciphertext &operand);

// Assignment operators
Ciphertext &operator+=(Ciphertext &lhs, const Ciphertext &rhs);
Ciphertext &operator+=(Ciphertext &lhs, const Plaintext &rhs);
Ciphertext &operator-=(Ciphertext &lhs, const Ciphertext &rhs);
Ciphertext &operator-=(Ciphertext &lhs, const Plaintext &rhs);
Ciphertext &operator*=(Ciphertext &lhs, const Ciphertext &rhs);
Ciphertext &operator*=(Ciphertext &lhs, const Plaintext &rhs);

/**
 * @brief Clears the internal static cache used by operator*.
 *
 * Must be called before thread exit to prevent memory teardown crashes.
 */
void clear_operator_cache();

}  // namespace bfv
}  // namespace crypto
