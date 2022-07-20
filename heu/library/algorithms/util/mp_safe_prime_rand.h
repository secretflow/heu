#pragma once
#include "tommath_private.h"

namespace heu::lib::algorithms {
// Reference: https://eprint.iacr.org/2003/186.pdf
// libtommath style
void mp_safe_prime_rand(mp_int *a, int t, int size);

}  // namespace heu::lib::algorithms
