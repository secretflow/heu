
#include <chrono>
#include <iostream>
#include <memory>
#include <vector>

#include "math/context.h"
#include "math/modulus.h"
#include "math/substitution_exponent.h"

using namespace bfv::math::rq;
using namespace std;

int main() {
  vector<uint64_t> moduli = {1152921504606846977UL, 1152921504606781441UL,
                             1152921504606765057UL,
                             1152921504606748673UL};  // Distinct Primes
  auto ctx = Context::create(moduli, 8192);

  auto start = chrono::high_resolution_clock::now();
  int iters = 1000;
  for (int i = 0; i < iters; ++i) {
    auto exp = SubstitutionExponent::create(ctx, 3);
  }
  auto end = chrono::high_resolution_clock::now();
  auto dur = chrono::duration_cast<chrono::microseconds>(end - start).count();
  cout << "Avg SubstitutionExponent::create: " << dur / (double)iters << " us"
       << endl;

  return 0;
}
