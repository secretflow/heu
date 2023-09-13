// Copyright 2022 Ant Group Co., Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "heu/library/algorithms/mock/evaluator.h"

#include "fmt/ranges.h"

namespace heu::lib::algorithms::mock {

#ifdef IMPL_SCALAR_SPI
void Evaluator::Randomize(Ciphertext* ct) const { (void)ct; }

void CheckRange(const PublicKey& pk, const Ciphertext&, const Plaintext& p) {
  YACL_ENFORCE(p.bn_.CompareAbs(pk.PlaintextBound().bn_) < 0,
               "plaintext number out of range, message={}, max (abs)={}",
               p.ToHexString(), pk.PlaintextBound());
}

void CheckRange(const PublicKey& pk, const Plaintext& p, const Ciphertext&) {
  YACL_ENFORCE(p.bn_.CompareAbs(pk.PlaintextBound().bn_) < 0,
               "plaintext number out of range, message={}, max (abs)={}",
               p.ToHexString(), pk.PlaintextBound());
}

void CheckRange(const PublicKey& pk, const Ciphertext&, const Ciphertext&) {}

void CheckRange(const PublicKey& pk, const Plaintext&, const Plaintext&) {}

#define SCALAR_FUNCTION_IMPL(NAME, RET, T1, OP, T2)     \
  RET Evaluator::NAME(const T1& a, const T2& b) const { \
    CheckRange(pk_, a, b);                              \
    return RET(a.bn_ OP b.bn_);                         \
  }

// Keep same with Paillier
// No need to check size of plaintext because ciphertext overflow is allowed
#define SCALAR_FUNCTION_IMPL_MUL(RET, T1, OP, T2)      \
  RET Evaluator::Mul(const T1& a, const T2& b) const { \
    return RET(a.bn_ OP b.bn_);                        \
  }

SCALAR_FUNCTION_IMPL(Add, Ciphertext, Ciphertext, +, Ciphertext);
SCALAR_FUNCTION_IMPL(Add, Ciphertext, Ciphertext, +, Plaintext);
SCALAR_FUNCTION_IMPL(Add, Ciphertext, Plaintext, +, Ciphertext);
SCALAR_FUNCTION_IMPL(Add, Plaintext, Plaintext, +, Plaintext);

SCALAR_FUNCTION_IMPL(Sub, Ciphertext, Ciphertext, -, Ciphertext);
SCALAR_FUNCTION_IMPL(Sub, Ciphertext, Ciphertext, -, Plaintext);
SCALAR_FUNCTION_IMPL(Sub, Ciphertext, Plaintext, -, Ciphertext);
SCALAR_FUNCTION_IMPL(Sub, Plaintext, Plaintext, -, Plaintext);

SCALAR_FUNCTION_IMPL_MUL(Ciphertext, Ciphertext, *, Plaintext);
SCALAR_FUNCTION_IMPL_MUL(Ciphertext, Plaintext, *, Ciphertext);
SCALAR_FUNCTION_IMPL_MUL(Plaintext, Plaintext, *, Plaintext);

#define SCALAR_INPLACE_FUNCTION_IMPL(NAME, T1, OP, T2) \
  void Evaluator::NAME(T1* a, const T2& b) const {     \
    CheckRange(pk_, *a, b);                            \
    a->bn_ OP b.bn_;                                   \
  }

#define SCALAR_INPLACE_FUNCTION_IMPL_MUL(T1, OP, T2) \
  void Evaluator::MulInplace(T1* a, const T2& b) const { a->bn_ OP b.bn_; }

SCALAR_INPLACE_FUNCTION_IMPL(AddInplace, Ciphertext, +=, Ciphertext);
SCALAR_INPLACE_FUNCTION_IMPL(AddInplace, Ciphertext, +=, Plaintext);
SCALAR_INPLACE_FUNCTION_IMPL(AddInplace, Plaintext, +=, Plaintext);

SCALAR_INPLACE_FUNCTION_IMPL(SubInplace, Ciphertext, -=, Ciphertext);
SCALAR_INPLACE_FUNCTION_IMPL(SubInplace, Ciphertext, -=, Plaintext);
SCALAR_INPLACE_FUNCTION_IMPL(SubInplace, Plaintext, -=, Plaintext);

SCALAR_INPLACE_FUNCTION_IMPL_MUL(Ciphertext, *=, Plaintext);
SCALAR_INPLACE_FUNCTION_IMPL_MUL(Plaintext, *=, Plaintext)

Ciphertext Evaluator::Negate(const Ciphertext& a) const {
  Ciphertext out;
  a.bn_.Negate(&out.bn_);
  return out;
}

void Evaluator::NegateInplace(Ciphertext* a) const { *a = Negate(*a); }

#endif

#ifdef IMPL_VECTORIZED_SPI
void Evaluator::Randomize(Span<Ciphertext> ct) const { /* nothing to do */
}

#define SIMD_FUNCTION_IMPL(NAME, RET, T1, OP, T2)                             \
  std::vector<RET> Evaluator::NAME(ConstSpan<T1> a, ConstSpan<T2> b) const {  \
    YACL_ENFORCE(a.size() == b.size(),                                        \
                 "Function {}: array not equal, a={}, b={}", #NAME, a.size(), \
                 b.size());                                                   \
                                                                              \
    std::vector<RET> res;                                                     \
    res.reserve(a.size());                                                    \
    for (size_t i = 0; i < a.size(); ++i) {                                   \
      res.emplace_back(a[i]->bn_ OP b[i]->bn_);                               \
    }                                                                         \
                                                                              \
    return res;                                                               \
  }

SIMD_FUNCTION_IMPL(Add, Ciphertext, Ciphertext, +, Ciphertext);
SIMD_FUNCTION_IMPL(Add, Ciphertext, Ciphertext, +, Plaintext);
SIMD_FUNCTION_IMPL(Add, Ciphertext, Plaintext, +, Ciphertext);
SIMD_FUNCTION_IMPL(Add, Plaintext, Plaintext, +, Plaintext);

SIMD_FUNCTION_IMPL(Sub, Ciphertext, Ciphertext, -, Ciphertext);
SIMD_FUNCTION_IMPL(Sub, Ciphertext, Ciphertext, -, Plaintext);
SIMD_FUNCTION_IMPL(Sub, Ciphertext, Plaintext, -, Ciphertext);
SIMD_FUNCTION_IMPL(Sub, Plaintext, Plaintext, -, Plaintext);

SIMD_FUNCTION_IMPL(Mul, Ciphertext, Ciphertext, *, Plaintext);
SIMD_FUNCTION_IMPL(Mul, Ciphertext, Plaintext, *, Ciphertext);
SIMD_FUNCTION_IMPL(Mul, Plaintext, Plaintext, *, Plaintext);

#define SIMD_INPLACE_FUNCTION_IMPL(NAME, T1, OP, T2)                          \
  void Evaluator::NAME(Span<T1> a, ConstSpan<T2> b) const {                   \
    YACL_ENFORCE(a.size() == b.size(),                                        \
                 "Function {}: array not equal, a={}, b={}", #NAME, a.size(), \
                 b.size());                                                   \
    for (size_t i = 0; i < a.size(); ++i) {                                   \
      a[i]->bn_ OP b[i]->bn_;                                                 \
    }                                                                         \
  }

SIMD_INPLACE_FUNCTION_IMPL(AddInplace, Ciphertext, +=, Ciphertext);
SIMD_INPLACE_FUNCTION_IMPL(AddInplace, Ciphertext, +=, Plaintext);
SIMD_INPLACE_FUNCTION_IMPL(AddInplace, Plaintext, +=, Plaintext);

SIMD_INPLACE_FUNCTION_IMPL(SubInplace, Ciphertext, -=, Ciphertext);
SIMD_INPLACE_FUNCTION_IMPL(SubInplace, Ciphertext, -=, Plaintext);
SIMD_INPLACE_FUNCTION_IMPL(SubInplace, Plaintext, -=, Plaintext);

SIMD_INPLACE_FUNCTION_IMPL(MulInplace, Ciphertext, *=, Plaintext);
SIMD_INPLACE_FUNCTION_IMPL(MulInplace, Plaintext, *=, Plaintext)

std::vector<Ciphertext> Evaluator::Negate(ConstSpan<Ciphertext> a) const {
  std::vector<Ciphertext> res;
  res.reserve(a.size());
  for (size_t i = 0; i < a.size(); ++i) {
    res.emplace_back(-a[i]->bn_);
  }
  return res;
}

void Evaluator::NegateInplace(Span<Ciphertext> a) const {
  for (const auto& item : a) {
    item->bn_.NegateInplace();
  }
};

#endif

}  // namespace heu::lib::algorithms::mock
