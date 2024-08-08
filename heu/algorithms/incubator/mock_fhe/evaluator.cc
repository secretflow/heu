// Copyright 2024 Ant Group Co., Ltd.
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

#include "heu/algorithms/incubator/mock_fhe/evaluator.h"

#include <memory>
#include <vector>

#include "heu/spi/he/he_configs.h"
#include "heu/spi/utils/math_tool.h"

namespace heu::algos::mock_fhe {

Evaluator::Evaluator(size_t poly_degree, spi::Schema schema, int64_t scale,
                     const std::shared_ptr<PublicKey> &pk,
                     const std::shared_ptr<RelinKeys> &rlk,
                     const std::shared_ptr<GaloisKeys> &glk,
                     const std::shared_ptr<BootstrapKey> &bsk)
    : poly_degree_(poly_degree),
      schema_(schema),
      scale_(scale),
      pk_(pk),
      rlk_(rlk),
      glk_(glk),
      bsk_(bsk) {
  YACL_ENFORCE(spi::utils::IsPowerOf2(poly_degree_), "Illegal poly degree {}",
               poly_degree_);
  if (schema_ == spi::Schema::MockCkks) {
    YACL_ENFORCE(scale_ != 0, "scale must not be zero");
  }
  half_degree_ = poly_degree_ / 2;
}

Plaintext Evaluator::Negate(const Plaintext &a) const {
  Plaintext res;
  res->resize(a->size());
  std::transform(a->cbegin(), a->cend(), res->begin(), std::negate<int64_t>());
  res.scale_ = a.scale_;
  return res;
}

void Evaluator::NegateInplace(Plaintext *a) const {
  std::transform(a->array_.cbegin(), a->array_.cend(), a->array_.begin(),
                 std::negate<int64_t>());
}

Ciphertext Evaluator::Negate(const Ciphertext &a) const {
  Ciphertext res;
  res->resize(a->size());
  std::transform(a->cbegin(), a->cend(), res->begin(), std::negate<int64_t>());
  res.scale_ = a.scale_;
  return res;
}

void Evaluator::NegateInplace(Ciphertext *a) const {
  std::transform(a->array_.cbegin(), a->array_.cend(), a->array_.begin(),
                 std::negate<int64_t>());
}

namespace {
template <typename RES_T, typename OP_T>
RES_T DoAdd(const MockObj &a, const MockObj &b, OP_T binary_op) {
  YACL_ENFORCE_EQ(a->size(), b->size(), "Illegal input");
  YACL_ENFORCE(std::abs(a.scale_ - b.scale_) <= 1e-2,
               "scale mismatch, a is {}, b is {}", a.ToString(), b.ToString());
  RES_T res;
  res->resize(a->size());
  res.scale_ = (a.scale_ + b.scale_) / 2;
  std::transform(a->cbegin(), a->cend(), b->cbegin(), res->begin(), binary_op);
  return res;
}

template <typename OP_T>
void DoAddInplace(MockObj *a, const MockObj &b, OP_T binary_op) {
  YACL_ENFORCE_EQ((*a)->size(), b->size(), "Illegal input");
  YACL_ENFORCE(std::abs(a->scale_ - b.scale_) <= 1e-2,
               "scale mismatch, a is {}, b is {}", a->ToString(), b.ToString());
  a->scale_ = (a->scale_ + b.scale_) / 2;
  std::transform((*a)->cbegin(), (*a)->cend(), b->cbegin(), (*a)->begin(),
                 binary_op);
}
}  // namespace

Plaintext Evaluator::Add(const Plaintext &a, const Plaintext &b) const {
  return DoAdd<Plaintext>(a, b, std::plus<int64_t>());
}

Ciphertext Evaluator::Add(const Ciphertext &a, const Plaintext &b) const {
  return DoAdd<Ciphertext>(a, b, std::plus<int64_t>());
}

Ciphertext Evaluator::Add(const Ciphertext &a, const Ciphertext &b) const {
  return DoAdd<Ciphertext>(a, b, std::plus<int64_t>());
}

void Evaluator::AddInplace(Ciphertext *a, const Plaintext &b) const {
  DoAddInplace(a, b, std::plus<int64_t>());
}

void Evaluator::AddInplace(Ciphertext *a, const Ciphertext &b) const {
  DoAddInplace(a, b, std::plus<int64_t>());
}

void Evaluator::DoMul(const MockObj &a, const MockObj &b, MockObj *out) const {
  YACL_ENFORCE_EQ(a->size(), b->size(), "Illegal input");
  out->array_.resize(a->size());

  if (schema_ == spi::Schema::MockBfv) {
    std::transform(a->cbegin(), a->cend(), b->cbegin(), (*out)->begin(),
                   std::multiplies<int64_t>());
    out->scale_ = 1;
  } else {
    // ckks
    int64_t real, imag;
    for (size_t i = 0; i < half_degree_; ++i) {
      real = a.array_[i] * b.array_[i] -
             a.array_[i + half_degree_] * b.array_[i + half_degree_];
      imag = a.array_[i] * b.array_[i + half_degree_] +
             b.array_[i] * a.array_[i + half_degree_];
      out->array_.at(i) = real;
      out->array_.at(i + half_degree_) = imag;
    }
    out->scale_ = a.scale_ * b.scale_;
  }
}

Plaintext Evaluator::Mul(const Plaintext &a, const Plaintext &b) const {
  Plaintext res;
  DoMul(a, b, &res);
  return res;
}

Ciphertext Evaluator::Mul(const Ciphertext &a, const Plaintext &b) const {
  Ciphertext res;
  DoMul(a, b, &res);
  return res;
}

Ciphertext Evaluator::Mul(const Ciphertext &a, const Ciphertext &b) const {
  Ciphertext res;
  DoMul(a, b, &res);
  return res;
}

void Evaluator::MulInplace(Ciphertext *a, const Plaintext &b) const {
  DoMul(*a, b, a);
}

void Evaluator::MulInplace(Ciphertext *a, const Ciphertext &b) const {
  DoMul(*a, b, a);
}

Plaintext Evaluator::Square(const Plaintext &a) const { return Mul(a, a); }

Ciphertext Evaluator::Square(const Ciphertext &a) const { return Mul(a, a); }

void Evaluator::SquareInplace(Plaintext *a) const { DoMul(*a, *a, a); }

void Evaluator::SquareInplace(Ciphertext *a) const { DoMul(*a, *a, a); }

template <typename T>
void Evaluator::DoPow(const T &a, int64_t exp, T *out) const {
  YACL_ENFORCE(
      rlk_, "RelinKey is not enabled according to your config, cannot do Pow");
  YACL_ENFORCE(exp > 0, "exponent cannot be 0");

  bool first = true;
  T s = a;
  while (exp != 0) {
    if (exp & 1) {
      if (first) {
        *out = s;
        first = false;
      } else {
        DoMul(*out, s, out);
      }
    }
    exp >>= 1;
    if (exp != 0) {
      DoMul(s, s, &s);
    }
  }
}

Plaintext Evaluator::Pow(const Plaintext &a, int64_t exponent) const {
  Plaintext res;
  DoPow(a, exponent, &res);
  return res;
}

Ciphertext Evaluator::Pow(const Ciphertext &a, int64_t exponent) const {
  Ciphertext res;
  DoPow(a, exponent, &res);
  return res;
}

void Evaluator::PowInplace(Plaintext *a, int64_t exponent) const {
  DoPow(*a, exponent, a);
}

void Evaluator::PowInplace(Ciphertext *a, int64_t exponent) const {
  DoPow(*a, exponent, a);
}

void Evaluator::Randomize(Ciphertext *) const {
  // nothing to do
}

Ciphertext Evaluator::Relinearize(const Ciphertext &a) const {
  YACL_ENFORCE(rlk_,
               "RelinKey is not enabled according to your config, cannot do "
               "relinearize");
  return a;
}

void Evaluator::RelinearizeInplace(Ciphertext *) const {
  YACL_ENFORCE(rlk_,
               "RelinKey is not enabled according to your config, cannot do "
               "relinearize");
}

Ciphertext Evaluator::ModSwitch(const Ciphertext &a) const {
  return schema_ == spi::Schema::MockCkks ? Rescale(a) : a;
}

void Evaluator::ModSwitchInplace(Ciphertext *a) const {
  if (schema_ == spi::Schema::MockCkks) {
    ModSwitchInplace(a);
  }
}

Ciphertext Evaluator::Rescale(const Ciphertext &a) const {
  YACL_ENFORCE(schema_ == spi::Schema::MockCkks,
               "Only mock_ckks algo supports rescale");
  Ciphertext res;
  res->resize(a->size());
  std::transform(a->begin(), a->end(), res->begin(),
                 [this](int64_t in) { return in / scale_; });
  res.scale_ /= scale_;
  return res;
}

void Evaluator::RescaleInplace(Ciphertext *a) const {
  YACL_ENFORCE(schema_ == spi::Schema::MockCkks,
               "Only mock_ckks algo supports rescale");
  std::for_each(a->array_.begin(), a->array_.end(),
                [&](int64_t &in) { in /= scale_; });
  a->scale_ /= scale_;
}

Ciphertext Evaluator::SwapRows(const Ciphertext &a) const {
  YACL_ENFORCE(schema_ == spi::Schema::MockBfv,
               "Only bfv and bgv schema can swap rows");
  YACL_ENFORCE(glk_,
               "Galois key is not enabled according to your config, cannot do "
               "SwapRows");
  YACL_ENFORCE_EQ(a->size(), poly_degree_, "illegal ciphertext with degree {}",
                  a->size());

  Ciphertext res;
  res->resize(poly_degree_);
  std::copy_n(a->begin() + half_degree_, half_degree_, res->begin());
  std::copy_n(a->begin(), half_degree_, res->begin() + half_degree_);
  return res;
}

void Evaluator::SwapRowsInplace(Ciphertext *a) const {
  YACL_ENFORCE(schema_ == spi::Schema::MockBfv,
               "Only bfv and bgv schema can swap rows");
  YACL_ENFORCE(glk_,
               "Galois key is not enabled according to your config, cannot do "
               "SwapRows");
  YACL_ENFORCE_EQ(a->array_.size(), poly_degree_,
                  "illegal ciphertext with degree {}", a->array_.size());

  for (size_t i = 0; i < half_degree_; ++i) {
    std::swap(a->array_[i], a->array_[i + half_degree_]);
  }
}

Ciphertext Evaluator::Conjugate(const Ciphertext &a) const {
  Ciphertext res;
  res->resize(a->size());
  std::copy_n(a->cbegin(), half_degree_, res->begin());
  std::transform(a->cbegin() + half_degree_, a->cend(),
                 res->begin() + half_degree_, std::negate<int64_t>());
  res.scale_ = a.scale_;
  return res;
}

void Evaluator::ConjugateInplace(Ciphertext *a) const {
  YACL_ENFORCE(schema_ == spi::Schema::MockCkks,
               "Only ckks supports conjugate");
  YACL_ENFORCE_EQ(a->array_.size(), poly_degree_,
                  "illegal ciphertext with degree {}", a->array_.size());
  std::for_each(a->array_.begin() + half_degree_, a->array_.end(),
                [&](int64_t &in) { in = -in; });
}

// rotates the vector cyclically to the left (steps > 0) or to the right (steps
// < 0).
Ciphertext Evaluator::Rotate(const Ciphertext &a, int steps) const {
  YACL_ENFORCE(glk_,
               "Galois key is not enabled according to your config, cannot do "
               "SwapRows");
  YACL_ENFORCE_EQ(a->size(), poly_degree_, "illegal ciphertext with degree {}",
                  a->size());
  YACL_ENFORCE(std::abs(steps) < half_degree_, "the step {} is too large",
               steps);

  Ciphertext res;
  res->resize(poly_degree_);
  for (size_t i = 0; i < half_degree_; ++i) {
    size_t new_loc = (i - steps) % half_degree_;
    res.array_[new_loc] = a.array_[i];
    res.array_[new_loc + half_degree_] = a.array_[i + half_degree_];
  }
  res.scale_ = a.scale_;
  return res;
}

void Evaluator::RotateInplace(Ciphertext *a, int steps) const {
  *a = Rotate(*a, steps);
}

void Evaluator::BootstrapInplace(Ciphertext *) const {
  YACL_ENFORCE(
      bsk_,
      "Bootstrapping key is not enabled according to your config, cannot do "
      "SwapRows");
}

}  // namespace heu::algos::mock_fhe
