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

#pragma once

#include "heu/library/numpy/matrix.h"
#include "heu/library/phe/phe.h"

namespace heu::lib::numpy {

class Evaluator : public phe::Evaluator {
 public:
  explicit Evaluator(phe::Evaluator evaluator)
      : phe::Evaluator(std::move(evaluator)) {}

  // dense cwise add
  CMatrix Add(const CMatrix& x, const CMatrix& y) const;
  CMatrix Add(const CMatrix& x, const PMatrix& y) const;
  CMatrix Add(const PMatrix& x, const CMatrix& y) const;
  PMatrix Add(const PMatrix& x, const PMatrix& y) const;

  // dense cwise sub
  CMatrix Sub(const CMatrix& x, const CMatrix& y) const;
  CMatrix Sub(const CMatrix& x, const PMatrix& y) const;
  CMatrix Sub(const PMatrix& x, const CMatrix& y) const;
  PMatrix Sub(const PMatrix& x, const PMatrix& y) const;

  // dense cwise mul
  CMatrix Mul(const CMatrix& x, const CMatrix& y) const;
  CMatrix Mul(const CMatrix& x, const PMatrix& y) const;
  CMatrix Mul(const PMatrix& x, const CMatrix& y) const;
  PMatrix Mul(const PMatrix& x, const PMatrix& y) const;

  // dense matrix mul
  CMatrix MatMul(const CMatrix& x, const PMatrix& y) const;
  CMatrix MatMul(const PMatrix& x, const CMatrix& y) const;
  PMatrix MatMul(const PMatrix& x, const PMatrix& y) const;

  // reduce add
  template <typename T>
  T Sum(const DenseMatrix<T>& x) const;  // x is PMatrix or CMatrix
};

}  // namespace heu::lib::numpy
