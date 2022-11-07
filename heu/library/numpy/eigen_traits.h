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

#include "Eigen/Core"

#include "heu/library/phe/phe.h"

namespace Eigen {

using Plaintext = heu::lib::phe::Plaintext;
using Ciphertext = heu::lib::phe::Ciphertext;

template <>
struct NumTraits<Plaintext> : GenericNumTraits<Plaintext> {
  typedef Plaintext Real;
  typedef Plaintext NonInteger;
  typedef Plaintext Nested;

  //  static inline Real epsilon() { return Real(0); }
  //  static inline Real dummy_precision() { return Real(0); }
  static inline int digits10() { return 0; }

  enum {
    IsInteger = 1,
    IsSigned = 1,
    IsComplex = 0,
    RequireInitialization = 1,
    ReadCost = 1,
    AddCost = 3,
    MulCost = 10,
  };
};

template <>
struct NumTraits<Ciphertext> : GenericNumTraits<Ciphertext> {
  typedef Ciphertext Real;
  typedef Ciphertext NonInteger;
  typedef Ciphertext Nested;

  static inline int digits10() { return 0; }

  enum {
    IsInteger = 0,
    IsSigned = 0,
    IsComplex = 0,
    RequireInitialization = 1,
    ReadCost = 2,
    AddCost = 1000,
    MulCost = 50000,
  };
};

}  // namespace Eigen
