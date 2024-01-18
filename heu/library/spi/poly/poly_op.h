// Copyright 2023 Ant Group Co., Ltd.
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

#include <cstdint>
#include <vector>

#include "heu/library/spi/poly/poly_def.h"

namespace heu::lib::spi {

class ElementWisePolyOperator {
 public:
  virtual ~ElementWisePolyOperator() = default;

  //=== Element-wise polynomial operations ===//

  // just mod the coefficients
  /// \param coeff_modulus coefficient modulus of each polynomial
  virtual Polys Mod(const Polys &in, const Moduli &coeff_modulus) const = 0;
  virtual void ModInplace(Polys *polys, const Moduli &coeff_modulus) const = 0;

  // just mod the coefficients
  virtual Polys NegateMod(const Polys &in,
                          const Moduli &coeff_modulus) const = 0;
  virtual void NegateModInplace(Polys *polys,
                                const Moduli &coeff_modulus) const = 0;

  /// Add two batches of polynomials
  /// \param in1 first batch of polynomials
  /// \param in2 second batch of polynomials
  /// \param coeff_modulus coefficient modulus of each polynomial
  virtual Polys AddMod(const Polys &in1, const Polys &in2,
                       const Moduli &coeff_modulus) const = 0;
  virtual void AddModInplace(Polys *polys_1, const Polys &polys_2,
                             const Moduli &coeff_modulus) const = 0;

  // add scalar to coefficients with broadcast
  virtual Polys AddMod(const Polys &polys_in,
                       const std::vector<uint64_t> &scalar_in,
                       const Moduli &coeff_modulus) const = 0;
  virtual void AddModInplace(Polys *polys,
                             const std::vector<uint64_t> &scalar_in,
                             const Moduli &coeff_modulus) const = 0;

  virtual Polys SubMod(const Polys &in1, const Polys &in2,
                       const Moduli &coeff_modulus) const = 0;
  virtual void SubModInplace(Polys *polys_1, const Polys &polys_2,
                             const Moduli &coeff_modulus) const = 0;

  // Sub with broadcast
  virtual Polys SubMod(const Polys &polys_in,
                       const std::vector<uint64_t> &scalar_in,
                       const Moduli &coeff_modulus) const = 0;
  virtual void SubModInplace(Polys *polys,
                             const std::vector<uint64_t> &scalar_in,
                             const Moduli &coeff_modulus) const = 0;

  // Element-wise mul
  virtual Polys MulMod(const Polys &in1, const Polys &in2,
                       const Moduli &coeff_modulus) const = 0;
  virtual void MulModInplace(Polys *polys_1, const Polys &polys_2,
                             const Moduli &coeff_modulus) const = 0;

  // Element-wise mul with broadcast
  virtual Polys MulMod(const Polys &polys_in,
                       const std::vector<uint64_t> &scalar_in,
                       const Moduli &coeff_modulus) const = 0;
  virtual void MulModInplace(Polys *polys,
                             const std::vector<uint64_t> &scalar_in,
                             const Moduli &coeff_modulus) const = 0;

  // permute coefficients
  // coeff[offset * i] = sign * coeff[i].
  // if offset * i >= N, then sign is -1, otherwise 1
  virtual Polys Automorphism(const Polys &in, size_t offset,
                             const Moduli &coeff_modulus) const = 0;
  virtual void AutomorphismInplace(Polys *polys, size_t offset,
                                   const Moduli &coeff_modulus) const = 0;
};

}  // namespace heu::lib::spi
