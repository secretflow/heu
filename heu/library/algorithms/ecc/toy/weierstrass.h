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

#include "heu/library/algorithms/ecc/ecc_spi.h"

namespace heu::lib::algorithms::ecc::toy {

struct WeierstrassCurveParam {
  MPInt A;
  MPInt B;
  AffinePoint G;
  MPInt p;
  MPInt n;
  MPInt h;

  WeierstrassCurveParam() = default;
};

// y^2 = x^3 + Ax + B
class WeierstrassCurveGroup : public CurveGroup {
 public:
  WeierstrassCurveGroup(const std::string &curve_name);

  CurveName GetCurveName() const override;
  SupplyLib GetSupplyLib() const override;
  CurveType GetCurveType() const override;

  MPInt GetCofactor() const override;
  MPInt GetField() const override;
  MPInt GetOrder() const override;
  EcPoint GetGenerator() const override;
  size_t GetSecurityStrength() const override;
  std::string ToString() override;
  EcPoint Add(const EcPoint &p1, const EcPoint &p2) const override;
  EcPoint Sub(const EcPoint &p1, const EcPoint &p2) const override;
  EcPoint MulBase(const MPInt &scalar) const override;
  EcPoint Mul(const MPInt &scalar, const EcPoint &point) const override;
  EcPoint MulDoubleBase(const MPInt &s1, const EcPoint &p1,
                        const MPInt &s2) const override;
  EcPoint Div(const EcPoint &point, const MPInt &scalar) const override;
  EcPoint Negate(const EcPoint &point) const override;
  AffinePoint GetAffinePoint(const EcPoint &point) const override;
  yacl::Buffer SerializePoint(const EcPoint &point) const override;
  void SerializePoint(const EcPoint &point, yacl::Buffer *buf) const override;
  EcPoint DeserializePoint(yacl::ByteContainerView buf) const override;
  EcPoint HashToCurve(HashToCurveStrategy strategy,
                      std::string_view str) const override;
  bool PointEqual(const EcPoint &p1, const EcPoint &p2) const override;
  bool IsInCurveGroup(const EcPoint &point) const override;
  bool IsInfinity(const EcPoint &point) const override;
  bool IsInfinity(const AffinePoint &point) const;

 private:
  AffinePoint Add(const AffinePoint &p1, const AffinePoint &p2) const;

  CurveName name_;
  WeierstrassCurveParam params_;
};

}  // namespace heu::lib::algorithms::ecc::toy
