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

#include "heu/library/algorithms/ecc/toy/weierstrass.h"

namespace heu::lib::algorithms::ecc::toy {

static std::map<CurveName, WeierstrassCurveParam> kPredefinedCurves = {
    {"secp256k1",
     {
         "0x0"_mp,  // A
         "0x7"_mp,  // B
         {"0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"_mp,
          "0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"_mp},
         "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"_mp,
         "0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"_mp,
         "0x1"_mp  // h
     }},
    // https://www.oscca.gov.cn/sca/xxgk/2010-12/17/content_1002386.shtml
    {"sm2",
     {
         "0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC"_mp,
         "0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93"_mp,
         {"0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7"_mp,
          "0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0"_mp},
         "0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF"_mp,
         "0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123"_mp,
         "0x1"_mp  // h
     }},
};

static const AffinePoint kInfPoint = AffinePoint(MPInt(0), MPInt(0));
static const EcPoint kInfEcPoint = kInfPoint;

WeierstrassCurveGroup::WeierstrassCurveGroup(const std::string &curve_name)
    : name_(curve_name) {
  YACL_ENFORCE(kPredefinedCurves.find(curve_name) != kPredefinedCurves.end(),
               "curve {} not supported", curve_name);
  params_ = kPredefinedCurves.at(curve_name);
}

CurveName WeierstrassCurveGroup::GetCurveName() const { return name_; }

CurveType WeierstrassCurveGroup::GetCurveType() const {
  return CurveType::WEIERSTRASS;
}

SupplyLib WeierstrassCurveGroup::GetSupplyLib() const { return SupplyLib::TOY; }

MPInt WeierstrassCurveGroup::GetCofactor() const { return params_.h; }

MPInt WeierstrassCurveGroup::GetField() const { return params_.p; }
MPInt WeierstrassCurveGroup::GetOrder() const { return params_.n; }

EcPoint WeierstrassCurveGroup::GetGenerator() const { return params_.G; }

size_t WeierstrassCurveGroup::GetSecurityStrength() const { return 128; }

std::string WeierstrassCurveGroup::ToString() {
  return fmt::format("{} ==> y^2 = x^3 + {}x + {} (mod {})", name_, params_.A,
                     params_.B, params_.p);
}

AffinePoint WeierstrassCurveGroup::Add(const AffinePoint &p1,
                                       const AffinePoint &p2) const {
  if (IsInfinity(p1)) {
    return p2;
  }

  if (IsInfinity(p2)) {
    return p1;
  }

  if (p1.x == p2.x && p1.y != p2.y) {
    return kInfPoint;
  }

  MPInt lambda(0, params_.p.BitCount());
  if (p1.x == p2.x) {
    // p1 == p2, double it
    auto tmp = p1.x.Pow(2);
    tmp.MulInplace(3);
    tmp += params_.A;
    MPInt::MulMod(tmp, p1.y.Mul(2).InvertMod(params_.p), params_.p, &lambda);
  } else {
    MPInt::MulMod(p2.y - p1.y,
                  (p2.x.SubMod(p1.x, params_.p)).InvertMod(params_.p),
                  params_.p, &lambda);
  }

  auto x3 = lambda.Pow(2).SubMod(p1.x + p2.x, params_.p);
  auto y3 = (lambda * (p1.x - x3)).SubMod(p1.y, params_.p);
  return AffinePoint(x3, y3);
}

EcPoint WeierstrassCurveGroup::Add(const EcPoint &p1, const EcPoint &p2) const {
  const AffinePoint &op1 = std::get<AffinePoint>(p1);
  const AffinePoint &op2 = std::get<AffinePoint>(p2);
  return Add(op1, op2);
}

EcPoint WeierstrassCurveGroup::Sub(const EcPoint &p1, const EcPoint &p2) const {
  return Add(p1, Negate(p2));
}

EcPoint WeierstrassCurveGroup::MulBase(const MPInt &scalar) const {
  return Mul(scalar, params_.G);
}

EcPoint WeierstrassCurveGroup::Mul(const MPInt &scalar,
                                   const EcPoint &point) const {
  const AffinePoint &op = std::get<AffinePoint>(point);

  if (IsInfinity(op)) {
    return kInfEcPoint;
  }

  if ((scalar % params_.n).IsZero()) {
    return kInfEcPoint;
  }

  AffinePoint base = op;
  MPInt exp = scalar.Abs();

  auto res = MPInt::CustomGroupPowSlow<AffinePoint>(
      kInfPoint, base, exp,
      [this](AffinePoint *a, const AffinePoint &b) { *a = Add(*a, b); });

  if (scalar.IsNegative()) {
    return Negate(res);
  } else {
    return res;
  }
}

EcPoint WeierstrassCurveGroup::MulDoubleBase(const MPInt &s1, const EcPoint &p1,
                                             const MPInt &s2) const {
  return Add(Mul(s1, p1), MulBase(s2));
}

EcPoint WeierstrassCurveGroup::Div(const EcPoint &point,
                                   const MPInt &scalar) const {
  YACL_ENFORCE(!scalar.IsZero(), "Ecc point can not div by zero!");

  if (scalar.IsPositive()) {
    return Mul(scalar.InvertMod(params_.n), point);
  }

  auto res = Mul(scalar.Abs().InvertMod(params_.n), point);
  return Negate(res);
}

EcPoint WeierstrassCurveGroup::Negate(const EcPoint &point) const {
  const AffinePoint &op = std::get<AffinePoint>(point);
  if (IsInfinity(op)) {
    return point;
  }
  return AffinePoint(op.x, params_.p - op.y);
}

AffinePoint WeierstrassCurveGroup::GetAffinePoint(const EcPoint &point) const {
  return std::get<AffinePoint>(point);
}

yacl::Buffer WeierstrassCurveGroup::SerializePoint(const EcPoint &point) const {
  const AffinePoint &op = std::get<AffinePoint>(point);
  return op.Serialize();
}

void WeierstrassCurveGroup::SerializePoint(const EcPoint &point,
                                           yacl::Buffer *buf) const {
  *buf = SerializePoint(point);
}

EcPoint WeierstrassCurveGroup::DeserializePoint(
    yacl::ByteContainerView buf) const {
  AffinePoint op;
  op.Deserialize(buf);
  return op;
}

EcPoint WeierstrassCurveGroup::HashToCurve(HashToCurveStrategy strategy,
                                           std::string_view str) const {
  YACL_THROW("not impl");
}

bool WeierstrassCurveGroup::PointEqual(const EcPoint &p1,
                                       const EcPoint &p2) const {
  return std::get<AffinePoint>(p1) == std::get<AffinePoint>(p2);
}

bool WeierstrassCurveGroup::IsInCurveGroup(const EcPoint &point) const {
  const AffinePoint &p = std::get<AffinePoint>(point);
  return IsInfinity(p) ||
         ((p.y.Pow(2) - p.x.Pow(3) - params_.A * p.x - params_.B) % params_.p)
             .IsZero();
}

bool WeierstrassCurveGroup::IsInfinity(const EcPoint &point) const {
  return IsInfinity(std::get<AffinePoint>(point));
}

bool WeierstrassCurveGroup::IsInfinity(const AffinePoint &p) const {
  return p.x.IsZero() && p.y.IsZero();
}

}  // namespace heu::lib::algorithms::ecc::toy
