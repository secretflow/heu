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

#include <ostream>
#include <tuple>
#include <variant>

#include "yacl/base/byte_container_view.h"

#include "heu/library/algorithms/util/he_object.h"
#include "heu/library/algorithms/util/mp_int.h"

// We will move MPInt & ECC module to YACL when stable
namespace heu::lib::algorithms::ecc {

// Some cryptographers (like Daniel Bernstein) believe that most of the curves,
// described in the official crypto-standards are "unsafe" and define their own
// crypto-standards, which consider the ECC security in much broader level.
//
// The Bernstein's SafeCurves standard lists the curves, which are safe
// according to a set of ECC security requirements. The standard is available at
// https://safecurves.cr.yp.to.
using CurveName = std::string;

const CurveName kCurveSecp256k1 = "secp256k1";
const CurveName kCurveSm2 = "sm2";
const CurveName kCurveX25519 = "x25519";
const CurveName kCurveEd25519 = "ed25519";
const CurveName kCurveFourQ = "fourq";

enum class CurveType {
  // Non-binary Curves, define on E(F_p) where p is prime
  WEIERSTRASS,
  MONTGOMERY,
  TWISTED_EDWARDS,
  // Binary Curves, define on E(F_{2^m}), not recommend:
  // - Certicom has/had patents on these curves
  // - Security: Binary fields has more attack vectors than prime fields
  // Detail: https://crypto.stackexchange.com/q/91610
  WEIERSTRASS_BINARY
};

enum class SupplyLib {
  AUTO,  // auto select best supply lib
  TOY,
  OPENSSL,
  SODIUM,
};

enum class HashToCurveStrategy {
  // https://eprint.iacr.org/2009/226.pdf
  TRY_AND_INCREMENT
};

// Points represented in human-readable format
struct AffinePoint : HeObject<AffinePoint> {
  MPInt x;
  MPInt y;
  MSGPACK_DEFINE(x, y);

  AffinePoint(const MPInt &x, const MPInt &y) : x(x), y(y) {}
  AffinePoint() = default;

  bool operator==(const AffinePoint &rhs) const {
    return std::tie(x, y) == std::tie(rhs.x, rhs.y);
  }

  bool operator!=(const AffinePoint &rhs) const { return !(rhs == *this); }

  std::string ToString() const override {
    return fmt::format("({}, {})", x, y);
  }

  friend std::ostream &operator<<(std::ostream &os, const AffinePoint &point) {
    os << point.ToString();
    return os;
  }
};

// Feel free to add more storage types if you need.
using Array32 = std::array<char, 32>;  // 256bits, enough to store X25519 point
using Array33 = std::array<char, 33>;  // 264bits, x coordinate + 1 sign bit
using Array64 = std::array<char, 64>;  // 512bits, store (x, y)
// The storage format inside EcPoint is explained by each curve itself, here is
// a black box
using EcPoint = std::variant<Array32, Array33, Array64, AffinePoint>;

// Base class of elliptic curve
// Each subclass can implement one or more curve group.
// Elliptic curves over finite field act as an abel group
class CurveGroup {
 public:
  virtual ~CurveGroup() = default;

  //================================//
  // Elliptic curve meta info query //
  //================================//

  virtual CurveName GetCurveName() const = 0;
  virtual CurveType GetCurveType() const = 0;
  virtual SupplyLib GetSupplyLib() const = 0;

  // The h, cofactor.
  // Cofactor is the number of non-overlapping subgroups of points, which
  // together hold all curve points
  virtual MPInt GetCofactor() const = 0;

  // The p, the field size of curve
  virtual MPInt GetField() const = 0;

  // The n, order of G, s.t. n < p
  // n is the order of the curve (the number of all its points)
  virtual MPInt GetOrder() const = 0;

  // The G, generator
  // Every elliptic curve defines a special pre-defined (constant) EC point
  // called generator point G (base point), which can generate any other point
  // in its subgroup over the elliptic curve by multiplying G by some integer.
  // When G and n are carefully selected, and the cofactor = 1, all possible EC
  // points on the curve (including the special point infinity) can be generated
  // from the generator G by multiplying it by integer in the range [1...n].
  virtual EcPoint GetGenerator() const = 0;

  // Because the fastest known algorithm to solve the ECDLP for key of size k
  // needs sqrt(k) steps, this means that to achieve a k-bit security strength,
  // at least 2*k-bit curve is needed. Thus, 256-bit elliptic curves (where the
  // field size p is 256-bit number) typically provide nearly 128-bit security
  // strength.
  // Warning: This function only returns an approximate security strength.
  // In fact, the actual strength is slightly less than the value returned by
  // GetSecurityStrength(), because the order of the curve (n) is typically less
  // than the fields size (p) and because the curve may have cofactor h > 1 and
  // because the number of steps is not exactly sqrt(k), but is 0.886*sqrt(k).
  // If you want to know the precise security strength, please check
  // http://safecurves.cr.yp.to/rho.html
  // For example, the secp256k1 curve returns 128-bit security, but real is
  // 127.8-bit and Curve25519 also returns 128-bit security, but real is
  // 125.8-bit.
  virtual size_t GetSecurityStrength() const = 0;

  virtual std::string ToString() = 0;

  //================================//
  //   Elliptic curve computation   //
  //================================//

  virtual EcPoint Add(const EcPoint &p1, const EcPoint &p2) const = 0;
  virtual EcPoint Sub(const EcPoint &p1, const EcPoint &p2) const = 0;

  // three types of scalar multiplications:
  //
  // - Fixed-Base: when the input point of the scalar multiplication is known at
  // design time
  // - Variable-Base: when the input point of the scalar multiplication is not
  // known in advance
  // - Double-Base: when the protocol actually requires to compute two scalar
  // multiplications and then to add both results. (e.g. 𝑘𝑃+𝑟𝐵)
  // @param scalar: can be < 0
  virtual EcPoint MulBase(const MPInt &scalar) const = 0;
  virtual EcPoint Mul(const MPInt &scalar, const EcPoint &point) const = 0;
  // Returns: s1*p1 + s2*G
  virtual EcPoint MulDoubleBase(const MPInt &scalar1, const EcPoint &point1,
                                const MPInt &scalar2) const = 0;

  // Output: p / s = p * s^-1
  // Please note that not all scalars have inverses
  // An exception will be thrown if the inverse of s does not exist
  virtual EcPoint Div(const EcPoint &point, const MPInt &scalar) const = 0;

  // Output: -p
  virtual EcPoint Negate(const EcPoint &point) const = 0;

  //================================//
  //     EcPoint helper tools       //
  //================================//

  // Get a human-readable representation of elliptic curve point
  virtual AffinePoint GetAffinePoint(const EcPoint &point) const = 0;

  // Compress and serialize a point
  virtual yacl::Buffer SerializePoint(const EcPoint &point) const = 0;
  virtual void SerializePoint(const EcPoint &point,
                              yacl::Buffer *buf) const = 0;

  // load a point
  virtual EcPoint DeserializePoint(yacl::ByteContainerView buf) const = 0;

  // map a string to curve point
  virtual EcPoint HashToCurve(HashToCurveStrategy strategy,
                              std::string_view str) const = 0;

  // Check p1 & p2 are equal
  // It is not recommended to directly compare the buffer of EcPoint using
  // "p1 == p2" since EcPoint is a black box, same point may have multiple
  // representations.
  virtual bool PointEqual(const EcPoint &p1, const EcPoint &p2) const = 0;

  // Is point on this curve
  // Every override function in subclass must support EcPoint<AffinePoint>
  // representation.
  virtual bool IsInCurveGroup(const EcPoint &point) const = 0;

  // Is the point at infinity
  virtual bool IsInfinity(const EcPoint &point) const = 0;
};

}  // namespace heu::lib::algorithms::ecc
