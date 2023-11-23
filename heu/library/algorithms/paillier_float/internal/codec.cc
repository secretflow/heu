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

#include "heu/library/algorithms/paillier_float/internal/codec.h"

namespace heu::lib::algorithms::paillier_f::internal {

const MPInt Codec::kBaseCache = MPInt(Codec::kBase);

EncodedNumber Codec::Encode(const MPInt& scalar, int exponent) const {
  YACL_ENFORCE(scalar.CompareAbs(pk_.PlaintextBound()) <= 0,
               "integer scalar should in +/- {}, but get {}",
               pk_.PlaintextBound().ToHexString(), scalar.ToHexString());

  EncodedNumber out;

  // wrap negative numbers by adding n_
  MPInt::Mod(scalar, pk_.n_, &out.encoding);
  out.exponent = exponent;

  return out;
}

EncodedNumber Codec::Encode(double scalar, absl::optional<float> precision,
                            absl::optional<int> max_exponent) const {
  int precision_exp = 0;
  if (!precision.has_value()) {
    // scalar's base-2 exponent
    int bin_exp = 0;
    frexp(scalar, &bin_exp);
    int lsb_exp = bin_exp - kDoubleMantissaBits;

    precision_exp = floor(lsb_exp / kLog2Base);
  } else {
    precision_exp = floor(log2(*precision) / kLog2Base);
  }

  if (max_exponent.has_value() && precision_exp > *max_exponent) {
    precision_exp = *max_exponent;
  }
  // FIXME: avoid overflow
  int64_t int_rep = llround(scalar * pow(kBase, -precision_exp));

  MPInt mp_int_rep(int_rep);

  return Encode(mp_int_rep, precision_exp);
}

// bool EncodedNumber::DecreaseExponentTo(int new_exp) {
//   if (new_exp > exponent_) {
//     COSMOS_SYSTEM_LOG_WARN("new exponent %d should less than old exponent
//     %d",
//                            new_exp, exponent_);
//     return false;
//   }

//   MPInt factor;
//   MPInt::Pow(EncodedNumber::kBaseCache, exponent_ - new_exp, &factor);

//   MPInt::MulMod(encoding_, factor, pk_.n_, &encoding_);
//   exponent_ = new_exp;

//   return true;
// }

MPInt Codec::GetMantissa(const EncodedNumber& encoded) const {
  YACL_ENFORCE(encoded.encoding < pk_.n_, "number corrupted");

  MPInt mantissa;

  if (encoded.encoding <= pk_.max_int_) {
    // positive
    mantissa = encoded.encoding;
  } else if (encoded.encoding >= pk_.n_ - pk_.max_int_) {
    // negative
    mantissa = encoded.encoding - pk_.n_;
  } else {
    YACL_THROW("overflow detected");
  }
  return mantissa;
}

void Codec::Decode(const EncodedNumber& in, double* x) const {
  MPInt mantissa = GetMantissa(in);

  if (in.exponent >= 0) {
    MPInt value;
    MPInt factor;
    MPInt::Pow(kBaseCache, in.exponent, &factor);
    MPInt::Mul(mantissa, factor, &value);

    *x = value.Get<double>();
  } else {
    MPInt divisor;
    MPInt::Pow(kBaseCache, -in.exponent, &divisor);

    *x = mantissa.Get<double>() / divisor.Get<double>();
  }
}

void Codec::Decode(const EncodedNumber& in, MPInt* x) const {
  MPInt mantissa = GetMantissa(in);

  if (in.exponent >= 0) {
    MPInt factor;
    MPInt::Pow(kBaseCache, in.exponent, &factor);
    MPInt::Mul(mantissa, factor, x);
  } else {
    MPInt divisor;
    MPInt::Pow(kBaseCache, -in.exponent, &divisor);
    MPInt::Div(mantissa, divisor, x, nullptr);
  }
}

}  // namespace heu::lib::algorithms::paillier_f::internal
