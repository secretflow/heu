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

#include "heu/library/algorithms/util/mp_int.h"

#include "heu/library/algorithms/util/mp_safe_prime_rand.h"
#include "heu/library/algorithms/util/tommath_ext.h"

namespace heu::lib::algorithms {

const MPInt MPInt::_1_(1);
const MPInt MPInt::_2_(2);

MPInt::MPInt() { MPINT_ENFORCE_OK(mp_init(&n_)); }

MPInt::MPInt(uint64_t value, size_t reserved_bits) {
  MPINT_ENFORCE_OK(mp_init_size(&n_, reserved_bits));
  mp_set_u64(&n_, value);
}

MPInt::MPInt(int32_t x) { MPINT_ENFORCE_OK(mp_init_i32(&n_, x)); }
MPInt::MPInt(uint32_t x) { MPINT_ENFORCE_OK(mp_init_u32(&n_, x)); }

MPInt::MPInt(int64_t x) { MPINT_ENFORCE_OK(mp_init_i64(&n_, x)); }
MPInt::MPInt(uint64_t x) { MPINT_ENFORCE_OK(mp_init_u64(&n_, x)); }

MPInt::MPInt(int128_t x) { MPINT_ENFORCE_OK(mp_init_i128(&n_, x)); }
MPInt::MPInt(uint128_t x) { MPINT_ENFORCE_OK(mp_init_u128(&n_, x)); }

MPInt::MPInt(double x) {
  MPINT_ENFORCE_OK(mp_init(&n_));
  MPINT_ENFORCE_OK(mp_set_double(&n_, x));
}

// [mum]: Why not use std::string_view?
// A std::string_view doesn't provide a conversion to a const char* because
// it doesn't store a null-terminated string. It stores a pointer to the
// first element, and the length of the string, basically.
MPInt::MPInt(const std::string &num, int radix) {
  MPINT_ENFORCE_OK(mp_init(&n_));
  MPINT_ENFORCE_OK(mp_read_radix(&n_, num.c_str(), radix));
}

MPInt::MPInt(MPInt &&other) noexcept {
  // /* the infamous mp_int structure */
  // typedef struct {
  //   int used, alloc;
  //   mp_sign sign;
  //   mp_digit *dp;
  // } mp_int;
  n_ = other.n_;
  // NOTE: We've checked mp_clear does nothing if `dp` is nullptr.
  other.n_.dp = nullptr;
}

MPInt::MPInt(const MPInt &other) {
  MPINT_ENFORCE_OK(mp_init_copy(&n_, &other.n_));
}

size_t MPInt::BitCount() const { return mp_count_bits(&n_); }

int MPInt::Compare(const MPInt &other) const { return mp_cmp(&n_, &other.n_); }

int MPInt::CompareAbs(const MPInt &other) const {
  return mp_cmp_mag(&n_, &other.n_);
}

bool MPInt::IsZero() const { return mp_iszero(&n_) == MP_YES; }

void MPInt::SetZero() { mp_zero(&n_); }

MPInt &MPInt::DecrOne() & {
  MPINT_ENFORCE_OK(mp_decr(&n_));
  return *this;
}

MPInt &MPInt::IncrOne() & {
  MPINT_ENFORCE_OK(mp_incr(&n_));
  return *this;
}

MPInt MPInt::DecrOne() && {
  MPINT_ENFORCE_OK(mp_decr(&n_));
  return *this;
}

MPInt MPInt::IncrOne() && {
  MPINT_ENFORCE_OK(mp_incr(&n_));
  return *this;
}

MPInt &MPInt::operator=(const MPInt &other) {
  MPINT_ENFORCE_OK(mp_copy(&other.n_, &n_));
  return *this;
}

MPInt &MPInt::operator=(MPInt &&other) noexcept {
  std::swap(n_, other.n_);
  return *this;
}

MPInt MPInt::operator+(const MPInt &operand2) const {
  MPInt result;
  MPINT_ENFORCE_OK(mp_add(&n_, &operand2.n_, &result.n_));
  return result;
}

MPInt MPInt::operator-(const MPInt &operand2) const {
  MPInt result;
  MPINT_ENFORCE_OK(mp_sub(&n_, &operand2.n_, &result.n_));
  return result;
}

MPInt MPInt::operator*(const MPInt &operand2) const {
  MPInt result;
  Mul(*this, operand2, &result);
  return result;
}

MPInt MPInt::operator/(const MPInt &operand2) const {
  MPInt result;
  Div(*this, operand2, &result, nullptr);
  return result;
}

MPInt MPInt::operator<<(size_t operand2) const {
  MPInt result;
  MPINT_ENFORCE_OK(mp_mul_2d(&this->n_, operand2, &result.n_));
  return result;
}

MPInt MPInt::operator>>(size_t operand2) const {
  MPInt result;
  MPINT_ENFORCE_OK(mp_div_2d(&this->n_, operand2, &result.n_, nullptr));
  return result;
}

MPInt MPInt::operator%(const MPInt &operand2) const {
  MPInt result;
  Mod(*this, operand2, &result);
  return result;
}

MPInt MPInt::operator-() const {
  MPInt result;
  Negate(&result);
  return result;
}

MPInt MPInt::operator-=(const MPInt &operand2) {
  MPINT_ENFORCE_OK(mp_sub(&n_, &operand2.n_, &n_));
  return *this;
}

MPInt MPInt::operator+=(const MPInt &operand2) {
  MPINT_ENFORCE_OK(mp_add(&n_, &operand2.n_, &n_));
  return *this;
}

MPInt MPInt::operator*=(const MPInt &operand2) {
  MPINT_ENFORCE_OK(mp_mul(&n_, &operand2.n_, &n_));
  return *this;
}

MPInt MPInt::operator/=(const MPInt &operand2) {
  MPINT_ENFORCE_OK(mp_div(&n_, &operand2.n_, &n_, nullptr));
  return *this;
}

MPInt MPInt::operator%=(const MPInt &operand2) {
  MPINT_ENFORCE_OK(mp_mod(&n_, &operand2.n_, &n_));
  return *this;
}

MPInt MPInt::operator<<=(size_t operand2) {
  MPINT_ENFORCE_OK(mp_mul_2d(&this->n_, operand2, &this->n_));
  return *this;
}

MPInt MPInt::operator|=(const MPInt &operand2) {
  MPINT_ENFORCE_OK(mp_or(&n_, &operand2.n_, &n_));
  return *this;
}

std::ostream &operator<<(std::ostream &os, const MPInt &an_int) {
  return os << an_int.ToString();
}

MPInt MPInt::Abs() const {
  MPInt result;
  MPINT_ENFORCE_OK(mp_abs(&n_, &result.n_));
  return result;
}

template <>
int8_t MPInt::As() const {
  return mp_get_i8(&n_);
}

template <>
int16_t MPInt::As() const {
  return mp_get_i16(&n_);
}

template <>
int32_t MPInt::As() const {
  return mp_get_i32(&n_);
}

template <>
int64_t MPInt::As() const {
  return mp_get_i64(&n_);
}

template <>
int128_t MPInt::As() const {
  return mp_get_i128(&n_);
}

template <>
uint8_t MPInt::As() const {
  return mp_get_mag_u8(&n_);
}

template <>
uint16_t MPInt::As() const {
  return mp_get_mag_u16(&n_);
}

template <>
uint32_t MPInt::As() const {
  return mp_get_mag_u32(&n_);
}

template <>
uint64_t MPInt::As() const {
  return mp_get_mag_u64(&n_);
}

template <>
uint128_t MPInt::As() const {
  return mp_get_mag_u128(&n_);
}

template <>
float MPInt::As() const {
  return static_cast<float>(mp_get_double(&n_));
}

template <>
double MPInt::As() const {
  return mp_get_double(&n_);
}

std::string MPInt::ToRadixString(int radix) const {
  int size = 0;
  MPINT_ENFORCE_OK(mp_radix_size(&n_, radix, &size));

  std::string output;
  output.resize(size);
  MPINT_ENFORCE_OK(mp_to_radix(&n_, &(output[0]), size, nullptr, radix));
  output.pop_back();  // remove tailing '\0'
  return output;
}

std::string MPInt::ToHexString() const { return ToRadixString(16); }

std::string MPInt::ToString() const { return ToRadixString(10); }

void MPInt::Serialize(std::string *str) const {
  str->clear();
  size_t size = mp_sbin_size(&n_);
  str->resize(size);
  MPINT_ENFORCE_OK(
      mp_to_sbin(&n_, (unsigned char *)&((*str)[0]), size, nullptr));
}

bool MPInt::Deserialize(const std::string &str, MPInt *result) {
  mp_err error =
      mp_from_sbin(&result->n_, (const unsigned char *)str.data(), str.size());

  return error == MP_OKAY;
}

void MPInt::RandPrimeOver(size_t bit_size, MPInt *x, PrimeType prime_type) {
  int trials = mp_prime_rabin_miller_trials(bit_size);
  MPINT_ENFORCE_OK(
      mp_prime_rand(&x->n_, trials, bit_size, static_cast<int>(prime_type)));
}

void MPInt::RandSafePrimeOver(size_t bit_size, MPInt *x) {
  int trials = mp_prime_rabin_miller_trials(bit_size);
  mp_safe_prime_rand(&x->n_, trials, bit_size);
}

bool MPInt::IsPrime() const {
  int trials = mp_prime_rabin_miller_trials(BitCount());
  mp_bool result;
  MPINT_ENFORCE_OK(mp_prime_is_prime(&n_, trials, &result));
  return result > 0;
}

void MPInt::Mul(const MPInt &a, const MPInt &b, MPInt *c) {
  MPINT_ENFORCE_OK(mp_mul(&a.n_, &b.n_, &c->n_));
}

void MPInt::RandomRoundDown(size_t bit_size, MPInt *r) {
  // floor (向下取整)
  mp_int *n = &r->n_;
  MPINT_ENFORCE_OK(mp_rand(n, bit_size / MP_DIGIT_BIT));
}

void MPInt::RandomRoundUp(size_t bit_size, MPInt *r) {
  // ceil (向上取整)
  mp_int *n = &r->n_;
  MPINT_ENFORCE_OK(mp_rand(n, (bit_size + MP_DIGIT_BIT - 1) / MP_DIGIT_BIT));
}

void MPInt::RandomExactBits(size_t bit_size, MPInt *r) {
  RandomRoundUp(bit_size, r);
  mp_int *n = &r->n_;
  MPINT_ENFORCE_OK(mp_mod_2d(n, bit_size, n));
}

void MPInt::RandomMonicExactBits(size_t bit_size, MPInt *r) {
  do {
    RandomExactBits(bit_size, r);
  } while (r->BitCount() != bit_size);
}

void MPInt::RandomLtN(const MPInt &n, MPInt *r) {
  do {
    MPInt::RandomRoundDown(n.BitCount(), r);
  } while (r->IsNegative() || r->Compare(n) >= 0);
}

void MPInt::MulMod(const MPInt &a, const MPInt &b, const MPInt &mod, MPInt *d) {
  MPINT_ENFORCE_OK(mp_mulmod(&a.n_, &b.n_, &mod.n_, &d->n_));
}

void MPInt::Pow(const MPInt &a, uint32_t b, MPInt *c) {
  MPINT_ENFORCE_OK(mp_expt_u32(&a.n_, b, &c->n_));
}

void MPInt::PowMod(const MPInt &a, const MPInt &b, const MPInt &mod, MPInt *d) {
  MPINT_ENFORCE_OK(mp_exptmod(&a.n_, &b.n_, &mod.n_, &d->n_));
}

void MPInt::Lcm(const MPInt &a, const MPInt &b, MPInt *c) {
  MPINT_ENFORCE_OK(mp_lcm(&a.n_, &b.n_, &c->n_));
}

void MPInt::Gcd(const MPInt &a, const MPInt &b, MPInt *c) {
  MPINT_ENFORCE_OK(mp_gcd(&a.n_, &b.n_, &c->n_));
}

/* a/b => cb + d == a */
void MPInt::Div(const MPInt &a, const MPInt &b, MPInt *c, MPInt *d) {
  mp_int *c_repl = (c == nullptr) ? nullptr : &c->n_;
  mp_int *d_repl = (d == nullptr) ? nullptr : &d->n_;
  MPINT_ENFORCE_OK(mp_div(&a.n_, &b.n_, c_repl, d_repl));
}

void MPInt::Div3(const MPInt &a, MPInt *b) {
  MPINT_ENFORCE_OK(mp_div_3(&a.n_, &b->n_, nullptr));
}

void MPInt::InvertMod(const MPInt &a, const MPInt &mod, MPInt *c) {
  MPINT_ENFORCE_OK(mp_invmod(&a.n_, &mod.n_, &c->n_));
}

void MPInt::Mod(const MPInt &a, const MPInt &mod, MPInt *c) {
  MPINT_ENFORCE_OK(mp_mod(&a.n_, &mod.n_, &c->n_));
}

}  // namespace heu::lib::algorithms
