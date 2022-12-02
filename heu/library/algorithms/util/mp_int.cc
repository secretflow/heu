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

#include "heu/library/algorithms/util/tommath_ext_features.h"
#include "heu/library/algorithms/util/tommath_ext_types.h"

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

MPInt MPInt::operator&(const MPInt &operand2) const {
  MPInt result;
  MPINT_ENFORCE_OK(mp_and(&n_, &operand2.n_, &result.n_));
  return result;
}

MPInt MPInt::operator|(const MPInt &operand2) const {
  MPInt result;
  MPINT_ENFORCE_OK(mp_or(&n_, &operand2.n_, &result.n_));
  return result;
}

MPInt MPInt::operator^(const MPInt &operand2) const {
  MPInt result;
  MPINT_ENFORCE_OK(mp_xor(&n_, &operand2.n_, &result.n_));
  return result;
}

MPInt MPInt::operator+=(const MPInt &operand2) {
  MPINT_ENFORCE_OK(mp_add(&n_, &operand2.n_, &n_));
  return *this;
}

MPInt MPInt::operator-=(const MPInt &operand2) {
  MPINT_ENFORCE_OK(mp_sub(&n_, &operand2.n_, &n_));
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

MPInt MPInt::operator>>=(size_t operand2) {
  MPINT_ENFORCE_OK(mp_div_2d(&this->n_, operand2, &this->n_, nullptr));
  return *this;
}

MPInt MPInt::operator&=(const MPInt &operand2) {
  MPINT_ENFORCE_OK(mp_and(&n_, &operand2.n_, &n_));
  return *this;
}

MPInt MPInt::operator|=(const MPInt &operand2) {
  MPINT_ENFORCE_OK(mp_or(&n_, &operand2.n_, &n_));
  return *this;
}

MPInt MPInt::operator^=(const MPInt &operand2) {
  MPINT_ENFORCE_OK(mp_xor(&n_, &operand2.n_, &n_));
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
int8_t MPInt::Get() const {
  return mp_get_i8(&n_);
}

template <>
int16_t MPInt::Get() const {
  return mp_get_i16(&n_);
}

template <>
int32_t MPInt::Get() const {
  return mp_get_i32(&n_);
}

template <>
int64_t MPInt::Get() const {
  return mp_get_i64(&n_);
}

template <>
int128_t MPInt::Get() const {
  return mp_get_i128(&n_);
}

template <>
uint8_t MPInt::Get() const {
  return mp_get_mag_u8(&n_);
}

template <>
uint16_t MPInt::Get() const {
  return mp_get_mag_u16(&n_);
}

template <>
uint32_t MPInt::Get() const {
  return mp_get_mag_u32(&n_);
}

template <>
uint64_t MPInt::Get() const {
  return mp_get_mag_u64(&n_);
}

template <>
uint128_t MPInt::Get() const {
  return mp_get_mag_u128(&n_);
}

template <>
float MPInt::Get() const {
  return static_cast<float>(mp_get_double(&n_));
}

template <>
double MPInt::Get() const {
  return mp_get_double(&n_);
}

template <>
MPInt MPInt::Get() const {
  return *this;
}

template <>
void MPInt::Set(int8_t value) {
  mp_set_i8(&n_, value);
}

template <>
void MPInt::Set(int16_t value) {
  mp_set_i16(&n_, value);
}

template <>
void MPInt::Set(int32_t value) {
  mp_set_i32(&n_, value);
}

template <>
void MPInt::Set(int64_t value) {
  MPINT_ENFORCE_OK(mp_grow(&n_, 2));
  mp_set_i64(&n_, value);
}

template <>
void MPInt::Set(int128_t value) {
  MPINT_ENFORCE_OK(mp_grow(&n_, 3));
  mp_set_i128(&n_, value);
}

template <>
void MPInt::Set(uint8_t value) {
  mp_set_u8(&n_, value);
}

template <>
void MPInt::Set(uint16_t value) {
  mp_set_u16(&n_, value);
}

template <>
void MPInt::Set(uint32_t value) {
  mp_set_u32(&n_, value);
}

template <>
void MPInt::Set(uint64_t value) {
  MPINT_ENFORCE_OK(mp_grow(&n_, 2));
  mp_set_u64(&n_, value);
}

template <>
void MPInt::Set(uint128_t value) {
  MPINT_ENFORCE_OK(mp_grow(&n_, 3));
  mp_set_u128(&n_, value);
}

template <>
void MPInt::Set(float value) {
  MPINT_ENFORCE_OK(mp_grow(&n_, 2));
  MPINT_ENFORCE_OK(mp_set_double(&n_, value));
}

template <>
void MPInt::Set(double value) {
  MPINT_ENFORCE_OK(mp_grow(&n_, 2));
  MPINT_ENFORCE_OK(mp_set_double(&n_, value));
}

template <>
void MPInt::Set(MPInt value) {
  *this = std::move(value);
}

// [mum]: Why not use std::string_view?
// A std::string_view doesn't provide a conversion to a const char* because
// it doesn't store a null-terminated string. It stores a pointer to the
// first element, and the length of the string, basically.
void MPInt::Set(const std::string &num, int radix) {
  MPINT_ENFORCE_OK(mp_read_radix(&n_, num.c_str(), radix));
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

yacl::Buffer MPInt::Serialize() const {
  size_t size = mp_sbin_size(&n_);
  yacl::Buffer buffer(size);
  MPINT_ENFORCE_OK(
      mp_to_sbin(&n_, buffer.data<unsigned char>(), size, nullptr));
  return buffer;
}

void MPInt::Deserialize(yacl::ByteContainerView buffer) {
  MPINT_ENFORCE_OK(mp_from_sbin(&n_, buffer.data(), buffer.size()));
}

yacl::Buffer MPInt::ToBytes(size_t byte_len, Endian endian) const {
  yacl::Buffer buf(byte_len);
  ToBytes(buf.data<unsigned char>(), byte_len, endian);
  return buf;
}

void MPInt::ToBytes(unsigned char *buf, size_t buf_len,
                    heu::lib::algorithms::Endian endian) const {
  mp_ext_to_bytes(n_, buf, buf_len, endian);
}

void MPInt::RandPrimeOver(size_t bit_size, MPInt *out, PrimeType prime_type) {
  YACL_ENFORCE_GT(bit_size, 80u, "bit_size must > 80");
  int trials = mp_prime_rabin_miller_trials(bit_size);

  if (prime_type == PrimeType::FastSafe) {
    mp_ext_safe_prime_rand(&out->n_, trials, bit_size);
  } else {
    MPINT_ENFORCE_OK(mp_prime_rand(&out->n_, trials, bit_size,
                                   static_cast<int>(prime_type)));
  }
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
  mp_ext_rand_bits(&r->n_, bit_size);
}

void MPInt::RandomMonicExactBits(size_t bit_size, MPInt *r) {
  YACL_ENFORCE(bit_size > 0, "cannot gen monic random number of size 0");
  do {
    RandomExactBits(bit_size, r);
  } while (r->BitCount() != bit_size);
}

void MPInt::RandomLtN(const MPInt &n, MPInt *r) {
  do {
    MPInt::RandomExactBits(n.BitCount(), r);
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
