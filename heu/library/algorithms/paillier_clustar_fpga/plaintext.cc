// Copyright 2023 Clustar Technology Co., Ltd.
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

#include "heu/library/algorithms/paillier_clustar_fpga/plaintext.h"

#include <algorithm>

#include "yacl/base/int128.h"

namespace heu::lib::algorithms::paillier_clustar_fpga {

Plaintext::Plaintext(const Plaintext &other) : mp_int_(other.mp_int_) {}

Plaintext::Plaintext(Plaintext &&other) : mp_int_(std::move(other.mp_int_)) {}

Plaintext &Plaintext::operator=(const Plaintext &other) {
  mp_int_ = other.mp_int_;
  return *this;
}

Plaintext &Plaintext::operator=(Plaintext &&other) {
  mp_int_ = std::move(other.mp_int_);
  return *this;
}

// Get functions start
template <>
MPInt Plaintext::Get() const {
  return mp_int_;
}

template <>
uint8_t Plaintext::Get() const {
  return mp_int_.Get<uint8_t>();
}

template <>
uint16_t Plaintext::Get() const {
  return mp_int_.Get<uint16_t>();
}

template <>
uint32_t Plaintext::Get() const {
  return mp_int_.Get<uint32_t>();
}

template <>
uint64_t Plaintext::Get() const {
  return mp_int_.Get<uint64_t>();
}

template <>
uint128_t Plaintext::Get() const {
  return mp_int_.Get<uint128_t>();
}

template <>
int8_t Plaintext::Get() const {
  return mp_int_.Get<int8_t>();
}

template <>
int16_t Plaintext::Get() const {
  return mp_int_.Get<int16_t>();
}

template <>
int32_t Plaintext::Get() const {
  return mp_int_.Get<int32_t>();
}

template <>
int64_t Plaintext::Get() const {
  return mp_int_.Get<int64_t>();
}

template <>
int128_t Plaintext::Get() const {
  return mp_int_.Get<int128_t>();
}

template <>
float Plaintext::Get() const {
  return mp_int_.Get<float>();
}

template <>
double Plaintext::Get() const {
  return mp_int_.Get<double>();
}

// Get functions end

// Set functions start
template <>
void Plaintext::Set(MPInt value) {
  mp_int_ = value;
}

template <>
void Plaintext::Set(Plaintext value) {
  mp_int_ = value.Get<MPInt>();
}

template <>
void Plaintext::Set(uint8_t value) {
  mp_int_.Set<uint8_t>(value);
}

template <>
void Plaintext::Set(uint16_t value) {
  mp_int_.Set<uint16_t>(value);
}

template <>
void Plaintext::Set(uint32_t value) {
  mp_int_.Set<uint32_t>(value);
}

template <>
void Plaintext::Set(uint64_t value) {
  mp_int_.Set<uint64_t>(value);
}

template <>
void Plaintext::Set(uint128_t value) {
  mp_int_.Set<uint128_t>(value);
}

template <>
void Plaintext::Set(int8_t value) {
  mp_int_.Set<int8_t>(value);
}

template <>
void Plaintext::Set(int16_t value) {
  mp_int_.Set<int16_t>(value);
}

template <>
void Plaintext::Set(int32_t value) {
  mp_int_.Set<int32_t>(value);
}

template <>
void Plaintext::Set(int64_t value) {
  mp_int_.Set<int64_t>(value);
}

template <>
void Plaintext::Set(int128_t value) {
  mp_int_.Set<int128_t>(value);
}

template <>
void Plaintext::Set(float value) {
  mp_int_.Set<float>(value);
}

template <>
void Plaintext::Set(double value) {
  mp_int_.Set<double>(value);
}

void Plaintext::Set(const std::string &num, int radix) {
  mp_int_.Set(num, radix);
}

// Set functions end

yacl::Buffer Plaintext::Serialize() const { return mp_int_.Serialize(); }

void Plaintext::Deserialize(yacl::ByteContainerView buffer) {
  mp_int_.Deserialize(buffer);
}

std::string Plaintext::ToString() const { return mp_int_.ToString(); }

std::ostream &operator<<(std::ostream &os, const Plaintext &pt) {
  return os << pt.ToString();
}

std::string Plaintext::ToHexString() const { return mp_int_.ToHexString(); }

yacl::Buffer Plaintext::ToBytes(size_t byte_len, Endian endian) const {
  return mp_int_.ToBytes(byte_len, endian);
}

void Plaintext::ToBytes(unsigned char *buf, size_t buf_len,
                        Endian endian) const {
  mp_int_.ToBytes(buf, buf_len, endian);
}

size_t Plaintext::BitCount() const { return mp_int_.BitCount(); }

Plaintext Plaintext::operator-() const {
  Plaintext result;
  Negate(&result);
  return result;
}

void Plaintext::Negate(Plaintext *z) const { mp_int_.Negate(&z->mp_int_); }

void Plaintext::NegateInplace() { mp_int_.NegateInplace(); }

bool Plaintext::IsNegative() const { return mp_int_.IsNegative(); }

bool Plaintext::IsZero() const { return mp_int_.IsZero(); }

bool Plaintext::IsPositive() const { return mp_int_.IsPositive(); }

Plaintext Plaintext::operator+(const Plaintext &op2) const {
  Plaintext result;
  result.mp_int_ = this->mp_int_ + op2.mp_int_;
  return result;
}

Plaintext Plaintext::operator-(const Plaintext &op2) const {
  Plaintext result;
  result.mp_int_ = this->mp_int_ - op2.mp_int_;
  return result;
}

Plaintext Plaintext::operator*(const Plaintext &op2) const {
  Plaintext result;
  result.mp_int_ = this->mp_int_ * op2.mp_int_;
  return result;
}

Plaintext Plaintext::operator/(const Plaintext &op2) const {
  Plaintext result;
  result.mp_int_ = this->mp_int_ / op2.mp_int_;
  return result;
}

Plaintext Plaintext::operator%(const Plaintext &op2) const {
  Plaintext result;
  result.mp_int_ = this->mp_int_ % op2.mp_int_;
  return result;
}

Plaintext Plaintext::operator&(const Plaintext &op2) const {
  Plaintext result;
  result.mp_int_ = this->mp_int_ & op2.mp_int_;
  return result;
}

Plaintext Plaintext::operator|(const Plaintext &op2) const {
  Plaintext result;
  result.mp_int_ = this->mp_int_ | op2.mp_int_;
  return result;
}

Plaintext Plaintext::operator^(const Plaintext &op2) const {
  Plaintext result;
  result.mp_int_ = this->mp_int_ ^ op2.mp_int_;
  return result;
}

Plaintext Plaintext::operator<<(size_t op2) const {
  Plaintext result;
  result.mp_int_ = this->mp_int_ << op2;
  return result;
}

Plaintext Plaintext::operator>>(size_t op2) const {
  Plaintext result;
  result.mp_int_ = this->mp_int_ >> op2;
  return result;
}

Plaintext Plaintext::operator+=(const Plaintext &op2) {
  this->mp_int_ += op2.mp_int_;
  return *this;
}

Plaintext Plaintext::operator-=(const Plaintext &op2) {
  this->mp_int_ -= op2.mp_int_;
  return *this;
}

Plaintext Plaintext::operator*=(const Plaintext &op2) {
  this->mp_int_ *= op2.mp_int_;
  return *this;
}

Plaintext Plaintext::operator/=(const Plaintext &op2) {
  this->mp_int_ /= op2.mp_int_;
  return *this;
}

Plaintext Plaintext::operator%=(const Plaintext &op2) {
  this->mp_int_ %= op2.mp_int_;
  return *this;
}

Plaintext Plaintext::operator&=(const Plaintext &op2) {
  this->mp_int_ &= op2.mp_int_;
  return *this;
}

Plaintext Plaintext::operator|=(const Plaintext &op2) {
  this->mp_int_ |= op2.mp_int_;
  return *this;
}

Plaintext Plaintext::operator^=(const Plaintext &op2) {
  this->mp_int_ ^= op2.mp_int_;
  return *this;
}

Plaintext Plaintext::operator<<=(size_t op2) {
  this->mp_int_ <<= op2;
  return *this;
}

Plaintext Plaintext::operator>>=(size_t op2) {
  this->mp_int_ >>= op2;
  return *this;
}

bool Plaintext::operator>(const Plaintext &other) const {
  return this->mp_int_ > other.mp_int_;
}

bool Plaintext::operator<(const Plaintext &other) const {
  return this->mp_int_ < other.mp_int_;
}

bool Plaintext::operator>=(const Plaintext &other) const {
  return this->mp_int_ >= other.mp_int_;
}

bool Plaintext::operator<=(const Plaintext &other) const {
  return this->mp_int_ <= other.mp_int_;
}

bool Plaintext::operator==(const Plaintext &other) const {
  return this->mp_int_ == other.mp_int_;
}

bool Plaintext::operator!=(const Plaintext &other) const {
  return this->mp_int_ != other.mp_int_;
}

void Plaintext::RandomExactBits(size_t bit_size, Plaintext *r) {
  MPInt::RandomExactBits(bit_size, &r->mp_int_);
}

void Plaintext::RandomLtN(const Plaintext &n, Plaintext *r) {
  MPInt::RandomLtN(n.mp_int_, &r->mp_int_);
}

int Plaintext::CompareAbs(const Plaintext &other) const {
  return mp_int_.CompareAbs(other.mp_int_);
}

}  // namespace heu::lib::algorithms::paillier_clustar_fpga
