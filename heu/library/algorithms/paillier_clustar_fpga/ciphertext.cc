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

#include "heu/library/algorithms/paillier_clustar_fpga/ciphertext.h"

#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <sstream>

namespace heu::lib::algorithms::paillier_clustar_fpga {

Ciphertext::Ciphertext(unsigned size) : size_(size) {
  mantissa_ = static_cast<char *>(malloc(size_));
  memset(mantissa_, 0, size_);
  exp_ = 0;
}

Ciphertext::Ciphertext(const Ciphertext &other) { CopyInit(other); }

Ciphertext::Ciphertext(Ciphertext &&other) { MoveInit(std::move(other)); }

Ciphertext::Ciphertext(char *mantissa, unsigned size, int exp)
    : size_(size), exp_(exp) {
  mantissa_ = static_cast<char *>(malloc(size_));
  memset(mantissa_, 0, size_);
  memcpy(mantissa_, mantissa, size_);
}

Ciphertext &Ciphertext::operator=(const Ciphertext &other) {
  CopyInit(other);
  return *this;
}

Ciphertext &Ciphertext::operator=(Ciphertext &&other) {
  MoveInit(std::move(other));
  return *this;
}

void Ciphertext::CopyInit(const Ciphertext &other) {
  size_ = other.size_;
  exp_ = other.exp_;
  mantissa_ = static_cast<char *>(malloc(size_));
  memset(mantissa_, 0, size_);
  memcpy(mantissa_, other.mantissa_, size_);
}

void Ciphertext::MoveInit(Ciphertext &&other) {
  size_ = other.size_;
  exp_ = other.exp_;
  mantissa_ = other.mantissa_;
  other.mantissa_ = nullptr;
  other.exp_ = 0;
}

Ciphertext::~Ciphertext() {
  free(mantissa_);
  mantissa_ = nullptr;
  size_ = 0;
  exp_ = 0;
}

// Directly return hex format
std::string Ciphertext::ToString() const {
  std::ostringstream ss;
  // from low to high
  for (int i = 0; i < static_cast<int>(size_); i++) {
    ss << std::hex << std::setfill('0') << std::setw(2)
       << +static_cast<uint8_t>(*(mantissa_ + i));
  }
  return fmt::format("mantissa: {}, exp: {}", ss.str(), exp_);
}

// TODO: Only for type int since int's exp is 0
// Extend to double/float later
bool Ciphertext::operator==(const Ciphertext &other) const {
  if (this->size_ != other.size_) {
    return false;
  }

  if (this->exp_ != other.exp_) {
    return false;
  }

  if (std::memcmp(this->mantissa_, other.mantissa_, this->size_) != 0) {
    return false;
  }

  return true;
}

bool Ciphertext::operator!=(const Ciphertext &other) const {
  return !this->operator==(other);
}

// put size_ + exp_ + mantissa_ to buffer
yacl::Buffer Ciphertext::Serialize() const {
  yacl::Buffer buf(size_ + sizeof(int) * 2);
  unsigned char *buf_ptr = buf.data<unsigned char>();

  memcpy(buf_ptr, &size_, sizeof(int));
  memcpy(buf_ptr + sizeof(int), &exp_, sizeof(int));
  memcpy(buf_ptr + sizeof(int) * 2, mantissa_, size_);
  return buf;
}

// get mantissa_ + size_ + exp_ from buffer
void Ciphertext::Deserialize(yacl::ByteContainerView in) {
  // Release previous data first
  Release();

  //
  const unsigned char *buffer = in.data();
  size_t buf_len = in.size();
  memcpy(&size_, buffer, sizeof(int));
  YACL_ENFORCE(size_ + sizeof(int) * 2 == buf_len, "buffer len invalid");

  // Alloc new resource
  mantissa_ = static_cast<char *>(malloc(size_));
  memset(mantissa_, 0, size_);

  memcpy(&exp_, buffer + sizeof(int), sizeof(int));
  memcpy(mantissa_, buffer + sizeof(int) * 2, size_);
}

void Ciphertext::Release() {
  free(mantissa_);
  mantissa_ = nullptr;
  size_ = 0;
  exp_ = 0;
}

char *Ciphertext::GetMantissa() const { return mantissa_; }

void Ciphertext::SetExp(int exp) { exp_ = exp; }

int Ciphertext::GetExp() const { return exp_; }

unsigned Ciphertext::GetSize() const { return size_; }

}  // namespace heu::lib::algorithms::paillier_clustar_fpga
