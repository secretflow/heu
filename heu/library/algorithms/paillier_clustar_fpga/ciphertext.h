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

#pragma once

#include <ostream>
#include <string>

#include "yacl/base/byte_container_view.h"

#include "heu/library/algorithms/paillier_clustar_fpga/fpga_engine/paillier_operators/fpga_types.h"

namespace heu::lib::algorithms::paillier_clustar_fpga {

using fpga_engine::CFPGATypes;

class Ciphertext {
 public:
  Ciphertext() = default;
  explicit Ciphertext(unsigned size);
  Ciphertext(const Ciphertext &other);
  Ciphertext(Ciphertext &&other);
  explicit Ciphertext(char *mantissa, unsigned size, int exp);
  ~Ciphertext();

  Ciphertext &operator=(const Ciphertext &other);
  Ciphertext &operator=(Ciphertext &&other);

  std::string ToString() const;

  bool operator==(const Ciphertext &other) const;
  bool operator!=(const Ciphertext &other) const;

  yacl::Buffer Serialize() const;
  void Deserialize(yacl::ByteContainerView in);

  //
  char *GetMantissa() const;
  void SetExp(int exp);
  int GetExp() const;
  unsigned GetSize() const;

 private:
  void CopyInit(const Ciphertext &other);
  void MoveInit(Ciphertext &&other);
  void Release();

 private:
  char *mantissa_ = nullptr;
  unsigned size_ = 0;
  int exp_ = 0;
};

}  // namespace heu::lib::algorithms::paillier_clustar_fpga
