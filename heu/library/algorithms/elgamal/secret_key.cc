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

#include "heu/library/algorithms/elgamal/secret_key.h"

namespace heu::lib::algorithms::elgamal {

yacl::Buffer SecretKey::Serialize() const {
  msgpack::sbuffer buffer;
  msgpack::packer<msgpack::sbuffer> o(buffer);

  o.pack_array(3);
  o.pack(curve_->GetCurveName());
  o.pack(curve_->GetLibraryName());
  o.pack(x_);

  auto sz = buffer.size();
  return {buffer.release(), sz, [](void *ptr) { free(ptr); }};
}

void SecretKey::Deserialize(yacl::ByteContainerView in) {
  auto msg =
      msgpack::unpack(reinterpret_cast<const char *>(in.data()), in.size());
  msgpack::object object = msg.get();

  YACL_ENFORCE(
      object.type == msgpack::type::ARRAY && object.via.array.size == 3,
      "Cannot parse buffer, format error");

  auto curve_name = object.via.array.ptr[0].as<yacl::crypto::CurveName>();
  auto lib_name = object.via.array.ptr[1].as<std::string>();
  x_ = object.via.array.ptr[2].as<MPInt>();

  curve_ = ::yacl::crypto::EcGroupFactory::Instance().Create(
      curve_name, yacl::ArgLib = lib_name);
  table_ = std::make_shared<LookupTable>();
  table_->Init(curve_);
}

bool SecretKey::operator==(const SecretKey &other) const {
  return IsValid() && other.IsValid() &&
         curve_->GetCurveName() == other.curve_->GetCurveName() &&
         curve_->GetLibraryName() == other.curve_->GetLibraryName() &&
         x_ == other.x_;
}

bool SecretKey::operator!=(const SecretKey &other) const {
  return !(*this == other);
}

std::string SecretKey::ToString() const {
  return fmt::format("ElGamal SK: curve={}, x={}", curve_->GetCurveName(), x_);
}

}  // namespace heu::lib::algorithms::elgamal
