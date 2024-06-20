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

#include "heu/library/algorithms/elgamal/public_key.h"

#include "heu/library/algorithms/elgamal/utils/lookup_table.h"

namespace heu::lib::algorithms::elgamal {

bool PublicKey::operator==(const PublicKey &other) const {
  return IsValid() && other.IsValid() &&
         curve_->GetCurveName() == other.curve_->GetCurveName() &&
         curve_->GetLibraryName() == other.curve_->GetLibraryName() &&
         curve_->PointEqual(h_, other.h_);
}

bool PublicKey::operator!=(const PublicKey &other) const {
  return !(*this == other);
}

std::string PublicKey::ToString() const {
  return fmt::format("Elgamal PK: h={}, curve={}, secure_bits={}",
                     curve_->GetAffinePoint(h_), curve_->ToString(),
                     curve_->GetSecurityStrength());
}

const Plaintext &PublicKey::PlaintextBound() const & {
  return LookupTable::MaxSupportedValue();
}

yacl::Buffer PublicKey::Serialize() const {
  msgpack::sbuffer buffer;
  msgpack::packer<msgpack::sbuffer> o(buffer);

  o.pack_array(3);
  o.pack(curve_->GetCurveName());
  o.pack(curve_->GetLibraryName());
  o.pack(std::string_view(curve_->SerializePoint(h_)));

  auto sz = buffer.size();
  return {buffer.release(), sz, [](void *ptr) { free(ptr); }};
}

void PublicKey::Deserialize(yacl::ByteContainerView in) {
  auto msg =
      msgpack::unpack(reinterpret_cast<const char *>(in.data()), in.size());
  msgpack::object object = msg.get();

  if (object.type != msgpack::type::ARRAY) {
    throw msgpack::type_error();
  }
  if (object.via.array.size != 3) {
    throw msgpack::type_error();
  }

  auto curve_name = object.via.array.ptr[0].as<yacl::crypto::CurveName>();
  auto lib_name = object.via.array.ptr[1].as<std::string>();
  curve_ = ::yacl::crypto::EcGroupFactory::Instance().Create(
      curve_name, yacl::ArgLib = lib_name);

  h_ = curve_->DeserializePoint(object.via.array.ptr[2].as<std::string_view>());
}

}  // namespace heu::lib::algorithms::elgamal
