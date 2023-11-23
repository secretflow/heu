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

#include "heu/library/numpy/matrix.h"

#include "interconnection/runtime/data_exchange.pb.h"

namespace heu::lib::numpy {

namespace pb_ns = org::interconnection::v2::runtime;

template <typename T>
struct Typename {
  static std::string Name;
};

template <>
std::string Typename<phe::Ciphertext>::Name = "ciphertext";

template <>
std::string Typename<phe::Plaintext>::Name = "plaintext";

template <>
std::string Typename<std::string>::Name = "string";

template <typename T>
yacl::Buffer DenseMatrix<T>::Serialize4Ic() const {
  pb_ns::DataExchangeProtocol dep;
  dep.set_scalar_type(pb_ns::SCALAR_TYPE_OBJECT);
  dep.set_scalar_type_name(Typename<T>::Name);

  auto v_ndarray = dep.mutable_v_ndarray();
  auto shape = this->shape();
  for (const auto& s : shape) {
    v_ndarray->add_shape(s);
  }

  const T* buf = this->data();
  auto pb_items = v_ndarray->mutable_items();
  pb_items->Reserve(size());
  for (int i = 0; i < size(); ++i) {
    pb_items->Add();
  }
  yacl::parallel_for(0, size(), 1, [&](int64_t beg, int64_t end) {
    for (int64_t i = beg; i < end; ++i) {
      if constexpr (std::is_same_v<T, std::string>) {
        pb_items->at(i) = buf[i];
      } else {
        pb_items->at(i) = buf[i].Serialize();
      }
    }
  });

  yacl::Buffer buffer(dep.ByteSizeLong());
  YACL_ENFORCE(dep.SerializeToArray(buffer.data<uint8_t>(), buffer.size()),
               "serialize ndarray fail");
  return buffer;
}

template <typename T>
DenseMatrix<T> DenseMatrix<T>::LoadFromIc(yacl::ByteContainerView in) {
  pb_ns::DataExchangeProtocol dxp;
  YACL_ENFORCE(dxp.ParseFromArray(in.data(), in.size()),
               "deserialize ndarray fail");

  YACL_ENFORCE(dxp.scalar_type() == pb_ns::SCALAR_TYPE_OBJECT,
               "Buffer format illegal, scalar_type={}", dxp.scalar_type());
  YACL_ENFORCE(dxp.scalar_type_name() == Typename<T>::Name,
               "Buffer format illegal, scalar_type_name={}",
               (dxp.scalar_type_name()));

  YACL_ENFORCE(dxp.container_case() ==
                   pb_ns::DataExchangeProtocol::ContainerCase::kVNdarray,
               "unsupported container type {}", (int)dxp.container_case());

  auto v_ndarray = dxp.v_ndarray();
  auto s = v_ndarray.shape();
  DenseMatrix<T> res(s.size() > 0 ? s[0] : 1, s.size() > 1 ? s[1] : 1,
                     s.size());

  T* buf = res.data();
  auto pb_items = v_ndarray.items();
  YACL_ENFORCE(pb_items.size() == res.size(), "Pb: shape and len not match");
  yacl::parallel_for(0, res.size(), 1, [&](int64_t beg, int64_t end) {
    for (int64_t i = beg; i < end; ++i) {
      if constexpr (std::is_same_v<T, std::string>) {
        buf[i] = pb_items.at(i);
      } else {
        buf[i].Deserialize(pb_items.at(i));
      }
    }
  });

  return res;
}

template class DenseMatrix<phe::Plaintext>;
template class DenseMatrix<phe::Ciphertext>;
template class DenseMatrix<std::string>;

}  // namespace heu::lib::numpy
