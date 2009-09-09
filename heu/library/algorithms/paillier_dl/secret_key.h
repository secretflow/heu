// Copyright 2023 Denglin Co., Ltd.
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

#include "heu/library/algorithms/util/he_object.h"
#include "heu/library/algorithms/util/mp_int.h"
#include "heu/library/algorithms/paillier_dl/cgbn_wrapper/cgbn_wrapper_defs.h"
#include "heu/library/algorithms/paillier_dl/cgbn_wrapper/cgbn_wrapper.h"

#define NOT_SUPPORT do {                                                    \
  printf("%s:%d %s not support.\n", __FILE__, __LINE__, __FUNCTION__);      \
  abort();                                                                  \
} while (0)

namespace heu::lib::algorithms::paillier_dl {

class SecretKey : public HeObject<SecretKey> {
 public:
  ~SecretKey() {
    CGBNWrapper::DevFree(this);
  }
  
 public:
  MPInt g_;
  MPInt p_;
  MPInt q_;
  MPInt psquare_;
  MPInt qsquare_;
  MPInt q_inverse_;
  MPInt hp_;
  MPInt hq_;

  dev_mem_t<BITS> *dev_g_;
  dev_mem_t<BITS> *dev_p_;
  dev_mem_t<BITS> *dev_q_;
  dev_mem_t<BITS> *dev_psquare_;
  dev_mem_t<BITS> *dev_qsquare_;
  dev_mem_t<BITS> *dev_q_inverse_;
  dev_mem_t<BITS> *dev_hp_;
  dev_mem_t<BITS> *dev_hq_;
  SecretKey *dev_sk_;

  void Init(MPInt g, MPInt raw_p, MPInt raw_q);

  bool operator==(const SecretKey &other) const {
    NOT_SUPPORT;
    // return p_ == other.p_ && q_ == other.q_ && lambda_ == other.lambda_ &&
    //        mu_ == other.mu_;
  }

  bool operator!=(const SecretKey &other) const {
    NOT_SUPPORT;
    // return !this->operator==(other);
  }

  [[nodiscard]] std::string ToString() const override;
};

}  // namespace heu::lib::algorithms::paillier_dl

// clang-format off
namespace msgpack {
MSGPACK_API_VERSION_NAMESPACE(MSGPACK_DEFAULT_API_NS) {
namespace adaptor {

// template<>
// struct pack<heu::lib::algorithms::paillier_dl::SecretKey> {
//   template<typename Stream>
//   packer<Stream> &operator()(msgpack::packer<Stream> &o,
//       const heu::lib::algorithms::paillier_dl::SecretKey &sk) const {
//     // packing member variables as an array.
//     o.pack_array(4);
//     o.pack(sk.lambda_);
//     o.pack(sk.mu_);
//     o.pack(sk.p_);
//     o.pack(sk.q_);
//     return o;
//   }
// };

// template<>
// struct convert<heu::lib::algorithms::paillier_dl::SecretKey> {
//   msgpack::object const &operator()(const msgpack::object &object,
//       heu::lib::algorithms::paillier_dl::SecretKey &sk) const {
//     if (object.type != msgpack::type::ARRAY) { throw msgpack::type_error(); }
//     if (object.via.array.size != 4) { throw msgpack::type_error(); }

//     // The order here corresponds to the packer above
//     sk.lambda_ = object.via.array.ptr[0].as<heu::lib::algorithms::MPInt>();
//     sk.mu_ = object.via.array.ptr[1].as<heu::lib::algorithms::MPInt>();
//     sk.p_ = object.via.array.ptr[2].as<heu::lib::algorithms::MPInt>();
//     sk.q_ = object.via.array.ptr[3].as<heu::lib::algorithms::MPInt>();
//     sk.Init();
//     return object;
//   }
// };

}  // namespace adaptor
}  // namespace msgpack
}  // namespace msgpack
// clang-format on