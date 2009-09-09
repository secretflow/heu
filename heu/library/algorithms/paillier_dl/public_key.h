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

// The density parameter of each participant can be different, so density is
// a local configuration and will not be automatically passed to other parties
// through the protocol
void SetCacheTableDensity(size_t density);

class PublicKey : public HeObject<PublicKey> {
 public:
  ~PublicKey(){
    CGBNWrapper::DevFree(this);
  }

 public:
  MPInt g_;
  MPInt n_;
  MPInt nsquare_;
  MPInt max_int_;
  MPInt half_n_;
  dev_mem_t<BITS> *dev_g_;
  dev_mem_t<BITS> *dev_n_;
  dev_mem_t<BITS> *dev_nsquare_;
  dev_mem_t<BITS> *dev_max_int_;
  PublicKey *dev_pk_;

  // Init pk based on n_
  void Init(const MPInt &n, MPInt *g);
  [[nodiscard]] std::string ToString() const override;

  bool operator==(const PublicKey &other) const {
    NOT_SUPPORT;
    // return n_ == other.n_ && h_s_ == other.h_s_;
  }

  bool operator!=(const PublicKey &other) const {
    return !this->operator==(other);
  }

  // Valid plaintext range: (n_half_, -n_half)
  [[nodiscard]] inline const MPInt &PlaintextBound() const & { 
    NOT_SUPPORT;
    // MPInt tmp;
    // if (tmp.n_.alloc * sizeof(mp_digit) < max_int_->_mp_size * sizeof(mp_limb_t)) {
    //   printf("%s:%d No enough memory, need: %d, real: %d\n", __FILE__, __LINE__, max_int_->_mp_size, tmp.n_.alloc);
    //   abort();
    // }
    // memcpy(tmp.n_.dp, max_int_->_mp_d, max_int_->_mp_size * sizeof(mp_limb_t));
    // tmp.n_.sign = MP_ZPOS;
    // return tmp;
    // return n_half_; 
  }
};

}  // namespace heu::lib::algorithms::paillier_dl

// clang-format off
namespace msgpack {
MSGPACK_API_VERSION_NAMESPACE(MSGPACK_DEFAULT_API_NS) {
namespace adaptor {

// template<>
// struct pack<heu::lib::algorithms::paillier_dl::PublicKey> {
//   template<typename Stream>
//   packer<Stream> &operator()(msgpack::packer<Stream> &o,
//       const heu::lib::algorithms::paillier_dl::PublicKey &pk) const {
//     // packing member variables as an array.
//     o.pack_array(2);
//     o.pack(pk.n_);
//     o.pack(pk.h_s_);
//     return o;
//   }
// };

// template<>
// struct convert<heu::lib::algorithms::paillier_dl::PublicKey> {
//   msgpack::object const &operator()(const msgpack::object &object,
//       heu::lib::algorithms::paillier_dl::PublicKey &pk) const {
//     if (object.type != msgpack::type::ARRAY) { throw msgpack::type_error(); }
//     if (object.via.array.size != 2) { throw msgpack::type_error(); }

//     // The order here corresponds to the packer above
//     pk.n_ = object.via.array.ptr[0].as<heu::lib::algorithms::MPInt>();
//     pk.h_s_ = object.via.array.ptr[1].as<heu::lib::algorithms::MPInt>();
//     pk.Init();
//     return object;
//   }
// };

}  // namespace adaptor
}  // namespace msgpack
}  // namespace msgpack
// clang-format on
