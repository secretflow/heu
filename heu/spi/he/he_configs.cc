// Copyright 2024 Ant Group Co., Ltd.
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

#include "heu/spi/he/he_configs.h"

#include "yacl/base/byte_container_view.h"

namespace heu::spi {

//===== Common algorithm args =====//

DEFINE_ARG(yacl::ByteContainerView, ParamsFrom);

DEFINE_ARG_bool(GenNewPkSk);  // Generate a new public key & secret key
DEFINE_ARG_bool(GenNewRlk);   // Generate new relinearization keys
DEFINE_ARG_bool(GenNewGlk);   // Generate new galois keys
DEFINE_ARG_bool(GenNewBsk);   // Generate a new bootstrapping key

DEFINE_ARG(yacl::ByteContainerView, SkFrom);
DEFINE_ARG(yacl::ByteContainerView, PkFrom);
DEFINE_ARG(yacl::ByteContainerView, RlkFrom);
DEFINE_ARG(yacl::ByteContainerView, GlkFrom);
DEFINE_ARG(yacl::ByteContainerView, BskFrom);

//===== Common encoder args =====//

DEFINE_ARG_string(EncodingMethod);

DEFINE_ARG_int64(Scale);
DEFINE_ARG_uint64(Padding);

//== Args of PHE ==//

// mock / paillier / OU
DEFINE_ARG_int64(KeySize);

// ElGamal
DEFINE_ARG_string(Curve);

//== Common args for mock_fhe / bfv / bgv / ckks ==//

DEFINE_ARG_uint64(PolyModulusDegree);

}  // namespace heu::spi
