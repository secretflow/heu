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

#pragma once

#include <set>
#include <string>

#include "yacl/base/byte_container_view.h"
#include "yacl/utils/spi/argument/argument.h"

namespace heu::spi {

using yacl::ArgLib;

//=================================//
//   List of all supported args    //
//=================================//

//===== Common algorithm args =====//

// Deserialize HeKit params
DECLARE_ARG(yacl::ByteContainerView, ParamsFrom);

DECLARE_ARG_bool(GenNewPkSk);  // Generate a new public key & secret key
DECLARE_ARG_bool(GenNewRlk);   // Generate new relinearization keys
DECLARE_ARG_bool(GenNewGlk);   // Generate new galois keys
DECLARE_ARG_bool(GenNewBsk);   // Generate a new bootstrapping key

DECLARE_ARG(yacl::ByteContainerView, SkFrom);
DECLARE_ARG(yacl::ByteContainerView, PkFrom);
DECLARE_ARG(yacl::ByteContainerView, RlkFrom);
DECLARE_ARG(yacl::ByteContainerView, GlkFrom);
DECLARE_ARG(yacl::ByteContainerView, BskFrom);

// In He SPI, all HeKit instances are created through HeFactory, for example,
//  >> HeFactory::Instance().Create(...args...)
//
// Among them, the arguments passed to the Create() function have a significant
// impact on the functionality of the instance. Suppose there is a typical
// scenario: Alice encrypts data, Bob calculates on the ciphertext and returns
// the result to Alice, and Alice decrypts the result.
//
// Then Alice needs a HeKit containing the public key and secret key. She can
// create it like this:
//  >> HeFactory::Instance().Create(paillier, ArgGenNewPkSk = true,
//                                            ArgKeySize = 2048, ...);
//
// On the other hand, Bob needs a HeKit containing only the public key from
// Alice. Bob can create it like this:
//  >> HeFactory::Instance().Create(paillier, ArgLib=lib_name,
//                   /* optional */ ArgParamsFrom = buf_from_alice,
//                                  ArgPkFrom = buf_from_alice, ...);
// Please refer to the table below for details.
//
//                          Argument settings guide
// +----------------------+--------------------------+-------------------------+
// |     Content Type     |        Create New        | Deserialize from buffer |
// +----------------------+--------------------------+-------------------------+
// |     HeKit Params     | pass all args to factory |  ArgParamsFrom = buffer |
// +----------------------+--------------------------+-------------------------+
// |      Public Key      |                          |    ArgPkFrom = buffer   |
// +----------------------+   ArgGenNewPkSk = true   +-------------------------+
// |      Secret Key      |                          |        (Optional)       |
// |                      |                          |    ArgSKFrom = buffer   |
// +----------------------+--------------------------+-------------------------+
// | Relinearization keys |    ArgGenNewRlk = true   |   ArgRlkFrom = buffer   |
// +----------------------+--------------------------+-------------------------+
// |      Galois keys     |    ArgGenNewGlk = true   |   ArgGlkFrom = buffer   |
// +----------------------+--------------------------+-------------------------+
// |   Bootstrapping key  |    ArgGenNewBsk = true   |   ArgBskFrom = buffer   |
// +----------------------+--------------------------+-------------------------+

//===== Common encoder args =====//

// Encoding parameters control how cleartexts are encoded to plaintexts
// Supported encoding method:
// * plain
// * batch
DECLARE_ARG_string(EncodingMethod);
DECLARE_ARG_int64(Scale);  // ckks algo only

// Encoding parameters for PHE algorithms:
// Plain encoder: Plaintext = Cleartext * Scale
// Batch encoder: Plaintext = (Cleartext1 * Scale | Cleartext2 * Scale | ...)
DECLARE_ARG_int64(Scale);
DECLARE_ARG_uint64(Padding);  // BatchEncoder only

//== Args of mock_phe / paillier / OU ==//

DECLARE_ARG_int64(KeySize);

//== Args of ElGamal ==//

DECLARE_ARG_string(Curve);

//== Common args for mock_fhe / bfv / bgv / ckks ==//

DECLARE_ARG_uint64(PolyModulusDegree);

//== Spec args for mock_fhe ==//

DECLARE_ARG_int64(Scale);  // ckks algo only

}  // namespace heu::spi
