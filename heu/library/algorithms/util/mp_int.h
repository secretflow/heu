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

#pragma once

#include "yacl/crypto/base/mpint/montgomery_math.h"
#include "yacl/crypto/base/mpint/mp_int.h"

namespace heu::lib::algorithms {

// MPInt has moved to YACL, we leave a shortcut here ...
using yacl::crypto::MPInt;
using yacl::crypto::PrimeType;

using yacl::crypto::BaseTable;
using yacl::crypto::MontgomerySpace;

}  // namespace heu::lib::algorithms
