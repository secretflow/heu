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

#include "heu/library/algorithms/util/spi_traits.h"
#include "heu/library/algorithms/util/mp_int.h"
#include <string.h>

namespace heu::lib::algorithms::paillier_clustar_fpga::fpga_engine {

class CMPIntWrapper {
public:
    CMPIntWrapper() = default;
    ~CMPIntWrapper() = default;

    static void MPIntToBytes(const MPInt& v, char *ptr, size_t len);
};

} // heu::lib::algorithms::paillier_clustar_fpga::fpga_engine

