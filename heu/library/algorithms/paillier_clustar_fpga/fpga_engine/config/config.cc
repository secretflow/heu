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

#include "config.h"

namespace heu::lib::algorithms::paillier_clustar_fpga::fpga_engine {

struct timeval time_point[40];
struct timeval fpgaid_time_point[8][30];

// FPGA's longest wait_time in all cases(unit: us)

#ifdef MULTI_CARD_DEBUG
long double maximum_time = 10000000.0;
long double single_task_maximum_time = 10000000.0;
#else
long double maximum_time = 3600000000.0;
long double single_task_maximum_time = 3600000000.0;

}  // heu::lib::algorithms::paillier_clustar_fpga::fpga_engine

#endif
