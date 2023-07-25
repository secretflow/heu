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

#include "gtest/gtest.h"
#include <string>
#include "heu/library/algorithms/leichi_paillier/pcie/pcie.h"
#include "runtime.h"
namespace heu::lib::algorithms::leichi_paillier::test {

    class PCIeTest : public testing::Test {
        protected:
        static void SetUpTestSuite() { ; }

    };
    CPcieComm pPcie;
    TEST_F(PCIeTest, pcie){
        bool res = false;
        res = pPcie.open_device() > 0 ? true : false;
        if(res)
        {
            std::cout<<"open Pcie succuss..."<<std::endl;
        }
    };
}
