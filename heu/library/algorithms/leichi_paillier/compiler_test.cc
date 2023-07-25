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
#include <stdio.h>
#include "heu/library/algorithms/leichi_paillier/compiler/compiler.h"
#include <bits/stdc++.h>
namespace heu::lib::algorithms::leichi_paillier::test {

    class CompilerTest : public testing::Test {
        protected:
        static void SetUpTestSuite() { ; }

    };
    Compiler _compiler;
    TEST_F(CompilerTest, compiler){
        _compiler._program.type = "vector";
        _compiler._program.operation_type ="MOD_EXP_CONST_E";//"MOD_MUL";//"MOD_EXP_CONST_E";//"MOD_INV_CONST_P";//"MONT_CONST";//"MONT";//"MOD_ADD";//"MOD_EXP_CONST_A";//"MOD_MUL_CONST";//"MOD_EXP";// "PAILLIER_ENC";//"MOD_MUL";
        _compiler._program.p_bitcount = 4096;
        _compiler._program.e_bitcount = 2048;
        _compiler._program.vec_size = 100000;
        _compiler.compile();
    };
}
