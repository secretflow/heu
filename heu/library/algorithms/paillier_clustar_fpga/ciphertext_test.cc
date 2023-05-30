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

#include "heu/library/algorithms/paillier_clustar_fpga/ciphertext.h"
#include "gtest/gtest.h"
#include "heu/library/algorithms/paillier_clustar_fpga/fpga_engine/paillier_operators/fpga_types.h"

namespace heu::lib::algorithms::paillier_clustar_fpga::test {

class CiphertextTest : public ::testing::TestWithParam<size_t> {
};

INSTANTIATE_TEST_SUITE_P(SubTest, CiphertextTest,
                         ::testing::Values(512, 1024, 2048));

TEST_P(CiphertextTest, CKeyLenConfig) {
    unsigned key_len = GetParam();
    fpga_engine::CKeyLenConfig key_conf(key_len);
    if (key_len == 512) {
        ASSERT_EQ(key_conf.cipher_bits_, 1024);
        ASSERT_EQ(key_conf.cipher_byte_, 128);
        ASSERT_EQ(key_conf.plain_bits_, 1024);
        ASSERT_EQ(key_conf.plain_byte_, 128);
        ASSERT_EQ(key_conf.encr_random_bit_len_, 512);
        ASSERT_EQ(key_conf.encr_random_byte_, 64);
    } else if (key_len == 1024) {
        ASSERT_EQ(key_conf.cipher_bits_, 2048);
        ASSERT_EQ(key_conf.cipher_byte_, 256);
        ASSERT_EQ(key_conf.plain_bits_, 2048);
        ASSERT_EQ(key_conf.plain_byte_, 256);
        ASSERT_EQ(key_conf.encr_random_bit_len_, 1024);
        ASSERT_EQ(key_conf.encr_random_byte_, 128);
    } else if (key_len == 2048) {
        ASSERT_EQ(key_conf.cipher_bits_, 4096);
        ASSERT_EQ(key_conf.cipher_byte_, 512);
        ASSERT_EQ(key_conf.plain_bits_, 4096);
        ASSERT_EQ(key_conf.plain_byte_, 512);
        ASSERT_EQ(key_conf.encr_random_bit_len_, 2048);
        ASSERT_EQ(key_conf.encr_random_byte_, 256);
    }
}

TEST_P(CiphertextTest, All) {
    unsigned key_len = GetParam();
    fpga_engine::CKeyLenConfig key_conf(key_len);

    unsigned cipher_size = key_conf.cipher_byte_;
    Ciphertext cipher1(cipher_size);
    cipher1.SetExp(10);
    char *str1 = cipher1.GetMantissa();
    int64_t common_val = 0x1234560100;
    memcpy(str1, &common_val, sizeof(common_val));
    // std::string cipher1_str = cipher1.ToString();
    // std::cout<<"cipher1_str:"<<cipher1_str<<std::endl;

    Ciphertext cipher2(cipher1);
    EXPECT_EQ(cipher1, cipher2);

    Ciphertext cipher3(std::move(cipher2)); // cipher2 is empty now
    EXPECT_TRUE(cipher2.GetMantissa() == nullptr);
    EXPECT_TRUE(cipher2.GetExp() == 0);
    EXPECT_NE(cipher1, cipher2);
    EXPECT_EQ(cipher1, cipher3);

    Ciphertext cipher4(str1, cipher1.GetSize(), cipher1.GetExp());
    EXPECT_EQ(cipher1, cipher4);

    Ciphertext cipher5;
    cipher5 = cipher1;
    EXPECT_EQ(cipher1, cipher5);

    Ciphertext cipher6;
    cipher6 = std::move(cipher3); // cipher3 is empty now
    EXPECT_TRUE(cipher3.GetMantissa() == nullptr);
    EXPECT_TRUE(cipher3.GetExp() == 0);
    EXPECT_NE(cipher1, cipher3);
    EXPECT_EQ(cipher1, cipher6);

    yacl::Buffer buf = cipher1.Serialize();
    yacl::ByteContainerView buf_view(buf.data(), buf.size());
    Ciphertext cipher7;
    cipher7.Deserialize(buf_view);
    EXPECT_EQ(cipher1, cipher7);
}

} // heu::lib::algorithms::paillier_clustar_fpga
