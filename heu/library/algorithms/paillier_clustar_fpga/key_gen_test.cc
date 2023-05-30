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

#include "heu/library/algorithms/paillier_clustar_fpga/public_key.h"
#include "heu/library/algorithms/paillier_clustar_fpga/secret_key.h"
#include "heu/library/algorithms/paillier_clustar_fpga/key_generator.h"
#include "gtest/gtest.h"

namespace heu::lib::algorithms::paillier_clustar_fpga::test {

class KeyGenTest : public ::testing::TestWithParam<size_t> {

};

INSTANTIATE_TEST_SUITE_P(SubTest, KeyGenTest,
                         ::testing::Values(512, 1024, 2048));

// TODO: find suitable KeyFieldTest for FATE style
TEST_P(KeyGenTest, KeyFieldTest) {
    PublicKey pk;
    SecretKey sk;
    KeyGenerator::Generate(GetParam(), &sk, &pk);
    
    EXPECT_GE(pk.GetN().BitCount(), GetParam());
    EXPECT_TRUE(pk.GetNSquare() == pk.GetN() * pk.GetN());

    // TODO: this case will fail
    // EXPECT_GE((sk.GetP() - sk.GetQ()).Abs().BitCount(), GetParam() / 2 - 2);
}

TEST_P(KeyGenTest, Serialize) {
    // Generate public key and secret key
    PublicKey pk;
    SecretKey sk;
    KeyGenerator::Generate(GetParam(), &sk, &pk);

    // Serialize public key and Deserialize
    auto pk_buffer = pk.Serialize();
    PublicKey pk2;
    pk2.Deserialize(yacl::ByteContainerView(pk_buffer));
    EXPECT_EQ(pk, pk2);
    // comment since print many
    // std::cout<<"pk.ToString(): "<<pk.ToString()<<std::endl;
    // std::cout<<"pk2.ToString(): "<<pk2.ToString()<<std::endl;
    uint64_t max_val = static_cast<uint64_t>(std::numeric_limits<int64_t>::max()) + 1;
    EXPECT_EQ(Plaintext(max_val), pk.PlaintextBound());
    EXPECT_EQ(Plaintext(max_val), pk2.PlaintextBound());

    PublicKey temp_pub_key;
    EXPECT_NE(pk2, temp_pub_key);

    EXPECT_EQ(pk.GetN(), pk2.GetN());
    EXPECT_EQ(pk.GetG(), pk2.GetG());
    EXPECT_EQ(pk.GetNSquare(), pk2.GetNSquare());
    EXPECT_EQ(pk.GetMaxInt(), pk2.GetMaxInt());

    // Serialize secret key and Deserialize
    auto sk_buffer = sk.Serialize();
    SecretKey sk2;
    sk2.Deserialize(yacl::ByteContainerView(sk_buffer));
    EXPECT_EQ(sk, sk2);
    // comment since print many
    // std::cout<<"sk.ToString(): "<<sk.ToString()<<std::endl;
    // std::cout<<"sk2.ToString(): "<<sk2.ToString()<<std::endl;

    SecretKey temp_secr_key;
    EXPECT_NE(sk2, temp_secr_key);

    EXPECT_EQ(sk.GetP(), sk2.GetP());
    EXPECT_EQ(sk.GetQ(), sk2.GetQ());
    EXPECT_EQ(sk.GetPSquare(), sk2.GetPSquare());
    EXPECT_EQ(sk.GetQSquare(), sk2.GetQSquare());
    EXPECT_EQ(sk.GetQInverse(), sk2.GetQInverse());
    EXPECT_EQ(sk.GetHP(), sk2.GetHP());
    EXPECT_EQ(sk.GetHQ(), sk2.GetHQ());
    EXPECT_EQ(sk.GetPubKey(), sk2.GetPubKey());
}

TEST_P(KeyGenTest, PubKey) {
    PublicKey pk;
    SecretKey sk;
    KeyGenerator::Generate(GetParam(), &sk, &pk);
    uint64_t max_val = static_cast<uint64_t>(std::numeric_limits<int64_t>::max()) + 1;
    EXPECT_EQ(Plaintext(max_val), pk.PlaintextBound());

    // Check N odd/even, odd is OK
    size_t buf_len = 64;
    unsigned char buf[buf_len];
    memset(buf, 0, buf_len);
    pk.GetN().ToBytes(buf, buf_len, Endian::little);
    uint8_t flag = buf[0];
    ASSERT_NE(flag & 0x01, 0)<<"n is even, invalid, should be odd";

    EXPECT_EQ(pk.GetG(), pk.GetN() + MPInt::_1_);
    EXPECT_EQ(pk.GetNSquare(), pk.GetN() *pk.GetN());
    MPInt calc_max_int = pk.GetN() / MPInt(3) - MPInt::_1_;
    EXPECT_EQ(pk.GetMaxInt(), Plaintext(calc_max_int));
}

TEST_P(KeyGenTest, PriKey) {
    PublicKey pk;
    SecretKey sk;
    KeyGenerator::Generate(GetParam(), &sk, &pk);

    EXPECT_EQ(sk.GetP() * sk.GetQ(), pk.GetN());
    EXPECT_NE(sk.GetP(), sk.GetQ());
    EXPECT_EQ(sk.GetP() * sk.GetP(), sk.GetPSquare());
    EXPECT_EQ(sk.GetQ() * sk.GetQ(), sk.GetQSquare());

    MPInt q_inverse;
    MPInt::InvertMod(sk.GetQ(), sk.GetP(), &q_inverse);
    EXPECT_EQ(sk.GetQInverse(), q_inverse);

    MPInt p_pow_mod;
    MPInt::PowMod(pk.GetG(), sk.GetP() - MPInt::_1_, sk.GetPSquare(), &p_pow_mod);
    MPInt hp;
    MPInt::InvertMod((p_pow_mod - MPInt::_1_) / sk.GetP(), sk.GetP(), &hp);
    EXPECT_EQ(sk.GetHP(), hp);

    MPInt q_pow_mod;
    MPInt::PowMod(pk.GetG(), sk.GetQ() - MPInt::_1_, sk.GetQSquare(), &q_pow_mod);
    MPInt hq;
    MPInt::InvertMod((q_pow_mod - MPInt::_1_) / sk.GetQ(), sk.GetQ(), &hq);
    EXPECT_EQ(sk.GetHQ(), hq);
}

} // heu::lib::algorithms::paillier_clustar_fpga::test
