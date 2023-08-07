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

#include "heu/library/algorithms/paillier_clustar_fpga/plaintext.h"

#include <iomanip>
#include <limits>
#include <sstream>

#include "gtest/gtest.h"

namespace heu::lib::algorithms::paillier_clustar_fpga::test {

TEST(PlaintextTest, GetSet) {
  Plaintext pt;

  // Get/Set int
  int8_t a1 = -128;
  pt.Set(a1);
  int8_t b1 = pt.Get<int8_t>();
  EXPECT_EQ(a1, b1);
  int64_t b1_1 = pt.Get<int64_t>();
  EXPECT_EQ(a1, b1_1);

  int16_t a2 = -32768;
  pt.Set(a2);
  int16_t b2 = pt.Get<int16_t>();
  EXPECT_EQ(a2, b2);

  int32_t a3 = -2147483648;
  pt.Set(a3);
  int32_t b3 = pt.Get<int32_t>();
  EXPECT_EQ(a3, b3);

  int64_t a4 = std::numeric_limits<int64_t>::min();  // -9223372036854775808
  pt.Set(a4);
  int64_t b4 = pt.Get<int64_t>();
  EXPECT_EQ(a4, b4);

  int128_t a5 = -1.7014118346046923173168730371588 * pow(10, 38);
  pt.Set(a5);
  int128_t b5 = pt.Get<int128_t>();
  EXPECT_EQ(a5, b5);

  // Get/Set uint
  uint8_t c1 = 255;
  pt.Set(c1);
  uint8_t d1 = pt.Get<uint8_t>();
  EXPECT_EQ(c1, d1);

  uint16_t c2 = 65535;
  pt.Set(c2);
  uint16_t d2 = pt.Get<uint16_t>();
  EXPECT_EQ(c2, d2);

  uint32_t c3 = 4294967295;
  pt.Set(c3);
  uint32_t d3 = pt.Get<uint32_t>();
  EXPECT_EQ(c3, d3);

  uint64_t c4 = std::numeric_limits<int64_t>::max();  // 18446744073709551616
  pt.Set(c4);
  uint64_t d4 = pt.Get<uint64_t>();
  EXPECT_EQ(c4, d4);

  uint128_t c5 = 3.4028236692093846346337460743176 * pow(10, 38);
  pt.Set(c5);
  uint128_t d5 = pt.Get<uint128_t>();
  EXPECT_EQ(c5, d5);

  // // Get/Set float/double will fail
  // float e1 = -1.23456;
  // pt.Set<float>(e1);
  // float f1 = pt.Get<float>();
  // EXPECT_EQ(e1, f1);

  // double e2 = -10.23456789;
  // pt.Set<double>(e2);
  // double f2 = pt.Get<double>();
  // EXPECT_EQ(e2, f2);

  // float e11 = -1.23456;
  // MPInt mp_e11(e11);
  // float f11 = mp_e11.Get<float>();
  // EXPECT_EQ(e11, f11);

  // double e12 = -10.12;
  // MPInt mp_e12(e12);
  // double f12 = mp_e12.Get<double>();
  // EXPECT_EQ(e12, f12);
  // std::cout<<"e12: "<<e12<<" f12: "<<f12<<std::endl;

  // Get/Set string
  std::string g1 = "12345";
  pt.Set(g1, 16);
  int32_t h1 = 74565;
  int32_t h11 = pt.Get<int32_t>();
  EXPECT_EQ(h1, h11);

  std::string g2 = "123456";
  pt.Set(g2, 10);
  int32_t h2 = 123456;
  int32_t h22 = pt.Get<int32_t>();
  EXPECT_EQ(h2, h22);

  std::string g3 = "100111";
  pt.Set(g3, 2);
  int32_t h3 = 39;
  int32_t h33 = pt.Get<int32_t>();
  EXPECT_EQ(h3, h33);

  // Get/Set MPInt
  int32_t set_val = 12;
  MPInt i1(set_val);
  pt.Set(i1);
  int32_t j1 = pt.Get<int32_t>();
  EXPECT_EQ(j1, set_val);
  MPInt j2 = pt.Get<MPInt>();
  EXPECT_EQ(i1, j2);

  // Construct test
  Plaintext pt1;
  pt1.Set(12);
  Plaintext pt2(pt1);
  EXPECT_EQ(pt1, pt2);

  Plaintext pt3(std::move(pt1));  // pt1 is invalid now
  EXPECT_EQ(pt2, pt3);

  // Assignment test
  Plaintext pt4;
  pt4.Set(12);
  Plaintext pt5;
  pt5.Set(10);
  EXPECT_NE(pt4, pt5);
  pt5 = pt4;
  EXPECT_EQ(pt4, pt5);

  Plaintext pt6;
  pt6.Set(1);
  EXPECT_NE(pt4, pt6);
  pt6 = std::move(pt5);  // pt5 is invalid now
  EXPECT_EQ(pt4, pt6);
}

TEST(PlaintextTest, SerializeDeserialize) {
  Plaintext pt;
  pt.Set(123456);
  yacl::Buffer buf = pt.Serialize();

  Plaintext pt1;
  yacl::ByteContainerView buf_view(buf.data(), buf.size());
  pt1.Deserialize(buf_view);
  EXPECT_EQ(pt, pt1);
}

TEST(PlaintextTest, ToString) {
  Plaintext pt;
  pt.Set(123456);
  std::string pt_str = pt.ToString();
  std::string str = "123456";
  EXPECT_EQ(pt_str, str);

  std::string pt_hex_str = pt.ToHexString();
  std::string hex_str = "1E240";
  EXPECT_EQ(pt_hex_str, hex_str);
  std::string hex_str_lowercase = "1e240";
  EXPECT_NE(pt_hex_str, hex_str_lowercase);
  std::cout << "pt: " << pt << std::endl;
}

TEST(PlaintextTest, ToBytes) {
  Plaintext pt;
  pt.Set(0x123456);
  yacl::Buffer buff_1 = pt.ToBytes(3, Endian::little);
  EXPECT_EQ(buff_1.data<char>()[0], 0x56);
  EXPECT_EQ(buff_1.data<char>()[2], 0x12);

  auto buff_2 = pt.ToBytes(3, Endian::big);
  EXPECT_EQ(buff_2.data<char>()[0], 0x12);
  EXPECT_EQ(buff_2.data<char>()[2], 0x56);

  auto buff_3 = pt.ToBytes(3, Endian::native);
  EXPECT_EQ(buff_3.data<char>()[0], 0x56);

  size_t expect_bit_count = 21;
  auto bit_count = pt.BitCount();
  std::cout << "bit_count: " << bit_count << std::endl;
  EXPECT_EQ(expect_bit_count, bit_count);
}

TEST(PlaintextTest, Operators) {
  int64_t test_val = 100;
  Plaintext pt;
  pt.Set(test_val);
  EXPECT_TRUE(pt.IsPositive());

  Plaintext pt1 = -pt;
  int64_t val1 = pt1.Get<int64_t>();
  EXPECT_EQ(val1, test_val * -1);
  EXPECT_TRUE(pt1.IsNegative());

  pt1.NegateInplace();
  int64_t val2 = pt1.Get<int64_t>();
  EXPECT_EQ(val2, test_val);
  EXPECT_FALSE(pt1.IsNegative());
  EXPECT_FALSE(pt1.IsZero());

  pt1.Set(0);
  EXPECT_TRUE(pt1.IsZero());

  int32_t left = 20;
  int32_t right = 10;
  pt1.Set(left);
  Plaintext pt2;
  pt2.Set(right);
  int32_t result = left + right;
  EXPECT_EQ(pt1 + pt2, Plaintext(result));

  result = left - right;
  EXPECT_EQ(pt1 - pt2, Plaintext(result));

  result = left * right;
  EXPECT_EQ(pt1 * pt2, Plaintext(result));

  result = left / right;
  EXPECT_EQ(pt1 / pt2, Plaintext(result));

  result = left % right;
  EXPECT_EQ(pt1 % pt2, Plaintext(result));

  result = left & right;
  EXPECT_EQ(pt1 & pt2, Plaintext(result));

  result = left | right;
  EXPECT_EQ(pt1 | pt2, Plaintext(result));

  result = left ^ right;
  EXPECT_EQ(pt1 ^ pt2, Plaintext(result));

  result = left << right;
  EXPECT_EQ(pt1 << right, Plaintext(result));

  result = left >> right;
  EXPECT_EQ(pt1 >> right, Plaintext(result));

  int32_t init_val = 1;
  result = init_val;
  result += left;
  Plaintext init_pt;
  init_pt.Set(init_val);
  Plaintext result_pt = init_pt;
  result_pt += pt1;
  EXPECT_EQ(result_pt, Plaintext(result));

  result -= left;
  result_pt -= pt1;
  EXPECT_EQ(result_pt, Plaintext(result));

  result *= left;
  result_pt *= pt1;
  EXPECT_EQ(result_pt, Plaintext(result));

  result /= left;
  result_pt /= pt1;
  EXPECT_EQ(result_pt, Plaintext(result));

  result %= left;
  result_pt %= pt1;
  EXPECT_EQ(result_pt, Plaintext(result));

  result &= left;
  result_pt &= pt1;
  EXPECT_EQ(result_pt, Plaintext(result));

  result |= left;
  result_pt |= pt1;
  EXPECT_EQ(result_pt, Plaintext(result));

  result ^= left;
  result_pt ^= pt1;
  EXPECT_EQ(result_pt, Plaintext(result));

  result <<= left;
  result_pt <<= left;
  EXPECT_EQ(result_pt, Plaintext(result));

  result >>= left;
  result_pt >>= left;
  EXPECT_EQ(result_pt, Plaintext(result));

  EXPECT_TRUE(pt1 > pt2);
  EXPECT_FALSE(pt1 < pt2);
  EXPECT_TRUE(pt1 >= pt2);
  EXPECT_FALSE(pt1 <= pt2);
  EXPECT_FALSE(pt1 == pt2);
  EXPECT_TRUE(pt1 != pt2);
}

TEST(PlaintextTest, ValCmp) {
  MPInt pt1;
  pt1.Set(456);
  // std::cout<<"pt1: "<<std::endl;
  // std::cout<<pt1.ToHexString()<<std::endl;
  // std::cout<<"pt1.BitCount(): "<<pt1.BitCount()<<std::endl;
  // std::cout<<std::endl;

  MPInt pt2;
  pt2.SetZero();
  // std::cout<<"pt2.BitCount(): "<<pt2.BitCount()<<std::endl;
  size_t cipher_size = 256;
  uint64_t pt2_val = 0x00000000000001C8;
  std::shared_ptr<unsigned char[]> pt2_sptr(new unsigned char[cipher_size]);
  unsigned char* pt2_ptr = pt2_sptr.get();
  memset(pt2_ptr, 0, cipher_size);
  memcpy(pt2_ptr, reinterpret_cast<unsigned char*>(&pt2_val), sizeof(uint64_t));

  pt2.FromMagBytes({pt2_ptr, cipher_size}, Endian::little);
  // std::cout<<"pt2: "<<std::endl;
  // std::cout<<pt2.ToHexString()<<std::endl;
  // std::cout<<"pt2.BitCount(): "<<pt2.BitCount()<<std::endl;
  // std::cout<<std::endl;

  // if (pt2 > pt1) {
  //     std::cout<<"pt2: "<<pt2<<" > pt1: "<<pt1<<std::endl;
  // } else if (pt2 < pt1) {
  //     std::cout<<"pt2: "<<pt2<<" < pt1: "<<pt1<<std::endl;
  // } else if (pt2 == pt1) {
  //     std::cout<<"pt2: "<<pt2<<" == pt1: "<<pt1<<std::endl;
  // }

  EXPECT_EQ(pt1, pt2);

  uint64_t pt3_val = 0x0000000000000008;
  std::shared_ptr<unsigned char[]> pt3_sptr(new unsigned char[cipher_size]);
  unsigned char* pt3_ptr = pt3_sptr.get();
  memset(pt3_ptr, 0, cipher_size);
  memcpy(pt3_ptr, reinterpret_cast<unsigned char*>(&pt3_val), sizeof(uint64_t));
  pt2.FromMagBytes({pt3_ptr, cipher_size}, Endian::little);
  // std::cout<<"=================="<<std::endl;
  // std::cout<<"After reload"<<std::endl;
  // std::cout<<"pt2: "<<std::endl;
  // std::cout<<pt2.ToHexString()<<std::endl;
  // std::cout<<"pt2.BitCount(): "<<pt2.BitCount()<<std::endl;
  // std::cout<<std::endl;

  EXPECT_NE(pt1, pt2);
}

}  // namespace heu::lib::algorithms::paillier_clustar_fpga::test
