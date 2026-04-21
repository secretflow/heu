#include "math/ntt_tables.h"

#include <gtest/gtest.h>

#include "math/modulus.h"

using namespace bfv::math::ntt;
using namespace bfv::math::zq;

class NTTTablesTest : public ::testing::Test {
 protected:
  Modulus GetTestModulus() {
    // Use a prime that supports NTT for size 8: p = 17 (17-1 = 16 = 2*8)
    auto mod_opt = Modulus::New(17);
    EXPECT_TRUE(mod_opt.has_value());
    return std::move(*mod_opt);
  }
};

TEST_F(NTTTablesTest, CreateValidTables) {
  auto modulus = GetTestModulus();
  auto tables_opt = NTTTables::Create(modulus, 8);
  ASSERT_TRUE(tables_opt.has_value());

  auto tables = std::move(*tables_opt);
  EXPECT_EQ(tables.GetCoeffCount(), 8);
  EXPECT_EQ(tables.GetModulus().P(), 17);

  // Check that root powers are precomputed
  const auto &root_powers = tables.GetRootPowers();
  EXPECT_EQ(root_powers.size(), 8);

  // Check that inverse root powers are precomputed
  const auto &inv_root_powers = tables.GetInvRootPowers();
  EXPECT_EQ(inv_root_powers.size(), 8);
}

TEST_F(NTTTablesTest, InvalidParameters) {
  auto modulus = GetTestModulus();

  // Non-power-of-2 size should fail
  auto tables_opt = NTTTables::Create(modulus, 7);
  EXPECT_FALSE(tables_opt.has_value());

  // Size 0 should fail
  auto tables_opt2 = NTTTables::Create(modulus, 0);
  EXPECT_FALSE(tables_opt2.has_value());

  // Size 1 should fail
  auto tables_opt3 = NTTTables::Create(modulus, 1);
  EXPECT_FALSE(tables_opt3.has_value());
}

TEST_F(NTTTablesTest, PrimitiveRootFinding) {
  auto modulus = GetTestModulus();
  // Test primitive root finding for size 8 with modulus 17
  uint64_t root = NTTTables::FindPrimitiveRoot(8, modulus);
  EXPECT_NE(root, 0);
  EXPECT_TRUE(NTTTables::IsPrimitiveRoot(root, 8, modulus));
}

TEST_F(NTTTablesTest, BitReversal) {
  // Test bit reversal for 3 bits (size 8)
  EXPECT_EQ(NTTTables::ReverseBits(0, 3), 0);  // 000 -> 000
  EXPECT_EQ(NTTTables::ReverseBits(1, 3), 4);  // 001 -> 100
  EXPECT_EQ(NTTTables::ReverseBits(2, 3), 2);  // 010 -> 010
  EXPECT_EQ(NTTTables::ReverseBits(3, 3), 6);  // 011 -> 110
  EXPECT_EQ(NTTTables::ReverseBits(4, 3), 1);  // 100 -> 001
  EXPECT_EQ(NTTTables::ReverseBits(5, 3), 5);  // 101 -> 101
  EXPECT_EQ(NTTTables::ReverseBits(6, 3), 3);  // 110 -> 011
  EXPECT_EQ(NTTTables::ReverseBits(7, 3), 7);  // 111 -> 111
}

TEST_F(NTTTablesTest, CopyAndMove) {
  auto modulus = GetTestModulus();
  auto tables_opt = NTTTables::Create(modulus, 8);
  ASSERT_TRUE(tables_opt.has_value());

  auto original = std::move(*tables_opt);

  // Test copy constructor
  auto copied = original;
  EXPECT_EQ(copied.GetCoeffCount(), 8);
  EXPECT_EQ(copied.GetModulus().P(), 17);

  // Test move constructor
  auto moved = std::move(original);
  EXPECT_EQ(moved.GetCoeffCount(), 8);
  EXPECT_EQ(moved.GetModulus().P(), 17);
}
