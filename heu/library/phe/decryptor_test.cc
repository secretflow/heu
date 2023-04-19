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

#include "heu/library/phe/encoding/encoding.h"
#include "heu/library/phe/phe.h"

namespace heu::lib::phe::test {

class DecryptorTest : public ::testing::Test {
 protected:
  HeKit he_kit_ = HeKit(SchemaType::OU, 2048);
  PlainEncoder edr_ = he_kit_.GetEncoder<PlainEncoder>(1);
};

TEST_F(DecryptorTest, CheckRangeWorks) {
  auto pt = edr_.Encode(std::numeric_limits<uint64_t>::max());
  auto ct = he_kit_.GetEncryptor()->Encrypt(pt);
  EXPECT_NO_THROW(he_kit_.GetDecryptor()->DecryptInRange(ct, 64));

  he_kit_.GetEvaluator()->AddInplace(&ct, edr_.Encode(1));
  EXPECT_ANY_THROW(he_kit_.GetDecryptor()->DecryptInRange(ct, 64));
}

}  // namespace heu::lib::phe::test
