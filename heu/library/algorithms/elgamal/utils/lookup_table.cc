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

#include "heu/library/algorithms/elgamal/utils/lookup_table.h"

#include "yacl/utils/parallel.h"

namespace heu::lib::algorithms::elgamal {

constexpr static int kLookupTableBits = 20;
constexpr static int kExtraSearchBits = 12;

constexpr static int64_t kTableMaxValue = 1LL << kLookupTableBits;
constexpr static int64_t kSearchMaxValue = 1LL << kExtraSearchBits;

const MPInt &LookupTable::MaxSupportedValue() {
  const static MPInt max(kTableMaxValue * kSearchMaxValue);
  return max;
}

void LookupTable::Init(const std::shared_ptr<EcGroup> &curve) {
  curve_ = curve;

  // lambda: make a copy of curve, so that if LookupTable object moved, these
  // lambdas still work
  auto hash = [curve](const EcPoint &p) { return curve->HashPoint(p); };
  auto equal = [curve](const EcPoint &p1, const EcPoint &p2) {
    return curve->PointEqual(p1, p2);
  };

  // mG -> m
  // m in range [0, MAX_VALUE) U [n - MAX_VALUE, n), n is the order
  table_ =
      std::make_shared<HashMap<EcPoint, int64_t>>(kTableMaxValue, hash, equal);

  yacl::parallel_for(0, kTableMaxValue, 1, [&](int64_t beg, int64_t end) {
    auto g = curve_->GetGenerator();
    auto point = curve_->MulBase(MPInt(beg));
    table_->Insert(point, beg);
    for (int64_t i = beg + 1; i < end; ++i) {
      point = curve_->Add(point, g);
      table_->Insert(point, i);
    }
  });

  table_max_pos_ = curve_->MulBase(MPInt(kTableMaxValue));
  table_max_neg_ = curve_->Negate(table_max_pos_);
}

int64_t LookupTable::Search(const EcPoint &p) const {
  auto *it = table_->Find(p);
  if (it != nullptr) {
    return *it;
  }

  auto im_pos = curve_->Add(p, table_max_neg_);  // assume point is positive
  auto im_neg = curve_->Add(p, table_max_pos_);
  for (int64_t i = 1; i < kSearchMaxValue; ++i) {
    it = table_->Find(im_pos);
    if (it != nullptr) {
      return *it + i * kTableMaxValue;
    }

    it = table_->Find(im_neg);
    if (it != nullptr) {
      return *it - i * kTableMaxValue;
    }

    curve_->AddInplace(&im_pos, table_max_neg_);
    curve_->AddInplace(&im_neg, table_max_pos_);
  }

  // last try for negative point
  it = table_->Find(im_neg);
  if (it != nullptr) {
    return *it - kSearchMaxValue * kTableMaxValue;
  }

  YACL_THROW("ElGamal: Cannot decrypt, the plaintext is too big");
}

}  // namespace heu::lib::algorithms::elgamal
