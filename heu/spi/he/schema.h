// Copyright 2024 Ant Group Co., Ltd.
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

#include <set>
#include <string>
#include <string_view>
#include <unordered_map>

namespace heu::spi {

// The feature set name of homomorphic encryption algorithms
enum class FeatureSet {
  AdditivePHE,
  WordFHE,    // include bfv, bgv, mock_bfv
  ApproxFHE,  // include ckks, mock_ckks
};

enum class Schema {
  Unknown,
  MockPhe,   // mock of FeatureSet::AdditivePHE
  MockBfv,   // mock of FeatureSet::WordFHE
  MockCkks,  // mock of FeatureSet::ApproxFHE

  Paillier,
  OU,
  ElGamal,
  DJ,
  DGK,

  Bgv,
  Bfv,
  Ckks,
};

inline const std::unordered_map<Schema, std::string> kSchema2String = {
    {Schema::Unknown, "unknown"},
    {Schema::MockPhe, "mock_phe"},
    {Schema::MockBfv, "mock_bfv"},
    {Schema::MockCkks, "mock_ckks"},

    {Schema::Paillier, "paillier"},
    {Schema::OU, "okamoto–uchiyama"},
    {Schema::ElGamal, "elgamal"},
    {Schema::DJ, "damgard-jurik"},
    {Schema::DGK, "damgard-geisler-krøigaard(DGK)"},

    {Schema::Bgv, "bgv"},
    {Schema::Bfv, "bfv"},
    {Schema::Ckks, "ckks"},
};

const std::set<Schema> &ListAllSchema();

std::string Schema2String(Schema schema);

// if schema name not exists, return Unknown
Schema String2Schema(std::string_view name);

// for fmtlib
inline auto format_as(const Schema &s) { return Schema2String(s); }

}  // namespace heu::spi
