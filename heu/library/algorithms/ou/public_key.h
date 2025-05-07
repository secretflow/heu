// Copyright 2022 Ant Group Co., Ltd.
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

#include <string>

#include "fmt/format.h"

#include "heu/library/algorithms/util/big_int.h"
#include "heu/library/algorithms/util/he_object.h"

namespace heu::lib::algorithms::ou {

namespace internal_params {

inline constexpr size_t kRandomBits1024 = 80;
// Note: Why 110, not 112?
// 110 is divisible by kExpUnitBits, which can improve performance
inline constexpr size_t kRandomBits2048 = 110;
inline constexpr size_t kRandomBits3072 = 128;
}  // namespace internal_params

// The relationship between density and memory usage（per public_key)
// where max_plain_bits_ == 128 bits
// +---------+----------------+-------------+----------+
// | density | table_size(MB) | pk_size(MB) | speed_up |
// +---------+----------------+-------------+----------+
// | 1       | 0.067          | 0.20        | 1x       |
// +---------+----------------+-------------+----------+
// | 2       | 0.067          | 0.20        | 2x       |
// +---------+----------------+-------------+----------+
// | 3       | 0.089          | 0.27        | 3x       |
// +---------+----------------+-------------+----------+
// | 4       | 0.133          | 0.40        | 4x       |
// +---------+----------------+-------------+----------+
// | 5       | 0.213          | 0.64        | 5x       |
// +---------+----------------+-------------+----------+
// | 6       | 0.356          | 1.07        | 6x       |
// +---------+----------------+-------------+----------+
// | 7       | 0.610          | 1.83        | 7x       |
// +---------+----------------+-------------+----------+
// | 8       | 1.067          | 3.20        | 8x       |
// +---------+----------------+-------------+----------+
// | 9       | 1.897          | 5.69        | 9x       |
// +---------+----------------+-------------+----------+
// | 10      | 3.414          | 10.24       | 10x      |
// +---------+----------------+-------------+----------+
// | 11      | 6.207          | 18.62       | 11x      |
// +---------+----------------+-------------+----------+
// | 12      | 11.380         | 34.14       | 12x      |
// +---------+----------------+-------------+----------+
// | 13      | 21.010         | 63.03       | 13x      |
// +---------+----------------+-------------+----------+
// | 14      | 39.018         | 117.05      | 14x      |
// +---------+----------------+-------------+----------+
// | 15      | 72.833         | 218.50      | 15x      |
// +---------+----------------+-------------+----------+
// | 16      | 136.563        | 409.69      | 16x      |
// +---------+----------------+-------------+----------+
// | 17      | 257.059        | 771.18      | 17x      |
// +---------+----------------+-------------+----------+
// | 18      | 485.556        | 1456.67     | 18x      |
// +---------+----------------+-------------+----------+
// | 19      | 920.000        | 2760.00     | 19x      |
// +---------+----------------+-------------+----------+
// | 20      | 1748.000       | 5244.00     | 20x      |
// +---------+----------------+-------------+----------+
// Note 1: It can be seen that the memory size has a linear relationship with
// pk->max_plain_bits_
// Note 2: If max_plain_bits_ is adjusted, the memory size needs to be
// multiplied by the factor accordingly
void SetCacheTableDensity(size_t density);

// The density parameter of each participant can be different, so density is
// a local configuration and will not be automatically passed to other parties
// through the protocol

class PublicKey : public HeObject<PublicKey> {
 public:
  BigInt n_;          // n = p^2 * q
  BigInt capital_g_;  // G = g^u mod n for some random g \in [0, n)
  BigInt capital_h_;  // H = g'^{n*u} mod n for some random g' \in [0, n)

  BigInt capital_g_inv_;  // G^{-1} mod n
  BigInt max_plaintext_;  // always power of 2, e.g. max_plaintext_ == 2^681

  std::shared_ptr<MontgomerySpace> m_space_;
  // Cache table of bases (底数缓存表).
  // Used to speed up PowMod operations
  // The cache tables are relatively large (~10+MB), so place them in heap to
  // avoid copying the tables when public key is copied
  std::shared_ptr<BaseTable> cg_table_;   // Auxiliary array for capital_g_
  std::shared_ptr<BaseTable> cgi_table_;  // Auxiliary array for capital_g_inv_
  std::shared_ptr<BaseTable> ch_table_;   // Auxiliary array for capital_h_

  void Init();
  [[nodiscard]] std::string ToString() const override;

  bool operator==(const PublicKey &other) const {
    return n_ == other.n_ && capital_g_ == other.capital_g_ &&
           capital_h_ == other.capital_h_;
  }

  bool operator!=(const PublicKey &other) const {
    return !this->operator==(other);
  }

  // Valid plaintext range: [max_plaintext_, -max_plaintext_]
  [[nodiscard]] const BigInt &PlaintextBound() const & {
    return max_plaintext_;
  }
};

}  // namespace heu::lib::algorithms::ou

// clang-format off
namespace msgpack {
MSGPACK_API_VERSION_NAMESPACE(MSGPACK_DEFAULT_API_NS) {
namespace adaptor {

template<>
struct pack<heu::lib::algorithms::ou::PublicKey> {
  template<typename Stream>
  packer<Stream> &operator()(msgpack::packer<Stream> &o,
      const heu::lib::algorithms::ou::PublicKey &pk) const {
    // packing member variables as an array.
    o.pack_array(4);
    o.pack(pk.n_);
    o.pack(pk.capital_g_);
    o.pack(pk.capital_h_);
    o.pack(pk.max_plaintext_.BitCount() - 1);
    return o;
  }
};

template<>
struct convert<heu::lib::algorithms::ou::PublicKey> {
  msgpack::object const &operator()(const msgpack::object &object,
      heu::lib::algorithms::ou::PublicKey &pk) const {
    if (object.type != msgpack::type::ARRAY) { throw msgpack::type_error(); }
    if (object.via.array.size != 4) { throw msgpack::type_error(); }

    // The order here corresponds to the packer above
    pk.n_ = object.via.array.ptr[0].as<heu::lib::algorithms::BigInt>();
    pk.capital_g_ = object.via.array.ptr[1].as<heu::lib::algorithms::BigInt>();
    pk.capital_h_ = object.via.array.ptr[2].as<heu::lib::algorithms::BigInt>();
    pk.max_plaintext_ =
        heu::lib::algorithms::BigInt(1) << object.via.array.ptr[3].as<size_t>();
    pk.Init();
    return object;
  }
};

}  // namespace adaptor
}  // namespace msgpack
}  // namespace msgpack

// clang-format on
