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
#include "yacl/base/exception.h"

#include "heu/experimental/gemini-rlwe/lwe_types.h"
#include "heu/experimental/gemini-rlwe/poly_encoder.h"

namespace heu::expt::rlwe {

class MatVecProtocol {
 public:
  struct Meta {
    bool transposed;
    size_t nrows;
    size_t ncols;
  };

  explicit MatVecProtocol(const seal::SEALContext& context,
                          const ModulusSwitchHelper& ms_helper);

  void EncodeVector(const Meta& meta, absl::Span<const uint32_t> vec_view,
                    std::vector<RLWEPt>* out) const;

  void EncodeVector(const Meta& meta, absl::Span<const uint64_t> vec_view,
                    std::vector<RLWEPt>* out) const;

  void EncodeVector(const Meta& meta, absl::Span<const uint128_t> vec_view,
                    std::vector<RLWEPt>* out) const;

  void MatVec(const Meta& meta, absl::Span<const uint32_t> mat_view,
              const std::vector<RLWECt>& vec, std::vector<LWECt>* out) const;

  void MatVec(const Meta& meta, absl::Span<const uint64_t> mat_view,
              const std::vector<RLWECt>& vec, std::vector<LWECt>* out) const;

  void MatVec(const Meta& meta, absl::Span<const uint128_t> mat_view,
              const std::vector<RLWECt>& vec, std::vector<LWECt>* out) const;

  template <typename T>
  void MatVecRandomMat(const Meta& meta, const std::vector<RLWECt>& vec,
                       std::function<void(T*, size_t)> prng,
                       absl::Span<T> rnd_mat, std::vector<LWECt>* out) const {
    YACL_ENFORCE_EQ(seal::util::mul_safe(meta.nrows, meta.ncols),
                    rnd_mat.size());
    prng(rnd_mat.data(), rnd_mat.size());
    MatVec(meta, rnd_mat, vec, out);
  }

  inline size_t poly_degree() const { return poly_deg_; }

 protected:
  inline size_t GetVecSize(const Meta& meta) const {
    return meta.transposed ? meta.nrows : meta.ncols;
  }

  bool IsValidMeta(const Meta& meta) const;

  template <typename T>
  void DoEncodeVector(const Meta& meta, absl::Span<const T> vec_view,
                      std::vector<RLWEPt>* out) const;

  template <typename T>
  void DoMatVec(const Meta& meta, absl::Span<const T> mat_view,
                const std::vector<RLWECt>& vec, std::vector<LWECt>* out) const;

 private:
  size_t poly_deg_{0};

  PolyEncoder encoder_;
  seal::SEALContext context_;
};

}  // namespace heu::expt::rlwe
