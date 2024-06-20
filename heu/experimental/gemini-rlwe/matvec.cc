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

#include "heu/experimental/gemini-rlwe/matvec.h"

#include <array>

#include "absl/numeric/bits.h"
#include "seal/evaluator.h"
#include "seal/util/numth.h"
#include "yacl/base/exception.h"

namespace heu::expt::rlwe {

static std::array<size_t, 2> GetSubMatrixShape(const MatVecProtocol::Meta &meta,
                                               size_t poly_degree) {
  size_t ncols = meta.transposed ? meta.nrows : meta.ncols;
  size_t nrows = meta.transposed ? meta.ncols : meta.nrows;

  ncols = std::min(poly_degree, ncols);
  nrows = absl::bit_ceil(nrows);  // NextPow2
  auto log2 = absl::bit_width(poly_degree / ncols) - 1;
  size_t subnrows = std::min(nrows, 1UL << log2);

  return std::array<size_t, 2>{subnrows, ncols};
}

template <typename T>
inline static T CeilDiv(T a, T b) {
  return (a + b - 1) / b;
}

static void transform_to_ntt_inplace(RLWEPt &pt,
                                     const seal::SEALContext &context) {
  using namespace seal::util;
  auto cntxt_data = context.get_context_data(pt.parms_id());
  YACL_ENFORCE(cntxt_data != nullptr);

  auto L = cntxt_data->parms().coeff_modulus().size();
  YACL_ENFORCE(pt.coeff_count() % L == 0);

  auto ntt_tables = cntxt_data->small_ntt_tables();
  size_t n = pt.coeff_count() / L;
  auto pt_ptr = pt.data();
  for (size_t l = 0; l < L; ++l) {
    ntt_negacyclic_harvey(pt_ptr, ntt_tables[l]);
    pt_ptr += n;
  }
}

/// Concatenate the specified submatrix into one vector in row-major
/// Zero-padding the bottom-rows and right-most-columns of submatrix if
/// `extents` are smaller than the given `submat_shape`
template <typename T>
static void ConcatSubMatrix(absl::Span<const T> mat_view,
                            const MatVecProtocol::Meta &meta,
                            const std::array<size_t, 2> &starts,
                            const std::array<size_t, 2> &extents,
                            const std::array<size_t, 2> &submat_shape,
                            std::vector<T> *concat_submat) {
  for (int i : {0, 1}) {
    YACL_ENFORCE(starts[i] < (i == 0 ? meta.nrows : meta.ncols),
                 fmt::format("invalid start[{}]={}", i, starts[i]));

    YACL_ENFORCE(extents[i] > 0 && submat_shape[i] >= extents[i],
                 fmt::format("invalid extents[{}]={}", i, extents[i]));
  }

  concat_submat->resize(seal::util::mul_safe(submat_shape[0], submat_shape[1]));
  std::fill_n(concat_submat->data(), concat_submat->size(), 0);

  auto matrix_ptr = mat_view.data();
  for (size_t re = 0, r = starts[0]; re < extents[0]; ++re, ++r) {
    // NOTE(juhou) 2D matrix is stored in row-major
    auto dst_ptr = concat_submat->data() + re * submat_shape[1];
    auto src_ptr = matrix_ptr + r * meta.ncols;
    std::copy_n(src_ptr + starts[1], extents[1], dst_ptr);
  }
}

MatVecProtocol::MatVecProtocol(const seal::SEALContext &context,
                               const ModulusSwitchHelper &ms_helper)
    : poly_deg_(context.key_context_data()->parms().poly_modulus_degree()),
      encoder_(context, ms_helper),
      context_(context) {
  YACL_ENFORCE(context_.parameters_set());
}

bool MatVecProtocol::IsValidMeta(const Meta &meta) const {
  return meta.nrows > 0 && meta.ncols > 0;
}

template <typename T>
void MatVecProtocol::DoEncodeVector(const Meta &meta,
                                    absl::Span<const T> vec_view,
                                    std::vector<RLWEPt> *out) const {
  YACL_ENFORCE(IsValidMeta(meta));
  yacl::CheckNotNull(out);
  YACL_ENFORCE_EQ(vec_view.size(), GetVecSize(meta));
  auto submat_shape = GetSubMatrixShape(meta, poly_degree());

  size_t vec_len = vec_view.size();
  size_t num_subvec = CeilDiv(vec_len, submat_shape[1]);

  out->resize(num_subvec);
  for (size_t idx = 0; idx < num_subvec; ++idx) {
    size_t bgn = idx * submat_shape[1];
    size_t end = std::min(bgn + submat_shape[1], vec_len);
    absl::Span<const T> subvec(vec_view.data() + bgn, end - bgn);
    encoder_.Backward(subvec, out->data() + idx, /*scale*/ true);
  }
}

template <typename T>
void MatVecProtocol::DoMatVec(const Meta &meta, absl::Span<const T> mat_view,
                              const std::vector<RLWECt> &vec,
                              std::vector<LWECt> *out) const {
  YACL_ENFORCE(IsValidMeta(meta));
  YACL_ENFORCE_EQ(seal::util::mul_safe(meta.nrows, meta.ncols),
                  mat_view.size());
  yacl::CheckNotNull(out);

  auto submat_shape = GetSubMatrixShape(meta, poly_degree());

  std::array<size_t, 2> starts{0}, extents{0};
  std::vector<T> concat_submat(poly_deg_);
  seal::Evaluator evaluator(context_);

  out->resize(meta.nrows);
  for (size_t rbgn = 0; rbgn < meta.nrows; rbgn += submat_shape[0]) {
    starts[0] = rbgn;
    extents[0] = std::min(meta.nrows, rbgn + submat_shape[0]) - rbgn;

    RLWECt accumulated;
    for (size_t cbgn = 0; cbgn < meta.ncols; cbgn += submat_shape[1]) {
      starts[1] = cbgn;
      extents[1] = std::min(meta.ncols, cbgn + submat_shape[1]) - cbgn;

      ConcatSubMatrix<T>(mat_view, meta, starts, extents, submat_shape,
                         &concat_submat);

      if (!std::any_of(concat_submat.begin(), concat_submat.end(),
                       [](const T &x) { return x > 0; })) {
        // submatrix of all-zero entries
        continue;
      }

      RLWEPt mat_poly;
      encoder_.Forward(concat_submat, &mat_poly, /*scale*/ false);
      transform_to_ntt_inplace(mat_poly, context_);

      size_t col_block_idx = cbgn / submat_shape[1];
      RLWECt tmp;
      evaluator.multiply_plain(vec.at(col_block_idx), mat_poly, tmp);

      if (accumulated.size() > 0) {
        evaluator.add_inplace(accumulated, tmp);
      } else {
        accumulated = tmp;
      }
    }
    YACL_ENFORCE(accumulated.size() > 0,
                 fmt::format("all zero matrix is not supported for MatVec"));

    // position form for RLWE2LWE
    if (accumulated.is_ntt_form())
      evaluator.transform_from_ntt_inplace(accumulated);

    for (size_t r = 0; r < submat_shape[0]; ++r) {
      if (rbgn + r >= meta.nrows) break;
      size_t target_coeff = r * submat_shape[1];
      out->at(rbgn + r) = LWECt(accumulated, target_coeff, context_);
    }
  }
}

void MatVecProtocol::EncodeVector(const Meta &meta,
                                  absl::Span<const uint32_t> vec_view,
                                  std::vector<RLWEPt> *out) const {
  DoEncodeVector<uint32_t>(meta, vec_view, out);
}

void MatVecProtocol::EncodeVector(const Meta &meta,
                                  absl::Span<const uint64_t> vec_view,
                                  std::vector<RLWEPt> *out) const {
  DoEncodeVector<uint64_t>(meta, vec_view, out);
}

void MatVecProtocol::EncodeVector(const Meta &meta,
                                  absl::Span<const uint128_t> vec_view,
                                  std::vector<RLWEPt> *out) const {
  DoEncodeVector<uint128_t>(meta, vec_view, out);
}

void MatVecProtocol::MatVec(const Meta &meta,
                            absl::Span<const uint32_t> mat_view,
                            const std::vector<RLWECt> &vec,
                            std::vector<LWECt> *out) const {
  DoMatVec<uint32_t>(meta, mat_view, vec, out);
}

void MatVecProtocol::MatVec(const Meta &meta,
                            absl::Span<const uint64_t> mat_view,
                            const std::vector<RLWECt> &vec,
                            std::vector<LWECt> *out) const {
  DoMatVec<uint64_t>(meta, mat_view, vec, out);
}

void MatVecProtocol::MatVec(const Meta &meta,
                            absl::Span<const uint128_t> mat_view,
                            const std::vector<RLWECt> &vec,
                            std::vector<LWECt> *out) const {
  DoMatVec<uint128_t>(meta, mat_view, vec, out);
}

}  // namespace heu::expt::rlwe
