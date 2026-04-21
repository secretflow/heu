#include <algorithm>
#include <cstring>
#include <vector>

#include "math/context.h"
#include "math/exceptions.h"
#include "math/ntt_harvey.h"
#include "math/poly_storage.h"

namespace bfv::math::rq {

std::vector<uint64_t> Poly::to_u64_vector() const {
  const size_t degree = pimpl_->ctx->degree();
  const size_t num_moduli = pimpl_->ctx->q().size();
  std::vector<uint64_t> result;
  result.reserve(num_moduli * degree);

  for (size_t i = 0; i < num_moduli; ++i) {
    const uint64_t *ptr = pimpl_->coefficients.get() + i * degree;
    result.insert(result.end(), ptr, ptr + degree);
  }

  return result;
}

std::vector<::bfv::math::rns::BigUint> Poly::to_biguint_vector() const {
  std::vector<::bfv::math::rns::BigUint> result;
  const size_t degree = pimpl_->ctx->degree();
  const size_t num_moduli = pimpl_->ctx->q().size();
  result.reserve(degree);

  for (size_t i = 0; i < degree; ++i) {
    std::vector<uint64_t> coeff_values;
    coeff_values.reserve(num_moduli);

    for (size_t j = 0; j < num_moduli; ++j) {
      coeff_values.push_back((pimpl_->coefficients.get() + j * degree)[i]);
    }

    result.push_back(pimpl_->ctx->rns()->lift(coeff_values));
  }

  return result;
}

Poly Poly::from_u64_vector(const std::vector<uint64_t> &coeffs,
                           std::shared_ptr<const Context> context,
                           bool variable_time, Representation representation,
                           bool has_lazy_coefficients) {
  size_t expected_flattened_size = context->q().size() * context->degree();
  size_t expected_single_size = context->degree();

  if (coeffs.size() != expected_flattened_size &&
      coeffs.size() != expected_single_size) {
    throw DefaultException(
        "Coefficient vector size must match either context degree or "
        "moduli_count * degree");
  }

  auto poly = zero(context, Representation::PowerBasis);

  if (variable_time) {
    poly.pimpl_->allow_variable_time_computations = true;
  }

  if (coeffs.size() == expected_flattened_size) {
    for (size_t i = 0; i < context->q().size(); ++i) {
      const auto &qi = context->q()[i];
      uint64_t *poly_coeffs =
          poly.pimpl_->coefficients.get() + i * context->degree();

      for (size_t j = 0; j < context->degree(); ++j) {
        size_t coeff_idx = i * context->degree() + j;
        poly_coeffs[j] = qi.Reduce(coeffs[coeff_idx]);
      }
    }
  } else {
    for (size_t i = 0; i < context->q().size(); ++i) {
      const auto &qi = context->q()[i];
      uint64_t *poly_coeffs =
          poly.pimpl_->coefficients.get() + i * context->degree();

      for (size_t j = 0; j < coeffs.size(); ++j) {
        poly_coeffs[j] = qi.Reduce(coeffs[j]);
      }
    }
  }

  poly.pimpl_->has_lazy_coefficients = has_lazy_coefficients;

  if (representation != Representation::PowerBasis) {
    poly.change_representation(representation);
  }

  return poly;
}

Poly Poly::from_i64_vector(const std::vector<int64_t> &coeffs,
                           std::shared_ptr<const Context> context,
                           bool variable_time, Representation representation) {
  if (coeffs.size() != context->degree()) {
    throw DefaultException("Coefficient vector size must match context degree");
  }

  auto poly = zero(context, Representation::PowerBasis);

  if (variable_time) {
    poly.pimpl_->allow_variable_time_computations = true;
  }

  for (size_t i = 0; i < context->q().size(); ++i) {
    const auto &qi = context->q()[i];
    uint64_t *poly_coeffs =
        poly.pimpl_->coefficients.get() + i * context->degree();

    for (size_t j = 0; j < coeffs.size(); ++j) {
      if (coeffs[j] >= 0) {
        poly_coeffs[j] = qi.Reduce(static_cast<uint64_t>(coeffs[j]));
      } else {
        uint64_t abs_coeff = static_cast<uint64_t>(-coeffs[j]);
        poly_coeffs[j] = qi.Sub(0, qi.Reduce(abs_coeff));
      }
    }
  }

  if (representation != Representation::PowerBasis) {
    poly.change_representation(representation);
  }

  return poly;
}

Poly Poly::from_biguint_vector(
    const std::vector<::bfv::math::rns::BigUint> &coeffs,
    std::shared_ptr<const Context> context, bool variable_time,
    Representation representation) {
  if (coeffs.size() != context->degree()) {
    throw DefaultException("Coefficient vector size must match context degree");
  }

  auto poly = zero(context, Representation::PowerBasis);

  if (variable_time) {
    poly.pimpl_->allow_variable_time_computations = true;
  }

  for (size_t j = 0; j < coeffs.size(); ++j) {
    auto rns_coeff = context->rns()->project(coeffs[j]);

    for (size_t i = 0; i < context->q().size(); ++i) {
      (poly.pimpl_->coefficients.get() + i * context->degree())[j] =
          rns_coeff[i];
    }
  }

  if (representation != Representation::PowerBasis) {
    poly.change_representation(representation);
  }

  return poly;
}

Poly Poly::from_coefficients(
    const std::vector<std::vector<uint64_t>> &coefficients,
    std::shared_ptr<const Context> ctx, bool variable_time,
    Representation representation, bool has_lazy_coefficients) {
  if (coefficients.size() != ctx->q().size()) {
    throw DefaultException(
        "Coefficients outer size must match number of moduli");
  }
  for (const auto &mod_coeffs : coefficients) {
    if (mod_coeffs.size() != ctx->degree()) {
      throw DefaultException(
          "Coefficients inner size must match context degree");
    }
  }

  std::vector<std::vector<uint64_t>> reduced_coeffs = coefficients;

  for (size_t i = 0; i < ctx->q().size(); ++i) {
    const auto &qi = ctx->q()[i];
    auto &mod_coeffs = reduced_coeffs[i];
    for (size_t j = 0; j < ctx->degree(); ++j) {
      mod_coeffs[j] = qi.Reduce(mod_coeffs[j]);
    }
  }

  auto poly = from_coefficients_internal(
      ctx, Representation::PowerBasis, variable_time, std::move(reduced_coeffs),
      has_lazy_coefficients);

  if (representation != Representation::PowerBasis) {
    poly.change_representation(representation);
  }

  return poly;
}

Poly Poly::from_coefficients_internal(
    std::shared_ptr<const ::bfv::math::rq::Context> context,
    ::bfv::math::rq::Representation representation, bool allow_variable_time,
    std::vector<std::vector<uint64_t>> &&coefficients,
    bool has_lazy_coefficients) {
  auto impl = std::make_unique<Impl>();
  impl->ctx = std::move(context);
  impl->representation = representation;
  impl->allow_variable_time_computations = allow_variable_time;

  size_t size = impl->ctx->degree() * impl->ctx->q().size();
  impl->coefficients = impl->pool.allocate<uint64_t>(size);

  for (size_t i = 0; i < impl->ctx->q().size(); ++i) {
    std::copy(coefficients[i].begin(), coefficients[i].end(),
              impl->coefficients.get() + i * impl->ctx->degree());
  }

  impl->has_lazy_coefficients = has_lazy_coefficients;
  impl->coefficients_shoup = nullptr;

  return Poly(std::move(impl));
}

std::vector<uint8_t> Poly::to_bytes() const {
  std::vector<uint8_t> result;

  uint8_t repr_byte = static_cast<uint8_t>(pimpl_->representation);
  result.push_back(repr_byte);

  uint8_t var_time_byte = pimpl_->allow_variable_time_computations ? 1 : 0;
  result.push_back(var_time_byte);

  uint8_t lazy_byte = pimpl_->has_lazy_coefficients ? 1 : 0;
  result.push_back(lazy_byte);

  const size_t degree = pimpl_->ctx->degree();
  const size_t num_moduli = pimpl_->ctx->q().size();

  uint32_t num_moduli_u32 = static_cast<uint32_t>(num_moduli);
  result.insert(
      result.end(), reinterpret_cast<const uint8_t *>(&num_moduli_u32),
      reinterpret_cast<const uint8_t *>(&num_moduli_u32) + sizeof(uint32_t));

  uint32_t degree_u32 = static_cast<uint32_t>(degree);
  result.insert(
      result.end(), reinterpret_cast<const uint8_t *>(&degree_u32),
      reinterpret_cast<const uint8_t *>(&degree_u32) + sizeof(uint32_t));

  for (size_t i = 0; i < num_moduli; ++i) {
    const uint64_t *ptr = pimpl_->coefficients.get() + i * degree;
    const uint8_t *byte_ptr = reinterpret_cast<const uint8_t *>(ptr);
    result.insert(result.end(), byte_ptr, byte_ptr + degree * sizeof(uint64_t));
  }

  uint8_t has_multiply_hints = pimpl_->coefficients_shoup ? 1 : 0;
  result.push_back(has_multiply_hints);
  if (has_multiply_hints) {
    for (size_t i = 0; i < num_moduli; ++i) {
      const uint64_t *ptr = pimpl_->coefficients_shoup.get() + i * degree;
      const uint8_t *byte_ptr = reinterpret_cast<const uint8_t *>(ptr);
      result.insert(result.end(), byte_ptr,
                    byte_ptr + degree * sizeof(uint64_t));
    }
  }

  return result;
}

Poly Poly::from_bytes(const std::vector<uint8_t> &bytes,
                      std::shared_ptr<const ::bfv::math::rq::Context> context,
                      ::bfv::util::ArenaHandle pool) {
  if (bytes.size() < 11) {
    throw ::bfv::math::rq::DefaultException(
        "Invalid serialized polynomial data: too short");
  }

  size_t offset = 0;

  uint8_t repr_byte = bytes[offset++];
  ::bfv::math::rq::Representation representation =
      static_cast<::bfv::math::rq::Representation>(repr_byte);

  uint8_t var_time_byte = bytes[offset++];
  bool allow_variable_time = (var_time_byte != 0);

  uint8_t lazy_byte = bytes[offset++];
  bool has_lazy_coefficients = (lazy_byte != 0);

  uint32_t num_moduli;
  std::memcpy(&num_moduli, bytes.data() + offset, sizeof(uint32_t));
  offset += sizeof(uint32_t);

  uint32_t degree;
  std::memcpy(&degree, bytes.data() + offset, sizeof(uint32_t));
  offset += sizeof(uint32_t);

  if (context->q().size() != num_moduli || context->degree() != degree) {
    throw ::bfv::math::rq::DefaultException(
        "Serialized polynomial metadata does not match the requested ring "
        "context");
  }

  auto impl = std::make_unique<::bfv::math::rq::Poly::Impl>(std::move(pool));
  impl->ctx = context;
  impl->representation = representation;
  impl->allow_variable_time_computations = allow_variable_time;
  impl->has_lazy_coefficients = has_lazy_coefficients;

  size_t size = num_moduli * degree;
  impl->coefficients = impl->pool.allocate<uint64_t>(size);

  if (offset + size * sizeof(uint64_t) > bytes.size()) {
    throw ::bfv::math::rq::DefaultException(
        "Invalid serialized polynomial data: insufficient coefficient payload");
  }
  std::memcpy(impl->coefficients.get(), bytes.data() + offset,
              size * sizeof(uint64_t));
  offset += size * sizeof(uint64_t);

  if (offset >= bytes.size()) {
    throw ::bfv::math::rq::DefaultException(
        "Invalid serialized polynomial data: missing multiply-hint flag");
  }
  uint8_t has_multiply_hints = bytes[offset++];
  if (has_multiply_hints) {
    if (offset + size * sizeof(uint64_t) > bytes.size()) {
      throw ::bfv::math::rq::DefaultException(
          "Invalid serialized polynomial data: insufficient multiply-hint "
          "data");
    }
    impl->coefficients_shoup = impl->pool.allocate<uint64_t>(size);
    std::memcpy(impl->coefficients_shoup.get(), bytes.data() + offset,
                size * sizeof(uint64_t));
    offset += size * sizeof(uint64_t);
  }

  return ::bfv::math::rq::Poly(std::move(impl));
}

Poly Poly::
    create_constant_ntt_polynomial_with_lazy_coefficients_and_variable_time(
        const std::vector<uint64_t> &power_basis_coefficients,
        std::shared_ptr<const ::bfv::math::rq::Context> context) {
  return create_constant_ntt_polynomial_with_lazy_coefficients_and_variable_time(
      power_basis_coefficients.data(), power_basis_coefficients.size(),
      context);
}

Poly Poly::
    create_constant_ntt_polynomial_with_lazy_coefficients_and_variable_time(
        const uint64_t *power_basis_coefficients, size_t coefficient_count,
        std::shared_ptr<const ::bfv::math::rq::Context> context) {
  auto poly = ::bfv::math::rq::Poly::uninitialized(
      context, ::bfv::math::rq::Representation::Ntt);
  fill_constant_ntt_polynomial_with_lazy_coefficients_and_variable_time(
      power_basis_coefficients, coefficient_count, poly);
  return poly;
}

void Poly::
    fill_constant_ntt_polynomial_with_lazy_coefficients_and_variable_time(
        const uint64_t *power_basis_coefficients, size_t coefficient_count,
        Poly &out) {
  if (!out.pimpl_->ctx) {
    throw ::bfv::math::rq::DefaultException(
        "Output polynomial is not initialized");
  }
  if (out.pimpl_->representation != ::bfv::math::rq::Representation::Ntt) {
    throw ::bfv::math::rq::DefaultException(
        "Constant-NTT fill requires an output polynomial tagged as Ntt");
  }

  out.pimpl_->allow_variable_time_computations = true;
  out.pimpl_->has_lazy_coefficients = true;

  const auto &context = out.pimpl_->ctx;
  const size_t degree = context->degree();
  const size_t copy_len = std::min(coefficient_count, degree);
  for (size_t i = 0; i < context->q().size(); ++i) {
    const auto &qi = context->q()[i];
    uint64_t *poly_coeffs = out.data(i);

    for (size_t j = 0; j < copy_len; ++j) {
      poly_coeffs[j] = qi.LazyReduce(power_basis_coefficients[j]);
    }
    std::fill_n(poly_coeffs + copy_len, degree - copy_len, uint64_t{0});
    context->ops()[i].ForwardInPlaceLazy(poly_coeffs);
  }
}

void Poly::
    fill_constant_ntt_polynomial_with_lazy_coefficients_and_variable_time(
        const uint64_t *power_basis_coefficients, size_t coefficient_count,
        size_t source_modulus_index, Poly &out) {
  if (!out.pimpl_->ctx) {
    throw ::bfv::math::rq::DefaultException(
        "Output polynomial is not initialized");
  }
  if (out.pimpl_->representation != ::bfv::math::rq::Representation::Ntt) {
    throw ::bfv::math::rq::DefaultException(
        "Constant-NTT fill requires an output polynomial tagged as Ntt");
  }

  out.pimpl_->allow_variable_time_computations = true;
  out.pimpl_->has_lazy_coefficients = true;

  const auto &context = out.pimpl_->ctx;
  const size_t degree = context->degree();
  const size_t copy_len = std::min(coefficient_count, degree);
  const uint64_t source_modulus_value =
      (source_modulus_index < context->q().size())
          ? context->q()[source_modulus_index].P()
          : 0;
  for (size_t i = 0; i < context->q().size(); ++i) {
    const auto &qi = context->q()[i];
    uint64_t *poly_coeffs = out.data(i);
    const uint64_t target_modulus = qi.P();

    if (source_modulus_value != 0 && source_modulus_value <= target_modulus) {
      std::memcpy(poly_coeffs, power_basis_coefficients,
                  copy_len * sizeof(uint64_t));
    } else if (source_modulus_value != 0 &&
               source_modulus_value < (target_modulus << 1)) {
      for (size_t j = 0; j < copy_len; ++j) {
        uint64_t value = power_basis_coefficients[j];
        poly_coeffs[j] =
            value >= target_modulus ? value - target_modulus : value;
      }
    } else {
      std::memcpy(poly_coeffs, power_basis_coefficients,
                  copy_len * sizeof(uint64_t));
      qi.ReduceVec(poly_coeffs, copy_len);
    }
    std::fill_n(poly_coeffs + copy_len, degree - copy_len, uint64_t{0});
    context->ops()[i].ForwardInPlaceLazy(poly_coeffs);
  }
}

void Poly::
    fill_constant_ntt_polynomial4_with_lazy_coefficients_and_variable_time(
        const uint64_t *coeff0, const uint64_t *coeff1, const uint64_t *coeff2,
        const uint64_t *coeff3, size_t coefficient_count, Poly &out0,
        Poly &out1, Poly &out2, Poly &out3) {
  auto validate_output = [](Poly &out) {
    if (!out.pimpl_->ctx) {
      throw ::bfv::math::rq::DefaultException(
          "Output polynomial is not initialized");
    }
    if (out.pimpl_->representation != ::bfv::math::rq::Representation::Ntt) {
      throw ::bfv::math::rq::DefaultException(
          "Constant-NTT fill requires an output polynomial tagged as Ntt");
    }
    out.pimpl_->allow_variable_time_computations = true;
    out.pimpl_->has_lazy_coefficients = true;
  };

  validate_output(out0);
  validate_output(out1);
  validate_output(out2);
  validate_output(out3);

  const auto &context = out0.pimpl_->ctx;
  if (out1.pimpl_->ctx != context || out2.pimpl_->ctx != context ||
      out3.pimpl_->ctx != context) {
    throw ::bfv::math::rq::DefaultException(
        "All output polynomials must share the same context");
  }

  const size_t degree = context->degree();
  const size_t copy_len = std::min(coefficient_count, degree);
  for (size_t i = 0; i < context->q().size(); ++i) {
    const auto &qi = context->q()[i];
    uint64_t *out0_coeffs = out0.data(i);
    uint64_t *out1_coeffs = out1.data(i);
    uint64_t *out2_coeffs = out2.data(i);
    uint64_t *out3_coeffs = out3.data(i);

    for (size_t j = 0; j < copy_len; ++j) {
      out0_coeffs[j] = qi.LazyReduce(coeff0[j]);
      out1_coeffs[j] = qi.LazyReduce(coeff1[j]);
      out2_coeffs[j] = qi.LazyReduce(coeff2[j]);
      out3_coeffs[j] = qi.LazyReduce(coeff3[j]);
    }
    std::fill_n(out0_coeffs + copy_len, degree - copy_len, uint64_t{0});
    std::fill_n(out1_coeffs + copy_len, degree - copy_len, uint64_t{0});
    std::fill_n(out2_coeffs + copy_len, degree - copy_len, uint64_t{0});
    std::fill_n(out3_coeffs + copy_len, degree - copy_len, uint64_t{0});

    const auto *tables = context->ops()[i].GetNTTTables();
    if (tables) {
      ::bfv::math::ntt::HarveyNTT::HarveyNttLazy4(
          out0_coeffs, out1_coeffs, out2_coeffs, out3_coeffs, *tables);
    } else {
      context->ops()[i].ForwardInPlaceLazy(out0_coeffs);
      context->ops()[i].ForwardInPlaceLazy(out1_coeffs);
      context->ops()[i].ForwardInPlaceLazy(out2_coeffs);
      context->ops()[i].ForwardInPlaceLazy(out3_coeffs);
    }
  }
}

void Poly::
    fill_constant_ntt_polynomial4_with_lazy_coefficients_and_variable_time(
        const uint64_t *coeff0, const uint64_t *coeff1, const uint64_t *coeff2,
        const uint64_t *coeff3, size_t coefficient_count, size_t source_index0,
        size_t source_index1, size_t source_index2, size_t source_index3,
        Poly &out0, Poly &out1, Poly &out2, Poly &out3) {
  auto validate_output = [](Poly &out) {
    if (!out.pimpl_->ctx) {
      throw ::bfv::math::rq::DefaultException(
          "Output polynomial is not initialized");
    }
    if (out.pimpl_->representation != ::bfv::math::rq::Representation::Ntt) {
      throw ::bfv::math::rq::DefaultException(
          "Constant-NTT fill requires an output polynomial tagged as Ntt");
    }
    out.pimpl_->allow_variable_time_computations = true;
    out.pimpl_->has_lazy_coefficients = true;
  };

  validate_output(out0);
  validate_output(out1);
  validate_output(out2);
  validate_output(out3);

  const auto &context = out0.pimpl_->ctx;
  if (out1.pimpl_->ctx != context || out2.pimpl_->ctx != context ||
      out3.pimpl_->ctx != context) {
    throw ::bfv::math::rq::DefaultException(
        "All output polynomials must share the same context");
  }

  const size_t degree = context->degree();
  const size_t copy_len = std::min(coefficient_count, degree);
  const uint64_t source_modulus0 = (source_index0 < context->q().size())
                                       ? context->q()[source_index0].P()
                                       : 0;
  const uint64_t source_modulus1 = (source_index1 < context->q().size())
                                       ? context->q()[source_index1].P()
                                       : 0;
  const uint64_t source_modulus2 = (source_index2 < context->q().size())
                                       ? context->q()[source_index2].P()
                                       : 0;
  const uint64_t source_modulus3 = (source_index3 < context->q().size())
                                       ? context->q()[source_index3].P()
                                       : 0;
  for (size_t i = 0; i < context->q().size(); ++i) {
    const auto &qi = context->q()[i];
    uint64_t *out0_coeffs = out0.data(i);
    uint64_t *out1_coeffs = out1.data(i);
    uint64_t *out2_coeffs = out2.data(i);
    uint64_t *out3_coeffs = out3.data(i);
    const uint64_t target_modulus = qi.P();

    if (source_modulus0 != 0 && source_modulus0 <= target_modulus) {
      std::memcpy(out0_coeffs, coeff0, copy_len * sizeof(uint64_t));
    } else if (source_modulus0 != 0 &&
               source_modulus0 < (target_modulus << 1)) {
      for (size_t j = 0; j < copy_len; ++j) {
        uint64_t value = coeff0[j];
        out0_coeffs[j] =
            value >= target_modulus ? value - target_modulus : value;
      }
    } else {
      std::memcpy(out0_coeffs, coeff0, copy_len * sizeof(uint64_t));
      qi.ReduceVec(out0_coeffs, copy_len);
    }
    if (source_modulus1 != 0 && source_modulus1 <= target_modulus) {
      std::memcpy(out1_coeffs, coeff1, copy_len * sizeof(uint64_t));
    } else if (source_modulus1 != 0 &&
               source_modulus1 < (target_modulus << 1)) {
      for (size_t j = 0; j < copy_len; ++j) {
        uint64_t value = coeff1[j];
        out1_coeffs[j] =
            value >= target_modulus ? value - target_modulus : value;
      }
    } else {
      std::memcpy(out1_coeffs, coeff1, copy_len * sizeof(uint64_t));
      qi.ReduceVec(out1_coeffs, copy_len);
    }
    if (source_modulus2 != 0 && source_modulus2 <= target_modulus) {
      std::memcpy(out2_coeffs, coeff2, copy_len * sizeof(uint64_t));
    } else if (source_modulus2 != 0 &&
               source_modulus2 < (target_modulus << 1)) {
      for (size_t j = 0; j < copy_len; ++j) {
        uint64_t value = coeff2[j];
        out2_coeffs[j] =
            value >= target_modulus ? value - target_modulus : value;
      }
    } else {
      std::memcpy(out2_coeffs, coeff2, copy_len * sizeof(uint64_t));
      qi.ReduceVec(out2_coeffs, copy_len);
    }
    if (source_modulus3 != 0 && source_modulus3 <= target_modulus) {
      std::memcpy(out3_coeffs, coeff3, copy_len * sizeof(uint64_t));
    } else if (source_modulus3 != 0 &&
               source_modulus3 < (target_modulus << 1)) {
      for (size_t j = 0; j < copy_len; ++j) {
        uint64_t value = coeff3[j];
        out3_coeffs[j] =
            value >= target_modulus ? value - target_modulus : value;
      }
    } else {
      std::memcpy(out3_coeffs, coeff3, copy_len * sizeof(uint64_t));
      qi.ReduceVec(out3_coeffs, copy_len);
    }
    std::fill_n(out0_coeffs + copy_len, degree - copy_len, uint64_t{0});
    std::fill_n(out1_coeffs + copy_len, degree - copy_len, uint64_t{0});
    std::fill_n(out2_coeffs + copy_len, degree - copy_len, uint64_t{0});
    std::fill_n(out3_coeffs + copy_len, degree - copy_len, uint64_t{0});

    const auto *tables = context->ops()[i].GetNTTTables();
    if (tables) {
      ::bfv::math::ntt::HarveyNTT::HarveyNttLazy4(
          out0_coeffs, out1_coeffs, out2_coeffs, out3_coeffs, *tables);
    } else {
      context->ops()[i].ForwardInPlaceLazy(out0_coeffs);
      context->ops()[i].ForwardInPlaceLazy(out1_coeffs);
      context->ops()[i].ForwardInPlaceLazy(out2_coeffs);
      context->ops()[i].ForwardInPlaceLazy(out3_coeffs);
    }
  }
}

}  // namespace bfv::math::rq
