#include <stdexcept>
#include <string>
#include <vector>

#include "math/modulus.h"
#include "math/primes.h"
#include "math/rns_transfer_plan.h"

namespace bfv {
namespace math {
namespace rns {
namespace internal {

TransferKernelCache::DecodeBridgeBackend BuildDecodeBridgeBackend(
    const std::shared_ptr<RnsContext> &from_ctx,
    const std::shared_ptr<RnsContext> &to_ctx) {
  TransferKernelCache::DecodeBridgeBackend decode_backend;
  decode_backend.enabled = (to_ctx->moduli_u64().size() == 1);
  if (!decode_backend.enabled) {
    return decode_backend;
  }

  decode_backend.primary_channel_modulus = to_ctx->moduli_u64()[0];
  for (auto q : from_ctx->moduli_u64()) {
    if (q == decode_backend.primary_channel_modulus) {
      decode_backend.enabled = false;
      return decode_backend;
    }
  }

  BigUint q_product = from_ctx->modulus();
  decode_backend.neg_inv_q_mod_dual_channel.resize(2);
  uint64_t q_mod_primary =
      (q_product % BigUint(decode_backend.primary_channel_modulus)).to_u64();
  if (q_mod_primary == 0) {
    decode_backend.enabled = false;
    return decode_backend;
  }

  auto primary_channel =
      zq::Modulus::New(decode_backend.primary_channel_modulus);
  if (!primary_channel.has_value()) {
    throw std::runtime_error(
        "Decode bridge: unable to create the primary channel operator for " +
        std::to_string(decode_backend.primary_channel_modulus));
  }

  auto inv_q_primary = primary_channel->Inv(q_mod_primary);
  if (!inv_q_primary.has_value()) {
    throw std::runtime_error(
        "Decode bridge: unable to derive Q inverse inside the primary channel");
  }
  decode_backend.neg_inv_q_mod_dual_channel[0] =
      primary_channel->Neg(inv_q_primary.value());

  while (true) {
    auto maybe_correction = zq::generate_prime(60, 2, 1ULL << 60);
    if (!maybe_correction.has_value()) {
      decode_backend.correction_channel_modulus = 0xffffffffffc0001;
      break;
    }
    uint64_t candidate = maybe_correction.value();
    if (candidate == decode_backend.primary_channel_modulus) {
      continue;
    }
    bool disjoint = true;
    for (auto q : from_ctx->moduli_u64()) {
      if (q == candidate) {
        disjoint = false;
        break;
      }
    }
    if (disjoint) {
      decode_backend.correction_channel_modulus = candidate;
      break;
    }
  }

  decode_backend.dual_channel_ctx = RnsContext::create(
      std::vector<uint64_t>{decode_backend.primary_channel_modulus,
                            decode_backend.correction_channel_modulus});
  decode_backend.correction_channel_half =
      decode_backend.correction_channel_modulus >> 1;
  decode_backend.main_to_dual_channel_converter =
      std::make_unique<BaseConverter>(from_ctx,
                                      decode_backend.dual_channel_ctx);

  const size_t q_size = from_ctx->moduli_u64().size();
  decode_backend.primary_correction_scale_mod_q.resize(q_size);
  unsigned __int128 primary_correction_scale =
      (unsigned __int128)decode_backend.primary_channel_modulus *
      decode_backend.correction_channel_modulus;
  for (size_t i = 0; i < q_size; ++i) {
    decode_backend.primary_correction_scale_mod_q[i] =
        from_ctx->moduli()[i].ReduceU128(primary_correction_scale);
  }

  uint64_t q_mod_correction =
      (q_product % BigUint(decode_backend.correction_channel_modulus)).to_u64();
  auto correction_channel =
      zq::Modulus::New(decode_backend.correction_channel_modulus);
  if (!correction_channel.has_value()) {
    throw std::runtime_error(
        "Decode bridge: unable to create the correction channel operator");
  }

  auto inv_q_correction = correction_channel->Inv(q_mod_correction);
  if (!inv_q_correction.has_value()) {
    throw std::runtime_error(
        "Decode bridge: unable to derive Q inverse inside the correction "
        "channel");
  }
  decode_backend.neg_inv_q_mod_dual_channel[1] =
      correction_channel->Neg(inv_q_correction.value());

  decode_backend.inv_correction_channel_mod_primary =
      primary_channel
          ->Inv(decode_backend.primary_channel_modulus >
                        decode_backend.correction_channel_modulus
                    ? decode_backend.correction_channel_modulus
                    : (decode_backend.correction_channel_modulus %
                       decode_backend.primary_channel_modulus))
          .value();
  decode_backend.inv_correction_channel_mod_primary_shoup =
      primary_channel->Shoup(decode_backend.inv_correction_channel_mod_primary);
  return decode_backend;
}

}  // namespace internal
}  // namespace rns
}  // namespace math
}  // namespace bfv
