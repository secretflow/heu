#ifndef NTT_H
#define NTT_H

#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

#include "math/modulus.h"
#include "math/ntt_tables.h"

namespace bfv {
namespace math {
namespace ntt {

class NttOperator {
 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;

  NttOperator(std::unique_ptr<Impl> impl);
  void ForwardCore(uint64_t *data, bool reduce_output) const;
  void BackwardCore(uint64_t *data, bool reduce_output) const;

 public:
  NttOperator(const NttOperator &other);
  NttOperator(NttOperator &&other) noexcept;
  ~NttOperator();

  static std::optional<NttOperator> New(const zq::Modulus &p, size_t size);

  std::vector<uint64_t> Forward(const std::vector<uint64_t> &a) const;
  std::vector<uint64_t> Backward(const std::vector<uint64_t> &a) const;
  std::vector<uint64_t> ForwardVtLazy(const std::vector<uint64_t> &a) const;
  std::vector<uint64_t> ForwardVt(const std::vector<uint64_t> &a) const;
  std::vector<uint64_t> BackwardVt(const std::vector<uint64_t> &a) const;

  // Harvey NTT variants
  std::vector<uint64_t> ForwardHarvey(const std::vector<uint64_t> &a) const;
  std::vector<uint64_t> ForwardHarveyLazy(const std::vector<uint64_t> &a) const;
  std::vector<uint64_t> BackwardHarvey(const std::vector<uint64_t> &a) const;
  std::vector<uint64_t> BackwardHarveyLazy(
      const std::vector<uint64_t> &a) const;

  // Optimized variants with cache-friendly memory access
  std::vector<uint64_t> ForwardOptimized(const std::vector<uint64_t> &a) const;
  std::vector<uint64_t> BackwardOptimized(const std::vector<uint64_t> &a) const;
  uint64_t Reduce3(uint64_t x) const;
  std::vector<uint64_t> Reduce3Vt(const std::vector<uint64_t> &a) const;
  void Butterfly(uint64_t &u, uint64_t &v, uint64_t zeta,
                 uint64_t zeta_shoup) const;
  void ButterflyVt(uint64_t &u, uint64_t &v, uint64_t zeta,
                   uint64_t zeta_shoup) const;
  void InvButterfly(uint64_t &u, uint64_t &v, uint64_t zeta_inv,
                    uint64_t zeta_inv_shoup) const;
  void InvButterflyVt(uint64_t &u, uint64_t &v, uint64_t zeta_inv,
                      uint64_t zeta_inv_shoup) const;
  static uint64_t PrimitiveRoot(size_t size, const zq::Modulus &p);
  static bool IsPrimitiveRoot(uint64_t g, size_t size, const zq::Modulus &p);

  // In-place NTT operations for performance optimization
  void BackwardInPlace(uint64_t *data) const;
  void BackwardInPlaceLazy(uint64_t *data) const;
  void BackwardInPlaceLazyScaled(uint64_t *data, uint64_t scalar) const;
  void ForwardInPlaceLazy(uint64_t *data) const;
  void ForwardInPlace(uint64_t *data) const;

  // Access to internal NTT tables for direct Harvey NTT usage
  const NTTTables *GetNTTTables() const;
};

bool SupportsNtt(uint64_t p, size_t n);

}  // namespace ntt
}  // namespace math
}  // namespace bfv

#endif  // NTT_H
